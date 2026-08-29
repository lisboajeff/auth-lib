package knin.auth.jwt.demo;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import jakarta.inject.Inject;
import knin.auth.jwt.demo.dto.CreateTokenRequest;
import knin.auth.jwt.demo.dto.CreateTokenResponse;
import knin.auth.jwt.demo.dto.VerifyTokenResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.List;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

@QuarkusTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthResourceTest {

    private static final String BUCKET = "auth-bucket";
    private static final String S3_KEY = "jwks.json";

    @Inject
    S3AsyncClient s3AsyncClient;

    @Inject
    MemoryPolling memoryPolling;

    private String expectedKid;
    private boolean isLocalStackAvailable = false;

    @BeforeAll
    void setUp() {
        try {
            final RSAPublicKey pubKey = loadPublicKeyFromResource("private_key.pem");
            final RSAKey rsaJwk = new RSAKey.Builder(pubKey).build();
            this.expectedKid = rsaJwk.computeThumbprint().toString();

            final RSAKey rsaJwkWithKid = new RSAKey.Builder(pubKey)
                    .keyID(expectedKid)
                    .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256)
                    .build();
            final byte[] jwksBytes = new JWKSet(rsaJwkWithKid).toString().getBytes(StandardCharsets.UTF_8);

            try {
                s3AsyncClient.createBucket(CreateBucketRequest.builder().bucket(BUCKET).build()).join();
            } catch (Exception ignored) {}

            s3AsyncClient.putObject(
                    PutObjectRequest.builder().bucket(BUCKET).key(S3_KEY).contentType("application/json").build(),
                    AsyncRequestBody.fromBytes(jwksBytes)
            ).join();

            memoryPolling.refreshFromS3().join();
            isLocalStackAvailable = true;
        } catch (Exception e) {
            isLocalStackAvailable = false;
        }
    }

    @Test
    @DisplayName("POST /api/auth/token should create a signed JWT with RFC 7638 Thumbprint KID")
    void shouldCreateTokenSuccessfully() {
        final CreateTokenRequest request = new CreateTokenRequest(
                "john-doe",
                List.of("READ", "WRITE", "ORDERS_ADMIN"),
                3600_000L,
                false
        );

        final CreateTokenResponse response = given()
                .contentType(ContentType.JSON)
                .body(request)
                .when()
                .post("/api/auth/token")
                .then()
                .statusCode(201)
                .body("token", notNullValue())
                .body("kid", equalTo(expectedKid))
                .body("subject", equalTo("john-doe"))
                .body("scopes", hasItems("READ", "WRITE", "ORDERS_ADMIN"))
                .extract()
                .as(CreateTokenResponse.class);

        assertNotNull(response.token());
        assertEquals(expectedKid, response.kid());
        assertEquals("john-doe", response.subject());
    }

    @Test
    @DisplayName("POST /api/auth/verify should validate token passed via Authorization Bearer Header")
    void shouldVerifyTokenViaAuthorizationHeader() {
        if (!isLocalStackAvailable) return;

        // 1. Create token containing the server's required scope ("READ")
        final CreateTokenRequest createReqWithScope = new CreateTokenRequest(
                "alice",
                List.of("READ", "PAYMENTS_PROCESS"),
                3600_000L,
                false
        );

        final CreateTokenResponse tokenWithScope = given()
                .contentType(ContentType.JSON)
                .body(createReqWithScope)
                .when()
                .post("/api/auth/token")
                .then()
                .statusCode(201)
                .extract()
                .as(CreateTokenResponse.class);

        // 2. Verify token containing "READ" via Authorization Header -> 200 OK
        given()
                .header("Authorization", "Bearer " + tokenWithScope.token())
                .when()
                .post("/api/auth/verify")
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("hasRequiredScope", equalTo(true))
                .body("kid", equalTo(expectedKid))
                .body("formattedJwt", notNullValue());

        // 3. Create token MISSING the server's required scope ("READ")
        final CreateTokenRequest createReqMissingScope = new CreateTokenRequest(
                "charlie",
                List.of("ONLY_CUSTOM_SCOPE"),
                3600_000L,
                false
        );

        final CreateTokenResponse tokenWithoutScope = given()
                .contentType(ContentType.JSON)
                .body(createReqMissingScope)
                .when()
                .post("/api/auth/token")
                .then()
                .statusCode(201)
                .extract()
                .as(CreateTokenResponse.class);

        // 4. Verify token missing "READ" via Authorization Header -> 403 Forbidden
        given()
                .header("Authorization", "Bearer " + tokenWithoutScope.token())
                .when()
                .post("/api/auth/verify")
                .then()
                .statusCode(403)
                .body("valid", equalTo(true))
                .body("hasRequiredScope", equalTo(false));

        // 5. Verify request without Authorization Header -> 400 Bad Request
        given()
                .when()
                .post("/api/auth/verify")
                .then()
                .statusCode(400)
                .body("valid", equalTo(false));
    }

    @Test
    @DisplayName("POST /api/auth/token and /api/auth/verify should work seamlessly with 4-part GZIP tokens")
    void shouldCreateAndVerifyFourPartsGzipToken() {
        if (!isLocalStackAvailable) return;

        final CreateTokenRequest createReq = new CreateTokenRequest(
                "bob",
                List.of("READ", "GZIP_BILLING", "GZIP_REPORTS"),
                3600_000L,
                true
        );

        final CreateTokenResponse createResp = given()
                .contentType(ContentType.JSON)
                .body(createReq)
                .when()
                .post("/api/auth/token")
                .then()
                .statusCode(201)
                .extract()
                .as(CreateTokenResponse.class);

        // Verify that token has 4 segments
        assertEquals(4, createResp.token().split("\\.").length);

        // Verify via /verify endpoint (with Bearer header)
        final VerifyTokenResponse verifyResp = given()
                .header("Authorization", "Bearer " + createResp.token())
                .when()
                .post("/api/auth/verify")
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("hasRequiredScope", equalTo(true))
                .extract()
                .as(VerifyTokenResponse.class);

        // Verify returned JWT is formatted in 3 parts
        assertEquals(3, verifyResp.formattedJwt().split("\\.").length);
    }

    @Test
    @DisplayName("GET /.well-known/jwks.json and /api/auth/jwks should return public JWKS from memory cache")
    void shouldReturnPublicJwks() {
        if (!isLocalStackAvailable) return;

        // 1. Test standard OpenID Connect endpoint
        given()
                .when()
                .get("/.well-known/jwks.json")
                .then()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .body("keys", notNullValue())
                .body("keys.kid", hasItem(expectedKid))
                .body("keys.kty", hasItem("RSA"))
                .body("keys.alg", hasItem("RS256"));

        // 2. Test API endpoint
        given()
                .when()
                .get("/api/auth/jwks")
                .then()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .body("keys", notNullValue())
                .body("keys.kid", hasItem(expectedKid));
    }

    private static RSAPublicKey loadPublicKeyFromResource(final String resourcePath) {
        try (InputStream is = AuthResourceTest.class.getClassLoader().getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new IllegalArgumentException("Resource not found: " + resourcePath);
            }
            final String pem = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            final String privateKeyPEM = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");

            final byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
            final KeyFactory kf = KeyFactory.getInstance("RSA");
            final RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
            final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privKey.getModulus(), privKey.getPublicExponent());
            return (RSAPublicKey) kf.generatePublic(publicKeySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load public key from PEM", e);
        }
    }

}
