package knin.auth.jwt.demo;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import knin.auth.jwt.demo.dto.VerifyTokenResponse;
import knin.auth.jwt.domain.validate.Token;
import knin.auth.jwt.option.Introspect;
import knin.auth.jwt.option.Introspection;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@QuarkusTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class KeyRotationIntegrationTest {

    private static final String BUCKET = "auth-bucket";
    private static final String S3_KEY = "jwks.json";

    @Inject
    S3AsyncClient s3AsyncClient;

    @Inject
    Introspect introspect;

    @Inject
    MemoryPolling memoryPolling;

    @Inject
    AuthService authService;

    private boolean isLocalStackAvailable = false;

    @BeforeAll
    void setUp() {
        try {
            try {
                s3AsyncClient.createBucket(CreateBucketRequest.builder().bucket(BUCKET).build()).join();
            } catch (Exception ignored) {}

            isLocalStackAvailable = true;
        } catch (Exception e) {
            isLocalStackAvailable = false;
        }
    }

    @Test
    @DisplayName("Seamless Key Rotation: Old tokens remain valid while new rotated tokens are immediately accepted")
    void shouldHandleSeamlessKeyRotation() throws Exception {
        if (!isLocalStackAvailable) {
            System.out.println("[SKIP] LocalStack S3 is not running.");
            return;
        }

        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);

        // ==========================================
        // PHASE 1: Initial State with Key 1
        // ==========================================
        final KeyPair keyPair1 = kpg.generateKeyPair();
        final RSAKey rsaJwk1 = new RSAKey.Builder((RSAPublicKey) keyPair1.getPublic())
                .privateKey((RSAPrivateKey) keyPair1.getPrivate())
                .build();
        final String kid1 = rsaJwk1.computeThumbprint().toString();
        final RSAKey rsaJwk1WithKid = new RSAKey.Builder(rsaJwk1).keyID(kid1).build();

        // Publish JWKS containing [Key 1]
        final JWKSet jwksPhase1 = new JWKSet(List.of(rsaJwk1WithKid));
        s3AsyncClient.putObject(
                PutObjectRequest.builder().bucket(BUCKET).key(S3_KEY).contentType("application/json").build(),
                AsyncRequestBody.fromBytes(jwksPhase1.toString().getBytes(StandardCharsets.UTF_8))
        ).join();

        memoryPolling.refreshFromS3().join();

        // Issue Token 1 signed with Key 1
        final String token1 = createSignedToken(keyPair1, kid1, "alice", "READ WRITE");

        // Verify Token 1 works immediately
        final Introspection intro1 = introspect.introspect(token1).join();
        assertNotNull(intro1);
        assertTrue(intro1.hasToken(), "Token 1 signed with Key 1 must be valid");
        assertTrue(intro1.token().hasScope("read"));

        // ==========================================
        // PHASE 2: Key Rotation -> Key 2 is added, Key 1 is retained
        // ==========================================
        final KeyPair keyPair2 = kpg.generateKeyPair();
        final RSAKey rsaJwk2 = new RSAKey.Builder((RSAPublicKey) keyPair2.getPublic())
                .privateKey((RSAPrivateKey) keyPair2.getPrivate())
                .build();
        final String kid2 = rsaJwk2.computeThumbprint().toString();
        final RSAKey rsaJwk2WithKid = new RSAKey.Builder(rsaJwk2).keyID(kid2).build();

        // Rotated JWKS contains BOTH [Key 2 (new active), Key 1 (previous retained)]
        final JWKSet rotatedJwks = new JWKSet(List.of(rsaJwk2WithKid, rsaJwk1WithKid));
        s3AsyncClient.putObject(
                PutObjectRequest.builder().bucket(BUCKET).key(S3_KEY).contentType("application/json").build(),
                AsyncRequestBody.fromBytes(rotatedJwks.toString().getBytes(StandardCharsets.UTF_8))
        ).join();

        // Simulate MemoryPolling @Scheduled HeadObject check detecting the rotation in S3
        final Boolean detectedUpdate = memoryPolling.checkAndRefreshIfUpdated().join();
        assertTrue(detectedUpdate, "MemoryPolling must detect S3 update and refresh RAM cache");

        // Issue Token 2 signed with the new Key 2
        final String token2 = createSignedToken(keyPair2, kid2, "bob", "READ BILLING_ADMIN");

        // ==========================================
        // PHASE 3: Verify Both Tokens are Valid
        // ==========================================
        // 1. Token 2 (signed with NEW Key 2) is accepted
        final VerifyTokenResponse resp2 = authService.verifyToken(token2).join();
        assertTrue(resp2.valid(), "New token signed with Key 2 must be valid");
        assertTrue(resp2.hasRequiredScope(), "Token 2 must satisfy required scope");
        assertEquals(kid2, resp2.kid(), "Response KID must match the token's signing KID (Key 2)");

        // 2. Token 1 (signed with OLD Key 1) REMAINS valid (no disruption for active sessions)
        final VerifyTokenResponse resp1 = authService.verifyToken(token1).join();
        assertTrue(resp1.valid(), "Old token signed with Key 1 must remain valid during rotation grace period");
        assertTrue(resp1.hasRequiredScope(), "Token 1 must still be accepted");
        assertEquals(kid1, resp1.kid(), "Response KID must match the token's signing KID (Key 1)");

        // 3. Token signed with an UNKNOWN Key 3 is rejected
        final KeyPair keyPairUnknown = kpg.generateKeyPair();
        final String tokenUnknown = createSignedToken(keyPairUnknown, "unknown-kid", "eve", "READ");
        final VerifyTokenResponse respUnknown = authService.verifyToken(tokenUnknown).join();
        assertFalse(respUnknown.valid(), "Token signed with unknown key must be rejected");
    }

    private static String createSignedToken(final KeyPair keyPair, final String kid, final String subject, final String scopes) {
        try {
            final Date now = new Date();
            final Date exp = new Date(now.getTime() + 3600_000);

            final JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issuer("https://auth.knin.org")
                    .issueTime(now)
                    .expirationTime(exp);

            if (scopes != null && !scopes.isBlank()) {
                claimsBuilder.claim("scope", scopes);
            }

            final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(kid)
                    .build();

            final SignedJWT signedJWT = new SignedJWT(header, claimsBuilder.build());
            signedJWT.sign(new RSASSASigner((RSAPrivateKey) keyPair.getPrivate()));
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create test signed token", e);
        }
    }

}
