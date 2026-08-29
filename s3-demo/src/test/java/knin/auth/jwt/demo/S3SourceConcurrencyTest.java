package knin.auth.jwt.demo;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
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

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;

@QuarkusTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class S3SourceConcurrencyTest {

    private static final String BUCKET = "auth-bucket";
    private static final String S3_KEY = "jwks.json";

    @Inject
    S3AsyncClient s3AsyncClient;

    @Inject
    Introspect introspect;

    @Inject
    MemoryPolling memoryPolling;

    private JwtSigner jwtSigner;
    private String primaryKid;
    private boolean isLocalStackAvailable = false;

    @BeforeAll
    void setUp() {
        jwtSigner = new JwtSigner("private_key.pem");
        this.primaryKid = jwtSigner.getKid();

        try {
            final RSAPublicKey pubKey = loadPublicKeyFromResource("private_key.pem");
            final RSAKey rsaJwk = new RSAKey.Builder(pubKey).keyID(primaryKid).build();
            final byte[] jwksBytes = new JWKSet(rsaJwk).toString().getBytes(StandardCharsets.UTF_8);

            try {
                s3AsyncClient.createBucket(CreateBucketRequest.builder().bucket(BUCKET).build()).join();
            } catch (Exception ignored) {}

            s3AsyncClient.putObject(
                    PutObjectRequest.builder().bucket(BUCKET).key(S3_KEY).contentType("application/json").build(),
                    AsyncRequestBody.fromBytes(jwksBytes)
            ).join();

            // Refresh MemoryPolling with the seeded S3 data
            memoryPolling.refreshFromS3().join();

            isLocalStackAvailable = true;
            System.out.println("[+] LocalStack S3 seeded and MemoryPolling initialized with JWKS (KID: " + primaryKid + ")!");
        } catch (Exception e) {
            System.out.println("[-] LocalStack not reachable (" + e.getMessage() + ").");
            isLocalStackAvailable = false;
        }
    }

    @Test
    @DisplayName("Should successfully introspect JWT using MemoryPolling under 100 concurrent threads")
    void shouldIntrospectConcurrentlyViaMemoryPolling() throws Exception {
        if (!isLocalStackAvailable) {
            System.out.println("[SKIP] LocalStack S3 is not running.");
            return;
        }

        final String jwt = jwtSigner.signToken("user-42", "READ WRITE ADMIN", 120_000);

        final int threadCount = 100;
        final ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        final CountDownLatch startLatch = new CountDownLatch(1);
        final CountDownLatch doneLatch = new CountDownLatch(threadCount);
        final List<CompletableFuture<Introspection>> futures = new CopyOnWriteArrayList<>();

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    futures.add(introspect.introspect(jwt));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        // Release all 100 threads simultaneously
        startLatch.countDown();
        assertTrue(doneLatch.await(10, TimeUnit.SECONDS), "All 100 threads should complete execution");

        for (CompletableFuture<Introspection> f : futures) {
            final Introspection introspection = f.get(10, TimeUnit.SECONDS);
            assertNotNull(introspection);
            assertTrue(introspection.hasToken(), "Introspection must contain valid token");

            final Token token = introspection.token();
            assertNotNull(token);
            assertTrue(token.containScopes());
            assertTrue(token.hasScope("read"));
            assertTrue(token.hasScope("write"));
            assertTrue(token.hasScope("admin"));
            assertEquals(jwt, token.jwtToString());
        }

        executor.shutdown();
    }

    @Test
    @DisplayName("Should detect S3 updates via HeadObject and refresh memory cache automatically")
    void shouldDetectS3UpdateViaHeadObjectAndRefreshMemory() throws Exception {
        if (!isLocalStackAvailable) {
            System.out.println("[SKIP] LocalStack S3 is not running.");
            return;
        }

        // 1. Generate a second key pair
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        final KeyPair keyPair2 = kpg.generateKeyPair();
        final RSAKey rsaJwk2Temp = new RSAKey.Builder((RSAPublicKey) keyPair2.getPublic()).build();
        final String newKid = rsaJwk2Temp.computeThumbprint().toString();

        final RSAKey rsaJwk1 = new RSAKey.Builder(loadPublicKeyFromResource("private_key.pem"))
                .keyID(primaryKid)
                .build();

        final RSAKey rsaJwk2 = new RSAKey.Builder((RSAPublicKey) keyPair2.getPublic())
                .privateKey((RSAPrivateKey) keyPair2.getPrivate())
                .keyID(newKid)
                .build();

        final JWKSet updatedJwkSet = new JWKSet(List.of(rsaJwk1, rsaJwk2));
        final byte[] updatedJwksBytes = updatedJwkSet.toString().getBytes(StandardCharsets.UTF_8);

        // 2. Upload updated JWKS to S3
        s3AsyncClient.putObject(
                PutObjectRequest.builder().bucket(BUCKET).key(S3_KEY).contentType("application/json").build(),
                AsyncRequestBody.fromBytes(updatedJwksBytes)
        ).join();

        // 3. Trigger check via HeadObject (simulating the 10-second @Scheduled polling)
        final Boolean updated = memoryPolling.checkAndRefreshIfUpdated().join();
        assertTrue(updated, "MemoryPolling should detect the S3 update via HeadObject and refresh cache");

        // 4. Sign a JWT with the new key and introspect it
        final String jwtNew = createJwtWithSigningKey(rsaJwk2, newKid, "NEW_FEATURE");
        final Introspection introspection = introspect.introspect(jwtNew).join();

        assertNotNull(introspection);
        assertTrue(introspection.hasToken());
        final Token token = introspection.token();
        assertTrue(token.hasScope("new_feature"));
    }

    @Test
    @DisplayName("Should successfully introspect 4-part (GZIP) token under 100 concurrent threads using MemoryPolling")
    void shouldIntrospectFourPartsTokenUnderHeavyConcurrency() throws Exception {
        if (!isLocalStackAvailable) {
            System.out.println("[SKIP] LocalStack S3 is not running.");
            return;
        }

        final String jwt3Parts = jwtSigner.signToken("user-gzip-42", null, 120_000);
        final String jwt4Parts = jwtSigner.signFourPartsToken("user-gzip-42", "GZIP_READ,GZIP_WRITE,GZIP_ADMIN", 120_000);

        final int threadCount = 100;
        final ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        final CountDownLatch startLatch = new CountDownLatch(1);
        final CountDownLatch doneLatch = new CountDownLatch(threadCount);
        final List<CompletableFuture<Introspection>> futures = new CopyOnWriteArrayList<>();

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    futures.add(introspect.introspect(jwt4Parts));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        assertTrue(doneLatch.await(10, TimeUnit.SECONDS), "All 100 threads should complete execution");

        for (CompletableFuture<Introspection> f : futures) {
            final Introspection introspection = f.get(10, TimeUnit.SECONDS);
            assertNotNull(introspection);
            assertTrue(introspection.hasToken());

            final Token token = introspection.token();
            assertNotNull(token);
            assertTrue(token.containScopes());
            assertTrue(token.hasScope("gzip_read"));
            assertTrue(token.hasScope("gzip_write"));
            assertTrue(token.hasScope("gzip_admin"));
            assertEquals(jwt3Parts, token.jwtToString());
        }

        executor.shutdown();
    }

    private static String createJwtWithSigningKey(final RSAKey signingKey, final String kid, final String scopes) {
        try {
            final java.util.Date now = new java.util.Date();
            final java.util.Date exp = new java.util.Date(now.getTime() + 120_000);
            final com.nimbusds.jwt.JWTClaimsSet.Builder builder = new com.nimbusds.jwt.JWTClaimsSet.Builder()
                    .subject("user-rotational")
                    .issuer("https://auth.knin.org")
                    .issueTime(now)
                    .expirationTime(exp);
            if (scopes != null && !scopes.isBlank()) {
                builder.claim("scope", scopes);
            }
            final com.nimbusds.jose.JWSHeader header = new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                    .keyID(kid)
                    .build();
            final com.nimbusds.jwt.SignedJWT signedJWT = new com.nimbusds.jwt.SignedJWT(header, builder.build());
            signedJWT.sign(new com.nimbusds.jose.crypto.RSASSASigner(signingKey.toRSAPrivateKey()));
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign test token with RSAKey", e);
        }
    }

    private static RSAPublicKey loadPublicKeyFromResource(final String resourcePath) {
        try (InputStream is = S3SourceConcurrencyTest.class.getClassLoader().getResourceAsStream(resourcePath)) {
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
