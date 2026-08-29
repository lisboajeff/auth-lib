package knin.auth.jwt.demo;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import knin.auth.jwt.adapter.retriever.Source;
import knin.auth.jwt.domain.validate.Token;
import knin.auth.jwt.factory.AuthFactory;
import knin.auth.jwt.option.Introspect;
import knin.auth.jwt.option.Introspection;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.http.nio.netty.NettyNioAsyncHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class S3SourceConcurrencyTest {

    private static final String BUCKET = "auth-bucket";
    private static final String S3_KEY = "jwks.json";
    private static final String KID = "demo-auth-key-1";

    private static S3AsyncClient s3AsyncClient;
    private static JwtSigner jwtSigner;
    private static Introspect introspect;
    private static boolean isLocalStackAvailable = false;

    @BeforeAll
    static void setUp() {
        jwtSigner = new JwtSigner("private_key.pem", KID);

        final String localstackEndpoint = System.getenv().getOrDefault("LOCALSTACK_ENDPOINT", "http://localhost:4566");

        s3AsyncClient = S3AsyncClient.builder()
                .endpointOverride(URI.create(localstackEndpoint))
                .region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("test", "test")
                ))
                .httpClientBuilder(NettyNioAsyncHttpClient.builder()
                        .maxConcurrency(200))
                .forcePathStyle(true)
                .build();

        // Check if LocalStack S3 is reachable and seed data
        try {
            final byte[] jwksBytes = buildJwksFromResourcePem("private_key.pem", KID);

            s3AsyncClient.createBucket(CreateBucketRequest.builder().bucket(BUCKET).build()).join();

            s3AsyncClient.putObject(
                    PutObjectRequest.builder().bucket(BUCKET).key(S3_KEY).contentType("application/json").build(),
                    AsyncRequestBody.fromBytes(jwksBytes)
            ).join();

            isLocalStackAvailable = true;
            System.out.println("[+] LocalStack S3 is available and seeded with JWKS!");
        } catch (Exception e) {
            System.out.println("[-] LocalStack not reachable (" + e.getMessage() + "). Running with Mocked S3 fallback.");
            isLocalStackAvailable = false;
        }

        final AuthFactory authFactory = new AuthFactory();
        final S3AsyncSource s3Source = new S3AsyncSource(s3AsyncClient, BUCKET, S3_KEY);
        introspect = authFactory.createIntrospect(authFactory.createSource(s3Source));
    }

    @AfterAll
    static void tearDown() {
        if (s3AsyncClient != null) {
            s3AsyncClient.close();
        }
    }

    @Test
    @DisplayName("Should successfully introspect JWT signed with PEM private key using JWKS from S3 under 100 concurrent threads")
    void shouldIntrospectUnderHeavyConcurrency() throws Exception {
        if (!isLocalStackAvailable) {
            System.out.println("[SKIP] LocalStack S3 is not running. Start via docker-compose up -d in s3-demo to run integration test.");
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

        // Release all 100 threads at the exact same instant
        startLatch.countDown();
        assertTrue(doneLatch.await(10, TimeUnit.SECONDS), "All 100 threads should complete execution");

        // Validate that every single thread succeeded
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
    @DisplayName("Should successfully coordinate 100 concurrent threads against S3AsyncSource and Auth pipeline")
    void shouldIntrospectConcurrentlyWithS3SourceMock() throws Exception {
        final byte[] jwksBytes = buildJwksFromResourcePem("private_key.pem", KID);
        final String jwt = jwtSigner.signToken("user-standalone", "SCOPE_1 SCOPE_2", 120_000);

        final AuthFactory authFactory = new AuthFactory();
        final AtomicInteger s3FetchCount = new AtomicInteger(0);

        // Simulated S3 Async Source with delay
        final Source mockS3Source = () -> {
            s3FetchCount.incrementAndGet();
            return CompletableFuture.supplyAsync(() -> {
                try {
                    Thread.sleep(20);
                } catch (InterruptedException ignored) {}
                return jwksBytes;
            });
        };

        final Introspect mockIntrospect = authFactory.createIntrospect(authFactory.createSource(mockS3Source));

        final int threadCount = 100;
        final ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        final CountDownLatch startLatch = new CountDownLatch(1);
        final CountDownLatch doneLatch = new CountDownLatch(threadCount);
        final List<CompletableFuture<Introspection>> futures = new CopyOnWriteArrayList<>();

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    futures.add(mockIntrospect.introspect(jwt));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        assertTrue(doneLatch.await(10, TimeUnit.SECONDS));

        // Exactly 1 I/O call should occur thanks to Single-Flight
        assertEquals(1, s3FetchCount.get());

        for (CompletableFuture<Introspection> f : futures) {
            final Introspection introspection = f.get(10, TimeUnit.SECONDS);
            assertNotNull(introspection);
            assertTrue(introspection.hasToken());
            final Token token = introspection.token();
            assertTrue(token.containScopes());
            assertTrue(token.hasScope("scope_1"));
            assertTrue(token.hasScope("scope_2"));
            assertEquals(jwt, token.jwtToString());
        }

        executor.shutdown();
    }

    private static byte[] buildJwksFromResourcePem(final String resourcePath, final String kid) {
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
            final RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(publicKeySpec);

            final RSAKey rsaJwk = new RSAKey.Builder(pubKey)
                    .keyID(kid)
                    .build();

            final JWKSet jwkSet = new JWKSet(rsaJwk);
            return jwkSet.toString().getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Failed to build JWKS from PEM", e);
        }
    }

}
