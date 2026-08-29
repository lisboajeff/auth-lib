package knin.auth.jwt.demo;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import knin.auth.jwt.adapter.retriever.InMemory;
import knin.auth.jwt.domain.retriever.Keys;
import knin.auth.jwt.domain.retriever.TableChain;
import knin.auth.jwt.domain.validate.TokenHandle;
import knin.auth.jwt.factory.AuthFactory;
import knin.auth.jwt.option.Introspect;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.nio.netty.NettyNioAsyncHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3AsyncClient;

import java.net.URI;

@ApplicationScoped
public class AuthConfiguration {

    @Produces
    @Singleton
    public S3AsyncClient produceS3AsyncClient(
            @ConfigProperty(name = "auth.s3.endpoint", defaultValue = "http://localhost:4566") final String endpoint,
            @ConfigProperty(name = "auth.s3.region", defaultValue = "us-east-1") final String region,
            @ConfigProperty(name = "auth.s3.access-key", defaultValue = "test") final String accessKey,
            @ConfigProperty(name = "auth.s3.secret-key", defaultValue = "test") final String secretKey) {

        return S3AsyncClient.builder()
                .endpointOverride(URI.create(endpoint))
                .region(Region.of(region))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(accessKey, secretKey)))
                .httpClientBuilder(NettyNioAsyncHttpClient.builder()
                        .maxConcurrency(200))
                .forcePathStyle(true)
                .build();
    }

    @Produces
    @Singleton
    public S3AsyncSource produceS3AsyncSource(
            final S3AsyncClient s3AsyncClient,
            @ConfigProperty(name = "auth.s3.bucket", defaultValue = "auth-bucket") final String bucket,
            @ConfigProperty(name = "auth.s3.key", defaultValue = "jwks.json") final String key) {
        return new S3AsyncSource(s3AsyncClient, bucket, key);
    }

    @Produces
    @Singleton
    public AuthFactory produceAuthFactory() {
        return new AuthFactory();
    }

    @Produces
    @Singleton
    public JwtSigner produceJwtSigner(
            @ConfigProperty(name = "auth.jwt.private-key-path", defaultValue = "private_key.pem") final String pemPath) {
        return new JwtSigner(pemPath);
    }

    @Produces
    @Singleton
    public TableChain<String> produceTableChain(
            final AuthFactory authFactory,
            final MemoryPolling memoryPolling,
            final S3AsyncSource s3AsyncSource) {

        final TokenHandle tokenHandle = authFactory.createTokenHandle();

        // Level 3: S3 Async Fallback
        final TableChain<String> s3FallbackChain = authFactory.createSource(tokenHandle, s3AsyncSource);

        // Level 2: MemoryPolling Cache (refreshed via S3 HeadObject polling)
        final TableChain<String> memoryPollingChain = authFactory.createSource(tokenHandle, memoryPolling, s3FallbackChain);

        // Level 1: Ponta da cadeia (Head of Chain: InMemory L1 Cache)
        return new InMemory(memoryPollingChain);
    }

    @Produces
    @Singleton
    public Introspect produceIntrospect(
            final AuthFactory authFactory,
            final TableChain<String> tableChain) {

        final TokenHandle tokenHandle = authFactory.createTokenHandle();
        final Keys keys = (Keys) tableChain;
        return new Introspect(tokenHandle, keys);
    }

}
