package knin.auth.jwt.demo;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;

import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/**
 * Dedicated class whose sole responsibility is retrieving data from the S3 bucket.
 */
@ApplicationScoped
public class S3BucketReader {

    private final S3AsyncClient s3AsyncClient;
    private final String bucket;
    private final String key;

    @Inject
    public S3BucketReader(
            final S3AsyncClient s3AsyncClient,
            @ConfigProperty(name = "auth.s3.bucket", defaultValue = "auth-bucket") final String bucket,
            @ConfigProperty(name = "auth.s3.key", defaultValue = "jwks.json") final String key) {
        this.s3AsyncClient = Objects.requireNonNull(s3AsyncClient, "s3AsyncClient cannot be null");
        this.bucket = Objects.requireNonNull(bucket, "bucket cannot be null");
        this.key = Objects.requireNonNull(key, "key cannot be null");
    }

    public CompletableFuture<ResponseBytes<GetObjectResponse>> getObjectBytes() {
        final GetObjectRequest request = GetObjectRequest.builder()
                .bucket(bucket)
                .key(key)
                .build();

        return s3AsyncClient.getObject(request, AsyncResponseTransformer.toBytes());
    }

    public CompletableFuture<HeadObjectResponse> headObject() {
        final HeadObjectRequest request = HeadObjectRequest.builder()
                .bucket(bucket)
                .key(key)
                .build();

        return s3AsyncClient.headObject(request);
    }

    public String getBucket() {
        return bucket;
    }

    public String getKey() {
        return key;
    }

}
