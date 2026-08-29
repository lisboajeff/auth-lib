package knin.auth.jwt.demo;

import knin.auth.jwt.adapter.retriever.Source;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

import java.util.Objects;
import java.util.concurrent.CompletableFuture;

public final class S3AsyncSource implements Source {

    private final S3AsyncClient s3AsyncClient;
    private final String bucket;
    private final String key;

    public S3AsyncSource(final S3AsyncClient s3AsyncClient, final String bucket, final String key) {
        this.s3AsyncClient = Objects.requireNonNull(s3AsyncClient, "s3AsyncClient cannot be null");
        this.bucket = Objects.requireNonNull(bucket, "bucket cannot be null");
        this.key = Objects.requireNonNull(key, "key cannot be null");
    }

    @Override
    public CompletableFuture<byte[]> fetchData() {
        final GetObjectRequest request = GetObjectRequest.builder()
                .bucket(bucket)
                .key(key)
                .build();

        return s3AsyncClient.getObject(request, AsyncResponseTransformer.toBytes())
                .thenApply(ResponseBytes::asByteArray);
    }

}
