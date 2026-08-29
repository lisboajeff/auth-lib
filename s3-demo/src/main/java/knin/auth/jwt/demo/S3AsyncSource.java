package knin.auth.jwt.demo;

import knin.auth.jwt.adapter.retriever.Source;
import org.jboss.logging.Logger;

import java.util.Objects;
import java.util.concurrent.CompletableFuture;

public final class S3AsyncSource implements Source {

    private static final Logger LOG = Logger.getLogger(S3AsyncSource.class);

    private final S3BucketReader s3BucketReader;

    public S3AsyncSource(final S3BucketReader s3BucketReader) {
        this.s3BucketReader = Objects.requireNonNull(s3BucketReader, "s3BucketReader cannot be null");
    }

    @Override
    public CompletableFuture<byte[]> fetchData() {
        LOG.infof("[FALLBACK - Level 3 S3AsyncSource] Initiating live S3 getObject request for bucket: '%s', key: '%s'...",
                s3BucketReader.getBucket(), s3BucketReader.getKey());

        return s3BucketReader.getObjectBytes()
                .thenApply(responseBytes -> {
                    final byte[] bytes = responseBytes.asByteArray();
                    LOG.infof("[HIT - Level 3 S3AsyncSource] S3 live fetch HIT (size: %d bytes, ETag: %s)",
                            bytes.length, responseBytes.response().eTag());
                    return bytes;
                })
                .exceptionally(throwable -> {
                    LOG.warnf("[MISS/ERROR - Level 3 S3AsyncSource] S3 live fetch failed (NoSuchKey/Unreachable): %s", throwable.getMessage());
                    return null;
                });
    }

}
