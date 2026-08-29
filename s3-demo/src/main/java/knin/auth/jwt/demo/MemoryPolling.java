package knin.auth.jwt.demo;

import io.quarkus.runtime.Startup;
import io.quarkus.scheduler.Scheduled;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import knin.auth.jwt.adapter.retriever.Source;
import org.jboss.logging.Logger;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

@Startup
@ApplicationScoped
public class MemoryPolling implements Source {

    private static final Logger LOG = Logger.getLogger(MemoryPolling.class);

    private final S3BucketReader s3BucketReader;
    private final AtomicReference<byte[]> cachedBytes = new AtomicReference<>();
    private final AtomicReference<String> lastETag = new AtomicReference<>();
    private final AtomicReference<Instant> lastModified = new AtomicReference<>();

    @Inject
    public MemoryPolling(final S3BucketReader s3BucketReader) {
        this.s3BucketReader = Objects.requireNonNull(s3BucketReader, "s3BucketReader cannot be null");
    }

    @PostConstruct
    public void init() {
        LOG.infof("Initializing MemoryPolling for S3 bucket: '%s', key: '%s'...",
                s3BucketReader.getBucket(), s3BucketReader.getKey());
        refreshFromS3().whenComplete((bytes, error) -> {
            if (error != null) {
                LOG.warnf("Initial S3 fetch failed (will retry on next poll): %s", error.getMessage());
            } else {
                LOG.infof("Initial JWKS loaded into RAM from S3 (%d bytes)", bytes.length);
            }
        });
    }

    /**
     * Polls S3 every 10 seconds using a lightweight HeadObject request via S3BucketReader.
     * If the object in S3 has changed (different ETag or LastModified), fetches the new JWKS.
     */
    @Scheduled(every = "10s", delay = 10, delayUnit = java.util.concurrent.TimeUnit.SECONDS)
    public void pollS3ForUpdates() {
        LOG.info("Scheduled poll: checking S3 for JWKS updates...");
        checkAndRefreshIfUpdated();
    }

    public CompletableFuture<Boolean> checkAndRefreshIfUpdated() {
        return s3BucketReader.headObject()
                .thenCompose(headResponse -> {
                    final String currentETag = headResponse.eTag();
                    final Instant currentLastModified = headResponse.lastModified();

                    final boolean hasChanged = cachedBytes.get() == null
                            || (currentETag != null && !currentETag.equals(lastETag.get()))
                            || (currentLastModified != null && !currentLastModified.equals(lastModified.get()));

                    if (hasChanged) {
                        LOG.infof("S3 object updated (ETag: %s). Fetching new JWKS...", currentETag);
                        return refreshFromS3().thenApply(b -> true);
                    }

                    return CompletableFuture.completedFuture(false);
                })
                .exceptionally(throwable -> {
                    LOG.warnf("HeadObject check failed: %s", throwable.getMessage());
                    return false;
                });
    }

    public CompletableFuture<byte[]> refreshFromS3() {
        return s3BucketReader.getObjectBytes()
                .thenApply(responseBytes -> {
                    final byte[] bytes = responseBytes.asByteArray();
                    final GetObjectResponse response = responseBytes.response();

                    cachedBytes.set(bytes);
                    lastETag.set(response.eTag());
                    lastModified.set(response.lastModified());

                    LOG.infof("JWKS RAM cache refreshed from S3 (ETag: %s, size: %d bytes)", response.eTag(),
                            bytes.length);
                    return bytes;
                });
    }

    @Override
    public CompletableFuture<byte[]> fetchData() {
        final byte[] bytes = cachedBytes.get();
        if (bytes != null && bytes.length > 0) {
            LOG.infof("[HIT - Level 2 MemoryPolling] JWKS RAM cache HIT (size: %d bytes, ETag: %s)", bytes.length, lastETag.get());
        } else {
            LOG.info("[MISS - Level 2 MemoryPolling] JWKS RAM cache MISS (cache is empty or not yet synchronized with S3)");
        }
        return CompletableFuture.completedFuture(bytes);
    }

    public byte[] getCachedBytes() {
        return cachedBytes.get();
    }

    public String getLastETag() {
        return lastETag.get();
    }

    public Instant getLastModified() {
        return lastModified.get();
    }

}
