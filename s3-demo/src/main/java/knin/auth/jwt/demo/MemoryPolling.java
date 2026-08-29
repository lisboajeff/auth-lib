package knin.auth.jwt.demo;

import io.quarkus.runtime.Startup;
import io.quarkus.scheduler.Scheduled;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import knin.auth.jwt.adapter.retriever.Source;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;

import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

@Startup
@ApplicationScoped
public class MemoryPolling implements Source {

    private static final Logger LOG = Logger.getLogger(MemoryPolling.class);

    private final S3AsyncClient s3AsyncClient;
    private final String bucket;
    private final String key;
    private final S3AsyncSource s3AsyncSource;
    private final AtomicReference<byte[]> cachedBytes = new AtomicReference<>();
    private final AtomicReference<String> lastETag = new AtomicReference<>();
    private final AtomicReference<Instant> lastModified = new AtomicReference<>();

    @Inject
    public MemoryPolling(
            final S3AsyncClient s3AsyncClient,
            @ConfigProperty(name = "auth.s3.bucket", defaultValue = "auth-bucket") final String bucket,
            @ConfigProperty(name = "auth.s3.key", defaultValue = "jwks.json") final String key) {
        this.s3AsyncClient = Objects.requireNonNull(s3AsyncClient, "s3AsyncClient cannot be null");
        this.bucket = Objects.requireNonNull(bucket, "bucket cannot be null");
        this.key = Objects.requireNonNull(key, "key cannot be null");
        this.s3AsyncSource = new S3AsyncSource(s3AsyncClient, bucket, key);
    }

    @PostConstruct
    public void init() {
        LOG.infof("Initializing MemoryPolling for S3 bucket: '%s', key: '%s'...", bucket, key);
        refreshFromS3().whenComplete((bytes, error) -> {
            if (error != null) {
                LOG.warnf("Initial S3 fetch failed (will retry on next poll): %s", error.getMessage());
            } else {
                LOG.infof("Initial JWKS loaded into RAM from S3 (%d bytes)", bytes.length);
            }
        });
    }

    /**
     * Polls S3 every 10 seconds using a lightweight HeadObject request.
     * If the object in S3 has changed (different ETag or LastModified), fetches the
     * new JWKS.
     */
    @Scheduled(every = "10s", delay = 10, delayUnit = java.util.concurrent.TimeUnit.SECONDS)
    public void pollS3ForUpdates() {
        LOG.info("Scheduled poll: checking S3 for JWKS updates...");
        checkAndRefreshIfUpdated();
    }

    public CompletableFuture<Boolean> checkAndRefreshIfUpdated() {
        final HeadObjectRequest headRequest = HeadObjectRequest.builder()
                .bucket(bucket)
                .key(key)
                .build();

        return s3AsyncClient.headObject(headRequest)
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
        final GetObjectRequest getRequest = GetObjectRequest.builder()
                .bucket(bucket)
                .key(key)
                .build();

        return s3AsyncClient.getObject(getRequest, AsyncResponseTransformer.toBytes())
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
        // MemoryPolling returns exclusively what is in its RAM cache.
        // If not present, returns null future so the TableChain can continue to the
        // next handler in the chain.
        return CompletableFuture.completedFuture(cachedBytes.get());
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
