package knin.auth.jwt.adapter.retriever;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.nimbusds.jose.jwk.RSAKey;
import knin.auth.jwt.adapter.TokenTestHelper;
import knin.auth.jwt.adapter.validate.TokenHandleProxy;
import knin.auth.jwt.domain.retriever.JsonWebKeys;
import knin.auth.jwt.domain.validate.TokenHandle;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SourceChainTest {

    private final TokenHandle handle = new TokenHandleProxy();

    @Test
    @DisplayName("Should fetch and parse JsonWebKeys from Source when kid is present")
    void shouldFetchAndParseJsonWebKeysWhenKidIsPresent() {
        RSAKey rsaKey = TokenTestHelper.generateRsaJwk("source-kid-1");
        byte[] jwksBytes = TokenTestHelper.createJsonWebKeys(rsaKey);

        Source source = () -> CompletableFuture.completedFuture(jwksBytes);
        SourceChain sourceChain = new SourceChain(source, handle);

        Optional<JsonWebKeys> result = sourceChain.fetch("source-kid-1").join();

        assertTrue(result.isPresent());
        assertEquals(Set.of("source-kid-1"), result.get().getIds());
    }

    @Test
    @DisplayName("Should return empty optional when kid is not found in the fetched JWKS")
    void shouldReturnEmptyWhenKidNotInFetchedJwks() {
        RSAKey rsaKey = TokenTestHelper.generateRsaJwk("source-kid-1");
        byte[] jwksBytes = TokenTestHelper.createJsonWebKeys(rsaKey);

        Source source = () -> CompletableFuture.completedFuture(jwksBytes);
        SourceChain sourceChain = new SourceChain(source, handle);

        Optional<JsonWebKeys> result = sourceChain.fetch("non-existent-kid").join();

        assertFalse(result.isPresent());
    }

    @Test
    @DisplayName("Should deduplicate concurrent in-flight requests for the same kid (Single-Flight)")
    void shouldDeduplicateConcurrentInFlightRequests() throws Exception {
        RSAKey rsaKey = TokenTestHelper.generateRsaJwk("concurrent-kid-1");
        byte[] jwksBytes = TokenTestHelper.createJsonWebKeys(rsaKey);

        AtomicInteger callCount = new AtomicInteger(0);
        CompletableFuture<byte[]> delayedFuture = new CompletableFuture<>();

        Source source = () -> {
            callCount.incrementAndGet();
            return delayedFuture;
        };

        SourceChain sourceChain = new SourceChain(source, handle);

        // Trigger 5 concurrent requests for the same kid while the future is still
        // pending
        CompletableFuture<Optional<JsonWebKeys>> req1 = sourceChain.fetch("concurrent-kid-1");
        CompletableFuture<Optional<JsonWebKeys>> req2 = sourceChain.fetch("concurrent-kid-1");
        CompletableFuture<Optional<JsonWebKeys>> req3 = sourceChain.fetch("concurrent-kid-1");
        CompletableFuture<Optional<JsonWebKeys>> req4 = sourceChain.fetch("concurrent-kid-1");
        CompletableFuture<Optional<JsonWebKeys>> req5 = sourceChain.fetch("concurrent-kid-1");

        // source.fetchData() should have been called only ONCE
        assertEquals(1, callCount.get());

        // Complete the asynchronous source future
        delayedFuture.complete(jwksBytes);

        // All 5 requests must obtain the same successful result
        Optional<JsonWebKeys> r1 = req1.get(2, TimeUnit.SECONDS);
        Optional<JsonWebKeys> r2 = req2.get(2, TimeUnit.SECONDS);
        Optional<JsonWebKeys> r3 = req3.get(2, TimeUnit.SECONDS);
        Optional<JsonWebKeys> r4 = req4.get(2, TimeUnit.SECONDS);
        Optional<JsonWebKeys> r5 = req5.get(2, TimeUnit.SECONDS);

        assertTrue(r1.isPresent());
        assertTrue(r2.isPresent());
        assertTrue(r3.isPresent());
        assertTrue(r4.isPresent());
        assertTrue(r5.isPresent());
        assertEquals(Set.of("concurrent-kid-1"), r1.get().getIds());
        assertEquals(r1.get().getIds(), r2.get().getIds());
        assertEquals(r1.get().getIds(), r3.get().getIds());
        assertEquals(r1.get().getIds(), r4.get().getIds());
        assertEquals(r1.get().getIds(), r5.get().getIds());

        // Subsequent call after completion (inFlight cleared) should trigger the source
        // again
        sourceChain.fetch("concurrent-kid-1").join();
        assertEquals(2, callCount.get());
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    @Test
    @DisplayName("Should coordinate 50 concurrent threads and call Source only once")
    void shouldCoordinateFiftyConcurrentThreadsCallingSourceOnlyOnce() throws Exception {
        RSAKey rsaKey = TokenTestHelper.generateRsaJwk("heavy-kid-1");
        byte[] jwksBytes = TokenTestHelper.createJsonWebKeys(rsaKey);

        AtomicInteger callCount = new AtomicInteger(0);
        CompletableFuture<byte[]> delayedFuture = new CompletableFuture<>();

        Source source = () -> {
            callCount.incrementAndGet();
            return delayedFuture;
        };

        SourceChain sourceChain = new SourceChain(source, handle);

        int threadCount = 50;
        java.util.concurrent.ExecutorService executor = java.util.concurrent.Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        java.util.List<CompletableFuture<Optional<JsonWebKeys>>> futures = new java.util.concurrent.CopyOnWriteArrayList<>();

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    futures.add(sourceChain.fetch("heavy-kid-1"));
                } catch (InterruptedException ignored) {
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        // Release all 50 threads simultaneously at the same millisecond
        startLatch.countDown();
        doneLatch.await(5, TimeUnit.SECONDS);

        // source.fetchData() should have been called exactly 1 time
        assertEquals(1, callCount.get());

        // Complete the bytes
        delayedFuture.complete(jwksBytes);

        // All 50 futures complete with the same successful result
        for (CompletableFuture<Optional<JsonWebKeys>> f : futures) {
            Optional<JsonWebKeys> res = f.get(5, TimeUnit.SECONDS);
            assertTrue(res.isPresent());
            assertEquals(Set.of("heavy-kid-1"), res.get().getIds());
        }

        executor.shutdown();
    }

    @Test
    @DisplayName("Should execute set() safely as no-op")
    void shouldNotThrowOnSet() {
        SourceChain sourceChain = new SourceChain(() -> CompletableFuture.completedFuture(null), handle);
        org.junit.jupiter.api.Assertions.assertDoesNotThrow(() -> sourceChain.set(null));
    }
}
