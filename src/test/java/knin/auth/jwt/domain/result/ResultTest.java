package knin.auth.jwt.domain.result;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResultTest {

    private static class DummyException extends ResultException {
        DummyException(String message) {
            super(message);
        }
    }

    @Nested
    @DisplayName("1. SuccessResult Scenarios")
    class SuccessResultTests {

        @Test
        @DisplayName("Should correctly instantiate SuccessResult via of and success")
        void shouldInstantiateSuccessResult() {
            Result<String> res1 = Result.of("hello");
            Result<String> res2 = Result.success("world");

            assertTrue(res1.hasResult());
            assertFalse(res1.isError());
            assertFalse(res1.isEmpty());
            assertEquals("hello", res1.get());

            assertTrue(res2.hasResult());
            assertFalse(res2.isError());
            assertFalse(res2.isEmpty());
            assertEquals("world", res2.get());
        }

        @Test
        @DisplayName("Should execute Ok callback and bypass Error callback")
        void shouldExecuteOkAndBypassError() {
            AtomicReference<String> okCaptured = new AtomicReference<>();
            AtomicBoolean errorCalled = new AtomicBoolean(false);

            Result<String> result = Result.success("valid-data")
                    .Ok(okCaptured::set)
                    .Error(ex -> errorCalled.set(true));

            assertEquals("valid-data", okCaptured.get());
            assertFalse(errorCalled.get());
            assertTrue(result.hasResult());
        }

        @Test
        @DisplayName("Should transform value with flatMap across multiple types")
        void shouldFlatMapTransformValues() {
            Result<Integer> initial = Result.success(42);

            Result<String> transformed = initial
                    .flatMap(num -> Result.success("Number is " + num))
                    .flatMap(str -> Result.success(str.toUpperCase()));

            assertTrue(transformed.hasResult());
            assertEquals("NUMBER IS 42", transformed.get());
        }

        @Test
        @DisplayName("flatMapOrElse on SuccessResult should execute function and ignore alternative")
        void flatMapOrElseShouldIgnoreAlternativeOnSuccess() {
            AtomicBoolean alternativeCalled = new AtomicBoolean(false);

            Result<String> result = Result.success("primary")
                    .flatMapOrElse(
                            val -> Result.success(val + "-processed"),
                            () -> {
                                alternativeCalled.set(true);
                                return Result.success("fallback");
                            }
                    );

            assertTrue(result.hasResult());
            assertEquals("primary-processed", result.get());
            assertFalse(alternativeCalled.get());
        }

        @Test
        @DisplayName("mapFuture on SuccessResult should execute async transformation")
        void mapFutureShouldTransformAsync() throws Exception {
            Result<String> initial = Result.success("input");

            CompletableFuture<Result<Integer>> future = initial.mapFuture(
                    val -> CompletableFuture.supplyAsync(() -> Result.success(val.length()))
            );

            Result<Integer> asyncResult = future.get(2, TimeUnit.SECONDS);
            assertNotNull(asyncResult);
            assertTrue(asyncResult.hasResult());
            assertEquals(5, asyncResult.get());
        }
    }

    @Nested
    @DisplayName("2. FailedResult Scenarios & Exception Propagation")
    class FailedResultTests {

        @Test
        @DisplayName("Should correctly instantiate FailedResult")
        void shouldInstantiateFailedResult() {
            DummyException ex = new DummyException("auth error");
            Result<String> result = Result.failed(ex);

            assertFalse(result.hasResult());
            assertTrue(result.isError());
            assertFalse(result.isEmpty());
            assertNull(result.get());
        }

        @Test
        @DisplayName("Should execute Error callback and bypass Ok callback")
        void shouldExecuteErrorAndBypassOk() {
            DummyException ex = new DummyException("failure reason");
            AtomicBoolean okCalled = new AtomicBoolean(false);
            AtomicReference<ResultException> errorCaptured = new AtomicReference<>();

            Result<String> result = Result.<String>failed(ex)
                    .Ok(val -> okCalled.set(true))
                    .Error(errorCaptured::set);

            assertFalse(okCalled.get());
            assertNotNull(errorCaptured.get());
            assertSame(ex, errorCaptured.get());
            assertEquals("failure reason", errorCaptured.get().getMessage());
            assertTrue(result.isError());
        }

        @Test
        @DisplayName("Should bypass all downstream flatMap steps when initial step fails (short-circuit)")
        void shouldShortCircuitEntireChainOnInitialFailure() {
            DummyException originalEx = new DummyException("step-1-failed");
            AtomicInteger stepsExecuted = new AtomicInteger(0);

            Result<String> chainResult = Result.<Integer>failed(originalEx)
                    .flatMap(num -> {
                        stepsExecuted.incrementAndGet();
                        return Result.success("num=" + num);
                    })
                    .flatMap(str -> {
                        stepsExecuted.incrementAndGet();
                        return Result.success(str.length());
                    })
                    .flatMap(len -> {
                        stepsExecuted.incrementAndGet();
                        return Result.success("final");
                    });

            assertEquals(0, stepsExecuted.get(), "No downstream flatMap steps should execute on failure");
            assertTrue(chainResult.isError());
            assertFalse(chainResult.hasResult());

            AtomicReference<ResultException> captured = new AtomicReference<>();
            chainResult.Error(captured::set);
            assertSame(originalEx, captured.get());
        }

        @Test
        @DisplayName("Should interrupt chain mid-way when a middle step returns FailedResult")
        void shouldInterruptChainMidway() {
            AtomicInteger stepsExecuted = new AtomicInteger(0);
            DummyException midEx = new DummyException("mid-step-failure");

            Result<String> result = Result.success("initial")
                    .flatMap(val -> {
                        stepsExecuted.incrementAndGet();
                        return Result.success(val + " -> step1");
                    })
                    .flatMap(val -> {
                        stepsExecuted.incrementAndGet();
                        return Result.<Integer>failed(midEx);
                    })
                    .flatMap(num -> {
                        stepsExecuted.incrementAndGet();
                        return Result.success("never-reached: " + num);
                    });

            assertEquals(2, stepsExecuted.get(), "Only step 1 and step 2 should execute");
            assertTrue(result.isError());

            AtomicReference<ResultException> captured = new AtomicReference<>();
            result.Error(captured::set);
            assertSame(midEx, captured.get());
        }

        @Test
        @DisplayName("flatMapOrElse on FailedResult should keep original failure and ignore alternative")
        void flatMapOrElseShouldPreserveFailure() {
            DummyException ex = new DummyException("unrecoverable error");
            AtomicBoolean fnCalled = new AtomicBoolean(false);
            AtomicBoolean altCalled = new AtomicBoolean(false);

            Result<String> result = Result.<String>failed(ex)
                    .flatMapOrElse(
                            val -> {
                                fnCalled.set(true);
                                return Result.success("fn");
                            },
                            () -> {
                                altCalled.set(true);
                                return Result.success("fallback");
                            }
                    );

            assertTrue(result.isError());
            assertFalse(fnCalled.get());
            assertFalse(altCalled.get());
        }

        @Test
        @DisplayName("mapFuture on FailedResult should return completed future with FailedResult (no async exception)")
        void mapFutureShouldReturnCompletedFailedFuture() throws Exception {
            DummyException ex = new DummyException("async failure");
            AtomicBoolean fnCalled = new AtomicBoolean(false);

            CompletableFuture<Result<String>> future = Result.<Integer>failed(ex).mapFuture(
                    val -> {
                        fnCalled.set(true);
                        return CompletableFuture.completedFuture(Result.success("async"));
                    }
            );

            assertFalse(fnCalled.get());
            Result<String> asyncRes = future.get(2, TimeUnit.SECONDS);
            assertNotNull(asyncRes);
            assertTrue(asyncRes.isError());

            AtomicReference<ResultException> captured = new AtomicReference<>();
            asyncRes.Error(captured::set);
            assertSame(ex, captured.get());
        }
    }

    @Nested
    @DisplayName("3. EmptyResult Scenarios & Fallbacks")
    class EmptyResultTests {

        @Test
        @DisplayName("Should correctly instantiate EmptyResult via of(null) and empty()")
        void shouldInstantiateEmptyResult() {
            Result<String> res1 = Result.of(null);
            Result<String> res2 = Result.empty();

            assertFalse(res1.hasResult());
            assertFalse(res1.isError());
            assertTrue(res1.isEmpty());
            assertNull(res1.get());

            assertFalse(res2.hasResult());
            assertFalse(res2.isError());
            assertTrue(res2.isEmpty());
            assertNull(res2.get());
        }

        @Test
        @DisplayName("Should bypass both Ok and Error callbacks")
        void shouldBypassBothOkAndError() {
            AtomicBoolean okCalled = new AtomicBoolean(false);
            AtomicBoolean errorCalled = new AtomicBoolean(false);

            Result<String> result = Result.<String>empty()
                    .Ok(val -> okCalled.set(true))
                    .Error(ex -> errorCalled.set(true));

            assertFalse(okCalled.get());
            assertFalse(errorCalled.get());
            assertTrue(result.isEmpty());
        }

        @Test
        @DisplayName("flatMap on EmptyResult should return EmptyResult without invoking function")
        void flatMapShouldPropagateEmpty() {
            AtomicBoolean fnCalled = new AtomicBoolean(false);

            Result<Integer> result = Result.<String>empty()
                    .flatMap(val -> {
                        fnCalled.set(true);
                        return Result.success(val.length());
                    });

            assertFalse(fnCalled.get());
            assertTrue(result.isEmpty());
        }

        @Test
        @DisplayName("flatMapOrElse on EmptyResult should execute alternative (fallback mechanism)")
        void flatMapOrElseShouldExecuteAlternativeOnEmpty() {
            AtomicBoolean fnCalled = new AtomicBoolean(false);

            Result<String> result = Result.<String>empty()
                    .flatMapOrElse(
                            val -> {
                                fnCalled.set(true);
                                return Result.success("from-fn");
                            },
                            () -> Result.success("from-fallback")
                    );

            assertFalse(fnCalled.get());
            assertTrue(result.hasResult());
            assertEquals("from-fallback", result.get());
        }

        @Test
        @DisplayName("mapFuture on EmptyResult should return completed future with EmptyResult without NPE")
        void mapFutureShouldReturnEmptyFutureSafely() throws Exception {
            AtomicBoolean fnCalled = new AtomicBoolean(false);

            CompletableFuture<Result<Integer>> future = Result.<String>empty().mapFuture(
                    val -> {
                        fnCalled.set(true);
                        return CompletableFuture.completedFuture(Result.success(val.length()));
                    }
            );

            assertFalse(fnCalled.get());
            Result<Integer> res = future.get(2, TimeUnit.SECONDS);
            assertNotNull(res);
            assertTrue(res.isEmpty());
            assertFalse(res.hasResult());
            assertFalse(res.isError());
        }
    }

    @Nested
    @DisplayName("4. Complex & Hybrid Domain Pipelines")
    class ComplexPipelineTests {

        record UserToken(String kid, String subject, boolean active) {}

        @Test
        @DisplayName("Simulate realistic auth pipeline: kid extraction -> key fetch -> token decode -> verify")
        void simulateRealisticAuthPipeline() {
            String rawJwt = "valid.jwt.token";

            Result<String> pipeline = Result.of("kid-auth-1")
                    .flatMap(kid -> Result.success(new UserToken(kid, "john-doe", true)))
                    .flatMap(token -> {
                        if (!token.active()) {
                            return Result.failed(new DummyException("User is inactive"));
                        }
                        return Result.success("Authenticated: " + token.subject());
                    });

            assertTrue(pipeline.hasResult());
            assertEquals("Authenticated: john-doe", pipeline.get());
        }

        @Test
        @DisplayName("Simulate cache fallback: L1 Cache (Empty) -> L2 Cache (Hit)")
        void simulateCacheFallbackPipeline() {
            // L1 returns empty
            Result<String> l1Cache = Result.empty();

            Result<String> resolved = l1Cache.flatMapOrElse(
                    hit -> Result.success("L1: " + hit),
                    () -> Result.success("L2-fetched-key") // L2 fallback succeeds
            );

            assertTrue(resolved.hasResult());
            assertEquals("L2-fetched-key", resolved.get());
        }

        @Test
        @DisplayName("Simulate cache fallback: L1 Cache (Empty) -> L2 Cache (Miss) -> L3 Remote (Error)")
        void simulateMultiLevelCacheFailurePipeline() {
            Result<String> l1Cache = Result.empty();

            Result<String> resolved = l1Cache
                    .flatMapOrElse(
                            hit -> Result.success("L1: " + hit),
                            () -> Result.<String>empty() // L2 is also empty
                    )
                    .flatMapOrElse(
                            hit -> Result.success("L2: " + hit),
                            () -> Result.failed(new DummyException("S3 Remote Key Not Found")) // L3 fails
                    );

            assertTrue(resolved.isError());
            assertFalse(resolved.hasResult());

            AtomicReference<String> errorMsg = new AtomicReference<>();
            resolved.Error(ex -> errorMsg.set(ex.getMessage()));
            assertEquals("S3 Remote Key Not Found", errorMsg.get());
        }

        @Test
        @DisplayName("Deep asynchronous pipeline: non-blocking sequential mapFuture transformations")
        void deepAsyncPipelineTest() throws Exception {
            CompletableFuture<Result<String>> asyncPipeline = Result.success(10)
                    .mapFuture(val -> CompletableFuture.supplyAsync(() -> Result.success(val * 2)))
                    .thenCompose(res1 -> res1.mapFuture(val -> CompletableFuture.supplyAsync(() -> Result.success("Computed: " + val))))
                    .thenApply(res2 -> res2.flatMap(str -> Result.success(str + " [DONE]")));

            Result<String> finalResult = asyncPipeline.get(2, TimeUnit.SECONDS);
            assertNotNull(finalResult);
            assertTrue(finalResult.hasResult());
            assertEquals("Computed: 20 [DONE]", finalResult.get());
        }
    }
}
