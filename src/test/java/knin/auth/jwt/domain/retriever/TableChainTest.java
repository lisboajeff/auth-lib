package knin.auth.jwt.domain.retriever;

import knin.auth.jwt.domain.result.Result;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TableChainTest {

    @Test
    @DisplayName("Should return JsonWebKeys when key exists in current chain element")
    void shouldReturnDataWhenKeyExists() {
        final Set<String> identifiers = Set.of("123", "345");
        final TableChainSkeleton table = createTable(identifiers);

        final Result<JsonWebKeys> optional = table.get("123").join();

        assertTrue(optional.hasResult());
        final JsonWebKeys jsonWebKeys = optional.get();
        assertArrayEquals("COMPLETE".getBytes(StandardCharsets.UTF_8), jsonWebKeys.toBytes());
        assertEquals(identifiers, jsonWebKeys.getIds());
    }

    @Test
    @DisplayName("Should return empty optional when key does not exist in chain")
    void shouldReturnEmptyWhenKeyDoesNotExist() {
        final TableChainSkeleton table = createEmptyTable();

        final Result<JsonWebKeys> optional = table.get("123").join();

        assertTrue(optional.isEmpty());
    }

    @Test
    @DisplayName("Should delegate to next element in chain and populate current element via set()")
    void shouldDelegateToNextInChainAndPopulateCurrent() {
        final Set<String> identifiers = Set.of("123", "345");
        final AtomicReference<JsonWebKeys> atomic = new AtomicReference<>();

        final TableChainSkeleton table = new TableChainSkeleton(createTable(identifiers)) {
            @Override
            protected CompletableFuture<Result<JsonWebKeys>> fetch(final String s) {
                return CompletableFuture.completedFuture(Result.empty());
            }

            @Override
            protected void set(final JsonWebKeys responseData) {
                atomic.set(Objects.requireNonNull(responseData));
            }
        };

        final Result<JsonWebKeys> optional = table.get("123").join();

        assertTrue(optional.hasResult());
        final JsonWebKeys jsonWebKeys = optional.get();
        assertEquals(atomic.get(), jsonWebKeys);
        assertArrayEquals("COMPLETE".getBytes(StandardCharsets.UTF_8), jsonWebKeys.toBytes());
        assertEquals(identifiers, jsonWebKeys.getIds());
    }

    private static TableChainSkeleton createEmptyTable() {
        return new TableChainSkeleton() {
            @Override
            protected CompletableFuture<Result<JsonWebKeys>> fetch(final String s) {
                return CompletableFuture.completedFuture(Result.empty());
            }
        };
    }

    private static TableChainSkeleton createTable(final Set<String> identifiers) {
        return new TableChainSkeleton(createEmptyTable()) {
            @Override
            protected CompletableFuture<Result<JsonWebKeys>> fetch(final String s) {
                return CompletableFuture.completedFuture(
                        Result.of(
                                new JsonWebKeysSkeleton() {
                                    @Override
                                    public byte[] toBytes() {
                                        return "COMPLETE".getBytes(StandardCharsets.UTF_8);
                                    }

                                    @Override
                                    public Set<String> getIds() {
                                        return identifiers;
                                    }
                                }
                        )
                );
            }
        };
    }
}