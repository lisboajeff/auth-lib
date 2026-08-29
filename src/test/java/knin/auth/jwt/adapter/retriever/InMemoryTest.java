package knin.auth.jwt.adapter.retriever;

import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import knin.auth.jwt.domain.result.Result;
import knin.auth.jwt.domain.retriever.JsonWebKeys;
import knin.auth.jwt.domain.retriever.TableChain;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InMemoryTest {

    private static JsonWebKeys createMockJsonWebKeys(Set<String> ids, String content) {
        final byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        return new JsonWebKeys() {
            @Override
            public byte[] toBytes() {
                return bytes;
            }

            @Override
            public Set<String> getIds() {
                return ids;
            }
        };
    }

    @Test
    @DisplayName("Should store and retrieve JsonWebKeys by any of its IDs")
    void shouldStoreAndFetchByIds() {
        InMemory inMemory = new InMemory();
        JsonWebKeys keys1 = createMockJsonWebKeys(Set.of("kid-1", "kid-2"), "jwks-1");

        inMemory.set(keys1);

        Result<JsonWebKeys> result1 = inMemory.fetch("kid-1").join();
        Result<JsonWebKeys> result2 = inMemory.fetch("kid-2").join();
        Result<JsonWebKeys> result3 = inMemory.fetch("kid-3").join();

        assertTrue(result1.hasResult());
        assertEquals(keys1, result1.get());
        assertTrue(result2.hasResult());
        assertEquals(keys1, result2.get());
        assertFalse(result3.hasResult());
    }

    @Test
    @DisplayName("Should evict stale KIDs that do not match the new responseData.getIds()")
    void shouldEvictOldKidsNotPresentInNewResponseData() {
        InMemory inMemory = new InMemory();
        JsonWebKeys initialKeys = createMockJsonWebKeys(Set.of("kid-1", "kid-2"), "jwks-initial");
        inMemory.set(initialKeys);

        // Verify initial presence
        assertTrue(inMemory.fetch("kid-1").join().hasResult());
        assertTrue(inMemory.fetch("kid-2").join().hasResult());

        // Update with new set containing kid-2 and kid-3 (kid-1 was removed during key rotation)
        JsonWebKeys rotatedKeys = createMockJsonWebKeys(Set.of("kid-2", "kid-3"), "jwks-rotated");
        inMemory.set(rotatedKeys);

        // kid-1 is no longer present
        assertFalse(inMemory.fetch("kid-1").join().hasResult());
        // kid-2 and kid-3 are present and point to rotatedKeys
        Result<JsonWebKeys> resultKid2 = inMemory.fetch("kid-2").join();
        assertTrue(resultKid2.hasResult());
        assertEquals(rotatedKeys, resultKid2.get());

        Result<JsonWebKeys> resultKid3 = inMemory.fetch("kid-3").join();
        assertTrue(resultKid3.hasResult());
        assertEquals(rotatedKeys, resultKid3.get());
    }

    @Test
    @DisplayName("Should delegate to next element in chain and save automatically in InMemory cache")
    void shouldDelegateToNextChainAndSaveAutomatically() {
        JsonWebKeys upstreamKeys = createMockJsonWebKeys(Set.of("kid-remote-1"), "jwks-remote");

        TableChain<String> upstream = new TableChain<>() {
            @Override
            protected CompletableFuture<Result<JsonWebKeys>> fetch(String kid) {
                if ("kid-remote-1".equals(kid)) {
                    return CompletableFuture.completedFuture(Result.of(upstreamKeys));
                }
                return CompletableFuture.completedFuture(Result.empty());
            }

            @Override
            protected void set(JsonWebKeys responseData) {
            }
        };

        InMemory inMemory = new InMemory(upstream);

        // First call fetches from upstream and caches in InMemory
        Result<JsonWebKeys> firstCall = inMemory.get("kid-remote-1").join();
        assertTrue(firstCall.hasResult());
        assertEquals(upstreamKeys, firstCall.get());

        // Second call fetches directly from InMemory
        Result<JsonWebKeys> secondCall = inMemory.fetch("kid-remote-1").join();
        assertTrue(secondCall.hasResult());
        assertEquals(upstreamKeys, secondCall.get());
    }
}
