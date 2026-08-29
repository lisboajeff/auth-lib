package knin.auth.jwt.adapter.retriever;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

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

        Optional<JsonWebKeys> result1 = inMemory.fetch("kid-1").join();
        Optional<JsonWebKeys> result2 = inMemory.fetch("kid-2").join();
        Optional<JsonWebKeys> result3 = inMemory.fetch("kid-3").join();

        assertTrue(result1.isPresent());
        assertEquals(keys1, result1.get());
        assertTrue(result2.isPresent());
        assertEquals(keys1, result2.get());
        assertFalse(result3.isPresent());
    }

    @Test
    @DisplayName("Should evict stale KIDs that do not match the new responseData.getIds()")
    void shouldEvictOldKidsNotPresentInNewResponseData() {
        InMemory inMemory = new InMemory();
        JsonWebKeys initialKeys = createMockJsonWebKeys(Set.of("kid-1", "kid-2"), "jwks-initial");
        inMemory.set(initialKeys);

        // Verify initial presence
        assertTrue(inMemory.fetch("kid-1").join().isPresent());
        assertTrue(inMemory.fetch("kid-2").join().isPresent());

        // Update with new set containing kid-2 and kid-3 (kid-1 was removed during key rotation)
        JsonWebKeys rotatedKeys = createMockJsonWebKeys(Set.of("kid-2", "kid-3"), "jwks-rotated");
        inMemory.set(rotatedKeys);

        // kid-1 is no longer present
        assertFalse(inMemory.fetch("kid-1").join().isPresent());
        // kid-2 and kid-3 are present and point to rotatedKeys
        Optional<JsonWebKeys> resultKid2 = inMemory.fetch("kid-2").join();
        assertTrue(resultKid2.isPresent());
        assertEquals(rotatedKeys, resultKid2.get());

        Optional<JsonWebKeys> resultKid3 = inMemory.fetch("kid-3").join();
        assertTrue(resultKid3.isPresent());
        assertEquals(rotatedKeys, resultKid3.get());
    }

    @Test
    @DisplayName("Should delegate to next element in chain and save automatically in InMemory cache")
    void shouldDelegateToNextChainAndSaveAutomatically() {
        JsonWebKeys upstreamKeys = createMockJsonWebKeys(Set.of("kid-remote-1"), "jwks-remote");

        TableChain<String> upstream = new TableChain<>() {
            @Override
            protected CompletableFuture<Optional<JsonWebKeys>> fetch(String kid) {
                if ("kid-remote-1".equals(kid)) {
                    return CompletableFuture.completedFuture(Optional.of(upstreamKeys));
                }
                return CompletableFuture.completedFuture(Optional.empty());
            }

            @Override
            protected void set(JsonWebKeys responseData) {
            }
        };

        InMemory inMemory = new InMemory(upstream);

        // First call fetches from upstream and caches in InMemory
        Optional<JsonWebKeys> firstCall = inMemory.get("kid-remote-1").join();
        assertTrue(firstCall.isPresent());
        assertEquals(upstreamKeys, firstCall.get());

        // Second call fetches directly from InMemory
        Optional<JsonWebKeys> secondCall = inMemory.fetch("kid-remote-1").join();
        assertTrue(secondCall.isPresent());
        assertEquals(upstreamKeys, secondCall.get());
    }
}
