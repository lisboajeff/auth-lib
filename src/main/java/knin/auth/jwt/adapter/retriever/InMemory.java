package knin.auth.jwt.adapter.retriever;

import knin.auth.jwt.domain.retriever.JsonWebKeys;
import knin.auth.jwt.domain.retriever.TableChain;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

public final class InMemory extends TableChain<String> {

    public InMemory() {
        this.map = new ConcurrentHashMap<>();
    }

    public InMemory(final TableChain<? super String> next) {
        super(next);
        this.map = new ConcurrentHashMap<>();
    }

    private final ConcurrentHashMap<String, JsonWebKeys> map;

    @Override
    protected CompletableFuture<Optional<JsonWebKeys>> fetch(final String kid) {
        return CompletableFuture.completedFuture(Optional.ofNullable(map.get(kid)));
    }

    @Override
    protected void set(final JsonWebKeys responseData) {
        if (responseData == null || responseData.getIds() == null) {
            return;
        }
        map.keySet().retainAll(responseData.getIds());
        for (final String id : responseData.getIds()) {
            map.put(id, responseData);
        }
    }
}
