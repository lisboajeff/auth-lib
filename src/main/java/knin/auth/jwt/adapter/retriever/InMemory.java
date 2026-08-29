package knin.auth.jwt.adapter.retriever;

import knin.auth.jwt.domain.logging.Log;
import knin.auth.jwt.domain.result.Result;
import knin.auth.jwt.domain.retriever.JsonWebKeys;
import knin.auth.jwt.domain.retriever.Keys;
import knin.auth.jwt.domain.retriever.TableChain;

import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

public final class InMemory extends TableChain<String> implements Keys {

    private final ConcurrentHashMap<String, JsonWebKeys> map;
    private final Log log;

    public InMemory() {
        this(Log.noop());
    }

    public InMemory(final Log log) {
        super();
        this.map = new ConcurrentHashMap<>();
        this.log = log != null ? log : Log.noop();
    }

    public InMemory(final TableChain<? super String> next) {
        this(next, Log.noop());
    }

    public InMemory(final TableChain<? super String> next, final Log log) {
        super(next);
        this.map = new ConcurrentHashMap<>();
        this.log = log != null ? log : Log.noop();
    }

    @Override
    protected CompletableFuture<Result<JsonWebKeys>> fetch(final String kid) {
        final JsonWebKeys keys = map.get(kid);
        if (keys != null) {
            log.info("[HIT - Level 1 InMemory] Key ID '%s' found in L1 cache", kid);
        } else {
            log.info("[MISS - Level 1 InMemory] Key ID '%s' not found in L1 cache", kid);
        }
        return CompletableFuture.completedFuture(Result.of(keys));
    }

    @Override
    protected void set(final JsonWebKeys responseData) {
        if (responseData == null || responseData.getIds() == null) {
            return;
        }
        final Set<String> identifiers = responseData.getIds();
        log.info("[UPDATE - Level 1 InMemory] Updating L1 cache with %d key(s): %s", identifiers.size(), identifiers);
        for (final String id : identifiers) {
            if (id != null) {
                map.put(id, responseData);
            }
        }
        map.keySet().removeIf(existingKey -> !identifiers.contains(existingKey));
    }

}
