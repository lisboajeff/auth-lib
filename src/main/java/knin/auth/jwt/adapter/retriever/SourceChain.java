package knin.auth.jwt.adapter.retriever;

import knin.auth.jwt.domain.result.Result;
import knin.auth.jwt.domain.retriever.JsonWebKeys;
import knin.auth.jwt.domain.retriever.TableChain;
import knin.auth.jwt.domain.validate.TokenHandle;

import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

public final class SourceChain extends TableChain<String> {

    public SourceChain(final Source source, final TokenHandle tokenHandle) {
        this.source = source;
        this.tokenHandle = tokenHandle;
        this.inFlight = new ConcurrentHashMap<>();
    }

    public SourceChain(final Source source, final TokenHandle tokenHandle, final TableChain<? super String> next) {
        super(next);
        this.source = source;
        this.tokenHandle = tokenHandle;
        this.inFlight = new ConcurrentHashMap<>();
    }

    private final Source source;
    private final TokenHandle tokenHandle;
    private final ConcurrentHashMap<String, CompletableFuture<Result<JsonWebKeys>>> inFlight;

    @Override
    protected CompletableFuture<Result<JsonWebKeys>> fetch(final String kid) {

        final CompletableFuture<Result<JsonWebKeys>> future = inFlight.computeIfAbsent(kid, k -> source.fetchData()
                .thenApply(bytes -> {
                    if (bytes == null) {
                        return Result.empty();
                    }

                    final Set<String> identifiers = tokenHandle.extractIdentifiers(bytes);

                    if (identifiers == null || !identifiers.contains(k)) {
                        return Result.empty();
                    }

                    final JsonWebKeys keys = new JsonWebKeys() {
                        @Override
                        public byte[] toBytes() {
                            return bytes;
                        }

                        @Override
                        public Set<String> getIds() {
                            return identifiers;
                        }
                    };

                    return Result.success(keys);

                }));

        future.whenComplete((result, throwable) -> inFlight.remove(kid, future));

        return future;

    }

    @Override
    protected void set(final JsonWebKeys responseData) {
        //
    }

}
