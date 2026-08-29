package knin.auth.jwt.domain.retriever;

import knin.auth.jwt.domain.result.Result;

import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

public abstract class TableChain<E> implements Chain<E> {

    protected TableChain(final TableChain<? super E> next) {
        this.next = Objects.requireNonNull(next);
    }

    protected TableChain() {
        next = null;
    }

    private final TableChain<? super E> next;

    @Override
    public final CompletableFuture<Result<JsonWebKeys>> get(final E e) {
        return fetch(e)
                .thenCompose(result -> {
                    if (result.hasResult()) {
                        return CompletableFuture.completedFuture(result);
                    }
                    return nextHandle(e);
                });
    }

    private CompletionStage<Result<JsonWebKeys>> nextHandle(final E e) {
        if (next == null)
            return CompletableFuture.completedFuture(Result.empty());
        return next.get(e).thenApply(result -> result.Ok(this::set));
    }

    protected abstract CompletableFuture<Result<JsonWebKeys>> fetch(final E e);

    protected abstract void set(final JsonWebKeys responseData);

}
