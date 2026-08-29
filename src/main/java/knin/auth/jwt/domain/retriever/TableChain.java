package knin.auth.jwt.domain.retriever;

import java.util.Objects;
import java.util.Optional;
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
    public final CompletableFuture<Optional<JsonWebKeys>> get(final E e) {
        return fetch(e)
                .thenCompose(optional -> {
                    if (optional.isPresent()) {
                        return CompletableFuture.completedFuture(optional);
                    }
                    return nextHandle(e);
                });
    }

    private CompletionStage<Optional<JsonWebKeys>> nextHandle(final E e) {
        if (next == null)
            return CompletableFuture.completedFuture(Optional.empty());
        return next.get(e).thenApply(optional -> {
            optional.ifPresent(this::set);
            return optional;
        });
    }

    protected abstract CompletableFuture<Optional<JsonWebKeys>> fetch(final E e);

    protected abstract void set(final JsonWebKeys responseData);

}
