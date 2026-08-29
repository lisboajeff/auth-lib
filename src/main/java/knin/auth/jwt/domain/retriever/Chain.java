package knin.auth.jwt.domain.retriever;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;

@FunctionalInterface
public interface Chain<E> {

    CompletableFuture<Optional<JsonWebKeys>> get(final E e);

}
