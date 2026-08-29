package knin.auth.jwt.domain.retriever;

import knin.auth.jwt.domain.result.Result;

import java.util.concurrent.CompletableFuture;

@FunctionalInterface
public interface Chain<E> {

    CompletableFuture<Result<JsonWebKeys>> get(final E e);

}
