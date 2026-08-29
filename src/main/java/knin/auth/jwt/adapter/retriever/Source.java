package knin.auth.jwt.adapter.retriever;

import java.util.concurrent.CompletableFuture;

@FunctionalInterface
public interface Source {

    CompletableFuture<byte[]> fetchData();

}
