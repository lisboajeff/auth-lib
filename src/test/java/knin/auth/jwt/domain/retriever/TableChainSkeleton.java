package knin.auth.jwt.domain.retriever;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;

public class TableChainSkeleton extends TableChain<String> {

    public TableChainSkeleton(final TableChainSkeleton next) {
        super(next);
    }

    public TableChainSkeleton() {
    }

    @Override
    protected CompletableFuture<Optional<JsonWebKeys>> fetch(final String s) {
        throw new IllegalCallerException();
    }

    @Override
    protected void set(final JsonWebKeys responseData) {
        throw new IllegalCallerException();
    }

}
