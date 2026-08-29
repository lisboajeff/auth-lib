package knin.auth.jwt.domain.result;

import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

final class EmptyResult<Data> implements Result<Data> {

    static final EmptyResult<?> D_EMPTY_RESULT = new EmptyResult<>();

    @Override
    public <Other> Result<Other> flatMap(final Function<? super Data, ? extends Result<Other>> function) {
        return Result.empty();
    }

    @Override
    public <Other> Result<Other> flatMapOrElse(final Function<? super Data, ? extends Result<Other>> function, final Supplier<? extends Result<Other>> alternative) {
        return alternative.get();
    }

    @Override
    public <Other> CompletableFuture<Result<Other>> mapFuture(final Function<? super Data, ? extends CompletableFuture<Result<Other>>> function) {
        return CompletableFuture.completedFuture(Result.empty());
    }

    @Override
    public Result<Data> Ok(Consumer<? super Data> consumer) {
        return this;
    }

    @Override
    public Data get() {
        return null;
    }

    @Override
    public boolean isError() {
        return false;
    }

    @Override
    public boolean hasResult() {
        return false;
    }

    @Override
    public Result<Data> Error(final Consumer<? super ResultException> consumer) {
        return this;
    }

    @Override
    public boolean isEmpty() {
        return true;
    }

}
