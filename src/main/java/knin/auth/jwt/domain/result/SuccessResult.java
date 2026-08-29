package knin.auth.jwt.domain.result;

import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

final class SuccessResult<Data> implements Result<Data> {

    SuccessResult(final Data data) {
        this.data = data;
    }

    private final Data data;

    @Override
    public <Other> Result<Other> flatMap(final Function<? super Data, ? extends Result<Other>> function) {
        return function.apply(data);
    }

    @Override
    public <Other> Result<Other> flatMapOrElse(final Function<? super Data, ? extends Result<Other>> function, final Supplier<? extends Result<Other>> alternative) {
        return function.apply(data);
    }

    @Override
    public <Other> CompletableFuture<Result<Other>> mapFuture(final Function<? super Data, ? extends CompletableFuture<Result<Other>>> function) {
        return function.apply(data);
    }

    @Override
    public Result<Data> Ok(final Consumer<? super Data> consumer) {
        consumer.accept(data);
        return this;
    }

    @Override
    public Data get() {
        return data;
    }

    @Override
    public boolean isError() {
        return false;
    }

    @Override
    public boolean hasResult() {
        return true;
    }

    @Override
    public Result<Data> Error(final Consumer<? super ResultException> consumer) {
        return this;
    }

    @Override
    public boolean isEmpty() {
        return false;
    }

}
