package knin.auth.jwt.domain.result;

import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

public interface Result<Data> {

    static <D> Result<D> of(final D data) {
        if (data == null) {
            return empty();
        }
        return success(data);
    }

    static <D> Result<D> success(final D data) {
        return new SuccessResult<>(data);
    }

    static <D> Result<D> failed(final ResultException exception) {
        return new FailedResult<>(exception);
    }

    @SuppressWarnings("unchecked")
    static <D> Result<D> empty() {
        return (Result<D>) EmptyResult.D_EMPTY_RESULT;
    }

    <Other> Result<Other> flatMap(final Function<? super Data, ? extends Result<Other>> function);

    <Other> Result<Other> flatMapOrElse(final Function<? super Data, ? extends Result<Other>> function, final Supplier<? extends Result<Other>> alternative);

    <Other> CompletableFuture<Result<Other>> mapFuture(final Function<? super Data, ? extends CompletableFuture<Result<Other>>> function);

    Result<Data> Ok(final Consumer<? super Data> consumer);

    Data get();

    boolean isError();

    boolean hasResult();

    Result<Data> Error(final Consumer<? super ResultException> function);

    boolean isEmpty();

}
