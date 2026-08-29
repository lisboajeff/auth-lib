package knin.auth.jwt.domain.result;

import java.util.function.Function;

public interface Result<Data> {

    static <D> Result<D> success(final D data) {
        return new SucessResult<>(data);
    }

    static <D> Result<D> failed(final ResultException exception) {
        return new FailedResult<>(exception);
    }

    Data Ok(final Function<? super Data, ? extends Data> function);

    boolean isOk();

    ResultException Error(final Function<? super ResultException, ? extends ResultException> function) throws ResultException;

}
