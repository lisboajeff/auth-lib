package knin.auth.jwt.domain.result;

import java.util.function.Function;

final class FailedResult<Data> implements Result<Data> {

    FailedResult(final ResultException exception) {
        this.exception = exception;
    }

    private final ResultException exception;

    @Override
    public Data Ok(final Function<? super Data, ? extends Data> function) {
        return null;
    }

    @Override
    public boolean isOk() {
        return false;
    }

    @Override
    public ResultException Error(final Function<? super ResultException, ? extends ResultException> function) {
        return function.apply(exception);
    }

}
