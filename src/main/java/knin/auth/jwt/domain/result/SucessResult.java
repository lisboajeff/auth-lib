package knin.auth.jwt.domain.result;

import java.util.function.Function;

final class SucessResult<Data> implements Result<Data> {

    SucessResult(final Data data) {
        this.data = data;
    }

    private final Data data;

    @Override
    public Data Ok(final Function<? super Data, ? extends Data> function) {
        return function.apply(data);
    }

    @Override
    public boolean isOk() {
        return true;
    }

    @Override
    public ResultException Error(final Function<? super ResultException, ? extends ResultException> supplier) {
        return null;
    }

}
