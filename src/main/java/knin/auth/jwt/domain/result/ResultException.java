package knin.auth.jwt.domain.result;

public class ResultException extends Exception {

    public ResultException(){}

    public ResultException(final String message) {
        super(message);
    }

}
