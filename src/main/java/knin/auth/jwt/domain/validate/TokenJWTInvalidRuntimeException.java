package knin.auth.jwt.domain.validate;

public final class TokenJWTInvalidRuntimeException extends RuntimeException {
    public TokenJWTInvalidRuntimeException(String message) {
        super(message);
    }
}
