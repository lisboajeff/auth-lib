package knin.auth.jwt.domain.validate;

import knin.auth.jwt.domain.result.ResultException;

public final class TokenJWTInvalidException extends ResultException {

    public TokenJWTInvalidException() {
    }

    public TokenJWTInvalidException(String message) {
        super(message);
    }
}
