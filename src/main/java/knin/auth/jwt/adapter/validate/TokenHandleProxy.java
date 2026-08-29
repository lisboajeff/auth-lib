package knin.auth.jwt.adapter.validate;

import knin.auth.jwt.domain.retriever.JsonWebKeys;
import knin.auth.jwt.domain.validate.TokenData;
import knin.auth.jwt.domain.validate.TokenHandle;
import knin.auth.jwt.domain.validate.TokenJWTInvalidException;
import knin.auth.jwt.domain.validate.TokenJWTInvalidRuntimeException;

import java.util.Set;

public final class TokenHandleProxy implements TokenHandle {

    public TokenHandleProxy() {
        this.proxy = new TokenUtil();
    }

    private final TokenUtil proxy;

    @Override
    public String getKid(String jwt) throws TokenJWTInvalidException {
        if (jwt == null || jwt.isBlank()) {
            throw new TokenJWTInvalidException();
        }
        return proxy.getKid(jwt);
    }

    @Override
    public TokenData decode(JsonWebKeys jsonWebKeys, String jwt) throws TokenJWTInvalidRuntimeException {
        if (jsonWebKeys == null || jsonWebKeys.toBytes() == null) {
            throw new TokenJWTInvalidRuntimeException("Keys cannot be null");
        }
        if (jwt == null || jwt.isBlank()) {
            throw new TokenJWTInvalidRuntimeException("JWT cannot be null or blank");
        }
        return proxy.decode(jsonWebKeys, jwt);
    }

    @Override
    public Set<String> extractIdentifiers(byte[] keysRaw) {
        if (keysRaw == null || keysRaw.length == 0) {
            return Set.of();
        }
        return proxy.extractIdentifiers(keysRaw);
    }

}
