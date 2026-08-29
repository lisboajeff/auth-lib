package knin.auth.jwt.adapter.validate;

import knin.auth.jwt.domain.result.Result;
import knin.auth.jwt.domain.retriever.JsonWebKeys;
import knin.auth.jwt.domain.validate.TokenData;
import knin.auth.jwt.domain.validate.TokenHandle;
import knin.auth.jwt.domain.validate.TokenJWTInvalidException;

import java.util.Set;

public final class TokenHandleProxy implements TokenHandle {

    public TokenHandleProxy() {
        this.proxy = new TokenUtil();
    }

    private final TokenUtil proxy;

    @Override
    public Result<String> getKid(String jwt) {
        if (jwt == null || jwt.isBlank()) {
            return Result.failed(new TokenJWTInvalidException());
        }
        return proxy.getKid(jwt);
    }

    @Override
    public Result<TokenData> decode(JsonWebKeys jsonWebKeys, String jwt) {
        if (jsonWebKeys == null || jsonWebKeys.toBytes() == null) {
            return Result.failed(new TokenJWTInvalidException("Keys cannot be null"));
        }
        if (jwt == null || jwt.isBlank()) {
            return Result.failed(new TokenJWTInvalidException("JWT cannot be null or blank"));
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
