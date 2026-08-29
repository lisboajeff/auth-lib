package knin.auth.jwt.option;

import knin.auth.jwt.domain.retriever.Keys;
import knin.auth.jwt.domain.validate.JWT;
import knin.auth.jwt.domain.validate.TokenHandle;
import knin.auth.jwt.domain.validate.TokenJWTInvalidException;

import java.util.concurrent.CompletableFuture;

public final class Introspect {

    public Introspect(final TokenHandle handle, final Keys keys) {
        this.handle = handle;
        this.keys = keys;
    }

    private final TokenHandle handle;

    private final Keys keys;

    public CompletableFuture<Introspection> introspect(final String jwt) throws TokenJWTInvalidException {
        return keys.get(handle.getKid(jwt))
                .thenApply(optional -> optional.map(jsonWebKeys -> JWT.from(handle.decode(jsonWebKeys, jwt))).map(IntrospectionImpl::new)
                        .orElse(new IntrospectionImpl()));
    }

}
