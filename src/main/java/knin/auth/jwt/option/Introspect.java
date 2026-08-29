package knin.auth.jwt.option;

import knin.auth.jwt.domain.result.Result;
import knin.auth.jwt.domain.retriever.Keys;
import knin.auth.jwt.domain.validate.JWT;
import knin.auth.jwt.domain.validate.TokenHandle;

import java.util.concurrent.CompletableFuture;

public final class Introspect {

    public Introspect(final TokenHandle handle, final Keys keys) {
        this.handle = handle;
        this.keys = keys;
    }

    private final TokenHandle handle;

    private final Keys keys;

    public CompletableFuture<Result<Introspection>> introspect(final String jwt) {

        return handle.getKid(jwt)
                .mapFuture(keys::get)
                .thenApply(result -> result
                        .flatMap(jsonWebKeys -> handle.decode(jsonWebKeys, jwt)
                                .flatMap(tokenData -> Result.success(JWT.from(tokenData)))
                                .flatMapOrElse(token -> Result.success(new IntrospectionImpl(token)),
                                        () -> Result.success(new IntrospectionImpl()))
                        ));
    }

}
