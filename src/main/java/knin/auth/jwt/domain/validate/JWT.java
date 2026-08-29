package knin.auth.jwt.domain.validate;

import java.util.Collections;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

public class JWT implements Token {

    public static Token from(final TokenData tokenData) {
        final Set<String> scopes = tokenData.getCollectionByKey("scopes")
                .stream()
                .map(String::trim)
                .map(String::toLowerCase)
                .collect(Collectors.toSet());
        return new JWT(scopes, tokenData.jwtToString());
    }

    private JWT(final Set<String> scopes, final String jwt) {
        this.scopes = scopes;
        this.jwt = jwt;
    }

    private final String jwt;

    private final Set<String> scopes;

    @Override
    public boolean containScopes() {
        return !scopes.isEmpty();
    }

    @Override
    public boolean hasScope(final String scope) {
        return scopes.contains(scope.toLowerCase(Locale.getDefault()));
    }

    @Override
    public Set<String> getScopes() {
        return Collections.unmodifiableSet(scopes);
    }

    @Override
    public String jwtToString() {
        return jwt;
    }

}
