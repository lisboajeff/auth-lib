package knin.auth.jwt.domain.validate;

import java.util.Set;

public interface Token {

    boolean containScopes();

    boolean hasScope(final String scope);

    Set<String> getScopes();

    String jwtToString();

}
