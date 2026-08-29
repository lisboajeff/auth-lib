package knin.auth.jwt.domain.validate;

public interface Token {

    boolean containScopes();

    boolean hasScope(final String scope);

    String jwtToString();

}
