package knin.auth.jwt.option;

import knin.auth.jwt.domain.validate.Token;

import java.util.Objects;

record IntrospectionImpl(Token token) implements Introspection {

    IntrospectionImpl() {
        this(null);
    }

    @Override
    public boolean hasToken() {
        return token != null;
    }

    @Override
    public Token token() {
        return Objects.requireNonNull(token);
    }

}
