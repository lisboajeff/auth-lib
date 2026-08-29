package knin.auth.jwt.option;

import knin.auth.jwt.domain.validate.Token;

public interface Introspection {

    boolean hasToken();

    Token token();

}
