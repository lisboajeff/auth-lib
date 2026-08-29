package knin.auth.jwt.factory;

import knin.auth.jwt.adapter.retriever.InMemory;
import knin.auth.jwt.adapter.validate.TokenHandleProxy;
import knin.auth.jwt.domain.retriever.Chain;
import knin.auth.jwt.domain.retriever.Keys;
import knin.auth.jwt.domain.retriever.TableChain;
import knin.auth.jwt.domain.validate.TokenHandle;
import knin.auth.jwt.option.Introspect;

public final class AuthFactory {

    public AuthFactory() {
    }

    public TokenHandle createTokenHandle() {
        return new TokenHandleProxy();
    }

    private Introspect createIntrospect(final TokenHandle tokenHandle, final Keys keys) {
        return new Introspect(tokenHandle, keys);
    }

    public Introspect createIntrospect(final TokenHandle tokenHandle, final TableChain<? super String> tableChain) {
        final Chain<String> keys = new InMemory(tableChain);
        return createIntrospect(tokenHandle, keys::get);
    }

}
