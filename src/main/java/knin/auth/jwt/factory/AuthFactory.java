package knin.auth.jwt.factory;

import knin.auth.jwt.adapter.retriever.InMemory;
import knin.auth.jwt.adapter.retriever.Source;
import knin.auth.jwt.adapter.retriever.SourceChain;
import knin.auth.jwt.adapter.validate.TokenHandleProxy;
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

    public Introspect createIntrospect(final TokenHandle tokenHandle, final TableChain<? super String> tableChain) {
        final Keys keys = new InMemory(tableChain);
        return new Introspect(tokenHandle, keys);
    }

    public Introspect createIntrospect(final TableChain<? super String> tableChain) {
        return createIntrospect(createTokenHandle(), tableChain);
    }

    public TableChain<String> createSource(final TokenHandle tokenHandle, final Source source) {
        return new SourceChain(source, tokenHandle);
    }

    public TableChain<String> createSource(final TokenHandle tokenHandle, final Source source,
            final TableChain<? super String> next) {
        return new SourceChain(source, tokenHandle, next);
    }

    public TableChain<String> createSource(final Source source, final TableChain<? super String> next) {
        return createSource(createTokenHandle(), source, next);
    }

    public TableChain<String> createSource(final Source source) {
        return createSource(createTokenHandle(), source);
    }

}
