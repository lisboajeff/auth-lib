package knin.auth.jwt.domain.retriever;

import knin.auth.jwt.domain.retriever.JsonWebKeys;

public class JsonWebKeysSkeleton implements JsonWebKeys {

    @Override
    public byte[] toBytes() {
        throw new IllegalCallerException();
    }

    @Override
    public java.util.Set<String> getIds() {
        throw new IllegalCallerException();
    }

}
