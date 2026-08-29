package knin.auth.jwt.domain.retriever;

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
