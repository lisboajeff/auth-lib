package knin.auth.jwt.domain.retriever;

import java.util.Set;

public interface JsonWebKeys {

    byte[] toBytes();

    Set<String> getIds();

}
