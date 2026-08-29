package knin.auth.jwt.domain.validate;

import java.util.Set;

public interface TokenData {

    Set<String> getCollectionByKey(final String key);

    String jwtToString();

}
