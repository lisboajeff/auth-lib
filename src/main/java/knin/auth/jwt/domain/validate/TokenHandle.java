package knin.auth.jwt.domain.validate;

import knin.auth.jwt.domain.result.Result;
import knin.auth.jwt.domain.retriever.JsonWebKeys;

import java.util.Set;

public interface TokenHandle {

    Result<String> getKid(final String jwt);

    Result<TokenData> decode(final JsonWebKeys jsonWebKeys, final String jwt);

    Set<String> extractIdentifiers(final byte[] keysRaw);

}
