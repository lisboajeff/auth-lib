package knin.auth.jwt.domain.validate;

import knin.auth.jwt.domain.retriever.JsonWebKeys;

import java.util.Set;

public interface TokenHandle {

    String getKid(final String jwt) throws TokenJWTInvalidException;

    TokenData decode(final JsonWebKeys jsonWebKeys, final String jwt) throws TokenJWTInvalidRuntimeException;

    Set<String> extractIdentifiers(final byte[] keysRaw);

}
