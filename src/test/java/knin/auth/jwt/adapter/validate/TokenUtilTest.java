package knin.auth.jwt.adapter.validate;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;

import com.nimbusds.jose.jwk.RSAKey;
import knin.auth.jwt.adapter.TokenTestHelper;
import knin.auth.jwt.domain.retriever.JsonWebKeys;
import knin.auth.jwt.domain.validate.JWT;
import knin.auth.jwt.domain.validate.Token;
import knin.auth.jwt.domain.validate.TokenData;
import knin.auth.jwt.domain.validate.TokenHandle;
import knin.auth.jwt.domain.validate.TokenJWTInvalidException;
import knin.auth.jwt.domain.validate.TokenJWTInvalidRuntimeException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenUtilTest {

    private final TokenHandle tokenUtil = new TokenHandleProxy();

    private static RSAKey rsaJWK;
    private static RSAKey otherRsaJWK;
    private static JsonWebKeys jsonWebKeys;

    @BeforeAll
    static void setUp() {
        rsaJWK = TokenTestHelper.generateRsaJwk("auth-key-1");
        otherRsaJWK = TokenTestHelper.generateRsaJwk("other-key-2");
        TokenHandle handle = new TokenHandleProxy();
        byte[] keys = TokenTestHelper.createJsonWebKeys(rsaJWK);
        final Set<String> identifiers = handle.extractIdentifiers(keys);
        jsonWebKeys = new JsonWebKeys() {
            @Override
            public byte[] toBytes() {
                return keys;
            }

            @Override
            public Set<String> getIds() {
                return identifiers;
            }
        };
    }

    @Test
    @DisplayName("Should extract identifiers (KIDs) from valid JWKS")
    void shouldExtractIdentifiersFromValidJwks() {
        RSAKey key1 = TokenTestHelper.generateRsaJwk("kid-1");
        RSAKey key2 = TokenTestHelper.generateRsaJwk("kid-2");
        byte[] keys = TokenTestHelper.createJsonWebKeys(key1, key2);

        Set<String> ids = tokenUtil.extractIdentifiers(keys);

        assertNotNull(ids);
        assertEquals(2, ids.size());
        assertEquals(Set.of("kid-1", "kid-2"), ids);
    }

    @Test
    @DisplayName("Should return empty Set for invalid or empty JWKS bytes in extractIdentifiers")
    void shouldReturnEmptySetForInvalidJwksBytes() {
        Set<String> idsEmpty = tokenUtil.extractIdentifiers(new byte[0]);
        assertTrue(idsEmpty.isEmpty());

        Set<String> idsInvalid = tokenUtil.extractIdentifiers("not-a-json".getBytes(StandardCharsets.UTF_8));
        assertTrue(idsInvalid.isEmpty());
    }

    @Test
    @DisplayName("Should extract kid successfully from a valid JWT token")
    void shouldExtractKidSuccessfully() throws TokenJWTInvalidException {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"my-key-id-123\"}";
        String headerB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String jwt = headerB64 + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";

        String kid = tokenUtil.getKid(jwt);

        assertEquals("my-key-id-123", kid);
    }

    @Test
    @DisplayName("Should throw TokenJWTInvalidException when kid is not present in the header")
    void shouldThrowWhenNoKidInHeader() {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String headerB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String jwt = headerB64 + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";

        assertThrows(TokenJWTInvalidException.class, () -> tokenUtil.getKid(jwt));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "invalid_no_dots", "notbase64!@#.payload.sig"})
    @DisplayName("Should throw TokenJWTInvalidException for null, blank, or malformed tokens")
    void shouldThrowForInvalidJwt(String jwt) {
        assertThrows(TokenJWTInvalidException.class, () -> tokenUtil.getKid(jwt));
    }

    @Test
    @DisplayName("3-part token with scope = 'A B C' should return collection containing those scopes")
    void shouldExtractScopesFromThreePartsTokenWithSpaceSeparatedString() {
        Date futureExp = new Date(System.currentTimeMillis() + 60_000);
        String jwt = TokenTestHelper.createJwt(rsaJWK, "auth-key-1", futureExp, "A B C");

        TokenData tokenData = tokenUtil.decode(jsonWebKeys, jwt);

        assertNotNull(tokenData);
        assertEquals(jwt, tokenData.jwtToString());
        Set<String> scopes = tokenData.getCollectionByKey("scopes");
        assertEquals(Set.of("A", "B", "C"), scopes);
    }

    @Test
    @DisplayName("3-part token without scope claim should return empty collection")
    void shouldReturnEmptyCollectionWhenTokenHasNoScopeClaim() {
        Date futureExp = new Date(System.currentTimeMillis() + 60_000);
        String jwt = TokenTestHelper.createJwt(rsaJWK, "auth-key-1", futureExp, null);

        TokenData tokenData = tokenUtil.decode(jsonWebKeys, jwt);

        assertNotNull(tokenData);
        assertEquals(jwt, tokenData.jwtToString());
        Set<String> scopes = tokenData.getCollectionByKey("scopes");
        assertNotNull(scopes);
        assertTrue(scopes.isEmpty());
    }

    @Test
    @DisplayName("4-part token with scope = 'A,B,C' should return collection containing those scopes and standard 3-part JWT")
    void shouldExtractScopesFromFourPartsTokenWithCommaSeparatedGzip() throws Exception {
        Date futureExp = new Date(System.currentTimeMillis() + 60_000);
        String jwt3Parts = TokenTestHelper.createJwt(rsaJWK, "auth-key-1", futureExp, null);
        String jwt4Parts = jwt3Parts + "." + TokenTestHelper.gzipAndBase64Url("A,B,C");

        TokenData tokenData = tokenUtil.decode(jsonWebKeys, jwt4Parts);

        assertNotNull(tokenData);
        assertEquals(jwt3Parts, tokenData.jwtToString());
        Set<String> scopes = tokenData.getCollectionByKey("scopes");
        assertEquals(Set.of("A", "B", "C"), scopes);
    }

    @Test
    @DisplayName("Should throw exception when token is expired")
    void shouldThrowWhenTokenIsExpired() {
        Date pastExp = new Date(System.currentTimeMillis() - 60_000);
        String expiredJwt = TokenTestHelper.createJwt(rsaJWK, "auth-key-1", pastExp, List.of("READ"));

        assertThrows(TokenJWTInvalidRuntimeException.class, () -> tokenUtil.decode(jsonWebKeys, expiredJwt));
    }

    @Test
    @DisplayName("Should throw exception when signature is invalid (signed by different key)")
    void shouldThrowWhenSignatureIsInvalid() {
        Date futureExp = new Date(System.currentTimeMillis() + 60_000);
        String invalidSignedJwt = TokenTestHelper.createJwt(otherRsaJWK, "auth-key-1", futureExp, List.of("READ"));

        assertThrows(TokenJWTInvalidRuntimeException.class, () -> tokenUtil.decode(jsonWebKeys, invalidSignedJwt));
    }

    @Test
    @DisplayName("Should throw exception when kid is not found in JWKS")
    void shouldThrowWhenKidNotFoundInJwks() {
        Date futureExp = new Date(System.currentTimeMillis() + 60_000);
        String unknownKidJwt = TokenTestHelper.createJwt(rsaJWK, "unknown-kid-999", futureExp, List.of("READ"));

        assertThrows(TokenJWTInvalidRuntimeException.class, () -> tokenUtil.decode(jsonWebKeys, unknownKidJwt));
    }

    @Test
    @DisplayName("Should seamlessly integrate with JWT.from(tokenData)")
    void shouldIntegrateWithJWTFrom() throws Exception {
        Date futureExp = new Date(System.currentTimeMillis() + 60_000);
        String jwt3Parts = TokenTestHelper.createJwt(rsaJWK, "auth-key-1", futureExp, null);
        String jwt4Parts = jwt3Parts + "." + TokenTestHelper.gzipAndBase64Url("ADMIN, USER");

        TokenData tokenData = tokenUtil.decode(jsonWebKeys, jwt4Parts);
        Token token = JWT.from(tokenData);

        assertTrue(token.containScopes());
        assertTrue(token.hasScope("admin"));
        assertTrue(token.hasScope("user"));
        assertEquals(jwt3Parts, token.jwtToString());
    }

    @Test
    @DisplayName("Should successfully decode 3-part token signed with EC (ES256)")
    void shouldDecodeValidEcTokenSuccessfully() {
        com.nimbusds.jose.jwk.ECKey ecKey = TokenTestHelper.generateEcJwk("ec-auth-key-1");
        byte[] ecJwksBytes = TokenTestHelper.createJsonWebKeys(ecKey);
        Set<String> ecIds = tokenUtil.extractIdentifiers(ecJwksBytes);
        JsonWebKeys ecJwks = new JsonWebKeys() {
            @Override
            public byte[] toBytes() {
                return ecJwksBytes;
            }

            @Override
            public Set<String> getIds() {
                return ecIds;
            }
        };

        Date futureExp = new Date(System.currentTimeMillis() + 60_000);
        String ecJwt = TokenTestHelper.createEcJwt(ecKey, "ec-auth-key-1", futureExp, "READ WRITE");

        TokenData tokenData = tokenUtil.decode(ecJwks, ecJwt);

        assertNotNull(tokenData);
        assertEquals(ecJwt, tokenData.jwtToString());
        assertEquals(Set.of("READ", "WRITE"), tokenData.getCollectionByKey("scopes"));
    }

    @Test
    @DisplayName("Should successfully decode 4-part (GZIP) token signed with EC (ES256)")
    void shouldDecodeFourPartsEcTokenSuccessfully() throws Exception {
        com.nimbusds.jose.jwk.ECKey ecKey = TokenTestHelper.generateEcJwk("ec-auth-key-2");
        byte[] ecJwksBytes = TokenTestHelper.createJsonWebKeys(ecKey);
        Set<String> ecIds = tokenUtil.extractIdentifiers(ecJwksBytes);
        JsonWebKeys ecJwks = new JsonWebKeys() {
            @Override
            public byte[] toBytes() {
                return ecJwksBytes;
            }

            @Override
            public Set<String> getIds() {
                return ecIds;
            }
        };

        Date futureExp = new Date(System.currentTimeMillis() + 60_000);
        String ecJwt3Parts = TokenTestHelper.createEcJwt(ecKey, "ec-auth-key-2", futureExp, null);
        String ecJwt4Parts = ecJwt3Parts + "." + TokenTestHelper.gzipAndBase64Url("SCOPE_A,SCOPE_B");

        TokenData tokenData = tokenUtil.decode(ecJwks, ecJwt4Parts);

        assertNotNull(tokenData);
        assertEquals(ecJwt3Parts, tokenData.jwtToString());
        assertEquals(Set.of("SCOPE_A", "SCOPE_B"), tokenData.getCollectionByKey("scopes"));
    }

    @Test
    @DisplayName("Should decode both RSA and EC tokens when JWKS contains mixed keys")
    void shouldDecodeBothRsaAndEcFromMixedJwks() {
        RSAKey mixedRsa = TokenTestHelper.generateRsaJwk("mixed-rsa-1");
        com.nimbusds.jose.jwk.ECKey mixedEc = TokenTestHelper.generateEcJwk("mixed-ec-1");
        byte[] mixedJwksBytes = TokenTestHelper.createJsonWebKeys(mixedRsa, mixedEc);
        Set<String> mixedIds = tokenUtil.extractIdentifiers(mixedJwksBytes);
        JsonWebKeys mixedJwks = new JsonWebKeys() {
            @Override
            public byte[] toBytes() {
                return mixedJwksBytes;
            }

            @Override
            public Set<String> getIds() {
                return mixedIds;
            }
        };

        Date futureExp = new Date(System.currentTimeMillis() + 60_000);
        String rsaJwt = TokenTestHelper.createJwt(mixedRsa, "mixed-rsa-1", futureExp, "RSA_SCOPE");
        String ecJwt = TokenTestHelper.createEcJwt(mixedEc, "mixed-ec-1", futureExp, "EC_SCOPE");

        TokenData rsaTokenData = tokenUtil.decode(mixedJwks, rsaJwt);
        TokenData ecTokenData = tokenUtil.decode(mixedJwks, ecJwt);

        assertEquals(Set.of("RSA_SCOPE"), rsaTokenData.getCollectionByKey("scopes"));
        assertEquals(Set.of("EC_SCOPE"), ecTokenData.getCollectionByKey("scopes"));
    }

    @Test
    @DisplayName("Should throw exception when jsonWebKeys is null or has null bytes")
    void shouldThrowWhenJsonWebKeysIsNull() {
        assertThrows(TokenJWTInvalidRuntimeException.class, () -> tokenUtil.decode(null, "some.valid.jwt"));

        JsonWebKeys keysWithNullBytes = new JsonWebKeys() {
            @Override
            public byte[] toBytes() {
                return null;
            }

            @Override
            public Set<String> getIds() {
                return Set.of();
            }
        };
        assertThrows(TokenJWTInvalidRuntimeException.class, () -> tokenUtil.decode(keysWithNullBytes, "some.valid.jwt"));
    }
}
