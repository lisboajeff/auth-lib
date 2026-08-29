package knin.auth.jwt.adapter.validate;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;

import com.nimbusds.jose.jwk.RSAKey;
import knin.auth.jwt.adapter.TokenTestHelper;
import knin.auth.jwt.domain.result.Result;
import knin.auth.jwt.domain.retriever.JsonWebKeys;
import knin.auth.jwt.domain.validate.JWT;
import knin.auth.jwt.domain.validate.Token;
import knin.auth.jwt.domain.validate.TokenData;
import knin.auth.jwt.domain.validate.TokenHandle;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
    void shouldExtractKidSuccessfully() {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"my-key-id-123\"}";
        String headerB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String jwt = headerB64 + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";

        Result<String> kidResult = tokenUtil.getKid(jwt);

        assertTrue(kidResult.hasResult());
        assertEquals("my-key-id-123", kidResult.get());
    }

    @Test
    @DisplayName("Should return error Result when kid is not present in the header")
    void shouldReturnErrorWhenNoKidInHeader() {
        String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String headerB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String jwt = headerB64 + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";

        Result<String> result = tokenUtil.getKid(jwt);
        assertTrue(result.isError());
        assertFalse(result.hasResult());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "invalid_no_dots", "notbase64!@#.payload.sig"})
    @DisplayName("Should return error Result for null, blank, or malformed tokens")
    void shouldReturnErrorForInvalidJwt(String jwt) {
        Result<String> result = tokenUtil.getKid(jwt);
        assertTrue(result.isError());
        assertFalse(result.hasResult());
    }

    @Test
    @DisplayName("3-part token with scope = 'A B C' should return collection containing those scopes")
    void shouldExtractScopesFromThreePartsTokenWithSpaceSeparatedString() {
        Date futureExp = new Date(System.currentTimeMillis() + 60_000);
        String jwt = TokenTestHelper.createJwt(rsaJWK, "auth-key-1", futureExp, "A B C");

        Result<TokenData> tokenResult = tokenUtil.decode(jsonWebKeys, jwt);

        assertTrue(tokenResult.hasResult());
        TokenData tokenData = tokenResult.get();
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

        Result<TokenData> tokenResult = tokenUtil.decode(jsonWebKeys, jwt);

        assertTrue(tokenResult.hasResult());
        TokenData tokenData = tokenResult.get();
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

        Result<TokenData> tokenResult = tokenUtil.decode(jsonWebKeys, jwt4Parts);

        assertTrue(tokenResult.hasResult());
        TokenData tokenData = tokenResult.get();
        assertNotNull(tokenData);
        assertEquals(jwt3Parts, tokenData.jwtToString());
        Set<String> scopes = tokenData.getCollectionByKey("scopes");
        assertEquals(Set.of("A", "B", "C"), scopes);
    }

    @Test
    @DisplayName("Should return error Result when token is expired")
    void shouldReturnErrorWhenTokenIsExpired() {
        Date pastExp = new Date(System.currentTimeMillis() - 60_000);
        String expiredJwt = TokenTestHelper.createJwt(rsaJWK, "auth-key-1", pastExp, List.of("READ"));

        Result<TokenData> result = tokenUtil.decode(jsonWebKeys, expiredJwt);
        assertTrue(result.isError());
        assertFalse(result.hasResult());
    }

    @Test
    @DisplayName("Should return error Result when signature is invalid (signed by different key)")
    void shouldReturnErrorWhenSignatureIsInvalid() {
        Date futureExp = new Date(System.currentTimeMillis() + 60_000);
        String invalidSignedJwt = TokenTestHelper.createJwt(otherRsaJWK, "auth-key-1", futureExp, List.of("READ"));

        Result<TokenData> result = tokenUtil.decode(jsonWebKeys, invalidSignedJwt);
        assertTrue(result.isError());
        assertFalse(result.hasResult());
    }

    @Test
    @DisplayName("Should return error Result when kid is not found in JWKS")
    void shouldReturnErrorWhenKidNotFoundInJwks() {
        Date futureExp = new Date(System.currentTimeMillis() + 60_000);
        String unknownKidJwt = TokenTestHelper.createJwt(rsaJWK, "unknown-kid-999", futureExp, List.of("READ"));

        Result<TokenData> result = tokenUtil.decode(jsonWebKeys, unknownKidJwt);
        assertTrue(result.isError());
        assertFalse(result.hasResult());
    }

    @Test
    @DisplayName("Should seamlessly integrate with JWT.from(tokenData)")
    void shouldIntegrateWithJWTFrom() throws Exception {
        Date futureExp = new Date(System.currentTimeMillis() + 60_000);
        String jwt3Parts = TokenTestHelper.createJwt(rsaJWK, "auth-key-1", futureExp, null);
        String jwt4Parts = jwt3Parts + "." + TokenTestHelper.gzipAndBase64Url("ADMIN, USER");

        Result<TokenData> tokenResult = tokenUtil.decode(jsonWebKeys, jwt4Parts);
        assertTrue(tokenResult.hasResult());
        Token token = JWT.from(tokenResult.get());

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

        Result<TokenData> tokenResult = tokenUtil.decode(ecJwks, ecJwt);

        assertTrue(tokenResult.hasResult());
        TokenData tokenData = tokenResult.get();
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

        Result<TokenData> tokenResult = tokenUtil.decode(ecJwks, ecJwt4Parts);

        assertTrue(tokenResult.hasResult());
        TokenData tokenData = tokenResult.get();
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

        Result<TokenData> rsaResult = tokenUtil.decode(mixedJwks, rsaJwt);
        Result<TokenData> ecResult = tokenUtil.decode(mixedJwks, ecJwt);

        assertTrue(rsaResult.hasResult());
        assertTrue(ecResult.hasResult());
        assertEquals(Set.of("RSA_SCOPE"), rsaResult.get().getCollectionByKey("scopes"));
        assertEquals(Set.of("EC_SCOPE"), ecResult.get().getCollectionByKey("scopes"));
    }

    @Test
    @DisplayName("Should return error Result when jsonWebKeys is null or has null bytes")
    void shouldReturnErrorWhenJsonWebKeysIsNull() {
        Result<TokenData> nullKeysResult = tokenUtil.decode(null, "some.valid.jwt");
        assertTrue(nullKeysResult.isError());

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
        Result<TokenData> nullBytesResult = tokenUtil.decode(keysWithNullBytes, "some.valid.jwt");
        assertTrue(nullBytesResult.isError());
    }
}
