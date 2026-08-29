package knin.auth.jwt.option;

import java.util.Date;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import com.nimbusds.jose.jwk.RSAKey;
import knin.auth.jwt.adapter.TokenTestHelper;
import knin.auth.jwt.domain.retriever.TableChain;
import knin.auth.jwt.domain.validate.Token;
import knin.auth.jwt.domain.validate.TokenHandle;
import knin.auth.jwt.domain.validate.TokenJWTInvalidException;
import knin.auth.jwt.domain.validate.TokenJWTInvalidRuntimeException;
import knin.auth.jwt.factory.AuthFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IntrospectTest {

    private static RSAKey rsaJWK;
    private static RSAKey otherRsaJWK;
    private static TableChain<String> keys;
    private static TokenHandle handle;
    private static AuthFactory authFactory;

    @BeforeAll
    static void setUp() {
        authFactory = new AuthFactory();
        rsaJWK = TokenTestHelper.generateRsaJwk("auth-key-jwks-1");
        otherRsaJWK = TokenTestHelper.generateRsaJwk("untrusted-key-2");
        handle = authFactory.createTokenHandle();
        keys = TokenTestHelper.createKeys(handle, rsaJWK);
    }

    @Test
    @DisplayName("Should successfully introspect a 3-part token using keys in JWKS format")
    void shouldIntrospectThreePartsTokenSuccessfullyWithJwks() throws Exception {
        Date futureExp = new Date(System.currentTimeMillis() + 60_000);
        String jwt = TokenTestHelper.createJwt(rsaJWK, "auth-key-jwks-1", futureExp, "A B C");

        Introspect introspect = createIntrospect();

        Introspection introspection = introspect.introspect(jwt).join();

        assertNotNull(introspection);
        assertTrue(introspection.hasToken());

        Token token = introspection.token();
        assertNotNull(token);
        assertTrue(token.containScopes());
        assertTrue(token.hasScope("a"));
        assertTrue(token.hasScope("b"));
        assertTrue(token.hasScope("c"));
        assertEquals(jwt, token.jwtToString());
    }

    private static Introspect createIntrospect() {
        return authFactory.createIntrospect(handle, keys);
    }

    @Test
    @DisplayName("Should successfully introspect a 4-part (GZIP) token using keys in JWKS format")
    void shouldIntrospectFourPartsTokenSuccessfullyWithJwks() throws Exception {
        Date futureExp = new Date(System.currentTimeMillis() + 60_000);
        String jwt4Parts = TokenTestHelper.createFourPartsJwt(rsaJWK, "auth-key-jwks-1", futureExp, "A,B,C");

        Introspect introspect = createIntrospect();

        Introspection introspection = introspect.introspect(jwt4Parts).join();

        assertNotNull(introspection);
        assertTrue(introspection.hasToken());

        Token token = introspection.token();
        assertNotNull(token);
        assertTrue(token.containScopes());
        assertTrue(token.hasScope("a"));
        assertTrue(token.hasScope("b"));
        assertTrue(token.hasScope("c"));
        assertEquals(jwt4Parts, token.jwtToString());
    }

    @Test
    @DisplayName("Should return empty introspection when JWKS is not found for the kid")
    void shouldReturnEmptyIntrospectionWhenKeyNotFoundInJwksRetriever() throws Exception {
        Date futureExp = new Date(System.currentTimeMillis() + 60_000);
        String jwt = TokenTestHelper.createJwt(rsaJWK, "non-existent-kid", futureExp, "A B");

        Introspect introspect = createIntrospect();

        Introspection introspection = introspect.introspect(jwt).join();

        assertNotNull(introspection);
        assertFalse(introspection.hasToken());
        assertThrows(NullPointerException.class, introspection::token);
    }

    @Test
    @DisplayName("Should synchronously throw TokenJWTInvalidException for malformed, blank or null tokens")
    void shouldThrowTokenJWTInvalidExceptionForMalformedToken() {
        Introspect introspect = createIntrospect();

        assertThrows(TokenJWTInvalidException.class, () -> introspect.introspect("not.a.valid.jwt"));
        assertThrows(TokenJWTInvalidException.class, () -> introspect.introspect(null));
        assertThrows(TokenJWTInvalidException.class, () -> introspect.introspect("   "));
    }

    @Test
    @DisplayName("Should complete exceptionally when token is expired")
    void shouldCompleteExceptionallyWhenTokenIsExpired() throws Exception {
        Date pastExp = new Date(System.currentTimeMillis() - 60_000);
        String expiredJwt = TokenTestHelper.createJwt(rsaJWK, "auth-key-jwks-1", pastExp, "A");

        Introspect introspect = createIntrospect();

        CompletableFuture<Introspection> future = introspect.introspect(expiredJwt);

        CompletionException ex = assertThrows(CompletionException.class, future::join);
        assertInstanceOf(TokenJWTInvalidRuntimeException.class, ex.getCause());
    }

    @Test
    @DisplayName("Should complete exceptionally when token signature is invalid")
    void shouldCompleteExceptionallyWhenSignatureIsInvalid() throws Exception {
        Date futureExp = new Date(System.currentTimeMillis() + 60_000);
        String invalidSignedJwt = TokenTestHelper.createJwt(otherRsaJWK, "auth-key-jwks-1", futureExp, "A");

        Introspect introspect = createIntrospect();

        CompletableFuture<Introspection> future = introspect.introspect(invalidSignedJwt);

        CompletionException ex = assertThrows(CompletionException.class, future::join);
        assertInstanceOf(TokenJWTInvalidRuntimeException.class, ex.getCause());
    }
}
