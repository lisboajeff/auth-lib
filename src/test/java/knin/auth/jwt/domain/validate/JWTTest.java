package knin.auth.jwt.domain.validate;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JWTTest {

    @Test
    @DisplayName("Should return false when JWT has no scopes")
    void shouldReturnFalseWhenJwtHasNoScopes() {
        final Token token = JWT.from(new TokenData() {
            @Override
            public Set<String> getCollectionByKey(final String key) {
                return Set.of();
            }

            @Override
            public String jwtToString() {
                return "jwt";
            }
        });

        assertFalse(token.containScopes());
        assertFalse(token.hasScope("123"));
        assertEquals("jwt", token.jwtToString());
    }

    @Test
    @DisplayName("Should find and sanitize scopes in JWT token successfully")
    void shouldFindScopesInToken() {
        final Token token = JWT.from(new TokenData() {
            @Override
            public Set<String> getCollectionByKey(final String key) {
                return Set.of("123", "456", "789", "  with_space", "with-hyphen ");
            }

            @Override
            public String jwtToString() {
                return "jwt.2";
            }
        });

        assertTrue(token.containScopes());
        assertTrue(token.hasScope("123"));
        assertTrue(token.hasScope("456"));
        assertTrue(token.hasScope("789"));
        assertTrue(token.hasScope("with_space"));
        assertTrue(token.hasScope("with-hyphen"));
        assertEquals("jwt.2", token.jwtToString());
    }
}