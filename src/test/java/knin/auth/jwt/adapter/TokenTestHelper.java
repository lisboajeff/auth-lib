package knin.auth.jwt.adapter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.zip.GZIPOutputStream;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import knin.auth.jwt.domain.retriever.JsonWebKeys;
import knin.auth.jwt.domain.retriever.TableChain;
import knin.auth.jwt.domain.validate.TokenHandle;

public final class TokenTestHelper {

    private TokenTestHelper() {
    }

    public static RSAKey generateRsaJwk(final String keyId) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair keyPair = kpg.generateKeyPair();

            return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey((RSAPrivateKey) keyPair.getPrivate())
                    .keyID(keyId)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate RSA JWK", e);
        }
    }

    public static JsonWebKeys createJsonWebKeys(final TokenHandle handle, final RSAKey... keys) {
        JWKSet jwkSet = new JWKSet(Arrays.stream(keys).map(k -> (JWK) k.toPublicJWK()).toList());
        final byte[] jwksBytes = jwkSet.toString().getBytes(StandardCharsets.UTF_8);
        final Set<String> ids = handle.extractIdentifiers(jwksBytes);

        return new JsonWebKeys() {
            @Override
            public byte[] toBytes() {
                return jwksBytes;
            }

            @Override
            public Set<String> getIds() {
                return ids;
            }
        };
    }

    public static TableChain<String> createKeys(final TokenHandle handle, final RSAKey... keys) {
        final JsonWebKeys jsonWebKeys = createJsonWebKeys(handle, keys);
        return new InMemoryKeys(jsonWebKeys);
    }

    public static String gzipAndBase64Url(final String input) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gzos = new GZIPOutputStream(baos)) {
            gzos.write(input.getBytes(StandardCharsets.UTF_8));
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(baos.toByteArray());
    }

    public static String createJwt(final RSAKey signingKey, final String kid, final Date exp, final Object scopeClaim) {
        try {
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                    .subject("test-user")
                    .issuer("https://auth.example.org")
                    .issueTime(new Date())
                    .expirationTime(exp);

            if (scopeClaim != null) {
                builder.claim("scope", scopeClaim);
            }

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build(),
                    builder.build()
            );
            signedJWT.sign(new RSASSASigner(signingKey.toRSAPrivateKey()));
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create JWT", e);
        }
    }

    public static String createFourPartsJwt(final RSAKey signingKey, final String kid, final Date exp, final String gzipScopes) throws IOException {
        String jwt3Parts = createJwt(signingKey, kid, exp, null);
        String part4 = gzipAndBase64Url(gzipScopes);
        return jwt3Parts + "." + part4;
    }

    private static final class InMemoryKeys extends TableChain<String> {

        private final JsonWebKeys jsonWebKeys;

        private InMemoryKeys(final JsonWebKeys jsonWebKeys) {
            this.jsonWebKeys = jsonWebKeys;
        }

        @Override
        protected CompletableFuture<Optional<JsonWebKeys>> fetch(final String kid) {
            if (kid != null && jsonWebKeys.getIds().contains(kid)) {
                return CompletableFuture.completedFuture(Optional.of(jsonWebKeys));
            }
            return CompletableFuture.completedFuture(Optional.empty());
        }

        @Override
        protected void set(final JsonWebKeys responseData) {
            // No-op for in-memory test implementation
        }
    }
}
