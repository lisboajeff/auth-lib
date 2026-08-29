package knin.auth.jwt.adapter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.CompletableFuture;
import java.util.zip.GZIPOutputStream;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import knin.auth.jwt.adapter.retriever.Source;
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

    public static ECKey generateEcJwk(final String keyId) {
        try {
            return new ECKeyGenerator(Curve.P_256)
                    .keyID(keyId)
                    .generate();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate EC JWK", e);
        }
    }

    public static byte[] createJsonWebKeys(final TokenHandle handle, final JWK... keys) {
        JWKSet jwkSet = new JWKSet(Arrays.stream(keys).map(JWK::toPublicJWK).toList());
        return jwkSet.toString().getBytes(StandardCharsets.UTF_8);
    }

    public static Source createSource(final TokenHandle handle, final JWK... keys) {
        final byte[] jsonWebKeys = createJsonWebKeys(handle, keys);
        return () -> CompletableFuture.completedFuture(jsonWebKeys);
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

            com.nimbusds.jwt.SignedJWT signedJWT = new com.nimbusds.jwt.SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build(),
                    builder.build()
            );
            signedJWT.sign(new RSASSASigner(signingKey.toRSAPrivateKey()));
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create RSA JWT", e);
        }
    }

    public static String createEcJwt(final ECKey signingKey, final String kid, final Date exp, final Object scopeClaim) {
        try {
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                    .subject("test-user")
                    .issuer("https://auth.example.org")
                    .issueTime(new Date())
                    .expirationTime(exp);

            if (scopeClaim != null) {
                builder.claim("scope", scopeClaim);
            }

            com.nimbusds.jwt.SignedJWT signedJWT = new com.nimbusds.jwt.SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(kid).build(),
                    builder.build()
            );
            signedJWT.sign(new ECDSASigner(signingKey.toECPrivateKey()));
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create EC JWT", e);
        }
    }

    public static String createFourPartsJwt(final RSAKey signingKey, final String kid, final Date exp, final String gzipScopes) throws IOException {
        String jwt3Parts = createJwt(signingKey, kid, exp, null);
        String part4 = gzipAndBase64Url(gzipScopes);
        return jwt3Parts + "." + part4;
    }

    public static String createFourPartsEcJwt(final ECKey signingKey, final String kid, final Date exp, final String gzipScopes) throws IOException {
        String jwt3Parts = createEcJwt(signingKey, kid, exp, null);
        String part4 = gzipAndBase64Url(gzipScopes);
        return jwt3Parts + "." + part4;
    }
}
