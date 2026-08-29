package knin.auth.jwt.demo;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Objects;

public final class JwtSigner {

    private final RSAPrivateKey privateKey;
    private final String kid;

    public JwtSigner(final String pemResourcePath, final String kid) {
        this.kid = Objects.requireNonNull(kid, "kid cannot be null");
        this.privateKey = loadPrivateKeyFromResource(pemResourcePath);
    }

    public String signToken(final String subject, final String scopes, final long expirationMillis) {
        try {
            final Date now = new Date();
            final Date exp = new Date(now.getTime() + expirationMillis);

            final JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issuer("https://auth.knin.org")
                    .issueTime(now)
                    .expirationTime(exp);

            if (scopes != null && !scopes.isBlank()) {
                claimsBuilder.claim("scope", scopes);
            }

            final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(kid)
                    .build();

            final SignedJWT signedJWT = new SignedJWT(header, claimsBuilder.build());
            signedJWT.sign(new RSASSASigner(privateKey));

            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign JWT token", e);
        }
    }

    private static RSAPrivateKey loadPrivateKeyFromResource(final String resourcePath) {
        try (InputStream is = JwtSigner.class.getClassLoader().getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new IllegalArgumentException("Resource not found: " + resourcePath);
            }
            final String pem = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            final String privateKeyPEM = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");

            final byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
            final KeyFactory kf = KeyFactory.getInstance("RSA");
            final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            return (RSAPrivateKey) kf.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load RSA private key from PEM: " + resourcePath, e);
        }
    }

}
