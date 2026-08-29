package knin.auth.jwt.demo;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Objects;

public final class JwtSigner {

    private final String pemPath;
    private final String overrideKid;

    public JwtSigner(final String pemPath) {
        this(pemPath, null);
    }

    public JwtSigner(final String pemPath, final String overrideKid) {
        this.pemPath = Objects.requireNonNull(pemPath, "pemPath cannot be null");
        this.overrideKid = overrideKid;
        // Verify key file can be read on startup
        loadKeyFromDisk();
    }

    public String getKid() {
        return loadKeyFromDisk().kid();
    }

    public String signToken(final String subject, final String scopes, final long expirationMillis) {
        try {
            final LoadedKey loaded = loadKeyFromDisk();
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
                    .keyID(loaded.kid())
                    .build();

            final SignedJWT signedJWT = new SignedJWT(header, claimsBuilder.build());
            signedJWT.sign(new RSASSASigner(loaded.privateKey()));

            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign JWT token", e);
        }
    }

    public String signFourPartsToken(final String subject, final String gzipScopes, final long expirationMillis) {
        try {
            final String jwt3Parts = signToken(subject, null, expirationMillis);
            final String part4 = gzipAndBase64Url(gzipScopes);
            return jwt3Parts + "." + part4;
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign 4-part JWT token", e);
        }
    }

    public static String gzipAndBase64Url(final String input) {
        try {
            final java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            try (java.util.zip.GZIPOutputStream gzos = new java.util.zip.GZIPOutputStream(baos)) {
                gzos.write(input.getBytes(StandardCharsets.UTF_8));
            }
            return Base64.getUrlEncoder().withoutPadding().encodeToString(baos.toByteArray());
        } catch (Exception e) {
            throw new RuntimeException("Failed to compress scopes to GZIP Base64URL", e);
        }
    }

    /**
     * Always reads the private key fresh from disk to guarantee instant reflection of rotations.
     */
    private LoadedKey loadKeyFromDisk() {
        try {
            byte[] bytes = null;

            // 1. Filesystem candidates (mount points and project root paths)
            final List<Path> candidatePaths = List.of(
                    Path.of(pemPath),
                    Path.of("secrets", Path.of(pemPath).getFileName().toString()),
                    Path.of("s3-demo/secrets", Path.of(pemPath).getFileName().toString()),
                    Path.of("../s3-demo/secrets", Path.of(pemPath).getFileName().toString())
            );

            for (final Path path : candidatePaths) {
                if (Files.exists(path) && Files.isRegularFile(path)) {
                    bytes = Files.readAllBytes(path);
                    break;
                }
            }

            // 2. Classpath resource fallback for unit tests
            if (bytes == null) {
                final String fileName = Path.of(pemPath).getFileName().toString();
                final List<String> candidateResources = List.of(pemPath, fileName, "private_key.pem");

                for (final String res : candidateResources) {
                    try (InputStream is = JwtSigner.class.getClassLoader().getResourceAsStream(res)) {
                        if (is != null) {
                            bytes = is.readAllBytes();
                            break;
                        }
                    }
                }
            }

            if (bytes == null) {
                throw new IllegalArgumentException("Private key PEM file not found at disk path or classpath: " + pemPath);
            }

            final String pem = new String(bytes, StandardCharsets.UTF_8);
            final String privateKeyPEM = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");

            final byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
            final KeyFactory kf = KeyFactory.getInstance("RSA");
            final RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));

            final String computedKid;
            if (overrideKid != null && !overrideKid.isBlank()) {
                computedKid = overrideKid;
            } else {
                final RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(privKey.getModulus(), privKey.getPublicExponent());
                final RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(pubSpec);
                final RSAKey rsaJwk = new RSAKey.Builder(pubKey).build();
                computedKid = rsaJwk.computeThumbprint().toString();
            }

            return new LoadedKey(privKey, computedKid);
        } catch (Exception e) {
            throw new RuntimeException("Failed to read RSA private key from disk: " + pemPath, e);
        }
    }

    private record LoadedKey(RSAPrivateKey privateKey, String kid) {}

}
