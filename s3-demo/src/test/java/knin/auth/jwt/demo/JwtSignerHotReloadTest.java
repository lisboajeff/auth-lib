package knin.auth.jwt.demo;

import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class JwtSignerHotReloadTest {

    @Test
    @DisplayName("JwtSigner should dynamically hot-reload private key when file on disk changes without restart")
    void shouldHotReloadPrivateKeyOnFileChange(@TempDir Path tempDir) throws Exception {
        final Path keyFile = tempDir.resolve("private_key.pem");
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);

        // 1. Write Initial Key 1 to disk
        final KeyPair keyPair1 = kpg.generateKeyPair();
        final String kid1 = computeKid((RSAPublicKey) keyPair1.getPublic());
        writePem(keyFile, (RSAPrivateKey) keyPair1.getPrivate());

        // 2. Instantiate JwtSigner pointing to the file
        final JwtSigner signer = new JwtSigner(keyFile.toString());
        assertEquals(kid1, signer.getKid(), "Initial KID must match Key 1");

        final String token1 = signer.signToken("user-1", "READ", 60_000);
        assertNotNull(token1);

        // Sleep briefly to ensure filesystem timestamp differs
        Thread.sleep(50);

        // 3. Overwrite file with new Key 2 (simulating rotation script)
        final KeyPair keyPair2 = kpg.generateKeyPair();
        final String kid2 = computeKid((RSAPublicKey) keyPair2.getPublic());
        assertNotEquals(kid1, kid2);
        writePem(keyFile, (RSAPrivateKey) keyPair2.getPrivate());

        // 4. Verify JwtSigner immediately detects file change on next call
        assertEquals(kid2, signer.getKid(), "JwtSigner must dynamically reload new KID from modified disk file");

        final String token2 = signer.signToken("user-2", "READ", 60_000);
        assertNotNull(token2);
        assertNotEquals(token1, token2);
    }

    private static String computeKid(final RSAPublicKey pubKey) {
        try {
            final RSAKey rsaJwk = new RSAKey.Builder(pubKey).build();
            return rsaJwk.computeThumbprint().toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void writePem(final Path file, final RSAPrivateKey privateKey) throws Exception {
        final String base64Key = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        final String pem = "-----BEGIN PRIVATE KEY-----\n" + base64Key + "\n-----END PRIVATE KEY-----\n";
        Files.writeString(file, pem);
    }

}
