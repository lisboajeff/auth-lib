package knin.auth.jwt.adapter.validate;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import java.util.zip.GZIPOutputStream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenSplitTest {

    private static String gzipAndBase64Url(String input) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gzos = new GZIPOutputStream(baos)) {
            gzos.write(input.getBytes(StandardCharsets.UTF_8));
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(baos.toByteArray());
    }

    @Test
    @DisplayName("Should correctly handle valid 3-part JWT token")
    void shouldHandleThreePartsToken() throws IOException {
        String jwt = "header123.payload456.signature789";
        TokenSplit split = new TokenSplit(jwt);

        assertTrue(split.isValid());
        assertEquals("header123", split.header());
        assertEquals("payload456", split.payload());
        assertEquals("signature789", split.signature());
        assertEquals("header123.payload456.signature789", split.toJwtString());
        assertEquals(Optional.empty(), split.compactedData());
    }

    @Test
    @DisplayName("Should correctly handle valid 4-part JWT token and decompress gzip scopes data")
    void shouldHandleFourPartsTokenAndDecompressData() throws IOException {
        String rawScopes = "scope_1,scope_2,scope_3";
        String part4 = gzipAndBase64Url(rawScopes);
        String jwt = "header123.payload456.signature789." + part4;

        TokenSplit split = new TokenSplit(jwt);

        assertTrue(split.isValid());
        assertEquals("header123", split.header());
        assertEquals("payload456", split.payload());
        assertEquals("signature789", split.signature());
        assertEquals("header123.payload456.signature789", split.toJwtString());

        Optional<String> compacted = split.compactedData();
        assertTrue(compacted.isPresent());
        assertEquals(rawScopes, compacted.get());
    }

    @Test
    @DisplayName("Should throw IOException if 4th part contains invalid Base64")
    void shouldThrowIOExceptionWhenPart4HasInvalidBase64() {
        String jwt = "header123.payload456.signature789.not-valid-base64!@#$";
        TokenSplit split = new TokenSplit(jwt);

        assertTrue(split.isValid());
        assertThrows(IOException.class, split::compactedData);
    }

    @Test
    @DisplayName("Should throw IOException if 4th part contains valid Base64 but content is not GZIP")
    void shouldThrowIOExceptionWhenPart4IsNotGzip() {
        String nonGzipBase64 = Base64.getUrlEncoder().encodeToString("just plain text".getBytes(StandardCharsets.UTF_8));
        String jwt = "header123.payload456.signature789." + nonGzipBase64;
        TokenSplit split = new TokenSplit(jwt);

        assertTrue(split.isValid());
        assertThrows(IOException.class, split::compactedData);
    }

    @ParameterizedTest
    @ValueSource(strings = {"single_part", "part1.part2", "p1.p2.p3.p4.p5"})
    @DisplayName("Should identify tokens with invalid part counts as invalid")
    void shouldIdentifyInvalidTokens(String jwt) throws IOException {
        TokenSplit split = new TokenSplit(jwt);

        assertFalse(split.isValid());
        assertEquals(Optional.empty(), split.compactedData());
    }
}
