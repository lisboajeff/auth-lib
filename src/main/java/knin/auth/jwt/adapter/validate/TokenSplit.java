package knin.auth.jwt.adapter.validate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;
import java.util.zip.GZIPInputStream;

final class TokenSplit {

    private final String[] data;
    private final int parts;

    TokenSplit(final String jwt) {
        this.data = Objects.requireNonNull(jwt).split("\\.");
        parts = data.length;
    }

    boolean isValid() {
        return parts == 3 || parts == 4;
    }

    String header() {
        return data[0];
    }

    String payload() {
        return data[1];
    }

    String signature() {
        return data[2];
    }

    Optional<String> compactedData() throws IOException {
        if (parts == 4) {
            try {
                final byte[] compressed = Base64.getUrlDecoder().decode(data[3]);
                try (ByteArrayInputStream bais = new ByteArrayInputStream(compressed);
                     GZIPInputStream gis = new GZIPInputStream(bais)) {
                    return Optional.of(new String(gis.readAllBytes(), StandardCharsets.UTF_8));
                }
            } catch (IllegalArgumentException e) {
                throw new IOException("Invalid Base64 in compacted data", e);
            }
        }
        return Optional.empty();
    }

    String toJwtString() {
        return header() + "." + payload() + "." + signature();
    }
}
