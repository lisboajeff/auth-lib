package knin.auth.jwt.demo.dto;

import java.util.List;

public record CreateTokenRequest(
        String subject,
        List<String> scopes,
        Long expirationMillis,
        Boolean fourParts
) {
    public String getEffectiveSubject() {
        return subject != null && !subject.isBlank() ? subject : "demo-user";
    }

    public long getEffectiveExpirationMillis() {
        return expirationMillis != null && expirationMillis > 0 ? expirationMillis : 3600_000L; // 1 hour
    }

    public boolean isFourParts() {
        return Boolean.TRUE.equals(fourParts);
    }
}
