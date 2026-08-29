package knin.auth.jwt.demo.dto;

import java.util.Set;

public record VerifyTokenResponse(
        boolean valid,
        boolean hasRequiredScope,
        String kid,
        Set<String> scopes,
        String formattedJwt,
        String message
) {
    public static VerifyTokenResponse success(final String kid, final Set<String> scopes, final String formattedJwt, final boolean hasRequiredScope) {
        return new VerifyTokenResponse(true, hasRequiredScope, kid, scopes, formattedJwt, "Token is valid and authenticated");
    }

    public static VerifyTokenResponse invalid(final String message) {
        return new VerifyTokenResponse(false, false, null, Set.of(), null, message);
    }
}
