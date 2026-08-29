package knin.auth.jwt.demo.dto;

import java.util.List;

public record CreateTokenResponse(
        String token,
        String kid,
        String subject,
        List<String> scopes
) {}
