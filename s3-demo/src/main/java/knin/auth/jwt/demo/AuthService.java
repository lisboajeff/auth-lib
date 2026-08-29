package knin.auth.jwt.demo;

import com.nimbusds.jwt.SignedJWT;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import knin.auth.jwt.demo.dto.CreateTokenRequest;
import knin.auth.jwt.demo.dto.CreateTokenResponse;
import knin.auth.jwt.demo.dto.VerifyTokenResponse;
import knin.auth.jwt.domain.validate.Token;
import knin.auth.jwt.domain.validate.TokenJWTInvalidException;
import knin.auth.jwt.option.Introspect;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

@ApplicationScoped
public class AuthService {

    private final JwtSigner jwtSigner;
    private final Introspect introspect;
    private final MemoryPolling memoryPolling;
    private final String requiredScope;

    @Inject
    public AuthService(
            final JwtSigner jwtSigner,
            final Introspect introspect,
            final MemoryPolling memoryPolling,
            @ConfigProperty(name = "auth.required-scope", defaultValue = "read") final String requiredScope) {
        this.jwtSigner = Objects.requireNonNull(jwtSigner, "jwtSigner cannot be null");
        this.introspect = Objects.requireNonNull(introspect, "introspect cannot be null");
        this.memoryPolling = Objects.requireNonNull(memoryPolling, "memoryPolling cannot be null");
        this.requiredScope = requiredScope != null ? requiredScope.trim().toLowerCase() : "";
    }

    /**
     * Generates and signs a JWT token with the specified scopes and subject.
     */
    public CreateTokenResponse createToken(final CreateTokenRequest request) {
        final CreateTokenRequest req = request != null ? request : new CreateTokenRequest("demo-user", List.of(), 3600_000L, false);

        final List<String> scopesList = req.scopes() != null ? req.scopes() : Collections.emptyList();
        final String scopesJoined = String.join(" ", scopesList);
        final String subject = req.getEffectiveSubject();
        final long expiration = req.getEffectiveExpirationMillis();

        final String token;
        if (req.isFourParts()) {
            final String commaScopes = String.join(",", scopesList);
            token = jwtSigner.signFourPartsToken(subject, commaScopes, expiration);
        } else {
            token = jwtSigner.signToken(subject, scopesJoined, expiration);
        }

        return new CreateTokenResponse(
                token,
                jwtSigner.getKid(),
                subject,
                scopesList
        );
    }

    /**
     * Returns the full public JWKS JSON directly from the MemoryPolling RAM cache.
     * Does not require a specific KID and serves all rotated public keys immediately.
     */
    public CompletableFuture<String> getJwksJson() {
        final byte[] cached = memoryPolling.getCachedBytes();
        if (cached != null && cached.length > 0) {
            return CompletableFuture.completedFuture(new String(cached, StandardCharsets.UTF_8));
        }
        return memoryPolling.refreshFromS3().thenApply(bytes -> new String(bytes, StandardCharsets.UTF_8));
    }

    /**
     * Verifies the token authenticity against JWKS via the async Introspect chain,
     * and validates if the token satisfies the server's required scope policy.
     */
    public CompletableFuture<VerifyTokenResponse> verifyToken(final String tokenString) {
        if (tokenString == null || tokenString.isBlank()) {
            return CompletableFuture.completedFuture(
                    VerifyTokenResponse.invalid("Token is required")
            );
        }

        return introspect.introspect(tokenString)
                .thenApply(result -> {
                    if (result == null || result.isEmpty() || result.isError() || !result.hasResult()) {
                        return VerifyTokenResponse.invalid("Token is invalid, expired, or signing key not found in S3 JWKS");
                    }

                    final knin.auth.jwt.option.Introspection introspection = result.get();
                    if (introspection == null || !introspection.hasToken()) {
                        return VerifyTokenResponse.invalid("Token is invalid, expired, or signing key not found in S3 JWKS");
                    }

                    final Token token = introspection.token();
                    final String formattedJwt = token.jwtToString();
                    final String tokenKid = extractKidFromJwt(formattedJwt);

                    final boolean hasScope = requiredScope.isBlank() || token.hasScope(requiredScope);
                    final Set<String> tokenScopes = token.getScopes();

                    if (!hasScope) {
                        return new VerifyTokenResponse(
                                true,
                                false,
                                tokenKid,
                                tokenScopes,
                                formattedJwt,
                                "Token is valid but missing server required scope: " + requiredScope
                        );
                    }

                    return VerifyTokenResponse.success(
                            tokenKid,
                            tokenScopes,
                            formattedJwt,
                            true
                    );
                })
                .exceptionally(throwable ->
                        VerifyTokenResponse.invalid("Token validation failed: " + throwable.getMessage())
                );
    }

    private static String extractKidFromJwt(final String jwt) {
        try {
            final SignedJWT signedJWT = SignedJWT.parse(jwt);
            return signedJWT.getHeader().getKeyID();
        } catch (Exception e) {
            return null;
        }
    }

    public String getRequiredScope() {
        return requiredScope;
    }

}
