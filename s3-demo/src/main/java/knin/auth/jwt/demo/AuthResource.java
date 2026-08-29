package knin.auth.jwt.demo;

import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import knin.auth.jwt.demo.dto.CreateTokenRequest;
import knin.auth.jwt.demo.dto.CreateTokenResponse;
import knin.auth.jwt.demo.dto.VerifyTokenResponse;

import java.util.Objects;
import java.util.concurrent.CompletableFuture;

@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class AuthResource {

    private final AuthService authService;

    @Inject
    public AuthResource(final AuthService authService) {
        this.authService = Objects.requireNonNull(authService, "authService cannot be null");
    }

    /**
     * Standard OpenID Connect / OAuth 2.0 JWKS endpoint.
     */
    @GET
    @Path("/.well-known/jwks.json")
    public CompletableFuture<Response> getWellKnownJwks() {
        return getJwksResponse();
    }

    /**
     * API JWKS endpoint.
     */
    @GET
    @Path("/api/auth/jwks")
    public CompletableFuture<Response> getApiJwks() {
        return getJwksResponse();
    }

    /**
     * Endpoint to create a new signed JWT token.
     */
    @POST
    @Path("/api/auth/token")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response createToken(final CreateTokenRequest request) {
        final CreateTokenResponse response = authService.createToken(request);
        return Response.status(Response.Status.CREATED).entity(response).build();
    }

    /**
     * Endpoint to verify a JWT token passed via Authorization Bearer header.
     */
    @POST
    @Path("/api/auth/verify")
    public CompletableFuture<Response> verifyToken(@HeaderParam("Authorization") final String authHeader) {
        final String token = extractBearerToken(authHeader);
        if (token == null) {
            return CompletableFuture.completedFuture(
                    Response.status(Response.Status.BAD_REQUEST)
                            .entity(VerifyTokenResponse.invalid("Authorization Bearer header is required (e.g. 'Authorization: Bearer <jwt>')"))
                            .build()
            );
        }

        return authService.verifyToken(token)
                .thenApply(this::toHttpResponse);
    }

    private CompletableFuture<Response> getJwksResponse() {
        return authService.getJwksJson()
                .thenApply(json -> Response.ok(json, MediaType.APPLICATION_JSON).build())
                .exceptionally(throwable ->
                        Response.status(Response.Status.SERVICE_UNAVAILABLE)
                                .entity("{\"error\":\"Failed to retrieve JWKS: " + throwable.getMessage() + "\"}")
                                .build()
                );
    }

    private Response toHttpResponse(final VerifyTokenResponse result) {
        if (!result.valid()) {
            return Response.status(Response.Status.UNAUTHORIZED).entity(result).build();
        }
        if (!result.hasRequiredScope()) {
            return Response.status(Response.Status.FORBIDDEN).entity(result).build();
        }
        return Response.ok(result).build();
    }

    private static String extractBearerToken(final String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            final String token = authHeader.substring(7).trim();
            if (!token.isEmpty()) {
                return token;
            }
        }
        return null;
    }

}
