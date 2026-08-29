package knin.auth.jwt.adapter.validate;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import knin.auth.jwt.domain.retriever.JsonWebKeys;
import knin.auth.jwt.domain.validate.TokenData;
import knin.auth.jwt.domain.validate.TokenHandle;
import knin.auth.jwt.domain.validate.TokenJWTInvalidException;
import knin.auth.jwt.domain.validate.TokenJWTInvalidRuntimeException;

final class TokenUtil implements TokenHandle {

    private static final Pattern KID_PATTERN = Pattern.compile("\"kid\"\\s*:\\s*\"([^\"]+)\"");

    TokenUtil() {
    }

    @Override
    public String getKid(final String jwt) throws TokenJWTInvalidException {

        final int firstDotIndex = jwt.indexOf('.');

        if (firstDotIndex <= 0) {
            throw new TokenJWTInvalidException();
        }

        final String headerB64 = jwt.substring(0, firstDotIndex);

        try {
            final byte[] headerBytes = Base64.getUrlDecoder().decode(headerB64);
            final String headerJson = new String(headerBytes, StandardCharsets.UTF_8);

            final Matcher matcher = KID_PATTERN.matcher(headerJson);
            if (matcher.find()) {
                return matcher.group(1);
            }
            throw new TokenJWTInvalidException();
        } catch (IllegalArgumentException e) {
            throw new TokenJWTInvalidException();
        }
    }

    @Override
    public TokenData decode(final JsonWebKeys keys, final String jwt) throws TokenJWTInvalidRuntimeException {

        final TokenSplit tokenSplit = new TokenSplit(jwt);

        if (!tokenSplit.isValid()) {
            throw new TokenJWTInvalidRuntimeException("Not Token Valid");
        }

        final JWTClaimsSet claims = processJwt(keys, tokenSplit.toJwtString());

        return createTokenData(tokenSplit, claims, jwt);

    }

    @Override
    public Set<String> extractIdentifiers(final byte[] keysRaw) {
        try {
            final JWKSet jwkSet = JWKSet.parse(new String(keysRaw, StandardCharsets.UTF_8));
            return jwkSet.getKeys().stream()
                    .map(com.nimbusds.jose.jwk.JWK::getKeyID)
                    .filter(java.util.Objects::nonNull)
                    .collect(Collectors.toSet());
        } catch (Exception e) {
            return Set.of();
        }
    }

    private JWTClaimsSet processJwt(final JsonWebKeys keys, final String standardJwt) {
        try {
            final JWKSet jwkSet = JWKSet.parse(new String(keys.toBytes(), StandardCharsets.UTF_8));
            final JWKSource<SecurityContext> keySource = new ImmutableJWKSet<>(jwkSet);

            final ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            final JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(
                    new HashSet<>(JWSAlgorithm.Family.RSA),
                    keySource
            );
            jwtProcessor.setJWSKeySelector(keySelector);

            return jwtProcessor.process(standardJwt, null);
        } catch (Exception e) {
            throw new TokenJWTInvalidRuntimeException(e.getMessage());
        }
    }

    private TokenData createTokenData(final TokenSplit tokenSplit, final JWTClaimsSet claims, final String rawJwt) {
        try {
            final Set<String> scopes;
            final Optional<String> compacted = tokenSplit.compactedData();
            if (compacted.isPresent()) {
                scopes = parseScopes(compacted.get());
            } else {
                scopes = extractScopes(claims.getClaims());
            }
            final Map<String, Set<String>> collections = new HashMap<>();

            collections.put("scopes", scopes);

            return new SimpleTokenData(collections, rawJwt);
        } catch (Exception e) {
            throw new TokenJWTInvalidRuntimeException(e.getMessage());
        }
    }

    private static Set<String> parseScopes(final String rawScopes) {
        return Arrays.stream(rawScopes.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
    }

    Set<String> extractScopes(final Map<String, Object> claims) {
        if (claims == null || claims.isEmpty()) {
            return Collections.emptySet();
        }
        final Object scopesObj = claims.get("scope");
        if (scopesObj instanceof List<?> list) {
            return list.stream().map(Object::toString).collect(Collectors.toSet());
        }
        if (scopesObj instanceof String str) {
            return Arrays.stream(str.split("[,\\s]+"))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .collect(Collectors.toSet());
        }
        return Collections.emptySet();
    }

    private record SimpleTokenData(Map<String, Set<String>> collections, String rawJwt) implements TokenData {
        @Override
        public Set<String> getCollectionByKey(final String key) {
            return collections.getOrDefault(key, Collections.emptySet());
        }

        @Override
        public String jwtToString() {
            return rawJwt;
        }
    }

}

