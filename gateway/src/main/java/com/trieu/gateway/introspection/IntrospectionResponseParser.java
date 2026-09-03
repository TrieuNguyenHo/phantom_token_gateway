package com.trieu.gateway.introspection;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Introspection endpoints answer in three different shapes in the wild, and the difference
 * decides whether the gateway ends up with a token it may forward downstream at all. Keeping
 * the parsing here (a pure function of content-type + body) is what makes it unit-testable
 * without a live Keycloak.
 *
 * <ol>
 *   <li><b>Plain RFC 7662 JSON</b> - {@code {"active":true,"sub":...}}. Metadata only:
 *       there is no JWT to forward, so {@code forwardableJwt} stays null.</li>
 *   <li><b>Keycloak's {@code Accept: application/jwt}</b> - still a JSON body, but with an
 *       extra {@code jwt} member holding the <i>full access token</i> as a JWT. That token was
 *       minted for the original audience, so it IS forwardable. This is the shape the phantom
 *       token flow wants.</li>
 *   <li><b>Strict RFC 9701</b> - {@code Content-Type: application/token-introspection+jwt} and
 *       the body is itself a JWT whose {@code token_introspection} claim carries the RFC 7662
 *       members. Careful: that JWT's {@code aud} is the <i>caller</i> (this gateway), so it is
 *       an answer, not a credential - forwarding it downstream would fail a correct audience
 *       check. We read the claims and leave {@code forwardableJwt} null.</li>
 * </ol>
 *
 * <p>We do not verify the signature of the case-3 JWT: the response arrives over TLS from an
 * endpoint we authenticated to with our own client credentials. Verifying it is defence in
 * depth and a reasonable thing to add if the AS is reached over an untrusted hop.
 */
@Slf4j
@Component
public class IntrospectionResponseParser {

    private static final String JWT_INTROSPECTION_TYPE = "application/token-introspection+jwt";

    private final ObjectMapper objectMapper;

    public IntrospectionResponseParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public IntrospectionResult parse(String contentType, String body) {
        if (body == null || body.isBlank()) {
            return IntrospectionResult.inactive();
        }
        try {
            boolean isJwtResponse = contentType != null && contentType.contains(JWT_INTROSPECTION_TYPE);
            JsonNode root = isJwtResponse ? decodeJwtPayload(body) : objectMapper.readTree(body);

            // Case 3: the RFC 9701 envelope nests the real answer one level down.
            JsonNode claims = root.has("token_introspection") ? root.get("token_introspection") : root;

            if (!claims.path("active").asBoolean(false)) {
                return IntrospectionResult.inactive();
            }

            // Case 2: Keycloak puts the forwardable access token in a "jwt" member.
            String forwardable = root.hasNonNull("jwt") ? root.get("jwt").asText()
                    : (claims.hasNonNull("jwt") ? claims.get("jwt").asText() : null);

            return new IntrospectionResult(
                    true,
                    forwardable,
                    claims.path("sub").asText(null),
                    claims.path("sid").asText(null),
                    claims.path("exp").asLong(0)
            );
        } catch (Exception e) {
            // An unreadable response is "we don't know", which must never become "it's valid".
            log.warn("Could not parse introspection response (content-type={})", contentType, e);
            return IntrospectionResult.inactive();
        }
    }

    private JsonNode decodeJwtPayload(String jwt) throws Exception {
        String[] parts = jwt.trim().split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("Not a JWT");
        }
        byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
        return objectMapper.readTree(new String(payload, StandardCharsets.UTF_8));
    }
}
