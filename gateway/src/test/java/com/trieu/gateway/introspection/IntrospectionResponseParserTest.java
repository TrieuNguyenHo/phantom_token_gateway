package com.trieu.gateway.introspection;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The three response shapes an introspection endpoint can answer with, and - the part that
 * actually matters - whether each one leaves us holding a token we may forward downstream.
 */
class IntrospectionResponseParserTest {

    private final IntrospectionResponseParser parser = new IntrospectionResponseParser(new ObjectMapper());

    private static String jwtWithPayload(String payloadJson) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String header = b64.encodeToString("{\"typ\":\"token-introspection+jwt\",\"alg\":\"RS256\"}"
                .getBytes(StandardCharsets.UTF_8));
        String payload = b64.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".c2lnbmF0dXJl";
    }

    @Test
    void plainRfc7662Json_isParsed_butGivesNoForwardableToken() {
        String body = """
                {"active":true,"sub":"user-1","sid":"sess-1","exp":9999999999,"scope":"orders:read"}""";

        IntrospectionResult result = parser.parse("application/json", body);

        assertThat(result.active()).isTrue();
        assertThat(result.sub()).isEqualTo("user-1");
        assertThat(result.sid()).isEqualTo("sess-1");
        assertThat(result.exp()).isEqualTo(9999999999L);
        assertThat(result.forwardableJwt()).isNull();
    }

    @Test
    void inactiveToken_isInactive() {
        IntrospectionResult result = parser.parse("application/json", "{\"active\":false}");

        assertThat(result.active()).isFalse();
        assertThat(result.forwardableJwt()).isNull();
    }

    @Test
    void keycloakJwtResponse_exposesTheForwardableAccessToken() {
        // Keycloak's Accept: application/jwt answer: still JSON, plus a "jwt" member holding
        // the full access token - this is the one we are allowed to put downstream.
        String body = """
                {"active":true,"sub":"user-1","sid":"sess-1","exp":9999999999,"jwt":"eyJhbGciOiJSUzI1NiJ9.body.sig"}""";

        IntrospectionResult result = parser.parse("application/json", body);

        assertThat(result.active()).isTrue();
        assertThat(result.forwardableJwt()).isEqualTo("eyJhbGciOiJSUzI1NiJ9.body.sig");
    }

    @Test
    void strictRfc9701Response_readsNestedClaims_andStaysNonForwardable() {
        // aud here is the gateway: this JWT is an answer addressed to us, not a credential.
        String body = jwtWithPayload("""
                {"iss":"https://keycloak/realms/demo","aud":"gateway","iat":1725350400,
                 "token_introspection":{"active":true,"sub":"user-9","sid":"sess-9","exp":1725350700}}""");

        IntrospectionResult result = parser.parse("application/token-introspection+jwt", body);

        assertThat(result.active()).isTrue();
        assertThat(result.sub()).isEqualTo("user-9");
        assertThat(result.sid()).isEqualTo("sess-9");
        assertThat(result.forwardableJwt())
                .as("an RFC 9701 response is audienced to the caller and must not be forwarded")
                .isNull();
    }

    @Test
    void unreadableBody_failsClosed() {
        assertThat(parser.parse("application/json", "{not json").active()).isFalse();
        assertThat(parser.parse("application/token-introspection+jwt", "not-a-jwt").active()).isFalse();
        assertThat(parser.parse("application/json", "").active()).isFalse();
        assertThat(parser.parse(null, null).active()).isFalse();
    }
}
