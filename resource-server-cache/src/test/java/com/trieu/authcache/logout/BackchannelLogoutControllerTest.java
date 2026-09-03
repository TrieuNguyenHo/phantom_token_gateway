package com.trieu.authcache.logout;

import com.trieu.authcache.introspection.IntrospectionCacheService;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * The controller trusts nothing about the incoming request except what survives JWT signature
 * verification via {@link JwtDecoder} - these tests mock that decoder so we can check the
 * controller's own logic (extracting sid, calling eviction, the 400-on-anything-unverified
 * behaviour required by the Back-Channel Logout spec) independent of real JWKS/crypto.
 */
class BackchannelLogoutControllerTest {

    private final JwtDecoder decoder = mock(JwtDecoder.class);
    private final IntrospectionCacheService cache = mock(IntrospectionCacheService.class);
    private final BackchannelLogoutController controller = new BackchannelLogoutController(decoder, cache);

    private Jwt logoutJwt(String sid, boolean withLogoutEvent) {
        Jwt.Builder builder = Jwt.withTokenValue("signed.jwt.value")
                .header("alg", "RS256")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .claim("iss", "http://keycloak/realms/demo")
                .claim("sub", "user-1");
        if (sid != null) {
            builder.claim("sid", sid);
        }
        if (withLogoutEvent) {
            builder.claim("events", Map.of("http://schemas.openid.net/event/backchannel-logout", Map.of()));
        }
        return builder.build();
    }

    @Test
    void validLogoutToken_evictsTheSessionAndReturns200() {
        when(decoder.decode("valid-token")).thenReturn(logoutJwt("sid-123", true));

        ResponseEntity<Void> response = controller.backchannelLogout("valid-token");

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        verify(cache).evictBySession(eq("sid-123"), any(Duration.class));
    }

    @Test
    void signatureVerificationFailure_isRejectedWithoutEvictingAnything() {
        when(decoder.decode("tampered-token")).thenThrow(new JwtException("bad signature"));

        ResponseEntity<Void> response = controller.backchannelLogout("tampered-token");

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        verifyNoInteractions(cache);
    }

    @Test
    void tokenMissingTheLogoutEventClaim_isRejected() {
        when(decoder.decode("not-a-logout-token")).thenReturn(logoutJwt("sid-123", false));

        ResponseEntity<Void> response = controller.backchannelLogout("not-a-logout-token");

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        verifyNoInteractions(cache);
    }

    @Test
    void tokenWithNoSidOrSub_isRejected() {
        Jwt jwt = Jwt.withTokenValue("v")
                .header("alg", "RS256")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .claim("iss", "http://keycloak/realms/demo")
                .claim("events", Map.of("http://schemas.openid.net/event/backchannel-logout", Map.of()))
                .build();
        when(decoder.decode("odd-token")).thenReturn(jwt);

        ResponseEntity<Void> response = controller.backchannelLogout("odd-token");

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        verifyNoInteractions(cache);
    }
}
