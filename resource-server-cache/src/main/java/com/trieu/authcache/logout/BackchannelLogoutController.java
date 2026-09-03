package com.trieu.authcache.logout;

import com.trieu.authcache.introspection.IntrospectionCacheService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

/**
 * Layer 3 of the invalidation strategy: OIDC Back-Channel Logout
 * (https://openid.net/specs/openid-connect-backchannel-1_0.html). Keycloak is configured with
 * this URL as the client's "Backchannel logout URL" and POSTs here, server-to-server, the moment
 * a user logs out anywhere - no dependency on the user's browser still being open, which is what
 * makes this stronger than front-channel logout.
 *
 * <p>This is preferred over the raw custom event-listener webhook
 * ({@link com.trieu.authcache.web.KeycloakEventWebhookController}) whenever it's available,
 * because it's the standard, is signed, and doesn't require a custom Keycloak SPI to be built
 * and deployed - it interviews well specifically because it's "use the platform", not
 * "build something bespoke".
 */
@Slf4j
@RestController
public class BackchannelLogoutController {

    /** Bounds how long a session stays on the revocation deny-list after logout. */
    private static final Duration DENY_LIST_TTL = Duration.ofMinutes(5);

    private final JwtDecoder logoutTokenDecoder;
    private final IntrospectionCacheService cache;

    public BackchannelLogoutController(JwtDecoder logoutTokenDecoder, IntrospectionCacheService cache) {
        this.logoutTokenDecoder = logoutTokenDecoder;
        this.cache = cache;
    }

    @PostMapping(value = "/backchannel-logout", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Void> backchannelLogout(@RequestParam("logout_token") String logoutToken) {
        Jwt jwt;
        try {
            jwt = logoutTokenDecoder.decode(logoutToken);
        } catch (JwtException e) {
            log.warn("Rejected logout_token: signature/claims verification failed", e);
            // Per spec: invalid token -> 400, do NOT evict anything based on unverified input.
            return ResponseEntity.badRequest().build();
        }

        if (!isLogoutEvent(jwt)) {
            return ResponseEntity.badRequest().build();
        }

        String sid = jwt.getClaimAsString("sid");
        String sub = jwt.getClaimAsString("sub");
        if (sid == null && sub == null) {
            return ResponseEntity.badRequest().build();
        }

        String sessionKey = sid != null ? sid : sub;
        cache.evictBySession(sessionKey, DENY_LIST_TTL);
        log.info("Backchannel logout processed for session={}", sessionKey);

        // Spec requires these two response headers on success.
        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.PRAGMA, "no-cache")
                .build();
    }

    private boolean isLogoutEvent(Jwt jwt) {
        Object events = jwt.getClaim("events");
        return events instanceof java.util.Map<?, ?> map
                && map.containsKey("http://schemas.openid.net/event/backchannel-logout");
    }
}
