package com.trieu.authcache.web;

import com.trieu.authcache.introspection.IntrospectionCacheService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Set;

/**
 * Layer 2 of the invalidation strategy: a custom Keycloak Event Listener SPI (deployed as a
 * .jar in Keycloak's providers/ directory) intercepts LOGOUT / REVOKE_GRANT events at the
 * moment they happen and pushes them out - either straight over HTTP to an endpoint like this
 * one, or onto a Redis Pub/Sub channel / Kafka topic that many service instances all consume
 * (see {@link RedisPubSubEvictionListener} for that alternative transport).
 *
 * <p>This class is the *consumer* side; writing the actual Keycloak SPI provider is a separate
 * Java project built against Keycloak's server SPI and is out of scope here, but this is exactly
 * the shape of endpoint it would call. A shared secret header stands in for whatever
 * authentication that provider is configured to send (mTLS, HMAC, etc. in a real deployment).
 */
@Slf4j
@RestController
public class KeycloakEventWebhookController {

    private static final Set<String> SESSION_INVALIDATING_EVENTS = Set.of("LOGOUT", "REVOKE_GRANT");
    private static final Duration DENY_LIST_TTL = Duration.ofMinutes(5);
    private static final String EXPECTED_SECRET = "dev-shared-secret"; // demo only - externalize in real deployments

    private final IntrospectionCacheService cache;

    public KeycloakEventWebhookController(IntrospectionCacheService cache) {
        this.cache = cache;
    }

    public record KeycloakEvent(String type, String sid, String userId) {
    }

    @PostMapping("/internal/keycloak-events")
    public ResponseEntity<Void> onKeycloakEvent(@RequestHeader("X-Event-Secret") String secret,
                                                  @RequestBody KeycloakEvent event) {
        if (!EXPECTED_SECRET.equals(secret)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if (!SESSION_INVALIDATING_EVENTS.contains(event.type())) {
            // Other event types (LOGIN, UPDATE_PROFILE, ...) don't need cache eviction.
            return ResponseEntity.ok().build();
        }
        if (event.sid() == null) {
            log.warn("Received {} event with no sid, cannot target eviction", event.type());
            return ResponseEntity.badRequest().build();
        }

        cache.evictBySession(event.sid(), DENY_LIST_TTL);
        log.info("Evicted cache for sid={} due to Keycloak event {}", event.sid(), event.type());
        return ResponseEntity.ok().build();
    }
}
