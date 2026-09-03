package com.trieu.gateway.web;

import com.trieu.gateway.config.PhantomTokenProperties;
import com.trieu.gateway.introspection.PhantomTokenCache;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Set;

/**
 * Consumer side of a custom Keycloak Event Listener SPI (LOGOUT / REVOKE_GRANT). Prefer
 * backchannel logout when it is available - it is the standard and needs no custom provider
 * deployed into Keycloak. This endpoint exists for the events backchannel logout does not
 * cover, such as an admin revoking a grant.
 */
@Slf4j
@RestController
public class KeycloakEventWebhookController {

    private static final Set<String> SESSION_INVALIDATING = Set.of("LOGOUT", "REVOKE_GRANT");

    private final PhantomTokenCache cache;
    private final PhantomTokenProperties props;

    public KeycloakEventWebhookController(PhantomTokenCache cache, PhantomTokenProperties props) {
        this.cache = cache;
        this.props = props;
    }

    public record KeycloakEvent(String type, String sid, String userId) {
    }

    @PostMapping("/internal/keycloak-events")
    public Mono<ResponseEntity<Void>> onEvent(@RequestHeader(value = "X-Event-Secret", required = false) String secret,
                                                @RequestBody KeycloakEvent event) {
        if (!props.eventWebhookSecret().equals(secret)) {
            return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
        }
        if (event.type() == null || !SESSION_INVALIDATING.contains(event.type())) {
            return Mono.just(ResponseEntity.ok().build());
        }
        if (event.sid() == null) {
            log.warn("{} event without sid - cannot target eviction", event.type());
            return Mono.just(ResponseEntity.badRequest().build());
        }
        return cache.evictBySession(event.sid())
                .doOnNext(n -> log.info("Evicted sid={} on Keycloak event {}", event.sid(), event.type()))
                .thenReturn(ResponseEntity.ok().build());
    }
}
