package com.trieu.gateway.logout;

import com.trieu.gateway.config.KeycloakProperties;
import com.trieu.gateway.introspection.PhantomTokenCache;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * OIDC Back-Channel Logout, now with exactly one listener for the whole system. In approach A
 * every service had to receive this event; here the gateway owns the only cache, so one
 * eviction is the entire invalidation.
 */
@Slf4j
@RestController
public class BackchannelLogoutController {

    private static final String LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

    private final ReactiveJwtDecoder logoutTokenDecoder;
    private final PhantomTokenCache cache;

    public BackchannelLogoutController(ReactiveJwtDecoder logoutTokenDecoder, PhantomTokenCache cache) {
        this.logoutTokenDecoder = logoutTokenDecoder;
        this.cache = cache;
    }

    @PostMapping(value = "/backchannel-logout", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Mono<ResponseEntity<Void>> backchannelLogout(@RequestParam("logout_token") String logoutToken) {
        return logoutTokenDecoder.decode(logoutToken)
                .flatMap(jwt -> {
                    if (!isLogoutEvent(jwt)) {
                        return Mono.just(ResponseEntity.badRequest().<Void>build());
                    }
                    String sid = jwt.getClaimAsString("sid");
                    String sub = jwt.getClaimAsString("sub");
                    String sessionKey = sid != null ? sid : sub;
                    if (sessionKey == null) {
                        return Mono.just(ResponseEntity.badRequest().<Void>build());
                    }
                    return cache.evictBySession(sessionKey)
                            .doOnNext(n -> log.info("Backchannel logout processed for session={}", sessionKey))
                            .thenReturn(ResponseEntity.ok()
                                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                                    .header(HttpHeaders.PRAGMA, "no-cache")
                                    .<Void>build());
                })
                // Signature or claim verification failed: reject, and evict nothing based on
                // input we could not verify.
                .onErrorResume(e -> {
                    log.warn("Rejected logout_token: {}", e.toString());
                    return Mono.just(ResponseEntity.badRequest().<Void>build());
                });
    }

    private boolean isLogoutEvent(Jwt jwt) {
        return jwt.getClaim("events") instanceof Map<?, ?> events && events.containsKey(LOGOUT_EVENT);
    }

    /**
     * The gateway itself validates access tokens by introspection, but a logout token is always
     * a signed JWT - so we need a small JWKS-backed decoder just for this endpoint.
     */
    @Configuration
    static class LogoutTokenDecoderConfig {
        @Bean
        ReactiveJwtDecoder logoutTokenDecoder(KeycloakProperties props) {
            return NimbusReactiveJwtDecoder.withJwkSetUri(props.jwksUri()).build();
        }
    }
}
