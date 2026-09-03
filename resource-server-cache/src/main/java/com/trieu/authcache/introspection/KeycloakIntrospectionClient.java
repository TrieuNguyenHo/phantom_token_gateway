package com.trieu.authcache.introspection;

import com.trieu.authcache.config.KeycloakProperties;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * The actual network call this whole cache exists to avoid making on every request:
 * {@code POST /realms/{realm}/protocol/openid-connect/token/introspect} on Keycloak.
 *
 * <p>Wrapped with a Resilience4j circuit breaker + rate limiter. This matters specifically for
 * the "Redis is down" scenario discussed in the interview answer: once the cache is bypassed,
 * every request would otherwise hit Keycloak directly, which is exactly the contention problem
 * this whole design exists to prevent. The breaker/limiter cap how hard we're allowed to hit
 * Keycloak even in degraded mode, so one dependency going down doesn't cascade into a second one
 * going down.
 */
@Slf4j
@Component
public class KeycloakIntrospectionClient {

    private final RestClient restClient;
    private final KeycloakProperties props;

    public KeycloakIntrospectionClient(RestClient.Builder restClientBuilder, KeycloakProperties props) {
        this.restClient = restClientBuilder.build();
        this.props = props;
    }

    @CircuitBreaker(name = "keycloakIntrospection", fallbackMethod = "fallback")
    @RateLimiter(name = "keycloakIntrospection")
    public IntrospectionResult introspect(String token) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("token", token);
        form.add("client_id", props.clientId());
        form.add("client_secret", props.clientSecret());

        @SuppressWarnings("unchecked")
        Map<String, Object> body = restClient.post()
                .uri(props.introspectionUri())
                .contentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);

        return toIntrospectionResult(body);
    }

    /**
     * Resilience4j fallback - signature must match introspect(...) plus a Throwable. Anything
     * that lands here (open circuit, timeout, connection refused, 5xx) becomes an
     * {@link IntrospectionUnavailableException}: an explicit "we don't know" that the caller
     * must turn into a rejected request, never an accepted one.
     */
    @SuppressWarnings("unused")
    private IntrospectionResult fallback(String token, Throwable throwable) {
        log.error("Keycloak introspection unavailable (circuit open or call failed): {}", throwable.toString());
        throw new IntrospectionUnavailableException("Unable to confirm token status with Keycloak", throwable);
    }

    private IntrospectionResult toIntrospectionResult(Map<String, Object> body) {
        if (body == null || !Boolean.TRUE.equals(body.get("active"))) {
            return IntrospectionResult.inactive();
        }
        Set<String> scopes = new HashSet<>();
        Object scopeClaim = body.get("scope");
        if (scopeClaim instanceof String s && !s.isBlank()) {
            scopes.addAll(Arrays.asList(s.split(" ")));
        }
        return new IntrospectionResult(
                true,
                stringOrNull(body.get("sub")),
                scopes,
                stringOrNull(body.get("client_id")),
                body.get("exp") instanceof Number n ? n.longValue() : Instant.now().plusSeconds(60).getEpochSecond(),
                stringOrNull(body.get("sid")),
                stringOrNull(body.get("jti"))
        );
    }

    private static String stringOrNull(Object o) {
        return o == null ? null : o.toString();
    }
}
