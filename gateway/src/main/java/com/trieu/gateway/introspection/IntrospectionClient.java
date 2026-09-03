package com.trieu.gateway.introspection;

import com.trieu.gateway.config.KeycloakProperties;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.ratelimiter.RateLimiter;
import io.github.resilience4j.ratelimiter.RateLimiterConfig;
import io.github.resilience4j.reactor.circuitbreaker.operator.CircuitBreakerOperator;
import io.github.resilience4j.reactor.ratelimiter.operator.RateLimiterOperator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * The one place in the whole system that calls Keycloak's introspection endpoint. Every other
 * component - including all downstream services - is now downstream of this class's cache.
 *
 * <p>Two guards, both aimed at the same failure mode (Redis dies, the cache stops absorbing
 * traffic, and every request suddenly lands on Keycloak):
 * <ul>
 *   <li>a circuit breaker, so a struggling Keycloak fails fast instead of tying up connections;</li>
 *   <li>a rate limiter, capping how hard the gateway is allowed to hit it even in degraded mode.</li>
 * </ul>
 * Both turn failure into an empty/inactive answer, and the caller rejects the request. There is
 * deliberately no "let it through" path.
 */
@Slf4j
@Component
public class IntrospectionClient {

    private final WebClient webClient;
    private final KeycloakProperties props;
    private final IntrospectionResponseParser parser;
    private final CircuitBreaker circuitBreaker;
    private final RateLimiter rateLimiter;

    public IntrospectionClient(WebClient.Builder webClientBuilder,
                                KeycloakProperties props,
                                IntrospectionResponseParser parser) {
        this.webClient = webClientBuilder.build();
        this.props = props;
        this.parser = parser;
        this.circuitBreaker = CircuitBreaker.of("keycloakIntrospection", CircuitBreakerConfig.custom()
                .slidingWindowSize(20)
                .minimumNumberOfCalls(10)
                .failureRateThreshold(50)
                .waitDurationInOpenState(Duration.ofSeconds(5))
                .permittedNumberOfCallsInHalfOpenState(5)
                .build());
        this.rateLimiter = RateLimiter.of("keycloakIntrospection", RateLimiterConfig.custom()
                .limitForPeriod(200)
                .limitRefreshPeriod(Duration.ofSeconds(1))
                .timeoutDuration(Duration.ofMillis(100))
                .build());
    }

    public Mono<IntrospectionResult> introspect(String token) {
        return webClient.post()
                .uri(props.introspectionUri())
                .headers(h -> h.setBasicAuth(props.clientId(), props.clientSecret()))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                // Keycloak answers this with the full JWT access token (embedded in a "jwt"
                // member of an otherwise-normal JSON body) when the client has the
                // corresponding attribute enabled; without it we simply get plain RFC 7662
                // JSON back and the parser copes. Must be exactly "application/jwt" - Keycloak
                // checks this header with String.equals(), not content negotiation, so
                // "application/jwt, application/json" silently falls back to plain JSON.
                .header(HttpHeaders.ACCEPT, "application/jwt")
                .body(BodyInserters.fromFormData("token", token)
                        .with("token_type_hint", "access_token"))
                .exchangeToMono(response -> {
                    String contentType = response.headers().contentType().map(MediaType::toString).orElse(null);
                    if (response.statusCode().isError()) {
                        return response.releaseBody()
                                .then(Mono.error(new IntrospectionUnavailableException(
                                        "Keycloak introspection returned " + response.statusCode())));
                    }
                    return response.bodyToMono(String.class)
                            .defaultIfEmpty("")
                            .map(body -> parser.parse(contentType, body));
                })
                .timeout(Duration.ofSeconds(2))
                .transformDeferred(RateLimiterOperator.of(rateLimiter))
                .transformDeferred(CircuitBreakerOperator.of(circuitBreaker))
                .onErrorResume(e -> {
                    log.error("Introspection unavailable: {}", e.toString());
                    return Mono.error(new IntrospectionUnavailableException(
                            "Unable to confirm token status with Keycloak", e));
                });
    }
}
