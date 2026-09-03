package com.trieu.gateway.exchange;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trieu.gateway.config.KeycloakProperties;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.ratelimiter.RateLimiter;
import io.github.resilience4j.ratelimiter.RateLimiterConfig;
import io.github.resilience4j.reactor.circuitbreaker.operator.CircuitBreakerOperator;
import io.github.resilience4j.reactor.ratelimiter.operator.RateLimiterOperator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * RFC 8693 token exchange: turns the caller's token into one minted for a single downstream
 * audience, so a token good at one service is not automatically good at another - the gap that
 * both {@code KEYCLOAK_JWT} and {@code ORIGINAL} leave open (see {@code PhantomTokenProperties}).
 *
 * <p>Same two guards as {@link com.trieu.gateway.introspection.IntrospectionClient}, for the same
 * reason: this is one more call to the same Keycloak that introspection already hits, and a
 * struggling exchange endpoint must not be allowed to become a struggling gateway.
 */
@Slf4j
@Component
public class TokenExchangeClient {

    private static final String EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

    private final WebClient webClient;
    private final KeycloakProperties props;
    private final ObjectMapper objectMapper;
    private final CircuitBreaker circuitBreaker;
    private final RateLimiter rateLimiter;

    public TokenExchangeClient(WebClient.Builder webClientBuilder,
                                KeycloakProperties props,
                                ObjectMapper objectMapper) {
        this.webClient = webClientBuilder.build();
        this.props = props;
        this.objectMapper = objectMapper;
        this.circuitBreaker = CircuitBreaker.of("keycloakTokenExchange", CircuitBreakerConfig.custom()
                .slidingWindowSize(20)
                .minimumNumberOfCalls(10)
                .failureRateThreshold(50)
                .waitDurationInOpenState(Duration.ofSeconds(5))
                .permittedNumberOfCallsInHalfOpenState(5)
                .build());
        this.rateLimiter = RateLimiter.of("keycloakTokenExchange", RateLimiterConfig.custom()
                .limitForPeriod(200)
                .limitRefreshPeriod(Duration.ofSeconds(1))
                .timeoutDuration(Duration.ofMillis(100))
                .build());
    }

    public Mono<ExchangedToken> exchange(String subjectToken, String audience) {
        return webClient.post()
                .uri(props.tokenUri())
                .headers(h -> h.setBasicAuth(props.clientId(), props.clientSecret()))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData("grant_type", EXCHANGE_GRANT_TYPE)
                        .with("subject_token", subjectToken)
                        .with("subject_token_type", ACCESS_TOKEN_TYPE)
                        .with("audience", audience))
                .exchangeToMono(response -> {
                    if (response.statusCode().isError()) {
                        return response.releaseBody()
                                .then(Mono.error(new TokenExchangeUnavailableException(
                                        "Keycloak token exchange returned " + response.statusCode()
                                                + " for audience " + audience)));
                    }
                    return response.bodyToMono(String.class).map(body -> parse(body, audience));
                })
                .timeout(Duration.ofSeconds(2))
                .transformDeferred(RateLimiterOperator.of(rateLimiter))
                .transformDeferred(CircuitBreakerOperator.of(circuitBreaker))
                .onErrorResume(e -> {
                    log.error("Token exchange unavailable for audience {}: {}", audience, e.toString());
                    return Mono.error(new TokenExchangeUnavailableException(
                            "Unable to exchange token for audience " + audience, e));
                });
    }

    private ExchangedToken parse(String body, String audience) {
        try {
            JsonNode root = objectMapper.readTree(body);
            String accessToken = root.path("access_token").asText(null);
            if (accessToken == null) {
                throw new IllegalStateException("response had no access_token");
            }
            return new ExchangedToken(accessToken, root.path("expires_in").asLong(0));
        } catch (Exception e) {
            throw new TokenExchangeUnavailableException(
                    "Unreadable token exchange response for audience " + audience, e);
        }
    }
}
