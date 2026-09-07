package com.trieu.gateway.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trieu.gateway.config.KeycloakProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Redeems a refresh token at Keycloak's token endpoint (RFC 6749 grant_type=refresh_token).
 *
 * <p>Refresh tokens in this realm are opaque Keycloak-managed credentials, not JWTs - unlike
 * access tokens they are never decoded locally, only ever handed back to Keycloak. Redeeming one
 * authenticates as the gateway's own confidential client ({@link KeycloakProperties#clientId()} /
 * {@link KeycloakProperties#clientSecret()}), the same credentials used for introspection.
 */
@Slf4j
@Service
public class RefreshTokenService {

    private final WebClient webClient;
    private final KeycloakProperties props;
    private final ObjectMapper objectMapper;

    public RefreshTokenService(WebClient.Builder webClientBuilder,
                                KeycloakProperties props,
                                ObjectMapper objectMapper) {
        this.webClient = webClientBuilder.build();
        this.props = props;
        this.objectMapper = objectMapper;
    }

    public Mono<RefreshedToken> refresh(String refreshToken) {
        return webClient.post()
                .uri(props.tokenUri())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData("grant_type", "refresh_token")
                        .with("client_id", props.clientId())
                        .with("client_secret", props.clientSecret())
                        .with("refresh_token", refreshToken))
                .exchangeToMono(response -> {
                    if (response.statusCode().isError()) {
                        // Expired, revoked, or already-rotated refresh token - Keycloak answers
                        // 400 invalid_grant. A rejection, not a transport failure.
                        return response.releaseBody()
                                .then(Mono.error(new RefreshTokenRejectedException(
                                        "Keycloak rejected the refresh token: " + response.statusCode())));
                    }
                    return response.bodyToMono(String.class).map(this::parse);
                })
                .timeout(Duration.ofSeconds(2))
                .onErrorMap(e -> !(e instanceof RefreshTokenRejectedException),
                        e -> new RefreshTokenRejectedException("Unable to refresh token", e));
    }

    private RefreshedToken parse(String body) {
        try {
            JsonNode root = objectMapper.readTree(body);
            String accessToken = root.path("access_token").asText(null);
            String rotatedRefreshToken = root.path("refresh_token").asText(null);
            if (accessToken == null || rotatedRefreshToken == null) {
                throw new IllegalStateException("response had no access_token/refresh_token");
            }
            return new RefreshedToken(accessToken, rotatedRefreshToken, root.path("expires_in").asLong(0));
        } catch (Exception e) {
            throw new RefreshTokenRejectedException("Unreadable refresh response", e);
        }
    }
}
