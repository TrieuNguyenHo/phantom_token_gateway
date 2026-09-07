package com.trieu.gateway.controller;

import com.trieu.gateway.service.RefreshTokenRejectedException;
import com.trieu.gateway.service.RefreshTokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * Redeems a refresh token for a new access token. The refresh token is opaque to the gateway -
 * it is never decoded here, only forwarded to Keycloak's token endpoint via
 * {@link RefreshTokenService}. The returned access token is not primed into PhantomTokenCache:
 * PhantomTokenFilter caches it the same way as any other token, the first time it is actually
 * used - this endpoint has no reason to duplicate that.
 */
@Slf4j
@RestController
public class RefreshTokenController {

    private final RefreshTokenService refreshTokenService;

    public record RefreshTokenRequest(String refreshToken) {
    }

    public record RefreshTokenResponse(String accessToken, String refreshToken, long expiresInSeconds) {
    }

    public RefreshTokenController(RefreshTokenService refreshTokenService) {
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping(value = "/refresh-token")
    public Mono<ResponseEntity<RefreshTokenResponse>> refreshAccessToken(@RequestBody RefreshTokenRequest request) {
        if (request.refreshToken() == null || request.refreshToken().isBlank()) {
            return Mono.just(ResponseEntity.badRequest().build());
        }
        return refreshTokenService.refresh(request.refreshToken())
                .map(refreshed -> ResponseEntity.ok()
                        // Response body carries live credentials - never let it be cached.
                        .header(HttpHeaders.CACHE_CONTROL, "no-store")
                        .header(HttpHeaders.PRAGMA, "no-cache")
                        .body(new RefreshTokenResponse(
                                refreshed.accessToken(), refreshed.refreshToken(), refreshed.expiresInSeconds())))
                .onErrorResume(RefreshTokenRejectedException.class, e -> {
                    log.warn("Refresh token rejected: {}", e.toString());
                    return Mono.just(ResponseEntity.status(401).<RefreshTokenResponse>build());
                });
    }
}
