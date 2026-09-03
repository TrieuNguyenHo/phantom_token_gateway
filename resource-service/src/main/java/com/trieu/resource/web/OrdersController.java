package com.trieu.resource.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Stand-in for any business endpoint. It echoes back what the service learned about the caller
 * so a demo can prove the point: everything here came out of the forwarded JWT, verified
 * locally - this process never spoke to Keycloak or Redis.
 */
@RestController
public class OrdersController {

    @GetMapping("/api/orders/{id}")
    public Map<String, Object> getOrder(@PathVariable String id,
                                          @AuthenticationPrincipal Jwt jwt,
                                          @RequestHeader(value = "X-Auth-Sid", required = false) String sidHeader) {
        return Map.of(
                "orderId", id,
                "sub", jwt.getSubject(),
                "audience", jwt.getAudience(),
                "scope", jwt.getClaimAsString("scope") == null ? "" : jwt.getClaimAsString("scope"),
                "sidFromGatewayHeader", sidHeader == null ? "" : sidHeader,
                "validatedBy", "local JWKS signature check - no call to Keycloak"
        );
    }

    @GetMapping("/api/whoami")
    public Map<String, Object> whoami(@AuthenticationPrincipal Jwt jwt) {
        return Map.of(
                "sub", jwt.getSubject(),
                "issuer", String.valueOf(jwt.getIssuer()),
                "audience", jwt.getAudience(),
                "expiresAt", String.valueOf(jwt.getExpiresAt())
        );
    }
}
