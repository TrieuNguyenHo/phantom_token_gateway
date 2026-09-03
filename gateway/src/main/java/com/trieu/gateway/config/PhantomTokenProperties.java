package com.trieu.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Everything the phantom-token filter needs, in one place.
 *
 * <p>{@link #internalToken()} is the interesting knob - it decides what actually gets put in the
 * Authorization header that goes downstream:
 * <ul>
 *   <li>{@code KEYCLOAK_JWT} - use the full JWT that Keycloak returns from the introspection
 *       endpoint when called with {@code Accept: application/jwt} (needs the client attribute
 *       enabling that, see README). This is the real phantom-token setup.</li>
 *   <li>{@code ORIGINAL} - forward the incoming token unchanged. Use when the authorization
 *       server cannot hand back a forwardable JWT (a strict RFC 9701 response is audienced to
 *       the gateway, so it is NOT a credential you may forward). Downstream then needs the
 *       token to be a verifiable JWT already.</li>
 *   <li>{@code EXCHANGE} - RFC 8693 token exchange: mint a token audienced to whichever route
 *       matched the request (the {@code audience} route metadata), instead of forwarding one
 *       token to every downstream service. Needs "Standard token exchange" enabled on the
 *       gateway's Keycloak client. This is what closes the "service A's token works at
 *       service B" hole that {@code KEYCLOAK_JWT} and {@code ORIGINAL} both leave open.</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "phantom-token")
public record PhantomTokenProperties(
        InternalToken internalToken,
        Duration positiveTtlCap,
        Duration negativeTtlMin,
        Duration negativeTtlMax,
        Duration lockTtl,
        Duration denyListTtl,
        String eventWebhookSecret
) {
    public enum InternalToken { KEYCLOAK_JWT, ORIGINAL, EXCHANGE }

    public PhantomTokenProperties {
        if (internalToken == null) internalToken = InternalToken.KEYCLOAK_JWT;
        if (positiveTtlCap == null) positiveTtlCap = Duration.ofSeconds(30);
        if (negativeTtlMin == null) negativeTtlMin = Duration.ofSeconds(2);
        if (negativeTtlMax == null) negativeTtlMax = Duration.ofSeconds(5);
        if (lockTtl == null) lockTtl = Duration.ofSeconds(3);
        if (denyListTtl == null) denyListTtl = Duration.ofMinutes(5);
        if (eventWebhookSecret == null) eventWebhookSecret = "dev-shared-secret";
    }
}
