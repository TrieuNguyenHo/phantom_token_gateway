package com.trieu.gateway.introspection;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Normalized outcome of one introspection call, and the only thing the gateway caches.
 *
 * @param active         whether Keycloak says the token is still usable
 * @param forwardableJwt the JWT to put in the downstream Authorization header, or null when the
 *                       authorization server did not hand back a token we are allowed to
 *                       forward (see {@link IntrospectionResponseParser})
 * @param sub            subject - the end user
 * @param sid            OIDC session id, the key everything is evicted by on logout
 * @param exp            access-token expiry, epoch seconds; caps the cache TTL
 */
public record IntrospectionResult(
        boolean active,
        String forwardableJwt,
        String sub,
        String sid,
        long exp
) {

    @JsonCreator
    public IntrospectionResult(
            @JsonProperty("active") boolean active,
            @JsonProperty("forwardableJwt") String forwardableJwt,
            @JsonProperty("sub") String sub,
            @JsonProperty("sid") String sid,
            @JsonProperty("exp") long exp) {
        this.active = active;
        this.forwardableJwt = forwardableJwt;
        this.sub = sub;
        this.sid = sid;
        this.exp = exp;
    }

    public static IntrospectionResult inactive() {
        return new IntrospectionResult(false, null, null, null, 0);
    }

    public boolean hasSession() {
        return sid != null && !sid.isBlank();
    }

    public long secondsUntilExpiry(long nowEpochSeconds) {
        return Math.max(0, exp - nowEpochSeconds);
    }
}
