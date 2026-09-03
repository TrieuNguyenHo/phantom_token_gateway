package com.trieu.authcache.introspection;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.Set;

/**
 * Normalized result of a token introspection call (either freshly fetched from Keycloak, or
 * read back from the Redis cache). This is the *only* thing we ever store in Redis for a
 * token — never the raw token itself.
 *
 * Field names mirror RFC 7662 (OAuth 2.0 Token Introspection) plus the OIDC-specific "sid"
 * claim, which is what lets us evict every cached token belonging to one login session in a
 * single operation (see {@link IntrospectionCacheService#evictBySession}).
 */
public record IntrospectionResult(
        boolean active,
        String sub,
        Set<String> scope,
        String clientId,
        long exp,          // epoch seconds
        String sid,        // session id (OIDC) - absent for client-credentials tokens
        String jti
) implements Serializable {

    @JsonCreator
    public IntrospectionResult(
            @JsonProperty("active") boolean active,
            @JsonProperty("sub") String sub,
            @JsonProperty("scope") Set<String> scope,
            @JsonProperty("clientId") String clientId,
            @JsonProperty("exp") long exp,
            @JsonProperty("sid") String sid,
            @JsonProperty("jti") String jti) {
        this.active = active;
        this.sub = sub;
        this.scope = scope == null ? Set.of() : scope;
        this.clientId = clientId;
        this.exp = exp;
        this.sid = sid;
        this.jti = jti;
    }

    public static IntrospectionResult inactive() {
        return new IntrospectionResult(false, null, Set.of(), null, 0, null, null);
    }

    public boolean hasSession() {
        return sid != null && !sid.isBlank();
    }

    /** Seconds remaining until the token's own expiry, floored at 0. */
    public long secondsUntilExpiry(long nowEpochSeconds) {
        return Math.max(0, exp - nowEpochSeconds);
    }
}
