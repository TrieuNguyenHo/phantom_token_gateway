package com.trieu.authcache.introspection;

/**
 * Thrown when Keycloak itself cannot be reached to confirm a token (circuit open, timeout,
 * non-2xx). This is intentionally NOT treated as "token invalid" vs. "token valid" - it is a
 * third state, "unknown", and the caller must reject the request rather than guess. That's the
 * fail-closed-on-security half of the Redis-down story: we degrade to calling Keycloak directly,
 * but we never degrade to assuming a token is valid just because we can't check it.
 */
public class IntrospectionUnavailableException extends RuntimeException {
    public IntrospectionUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
