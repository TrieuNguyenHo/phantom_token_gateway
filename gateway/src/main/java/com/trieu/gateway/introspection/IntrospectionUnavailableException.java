package com.trieu.gateway.introspection;

/**
 * "We could not determine whether this token is valid." Deliberately distinct from "the token
 * is invalid": both end in a rejected request, but only this one means the system is degraded
 * and worth alerting on.
 */
public class IntrospectionUnavailableException extends RuntimeException {
    public IntrospectionUnavailableException(String message) {
        super(message);
    }

    public IntrospectionUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
