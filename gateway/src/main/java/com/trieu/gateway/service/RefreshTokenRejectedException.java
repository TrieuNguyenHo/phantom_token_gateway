package com.trieu.gateway.service;

/**
 * "Keycloak would not redeem this refresh token" - expired, revoked (e.g. by backchannel logout),
 * already used (rotation), or unreadable. Always ends in a 401 to the caller; there is no path
 * that falls back to trusting a refresh token the gateway could not confirm.
 */
public class RefreshTokenRejectedException extends RuntimeException {
    public RefreshTokenRejectedException(String message) {
        super(message);
    }

    public RefreshTokenRejectedException(String message, Throwable cause) {
        super(message, cause);
    }
}
