package com.trieu.gateway.exchange;

/**
 * "We could not mint a per-service token." Distinct from introspection failure: the caller's
 * token was already confirmed active, but Keycloak's token-exchange endpoint could not be
 * reached or refused the exchange. Ends in a rejected request either way - there is no path
 * that falls back to forwarding an un-audienced token.
 */
public class TokenExchangeUnavailableException extends RuntimeException {
    public TokenExchangeUnavailableException(String message) {
        super(message);
    }

    public TokenExchangeUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
