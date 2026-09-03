package com.trieu.gateway.exchange;

/**
 * Result of one RFC 8693 token exchange call: an access token minted for a single audience,
 * and how long it is good for - the cache TTL is capped at this, same rule as introspection.
 */
public record ExchangedToken(String accessToken, long expiresInSeconds) {
}
