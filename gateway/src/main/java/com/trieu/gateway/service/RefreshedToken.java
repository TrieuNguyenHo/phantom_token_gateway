package com.trieu.gateway.service;

/**
 * Result of one refresh_token grant call: a new access token plus the rotated refresh token
 * Keycloak issues alongside it (refresh token rotation - the old one is single-use).
 */
public record RefreshedToken(String accessToken, String refreshToken, long expiresInSeconds) {
}
