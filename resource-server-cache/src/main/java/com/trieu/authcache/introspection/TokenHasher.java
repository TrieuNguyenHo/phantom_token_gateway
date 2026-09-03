package com.trieu.authcache.introspection;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * We never store the raw access token anywhere in Redis — a Redis dump, a slow-log entry, or a
 * misconfigured monitoring exporter would leak it as-is. Instead every cache/lock/index key is
 * derived from SHA-256(token). SHA-256 is one-way and collision-resistant enough for a cache
 * key; it does not need to be a "slow" hash (bcrypt/argon2) because the thing we're protecting
 * against is accidental exposure of the key material, not offline brute-forcing of a low-entropy
 * secret — opaque tokens issued by Keycloak carry ~256 bits of randomness.
 */
@Component
public class TokenHasher {

    public String sha256(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed to be available on every JVM; this can't actually happen.
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
