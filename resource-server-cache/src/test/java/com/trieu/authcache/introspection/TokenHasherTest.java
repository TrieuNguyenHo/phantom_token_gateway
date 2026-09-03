package com.trieu.authcache.introspection;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TokenHasherTest {

    private final TokenHasher hasher = new TokenHasher();

    @Test
    void sameTokenAlwaysHashesToTheSameKey() {
        String token = "opaque-access-token-abc123";
        assertThat(hasher.sha256(token)).isEqualTo(hasher.sha256(token));
    }

    @Test
    void differentTokensHashDifferently() {
        assertThat(hasher.sha256("token-a")).isNotEqualTo(hasher.sha256("token-b"));
    }

    @Test
    void hashIsHex64CharsAndNeverContainsTheRawToken() {
        String token = "super-secret-token-value";
        String hash = hasher.sha256(token);

        assertThat(hash).hasSize(64); // SHA-256 -> 32 bytes -> 64 hex chars
        assertThat(hash).matches("[0-9a-f]{64}");
        assertThat(hash).doesNotContain(token);
    }

    @Test
    void matchesKnownSha256Vector() {
        // echo -n "abc" | sha256sum
        assertThat(hasher.sha256("abc"))
                .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
