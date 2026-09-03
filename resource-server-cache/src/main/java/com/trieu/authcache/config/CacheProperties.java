package com.trieu.authcache.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Tunables for the introspection cache. Defaults match what's discussed in the interview
 * answer: positive TTL capped at 30s regardless of how long the token itself has left to
 * live, negative TTL kept much shorter so a freshly re-authenticated user isn't stuck
 * behind a stale "active: false" entry.
 */
@ConfigurationProperties(prefix = "auth-cache")
public record CacheProperties(
        Duration positiveTtlCap,
        Duration negativeTtlMin,
        Duration negativeTtlMax,
        Duration lockTtl,
        Duration lockWaitTimeout,
        Duration lockPollInterval
) {
    public CacheProperties {
        if (positiveTtlCap == null) positiveTtlCap = Duration.ofSeconds(30);
        if (negativeTtlMin == null) negativeTtlMin = Duration.ofSeconds(2);
        if (negativeTtlMax == null) negativeTtlMax = Duration.ofSeconds(5);
        if (lockTtl == null) lockTtl = Duration.ofSeconds(3);
        if (lockWaitTimeout == null) lockWaitTimeout = Duration.ofMillis(500);
        if (lockPollInterval == null) lockPollInterval = Duration.ofMillis(20);
    }
}
