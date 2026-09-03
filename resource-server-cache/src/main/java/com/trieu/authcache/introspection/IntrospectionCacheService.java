package com.trieu.authcache.introspection;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trieu.authcache.config.CacheProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

/**
 * All Redis access for the introspection cache lives here. This is the class that turns a
 * ~5-20ms (or, under load, ~200ms) Keycloak round trip into a &lt;1ms Redis GET on cache hit.
 *
 * <p>Four things this class is responsible for, matching the interview answer point-by-point:
 * <ol>
 *   <li><b>Positive/negative caching with an asymmetric TTL</b> — {@link #putPositive} caps the
 *       TTL at {@code min(secondsUntilExpiry, positiveTtlCap)}; {@link #putNegative} uses a much
 *       shorter, jittered TTL so a user who just logged back in doesn't stay 401'd.</li>
 *   <li><b>Session-indexed bulk eviction</b> — {@link #indexForSession} / {@link #evictBySession}
 *       so one logout evicts every token from that session in one round trip, with no
 *       {@code KEYS} / {@code SCAN} over the keyspace.</li>
 *   <li><b>A revocation deny-list</b> — {@link #markSessionRevoked} / {@link #isSessionRevoked},
 *       checked before trusting a cache hit, so a revoked session can never serve a stale
 *       "active" verdict for its remaining TTL window.</li>
 *   <li><b>Single-flight locking</b> — {@link #tryAcquireLock} / {@link #releaseLock} —
 *       so a Keycloak restart with a cold cache doesn't turn into a stampede of N concurrent
 *       introspection calls for the same token.</li>
 * </ol>
 */
@Slf4j
@Service
public class IntrospectionCacheService {

    /** Default Keycloak access-token lifespan, used to bound the revocation deny-list TTL. */
    private static final Duration DEFAULT_ACCESS_TOKEN_LIFESPAN = Duration.ofMinutes(5);

    private static final DefaultRedisScript<Long> UNLOCK_SCRIPT = new DefaultRedisScript<>("""
            if redis.call('get', KEYS[1]) == ARGV[1] then
              return redis.call('del', KEYS[1])
            else
              return 0
            end
            """, Long.class);

    private final StringRedisTemplate redis;
    private final ObjectMapper objectMapper;
    private final CacheProperties props;

    public IntrospectionCacheService(StringRedisTemplate redis, ObjectMapper objectMapper, CacheProperties props) {
        this.redis = redis;
        this.objectMapper = objectMapper;
        this.props = props;
    }

    // ---------------------------------------------------------------- read

    public Optional<IntrospectionResult> get(String tokenHash) {
        String raw = redis.opsForValue().get(RedisKeys.cache(tokenHash));
        if (raw == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(objectMapper.readValue(raw, IntrospectionResult.class));
        } catch (JsonProcessingException e) {
            // A corrupt cache entry must never crash auth — treat it as a miss and let the
            // caller fall through to a fresh introspection call.
            log.warn("Discarding unreadable cache entry for key={}", RedisKeys.cache(tokenHash), e);
            redis.delete(RedisKeys.cache(tokenHash));
            return Optional.empty();
        }
    }

    // --------------------------------------------------------------- write

    /**
     * Cache a successful (active=true) introspection result.
     * TTL = min(time left on the token, positiveTtlCap) — see class javadoc point 1.
     */
    public void putPositive(String tokenHash, IntrospectionResult result, Instant now) {
        long secondsLeft = result.secondsUntilExpiry(now.getEpochSecond());
        long ttlSeconds = Math.min(secondsLeft, props.positiveTtlCap().toSeconds());
        if (ttlSeconds <= 0) {
            // Already expired by the time we got the response - not worth caching.
            return;
        }
        write(tokenHash, result, Duration.ofSeconds(ttlSeconds));
        if (result.hasSession()) {
            indexForSession(tokenHash, result.sid(), Duration.ofSeconds(ttlSeconds));
        }
    }

    /**
     * Cache a negative (active=false / introspection failed) result with a short, jittered TTL
     * — see class javadoc point 1. Jitter avoids a thundering herd of expiries all landing on
     * the same millisecond under sustained invalid-token traffic (e.g. a retry storm).
     */
    public void putNegative(String tokenHash) {
        long minMs = props.negativeTtlMin().toMillis();
        long maxMs = props.negativeTtlMax().toMillis();
        long ttlMs = minMs >= maxMs ? minMs : ThreadLocalRandom.current().nextLong(minMs, maxMs);
        write(tokenHash, IntrospectionResult.inactive(), Duration.ofMillis(ttlMs));
    }

    private void write(String tokenHash, IntrospectionResult result, Duration ttl) {
        try {
            String json = objectMapper.writeValueAsString(result);
            redis.opsForValue().set(RedisKeys.cache(tokenHash), json, ttl);
        } catch (JsonProcessingException e) {
            // Serialization failure just means "no caching this round" - never let it break auth.
            log.warn("Failed to serialize introspection result for caching", e);
        }
    }

    // ------------------------------------------------------ session index

    void indexForSession(String tokenHash, String sid, Duration ttl) {
        String key = RedisKeys.sessionIndex(sid);
        redis.opsForSet().add(key, tokenHash);
        // Keep the index itself from growing unbounded if a session is never explicitly
        // logged out - it should not outlive the longest-lived member by much.
        redis.expire(key, ttl.plus(Duration.ofSeconds(5)));
    }

    /**
     * Evict every cached token that belongs to this session in one round trip
     * (SMEMBERS + DEL), and mark the session as revoked so any introspection response that
     * arrives *after* this call (a request already in flight when the user logged out) still
     * gets rejected. This is what layers 2 and 3 (event listener, backchannel logout) call.
     */
    public void evictBySession(String sid, Duration denyListTtl) {
        String indexKey = RedisKeys.sessionIndex(sid);
        Set<String> members = redis.opsForSet().members(indexKey);
        if (members != null && !members.isEmpty()) {
            List<String> cacheKeys = members.stream().map(RedisKeys::cache).toList();
            redis.delete(cacheKeys);
            log.info("Evicted {} cached introspection entries for sid={}", cacheKeys.size(), sid);
        }
        redis.delete(indexKey);
        markSessionRevoked(sid, denyListTtl);
    }

    public void evictBySession(String sid) {
        evictBySession(sid, DEFAULT_ACCESS_TOKEN_LIFESPAN);
    }

    // -------------------------------------------------------- deny-list

    /** Layer 4: a cheap SET with a bounded TTL, checked before trusting any cache hit. */
    public void markSessionRevoked(String sid, Duration ttl) {
        redis.opsForValue().set(RedisKeys.revokedSession(sid), "1", ttl);
    }

    public boolean isSessionRevoked(String sid) {
        if (sid == null) {
            return false;
        }
        return Boolean.TRUE.equals(redis.hasKey(RedisKeys.revokedSession(sid)));
    }

    // ------------------------------------------------- single-flight lock

    /**
     * Best-effort mutual exclusion so that when N requests miss the cache for the *same* token
     * at the same moment (classic cold-cache-after-restart stampede), only one of them calls
     * Keycloak; the rest either wait briefly for the winner's result or (after
     * {@code lockWaitTimeout}) proceed on their own rather than hang forever.
     *
     * <p>Returns a lock token to pass back into {@link #releaseLock} - never null-check the
     * key's raw value directly, that has a well-known race between the check and the delete.
     */
    public Optional<String> tryAcquireLock(String tokenHash) {
        String lockToken = UUID.randomUUID().toString();
        Boolean acquired = redis.opsForValue().setIfAbsent(RedisKeys.lock(tokenHash), lockToken, props.lockTtl());
        return Boolean.TRUE.equals(acquired) ? Optional.of(lockToken) : Optional.empty();
    }

    public void releaseLock(String tokenHash, String lockToken) {
        redis.execute(UNLOCK_SCRIPT, List.of(RedisKeys.lock(tokenHash)), lockToken);
    }

    public Duration lockWaitTimeout() {
        return props.lockWaitTimeout();
    }

    public Duration lockPollInterval() {
        return props.lockPollInterval();
    }
}
