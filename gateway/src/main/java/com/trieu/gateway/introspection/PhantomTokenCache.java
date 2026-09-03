package com.trieu.gateway.introspection;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.trieu.gateway.config.PhantomTokenProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

/**
 * The gateway's cache - the single copy that used to exist once per service in approach A.
 * Same rules as before, one place to run them:
 * <ul>
 *   <li>keys are {@code sha256(token)}, never the raw token (Redis dumps and slow logs leak);</li>
 *   <li>positive TTL is {@code min(remaining lifetime, cap)}, negative TTL is short and jittered;</li>
 *   <li>tokens are indexed by {@code sid} so one logout evicts a whole session in one round trip;</li>
 *   <li>a deny-list backs that up for anything already in flight.</li>
 * </ul>
 */
@Slf4j
@Component
public class PhantomTokenCache {

    private static final DefaultRedisScript<Long> UNLOCK = new DefaultRedisScript<>("""
            if redis.call('get', KEYS[1]) == ARGV[1] then
              return redis.call('del', KEYS[1])
            else
              return 0
            end
            """, Long.class);

    private final ReactiveStringRedisTemplate redis;
    private final ObjectMapper objectMapper;
    private final PhantomTokenProperties props;

    public PhantomTokenCache(ReactiveStringRedisTemplate redis,
                              ObjectMapper objectMapper,
                              PhantomTokenProperties props) {
        this.redis = redis;
        this.objectMapper = objectMapper;
        this.props = props;
    }

    // ------------------------------------------------------------- keys

    public String hash(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private String cacheKey(String hash) { return "phantom:cache:" + hash; }
    private String lockKey(String hash) { return "phantom:lock:" + hash; }
    private String sessionKey(String sid) { return "phantom:session:" + sid; }
    private String revokedKey(String sid) { return "phantom:revoked:sid:" + sid; }
    private String exchangeCacheKey(String audience, String hash) { return "phantom:exchange:" + audience + ":" + hash; }
    private String exchangeSessionKey(String sid) { return "phantom:session:exchange:" + sid; }

    // ------------------------------------------------------------- read

    public Mono<IntrospectionResult> get(String hash) {
        return redis.opsForValue().get(cacheKey(hash))
                .flatMap(raw -> {
                    try {
                        return Mono.just(objectMapper.readValue(raw, IntrospectionResult.class));
                    } catch (Exception e) {
                        log.warn("Dropping unreadable cache entry {}", cacheKey(hash), e);
                        return redis.delete(cacheKey(hash)).then(Mono.empty());
                    }
                })
                // A cache read must never take the request down with it.
                .onErrorResume(e -> {
                    log.warn("Redis unavailable on read, bypassing cache: {}", e.toString());
                    return Mono.empty();
                });
    }

    /** Cached RFC 8693 exchange result for this (token, target audience) pair, if any. */
    public Mono<String> getExchanged(String hash, String audience) {
        return redis.opsForValue().get(exchangeCacheKey(audience, hash))
                .onErrorResume(e -> {
                    log.warn("Redis unavailable on exchanged-token read, bypassing cache: {}", e.toString());
                    return Mono.empty();
                });
    }

    public Mono<Boolean> isSessionRevoked(String sid) {
        if (sid == null || sid.isBlank()) {
            return Mono.just(false);
        }
        return redis.hasKey(revokedKey(sid))
                // Cannot confirm the deny-list ⇒ treat as revoked. Fail closed: an
                // unverifiable revocation status must not be read as "not revoked".
                .onErrorReturn(true);
    }

    // ------------------------------------------------------------ write

    public Mono<Void> putPositive(String hash, IntrospectionResult result, Instant now) {
        long ttlSeconds = Math.min(result.secondsUntilExpiry(now.getEpochSecond()),
                props.positiveTtlCap().toSeconds());
        if (ttlSeconds <= 0) {
            return Mono.empty();
        }
        Duration ttl = Duration.ofSeconds(ttlSeconds);
        return write(hash, result, ttl)
                .then(result.hasSession() ? indexForSession(hash, result.sid(), ttl) : Mono.empty());
    }

    public Mono<Void> putNegative(String hash) {
        long min = props.negativeTtlMin().toMillis();
        long max = props.negativeTtlMax().toMillis();
        long ttlMs = min >= max ? min : ThreadLocalRandom.current().nextLong(min, max);
        return write(hash, IntrospectionResult.inactive(), Duration.ofMillis(ttlMs));
    }

    /** Same TTL rule as {@link #putPositive}: capped by the exchanged token's own expiry. */
    public Mono<Void> putExchanged(String hash, String audience, String accessToken, long expiresInSeconds, String sid) {
        long ttlSeconds = Math.min(expiresInSeconds, props.positiveTtlCap().toSeconds());
        if (ttlSeconds <= 0) {
            return Mono.empty();
        }
        Duration ttl = Duration.ofSeconds(ttlSeconds);
        String key = exchangeCacheKey(audience, hash);
        return redis.opsForValue().set(key, accessToken, ttl)
                .onErrorResume(e -> {
                    log.warn("Redis unavailable on exchanged-token write, result not cached: {}", e.toString());
                    return Mono.just(false);
                })
                .then(sid != null && !sid.isBlank() ? indexExchangeForSession(sid, key, ttl) : Mono.empty());
    }

    private Mono<Void> indexExchangeForSession(String sid, String exchangeKey, Duration ttl) {
        return redis.opsForSet().add(exchangeSessionKey(sid), exchangeKey)
                .then(redis.expire(exchangeSessionKey(sid), ttl.plusSeconds(5)))
                .onErrorReturn(false)
                .then();
    }

    private Mono<Void> write(String hash, IntrospectionResult result, Duration ttl) {
        try {
            String json = objectMapper.writeValueAsString(result);
            return redis.opsForValue().set(cacheKey(hash), json, ttl)
                    .onErrorResume(e -> {
                        log.warn("Redis unavailable on write, result not cached: {}", e.toString());
                        return Mono.just(false);
                    })
                    .then();
        } catch (Exception e) {
            log.warn("Could not serialize introspection result", e);
            return Mono.empty();
        }
    }

    private Mono<Void> indexForSession(String hash, String sid, Duration ttl) {
        return redis.opsForSet().add(sessionKey(sid), hash)
                .then(redis.expire(sessionKey(sid), ttl.plusSeconds(5)))
                .onErrorReturn(false)
                .then();
    }

    // ------------------------------------------------------- invalidation

    /**
     * One logout, two set reads: read the introspection session index and the exchanged-token
     * session index, delete every cached entry either points at, drop both indexes, and put the
     * session on the deny-list. No {@code KEYS}, no {@code SCAN}.
     */
    public Mono<Long> evictBySession(String sid) {
        Mono<List<String>> introspectionKeys = redis.opsForSet().members(sessionKey(sid))
                .map(this::cacheKey)
                .collectList();
        Mono<List<String>> exchangeKeys = redis.opsForSet().members(exchangeSessionKey(sid))
                .collectList();
        return Mono.zip(introspectionKeys, exchangeKeys)
                .flatMap(pair -> {
                    List<String> keys = new ArrayList<>(pair.getT1());
                    keys.addAll(pair.getT2());
                    return (keys.isEmpty() ? Mono.just(0L) : redis.delete(keys.toArray(String[]::new)))
                            .flatMap(deleted -> redis.delete(sessionKey(sid), exchangeSessionKey(sid))
                                    .then(markRevoked(sid))
                                    .thenReturn(deleted));
                })
                .doOnNext(n -> log.info("Evicted {} cached entries for sid={}", n, sid))
                .onErrorResume(e -> {
                    log.error("Eviction failed for sid={} - short TTL is the remaining safety net", sid, e);
                    return Mono.just(0L);
                });
    }

    public Mono<Void> markRevoked(String sid) {
        return redis.opsForValue().set(revokedKey(sid), "1", props.denyListTtl()).then();
    }

    // ------------------------------------------------- single-flight lock

    /** Empty when someone else already holds the lock for this token. */
    public Mono<String> tryAcquireLock(String hash) {
        String lockToken = UUID.randomUUID().toString();
        return redis.opsForValue().setIfAbsent(lockKey(hash), lockToken, props.lockTtl())
                .filter(Boolean::booleanValue)
                .map(acquired -> lockToken)
                .onErrorResume(e -> Mono.empty());
    }

    public Mono<Void> releaseLock(String hash, String lockToken) {
        return redis.execute(UNLOCK, List.of(lockKey(hash)), List.of(lockToken))
                .then()
                .onErrorResume(e -> Mono.empty());
    }
}
