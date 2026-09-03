package com.trieu.authcache.introspection;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.trieu.authcache.config.CacheProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.core.SetOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * These tests mock {@link StringRedisTemplate} directly rather than hitting a real Redis, so
 * they exercise exactly the logic this class is responsible for (TTL math, key naming, when
 * eviction/deny-list calls happen) without needing infrastructure. An integration test against
 * a real/embedded Redis is the natural next layer on top of these - see the README.
 */
class IntrospectionCacheServiceTest {

    private StringRedisTemplate redis;
    private ValueOperations<String, String> valueOps;
    private SetOperations<String, String> setOps;
    private IntrospectionCacheService service;
    private CacheProperties props;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        redis = mock(StringRedisTemplate.class);
        valueOps = mock(ValueOperations.class);
        setOps = mock(SetOperations.class);
        when(redis.opsForValue()).thenReturn(valueOps);
        when(redis.opsForSet()).thenReturn(setOps);

        props = new CacheProperties(
                Duration.ofSeconds(30), Duration.ofSeconds(2), Duration.ofSeconds(5),
                Duration.ofSeconds(3), Duration.ofMillis(500), Duration.ofMillis(20));
        service = new IntrospectionCacheService(redis, new ObjectMapper(), props);
    }

    @Test
    void putPositive_capsTtlAtPositiveTtlCap_whenTokenOutlivesTheCap() {
        Instant now = Instant.now();
        // Token has 10 minutes left - far more than the 30s cap.
        IntrospectionResult result = new IntrospectionResult(true, "user-1", Set.of("read"), "client-a",
                now.plusSeconds(600).getEpochSecond(), null, "jti-1");

        service.putPositive("hash1", result, now);

        ArgumentCaptor<Duration> ttlCaptor = ArgumentCaptor.forClass(Duration.class);
        verify(valueOps).set(eq("introspect:cache:hash1"), any(String.class), ttlCaptor.capture());
        assertThat(ttlCaptor.getValue()).isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    void putPositive_usesRemainingLifetime_whenTokenExpiresBeforeTheCap() {
        Instant now = Instant.now();
        // Token only has 10 seconds left - shorter than the 30s cap.
        IntrospectionResult result = new IntrospectionResult(true, "user-1", Set.of("read"), "client-a",
                now.plusSeconds(10).getEpochSecond(), null, "jti-1");

        service.putPositive("hash1", result, now);

        ArgumentCaptor<Duration> ttlCaptor = ArgumentCaptor.forClass(Duration.class);
        verify(valueOps).set(eq("introspect:cache:hash1"), any(String.class), ttlCaptor.capture());
        assertThat(ttlCaptor.getValue()).isEqualTo(Duration.ofSeconds(10));
    }

    @Test
    void putPositive_neverCachesAnAlreadyExpiredToken() {
        Instant now = Instant.now();
        IntrospectionResult result = new IntrospectionResult(true, "user-1", Set.of("read"), "client-a",
                now.minusSeconds(5).getEpochSecond(), null, "jti-1");

        service.putPositive("hash1", result, now);

        verifyNoInteractions(valueOps);
    }

    @Test
    void putPositive_indexesTheTokenUnderItsSession_whenSidIsPresent() {
        Instant now = Instant.now();
        IntrospectionResult result = new IntrospectionResult(true, "user-1", Set.of("read"), "client-a",
                now.plusSeconds(20).getEpochSecond(), "session-abc", "jti-1");

        service.putPositive("hash1", result, now);

        verify(setOps).add("introspect:session:session-abc", "hash1");
        verify(redis).expire(eq("introspect:session:session-abc"), any(Duration.class));
    }

    @Test
    void putPositive_doesNotTouchSessionIndex_whenSidIsAbsent() {
        Instant now = Instant.now();
        IntrospectionResult result = new IntrospectionResult(true, "user-1", Set.of("read"), "client-a",
                now.plusSeconds(20).getEpochSecond(), null, "jti-1");

        service.putPositive("hash1", result, now);

        verifyNoInteractions(setOps);
    }

    @Test
    void putNegative_usesAShortJitteredTtl_withinConfiguredBounds() {
        service.putNegative("hash-negative");

        ArgumentCaptor<Duration> ttlCaptor = ArgumentCaptor.forClass(Duration.class);
        verify(valueOps).set(eq("introspect:cache:hash-negative"), any(String.class), ttlCaptor.capture());

        Duration ttl = ttlCaptor.getValue();
        assertThat(ttl).isGreaterThanOrEqualTo(Duration.ofSeconds(2));
        assertThat(ttl).isLessThan(Duration.ofSeconds(5));
    }

    @Test
    void get_returnsEmpty_onCacheMiss() {
        when(valueOps.get("introspect:cache:missing")).thenReturn(null);
        assertThat(service.get("missing")).isEmpty();
    }

    @Test
    void get_deserializesACachedResult() {
        when(valueOps.get("introspect:cache:hash1"))
                .thenReturn("""
                        {"active":true,"sub":"user-1","scope":["read","write"],"clientId":"c1","exp":9999999999,"sid":"sid-1","jti":"jti-1"}""");

        var result = service.get("hash1");

        assertThat(result).isPresent();
        assertThat(result.get().active()).isTrue();
        assertThat(result.get().sub()).isEqualTo("user-1");
        assertThat(result.get().scope()).containsExactlyInAnyOrder("read", "write");
    }

    @Test
    void get_treatsCorruptJsonAsAMiss_andEvictsIt() {
        when(valueOps.get("introspect:cache:hash1")).thenReturn("{not-valid-json");

        assertThat(service.get("hash1")).isEmpty();
        verify(redis).delete("introspect:cache:hash1");
    }

    @Test
    void evictBySession_deletesEveryIndexedKeyAndTheIndexItself_andMarksTheDenyList() {
        when(setOps.members("introspect:session:sid-1")).thenReturn(Set.of("hashA", "hashB"));

        service.evictBySession("sid-1", Duration.ofMinutes(5));

        verify(redis).delete(argThat((java.util.Collection<String> keys) ->
                keys.containsAll(Set.of("introspect:cache:hashA", "introspect:cache:hashB"))));
        verify(redis).delete("introspect:session:sid-1");
        verify(valueOps).set("introspect:revoked:sid:sid-1", "1", Duration.ofMinutes(5));
    }

    @Test
    void evictBySession_stillMarksTheDenyList_whenThereWasNothingCached() {
        when(setOps.members("introspect:session:sid-empty")).thenReturn(Set.of());

        service.evictBySession("sid-empty", Duration.ofMinutes(5));

        verify(valueOps).set("introspect:revoked:sid:sid-empty", "1", Duration.ofMinutes(5));
    }

    @Test
    void isSessionRevoked_reflectsWhetherTheDenyListKeyExists() {
        when(redis.hasKey("introspect:revoked:sid:sid-1")).thenReturn(true);
        when(redis.hasKey("introspect:revoked:sid:sid-2")).thenReturn(false);

        assertThat(service.isSessionRevoked("sid-1")).isTrue();
        assertThat(service.isSessionRevoked("sid-2")).isFalse();
    }

    @Test
    void isSessionRevoked_isFalseForNullSid_withoutTouchingRedis() {
        assertThat(service.isSessionRevoked(null)).isFalse();
        verifyNoInteractions(redis);
    }

    @Test
    void tryAcquireLock_returnsAToken_whenSetIfAbsentSucceeds() {
        when(valueOps.setIfAbsent(eq("introspect:lock:hash1"), any(String.class), eq(Duration.ofSeconds(3))))
                .thenReturn(true);

        assertThat(service.tryAcquireLock("hash1")).isPresent();
    }

    @Test
    void tryAcquireLock_returnsEmpty_whenSomeoneElseAlreadyHoldsTheLock() {
        when(valueOps.setIfAbsent(eq("introspect:lock:hash1"), any(String.class), eq(Duration.ofSeconds(3))))
                .thenReturn(false);

        assertThat(service.tryAcquireLock("hash1")).isEmpty();
    }

    @Test
    void releaseLock_executesTheCompareAndDeleteScript() {
        service.releaseLock("hash1", "my-lock-token");

        verify(redis).execute(any(org.springframework.data.redis.core.script.RedisScript.class),
                eq(java.util.List.of("introspect:lock:hash1")), eq("my-lock-token"));
    }
}
