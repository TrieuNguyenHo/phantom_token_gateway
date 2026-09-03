package com.trieu.authcache.introspection;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;

import java.time.Duration;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Exercises {@link RedisCachedOpaqueTokenIntrospector} end to end with the cache and the
 * Keycloak client mocked out, which is exactly the boundary this class is meant to sit on. What
 * matters here is the *decision logic*: when does it trust the cache, when does it go to
 * Keycloak, and does a revoked/inactive/unverifiable result always come out as a rejection.
 */
class RedisCachedOpaqueTokenIntrospectorTest {

    private static final String TOKEN = "opaque-token-value";
    private static final String HASH = "deadbeef";

    private TokenHasher hasher;
    private IntrospectionCacheService cache;
    private KeycloakIntrospectionClient keycloakClient;
    private RedisCachedOpaqueTokenIntrospector introspector;

    @BeforeEach
    void setUp() {
        hasher = mock(TokenHasher.class);
        cache = mock(IntrospectionCacheService.class);
        keycloakClient = mock(KeycloakIntrospectionClient.class);
        when(hasher.sha256(TOKEN)).thenReturn(HASH);
        when(cache.lockWaitTimeout()).thenReturn(Duration.ofMillis(50));
        when(cache.lockPollInterval()).thenReturn(Duration.ofMillis(5));

        introspector = new RedisCachedOpaqueTokenIntrospector(hasher, cache, keycloakClient);
    }

    private IntrospectionResult activeResult(String sid) {
        return new IntrospectionResult(true, "user-1", Set.of("read", "write"), "client-a",
                Long.MAX_VALUE / 2, sid, "jti-1");
    }

    @Test
    void cacheHit_neverCallsKeycloak() {
        when(cache.get(HASH)).thenReturn(Optional.of(activeResult(null)));

        OAuth2AuthenticatedPrincipal principal = introspector.introspect(TOKEN);

        assertThat(principal.getName()).isEqualTo("user-1");
        verifyNoInteractions(keycloakClient);
    }

    @Test
    void cacheMiss_acquiresLock_callsKeycloakOnce_andCachesTheResult() {
        when(cache.get(HASH)).thenReturn(Optional.empty());
        when(cache.tryAcquireLock(HASH)).thenReturn(Optional.of("lock-token"));
        when(keycloakClient.introspect(TOKEN)).thenReturn(activeResult(null));

        OAuth2AuthenticatedPrincipal principal = introspector.introspect(TOKEN);

        assertThat(principal.getName()).isEqualTo("user-1");
        verify(keycloakClient, times(1)).introspect(TOKEN);
        verify(cache).putPositive(eq(HASH), any(IntrospectionResult.class), any());
        verify(cache).releaseLock(HASH, "lock-token");
    }

    @Test
    void cacheMiss_negativeResult_isCachedAsNegative_andRejected() {
        when(cache.get(HASH)).thenReturn(Optional.empty());
        when(cache.tryAcquireLock(HASH)).thenReturn(Optional.of("lock-token"));
        when(keycloakClient.introspect(TOKEN)).thenReturn(IntrospectionResult.inactive());

        assertThatThrownBy(() -> introspector.introspect(TOKEN))
                .isInstanceOf(BadOpaqueTokenException.class);

        verify(cache).putNegative(HASH);
        verify(cache, never()).putPositive(any(), any(), any());
    }

    @Test
    void lockAlreadyHeld_waitsForTheWinnersResultInsteadOfCallingKeycloakAgain() {
        when(cache.get(HASH))
                .thenReturn(Optional.empty())                       // first check: miss
                .thenReturn(Optional.of(activeResult(null)));       // winner published a result while we waited
        when(cache.tryAcquireLock(HASH)).thenReturn(Optional.empty()); // someone else holds the lock

        OAuth2AuthenticatedPrincipal principal = introspector.introspect(TOKEN);

        assertThat(principal.getName()).isEqualTo("user-1");
        verifyNoInteractions(keycloakClient);
    }

    @Test
    void revokedSession_isRejectedEvenOnACacheHit() {
        when(cache.get(HASH)).thenReturn(Optional.of(activeResult("sid-1")));
        when(cache.isSessionRevoked("sid-1")).thenReturn(true);

        assertThatThrownBy(() -> introspector.introspect(TOKEN))
                .isInstanceOf(BadOpaqueTokenException.class)
                .hasMessageContaining("revoked");
    }

    @Test
    void redisDown_onCacheRead_fallsBackToKeycloakDirectly_ratherThanFailingTheRequest() {
        when(cache.get(HASH)).thenThrow(new QueryTimeoutException("Redis unreachable"));
        when(keycloakClient.introspect(TOKEN)).thenReturn(activeResult(null));

        OAuth2AuthenticatedPrincipal principal = introspector.introspect(TOKEN);

        assertThat(principal.getName()).isEqualTo("user-1");
        verify(keycloakClient).introspect(TOKEN);
    }

    @Test
    void redisDown_onDenyListCheck_rejectsRatherThanAssumingNotRevoked() {
        when(cache.get(HASH)).thenReturn(Optional.of(activeResult("sid-1")));
        when(cache.isSessionRevoked("sid-1")).thenThrow(new QueryTimeoutException("Redis unreachable"));

        assertThatThrownBy(() -> introspector.introspect(TOKEN))
                .isInstanceOf(BadOpaqueTokenException.class);
    }

    @Test
    void keycloakUnavailable_propagatesAsARejection_notAnAcceptedToken() {
        when(cache.get(HASH)).thenReturn(Optional.empty());
        when(cache.tryAcquireLock(HASH)).thenReturn(Optional.of("lock-token"));
        when(keycloakClient.introspect(TOKEN)).thenThrow(new IntrospectionUnavailableException("circuit open", new RuntimeException()));

        assertThatThrownBy(() -> introspector.introspect(TOKEN))
                .isInstanceOf(IntrospectionUnavailableException.class);

        // Never cached, because we never actually confirmed a status.
        verify(cache, never()).putPositive(any(), any(), any());
        verify(cache, never()).putNegative(any());
    }
}
