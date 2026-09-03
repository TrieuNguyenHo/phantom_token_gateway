package com.trieu.authcache.introspection;

import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Drop-in replacement for Spring Security's default {@code NimbusOpaqueTokenIntrospector} that
 * fronts every introspection call with the Redis cache. This class is where the whole "câu 02"
 * answer lives end to end:
 *
 * <pre>
 *   revoked deny-list check -&gt; cache hit? -&gt; miss -&gt; single-flight lock -&gt; Keycloak call
 *                                                                          -&gt; cache the result
 * </pre>
 *
 * and, orthogonally, "Redis itself is down" is handled by falling back to calling Keycloak
 * directly (still behind the circuit breaker / rate limiter in
 * {@link KeycloakIntrospectionClient}) rather than either hanging or - worse - treating an
 * unverifiable token as valid.
 */
@Slf4j
public class RedisCachedOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private final TokenHasher hasher;
    private final IntrospectionCacheService cache;
    private final KeycloakIntrospectionClient keycloakClient;

    public RedisCachedOpaqueTokenIntrospector(TokenHasher hasher,
                                               IntrospectionCacheService cache,
                                               KeycloakIntrospectionClient keycloakClient) {
        this.hasher = hasher;
        this.cache = cache;
        this.keycloakClient = keycloakClient;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        String hash = hasher.sha256(token);
        IntrospectionResult result = resolve(hash, token);
        return toPrincipal(result);
    }

    private IntrospectionResult resolve(String hash, String token) {
        try {
            return resolveViaCache(hash, token);
        } catch (DataAccessException redisDown) {
            // Redis unreachable: fail-open on *availability*, fail-closed on *security*.
            // We skip the cache entirely and go straight to Keycloak (still rate-limited /
            // circuit-broken) instead of either hanging or - the one thing we must never do -
            // treating "we couldn't check" as "it's valid".
            log.warn("Redis unavailable, bypassing introspection cache for this request", redisDown);
            return fetchFresh(token, null);
        }
    }

    private IntrospectionResult resolveViaCache(String hash, String token) {
        Optional<IntrospectionResult> cached = cache.get(hash);
        if (cached.isPresent()) {
            return cached.get();
        }
        return fetchWithSingleFlight(hash, token);
    }

    /**
     * Cache miss path. Only one caller per token-hash actually calls Keycloak at a time;
     * everyone else either observes the winner's cached result or, if it takes too long,
     * proceeds independently rather than blocking forever. This is what keeps a Keycloak
     * restart (cache goes cold, thousands of requests miss simultaneously) from turning into
     * a thundering herd against Keycloak.
     */
    private IntrospectionResult fetchWithSingleFlight(String hash, String token) {
        Optional<String> lockToken = cache.tryAcquireLock(hash);
        if (lockToken.isPresent()) {
            try {
                return fetchFresh(token, hash);
            } finally {
                cache.releaseLock(hash, lockToken.get());
            }
        }

        // Someone else is already fetching this token - wait briefly for their result instead
        // of piling another concurrent request onto Keycloak.
        long deadline = System.nanoTime() + cache.lockWaitTimeout().toNanos();
        while (System.nanoTime() < deadline) {
            Optional<IntrospectionResult> result = cache.get(hash);
            if (result.isPresent()) {
                return result.get();
            }
            sleep(cache.lockPollInterval());
        }
        // Gave up waiting - fetch it ourselves rather than block indefinitely. Best-effort
        // coalescing, not a strict guarantee; that tradeoff is intentional for a hot auth path.
        return fetchFresh(token, hash);
    }

    private IntrospectionResult fetchFresh(String token, String hashOrNull) {
        IntrospectionResult result = keycloakClient.introspect(token);
        String hash = hashOrNull != null ? hashOrNull : hasher.sha256(token);
        try {
            if (result.active()) {
                cache.putPositive(hash, result, Instant.now());
            } else {
                cache.putNegative(hash);
            }
        } catch (DataAccessException redisDown) {
            // We already have the answer for *this* request; failing to cache it just means
            // the next request pays the full Keycloak round trip too. Never fail the request
            // over a caching side-effect.
            log.warn("Fetched introspection result but could not cache it (Redis unavailable)", redisDown);
        }
        return result;
    }

    private OAuth2AuthenticatedPrincipal toPrincipal(IntrospectionResult result) {
        if (!result.active()) {
            throw new BadOpaqueTokenException("Token is not active");
        }
        // Layer 4 (deny-list) is checked on every request, cache hit or not - this is what
        // makes revocation apply even to a result we just cached seconds ago on another node.
        if (result.hasSession() && isRevokedSafely(result.sid())) {
            throw new BadOpaqueTokenException("Session has been revoked");
        }

        Map<String, Object> attributes = Map.of(
                "sub", result.sub() == null ? "" : result.sub(),
                "client_id", result.clientId() == null ? "" : result.clientId(),
                "scope", String.join(" ", result.scope()),
                "active", true
        );
        Set<GrantedAuthority> authorities = result.scope().stream()
                .<GrantedAuthority>map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                .collect(Collectors.toSet());
        return new OAuth2IntrospectionAuthenticatedPrincipal(result.sub(), attributes, authorities);
    }

    private boolean isRevokedSafely(String sid) {
        try {
            return cache.isSessionRevoked(sid);
        } catch (DataAccessException redisDown) {
            // Can't confirm the deny-list either - same fail-closed principle as everywhere
            // else in this class: an unverifiable revocation status must not be treated as
            // "not revoked". BadOpaqueTokenException is what OpaqueTokenAuthenticationProvider
            // explicitly catches and turns into a clean 401 with a WWW-Authenticate header,
            // which is why every rejection path in this class uses it rather than a generic
            // AuthenticationException.
            log.warn("Redis unavailable, cannot check revocation deny-list for sid={}", sid, redisDown);
            throw new BadOpaqueTokenException("Authorization service temporarily unavailable");
        }
    }

    private static void sleep(Duration duration) {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
