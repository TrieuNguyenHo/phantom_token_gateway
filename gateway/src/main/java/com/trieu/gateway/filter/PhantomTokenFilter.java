package com.trieu.gateway.filter;

import com.trieu.gateway.config.PhantomTokenProperties;
import com.trieu.gateway.exchange.TokenExchangeClient;
import com.trieu.gateway.exchange.TokenExchangeUnavailableException;
import com.trieu.gateway.introspection.IntrospectionClient;
import com.trieu.gateway.introspection.IntrospectionResult;
import com.trieu.gateway.introspection.IntrospectionUnavailableException;
import com.trieu.gateway.introspection.PhantomTokenCache;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * The whole phantom-token flow, in one filter that every routed request passes through:
 *
 * <pre>
 *   Bearer &lt;AT&gt; → cache hit? → deny-list? → swap Authorization header → forward
 *                     ↓ miss
 *                 single-flight lock → introspect once → cache
 * </pre>
 *
 * Two properties matter more than the code: downstream services never see the incoming token
 * and never talk to Keycloak, and nothing here has a path that forwards a request whose token
 * could not be confirmed.
 */
@Slf4j
@Component
public class PhantomTokenFilter implements GlobalFilter, Ordered {

    private static final String BEARER = "Bearer ";
    private static final Duration LOCK_WAIT = Duration.ofMillis(120);

    /** Endpoints served by the gateway itself, not proxied, and not user-authenticated. */
    private static final List<String> PUBLIC_PATHS = List.of(
            "/actuator/health", "/backchannel-logout", "/internal/keycloak-events");

    private final PhantomTokenCache cache;
    private final IntrospectionClient client;
    private final TokenExchangeClient exchangeClient;
    private final PhantomTokenProperties props;

    public PhantomTokenFilter(PhantomTokenCache cache, IntrospectionClient client,
                               TokenExchangeClient exchangeClient, PhantomTokenProperties props) {
        this.cache = cache;
        this.client = client;
        this.exchangeClient = exchangeClient;
        this.props = props;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        if (PUBLIC_PATHS.stream().anyMatch(path::startsWith)) {
            return chain.filter(exchange);
        }

        String token = bearerToken(exchange);
        if (token == null) {
            return reject(exchange, HttpStatus.UNAUTHORIZED, "missing bearer token");
        }

        String hash = cache.hash(token);
        return resolve(hash, token)
                .flatMap(result -> {
                    if (!result.active()) {
                        return reject(exchange, HttpStatus.UNAUTHORIZED, "token is not active");
                    }
                    return cache.isSessionRevoked(result.sid())
                            .flatMap(revoked -> revoked
                                    ? reject(exchange, HttpStatus.UNAUTHORIZED, "session revoked")
                                    : forward(exchange, chain, hash, token, result));
                })
                .onErrorResume(IntrospectionUnavailableException.class,
                        e -> reject(exchange, HttpStatus.SERVICE_UNAVAILABLE, "cannot verify token right now"))
                .onErrorResume(TokenExchangeUnavailableException.class,
                        e -> reject(exchange, HttpStatus.SERVICE_UNAVAILABLE, "cannot mint downstream token right now"));
    }

    // ------------------------------------------------------------ resolve

    private Mono<IntrospectionResult> resolve(String hash, String token) {
        return cache.get(hash)
                .switchIfEmpty(Mono.defer(() -> fetchWithSingleFlight(hash, token)));
    }

    /**
     * Only the request that wins the lock calls Keycloak. The rest wait a beat, re-read the
     * cache, and only introspect themselves if the winner is still not done - best-effort
     * coalescing, which is what keeps a cold cache from turning into a stampede.
     */
    private Mono<IntrospectionResult> fetchWithSingleFlight(String hash, String token) {
        return cache.tryAcquireLock(hash)
                .flatMap(lockToken -> callAndCache(hash, token)
                        .flatMap(result -> cache.releaseLock(hash, lockToken).thenReturn(result))
                        .onErrorResume(e -> cache.releaseLock(hash, lockToken).then(Mono.error(e))))
                .switchIfEmpty(Mono.defer(() -> Mono.delay(LOCK_WAIT)
                        .then(cache.get(hash))
                        .switchIfEmpty(Mono.defer(() -> callAndCache(hash, token)))));
    }

    private Mono<IntrospectionResult> callAndCache(String hash, String token) {
        return client.introspect(token)
                .flatMap(result -> (result.active()
                        ? cache.putPositive(hash, result, Instant.now())
                        : cache.putNegative(hash))
                        .thenReturn(result));
    }

    // ------------------------------------------------------------ forward

    private Mono<Void> forward(ServerWebExchange exchange, GatewayFilterChain chain,
                                String hash, String originalToken, IntrospectionResult result) {
        Mono<String> internalToken = switch (props.internalToken()) {
            case KEYCLOAK_JWT -> keycloakJwt(result);
            case ORIGINAL -> Mono.just(originalToken);
            case EXCHANGE -> exchangedToken(exchange, hash, originalToken, result);
        };

        return internalToken
                // Whatever strategy is configured, coming up empty means downstream would get
                // a request with no usable Authorization header - reject rather than forward
                // something it cannot validate. Each branch above logs its own specific reason.
                .switchIfEmpty(Mono.defer(() ->
                        reject(exchange, HttpStatus.INTERNAL_SERVER_ERROR, "gateway token exchange misconfigured")
                                .then(Mono.<String>empty())))
                .flatMap(resolved -> {
                    ServerHttpRequest mutated = exchange.getRequest().mutate()
                            .headers(headers -> {
                                headers.set(HttpHeaders.AUTHORIZATION, BEARER + resolved);
                                // set(), never add(): this overwrites anything the caller tried to inject.
                                // These are for logs and tracing only - downstream authorizes on the JWT.
                                headers.set("X-Auth-Sub", result.sub() == null ? "" : result.sub());
                                headers.set("X-Auth-Sid", result.sid() == null ? "" : result.sid());
                            })
                            .build();
                    return chain.filter(exchange.mutate().request(mutated).build());
                });
    }

    private Mono<String> keycloakJwt(IntrospectionResult result) {
        if (result.forwardableJwt() == null) {
            // Configured for KEYCLOAK_JWT but the AS did not return a forwardable JWT - almost
            // always the client attribute for application/jwt introspection is off. Fail loudly
            // rather than quietly forwarding something downstream cannot validate.
            log.error("internal-token=KEYCLOAK_JWT but introspection returned no jwt claim. "
                    + "Enable the JWT introspection response on the gateway's Keycloak client, "
                    + "or set phantom-token.internal-token=ORIGINAL.");
        }
        return Mono.justOrEmpty(result.forwardableJwt());
    }

    /**
     * RFC 8693: mint (or reuse a cached) token audienced to whichever route matched this
     * request, so a token good at one downstream service is not automatically good at another.
     */
    private Mono<String> exchangedToken(ServerWebExchange exchange, String hash, String originalToken,
                                         IntrospectionResult result) {
        String audience = routeAudience(exchange);
        if (audience == null) {
            log.error("internal-token=EXCHANGE but route for {} has no 'audience' metadata configured.",
                    exchange.getRequest().getPath());
            return Mono.empty();
        }
        return cache.getExchanged(hash, audience)
                .switchIfEmpty(Mono.defer(() -> exchangeClient.exchange(originalToken, audience)
                        .flatMap(exchanged -> cache.putExchanged(
                                        hash, audience, exchanged.accessToken(), exchanged.expiresInSeconds(), result.sid())
                                .thenReturn(exchanged.accessToken()))));
    }

    private String routeAudience(ServerWebExchange exchange) {
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        Object audience = route == null ? null : route.getMetadata().get("audience");
        return audience == null ? null : audience.toString();
    }

    // ------------------------------------------------------------- helpers

    private String bearerToken(ServerWebExchange exchange) {
        String header = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith(BEARER)) {
            return null;
        }
        String value = header.substring(BEARER.length()).trim();
        return value.isEmpty() ? null : value;
    }

    private Mono<Void> reject(ServerWebExchange exchange, HttpStatus status, String reason) {
        log.debug("Rejecting {} {}: {}", exchange.getRequest().getMethod(),
                exchange.getRequest().getPath(), reason);
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().set(HttpHeaders.WWW_AUTHENTICATE,
                "Bearer error=\"invalid_token\"");
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        // Before routing, so the swapped Authorization header is what actually goes on the wire.
        return Ordered.HIGHEST_PRECEDENCE + 1;
    }
}
