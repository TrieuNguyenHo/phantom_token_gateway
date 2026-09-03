# CLAUDE.md

Context for Claude Code working in this repo. Keep this file short — it is loaded every session.

## What this repo is

A lab comparing **two ways to make Keycloak token validation fast**, kept side by side on
purpose. It is interview-prep material for "câu 02" (token introspection latency ~200ms → <5ms),
not a production system.

- **Approach A — `resource-server-cache/`**: every resource server introspects for itself and
  caches the result in Redis. This is what was actually built at work and what the CV number
  refers to.
- **Approach B — `gateway/` + `resource-service/`**: phantom token. The gateway is the only
  component that talks to Keycloak; it introspects once, caches, swaps the `Authorization`
  header for a JWT, and forwards. Downstream validates offline via JWKS.

Both must keep working. **Do not delete approach A** — the comparison is the point.

## Commands

```bash
mvn -q clean test              # all modules
mvn -q -pl gateway test        # one module
mvn -pl gateway spring-boot:run
docker compose up -d           # Redis + Keycloak 26.7 (realm setup notes in docker-compose.yml)
```

Ports: gateway 8080 · Keycloak 8081 · resource-service 8082 · resource-server-cache 8083.

## Module map

| Path | Role |
|---|---|
| `gateway/…/filter/PhantomTokenFilter` | The whole flow: cache → deny-list → single-flight → introspect → header swap → forward |
| `gateway/…/introspection/IntrospectionResponseParser` | Parses the 3 introspection response shapes; decides whether we hold a forwardable JWT |
| `gateway/…/introspection/PhantomTokenCache` | Reactive Redis: TTL rules, session index, deny-list, lock |
| `gateway/…/introspection/IntrospectionClient` | The only caller of Keycloak `/introspect`; circuit breaker + rate limiter |
| `gateway/…/exchange/TokenExchangeClient` | RFC 8693 - mints a per-route-audience token (`internal-token=EXCHANGE`); same breaker/limiter pattern as `IntrospectionClient` |
| `gateway/…/logout/BackchannelLogoutController` | OIDC backchannel logout → evict (one place for the whole system) |
| `resource-service/…/config/SecurityConfig` | JWKS validation + **audience check** |
| `resource-server-cache/…/RedisCachedOpaqueTokenIntrospector` | Approach A equivalent of the filter |

## Invariants — do not break these

1. **Never store or log a raw token.** Cache keys are `sha256(token)`; log the hash or the `sid`.
2. **Positive TTL = `min(remaining token lifetime, cap)`**, cap default 30s. Negative TTL is
   short (2–5s) and jittered, so a user who just re-authenticated is not stuck behind a 401.
3. **Fail closed on security, open on availability.** Redis down → bypass cache and call
   Keycloak (behind breaker + limiter). Cannot confirm a token → reject. There is no
   "let it through" path, ever. `isSessionRevoked` returns `true` when Redis is unreachable.
4. **Never scan the keyspace.** Evict by session index (`SMEMBERS` + `DEL`), never `KEYS`/`SCAN`.
5. **Deny-list is checked on every request**, cache hit included.
6. **Downstream services must not gain a Keycloak dependency.** No Redis, no client secret, no
   introspection call in `resource-service/` — that is the entire point of approach B.
7. `X-Auth-*` headers are observability only; authorization always comes from the JWT. They are
   `set()` (overwriting caller-supplied values), never `add()`.

## Config knobs

- `phantom-token.internal-token`: `KEYCLOAK_JWT` (forward the JWT Keycloak returns for
  `Accept: application/jwt`), `ORIGINAL` (forward the incoming token unchanged), or `EXCHANGE`
  (RFC 8693 token exchange - mint a token audienced to the matched route's `metadata.audience`;
  needs "Standard token exchange" enabled on the gateway's Keycloak client, the target service
  registered as its own client, and an Audience-mapper client scope for it assigned as a
  *default* scope on the gateway client - see `docker-compose.yml` steps 2-4). Verified
  end-to-end against a real Keycloak 26.6 instance.
- The gateway's Keycloak client also needs **"Allow token introspection without audience
  check"** (client Advanced tab). Without it Keycloak's introspection endpoint rejects any token
  that doesn't already carry "gateway" in its own `aud` - which in practice is every real
  end-user token, since only downstream-service audiences get mapped, not the gateway itself.
  This applies to all three `internal-token` strategies, not just `EXCHANGE`.
- A strict RFC 9701 response is **audienced to the gateway** — it is data, not a credential, and
  must not be forwarded. The parser deliberately leaves `forwardableJwt` null in that case.

## Known gaps / backlog

1. **Integration tests with Testcontainers** — real Redis + Keycloak; current tests are unit
   level with mocks so they run without Docker. `TokenExchangeClient` and the `EXCHANGE` path
   have no *automated* coverage yet - only a one-off manual run against a real Keycloak 26.6.
2. **JWKS rotation test** in `resource-service`.
3. **Metrics** — cache hit ratio, introspection latency, breaker state (Micrometer).
4. The Keycloak **Event Listener SPI provider** itself (the jar that runs inside Keycloak) is
   not in this repo; only the consumer webhook is.

Token exchange (RFC 8693) is done: `gateway/…/exchange/TokenExchangeClient` +
`internal-token=EXCHANGE`, wired through `PhantomTokenFilter` and cached per (token, audience) in
`PhantomTokenCache` (evicted alongside the session on logout, same as the introspection cache).

## Conventions

- Java 21, Spring Boot 3.3, Spring Cloud 2023.0.x. Gateway is **reactive** (WebFlux) — never add
  `spring-boot-starter-web` to it. `resource-server-cache` and `resource-service` are servlet.
- Comments explain *why* (the security or latency reason), not what the code does.
- Tests are unit level and must run without Docker or network.
