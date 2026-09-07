# Keycloak realm setup

One-time realm setup (admin console at http://localhost:8088, admin/admin). Verified
end-to-end against a real Keycloak 26.6 instance - every step below was exercised, not just
read from docs.

1. Realm `trieu_universal` (matches `KEYCLOAK_ISSUER_URI`'s default in every module's
   `application.yml` - change both together if you rename it).

2. Client `gateway` - confidential, service accounts ON. This is the ONLY client with
   introspection rights; copy its secret into `KEYCLOAK_CLIENT_SECRET` for the gateway.
   Client Advanced tab / Capability config:
   - **"Allow token introspection without audience check"**: ON, always. Without it Keycloak
     refuses to introspect ANY token that doesn't already carry "gateway" itself in its own
     `aud`, which in practice is every real end-user token. Applies to all 3 internal-token
     strategies below, not just EXCHANGE.
   - **"Always use lightweight access token"**: recommended ON (see CLAUDE.md "audience"
     discussion) - strips default claims from tokens minted for this client so a stolen one
     carries less. Affects step 4 below (lightweight tokens need an extra mapper flag).
   - **"Support JWT claim in Introspection Response"**: ON, only if using
     `phantom-token.internal-token=KEYCLOAK_JWT` (forwards the JWT Keycloak embeds in the
     introspection response's `jwt` field - `Accept` header must be exactly
     `application/jwt`, see `IntrospectionClient`). Skip and use `ORIGINAL` if the AS can't
     hand back a forwardable JWT.
   - **"Standard token exchange"**: ON, only if using `phantom-token.internal-token=EXCHANGE`.
   - **Direct Access Grants**: ON. There is no separate public client for logging in a test
     user - `gateway` is the only client, so a test user token is obtained directly from it
     via the password grant.

3. Per downstream service, only needed for EXCHANGE: client `resource-service` -
   confidential, no flows, no service account needed. Exists purely so Keycloak has
   something to resolve the token-exchange `audience` request parameter against; its
   clientId must equal the gateway route's `metadata.audience` and that service's
   `security.expected-audience`.

4. Per downstream service, only needed for EXCHANGE: client scope `aud-resource-service` -
   - Protocol mapper, type "Audience": Included Client Audience = `resource-service`,
     "Add to access token" ON. If `gateway` has lightweight access tokens ON (step 2), also
     flag "Add to lightweight access token" - otherwise the mapper silently produces no
     `aud` claim at all and the exchange fails with "Requested audience not available".
   - Assign this scope as a **DEFAULT** client scope on `gateway` (Client scopes tab).
     Standard token exchange's `audience` request parameter only *restricts* to audiences
     already available this way - it does not add new ones ("Audience not found" if the
     client doesn't exist at all, "Requested audience not available" if it exists but isn't
     reachable through a default/requested scope).

5. Only needed for `phantom-token.internal-token=ORIGINAL`: audience mapper on `gateway`
   adding `aud=resource-service`, so the token forwarded unchanged still passes the
   downstream service's audience check. Not needed for `KEYCLOAK_JWT` or `EXCHANGE` - both
   mint their own audience at the gateway instead.

6. Backchannel logout URL on `gateway`: `http://host.docker.internal:8080/backchannel-logout`

## Troubleshooting

### Re-adding the `aud-resource-service` Audience mapper after deleting it

Symptom: `aud` silently missing from new tokens even though the mapper looks configured
right.

1. Client scope `aud-resource-service` must exist (recreate it if you deleted the whole
   scope, not just the mapper) with a protocol mapper, type "Audience", Included Client
   Audience = `resource-service`, "Add to access token" ON.
2. If `gateway` has "Always use lightweight access token" ON (step 2), the mapper ALSO
   needs "Add to lightweight access token" ON - lightweight tokens drop default claims, so
   without this flag the mapper runs but `aud` never shows up, no error either.
3. The client scope itself must be (re-)assigned to `gateway` on its Client scopes tab
   (Default, or Optional + requested via `scope=`) - adding the mapper to a scope doesn't
   assign that scope to any client.
4. Fetch a brand-new token to verify - a token issued before the fix still has the old
   `aud`.
