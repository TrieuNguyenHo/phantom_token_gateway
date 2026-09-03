package com.trieu.authcache.config;

/**
 * Coordinates for the Keycloak realm this service validates tokens against.
 * introspectionUri points at {@code /realms/{realm}/protocol/openid-connect/token/introspect}.
 * clientId/clientSecret are this *resource server's* confidential-client credentials, used to
 * authenticate the introspection call itself (RFC 7662 requires the caller to authenticate).
 */
@org.springframework.boot.context.properties.ConfigurationProperties(prefix = "keycloak")
public record KeycloakProperties(
        String issuerUri,
        String introspectionUri,
        String jwksUri,
        String clientId,
        String clientSecret
) {
}
