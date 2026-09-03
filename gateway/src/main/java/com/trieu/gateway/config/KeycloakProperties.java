package com.trieu.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The gateway is a confidential client of Keycloak in its own right: RFC 7662 requires the
 * caller of the introspection endpoint to authenticate, and these are the gateway's own
 * credentials - never the end user's.
 */
@ConfigurationProperties(prefix = "keycloak")
public record KeycloakProperties(
        String issuerUri,
        String introspectionUri,
        String tokenUri,
        String jwksUri,
        String clientId,
        String clientSecret
) {
}
