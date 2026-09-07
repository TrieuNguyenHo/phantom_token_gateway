package com.trieu.authcache.logout;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.trieu.authcache.config.KeycloakProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Our resource server validates access tokens by introspection (opaque tokens - see
 * {@link com.trieu.authcache.introspection.RedisCachedOpaqueTokenIntrospector}), not by
 * decoding a JWT locally. But the OIDC Back-Channel Logout spec's "logout_token" is *always* a
 * signed JWT, independent of the access-token format the resource server uses - so we need a
 * small, separate JWT decoder just to verify it against Keycloak's JWKS.
 */
@Configuration
public class LogoutTokenVerifier {

    @Bean
    public JwtDecoder logoutTokenDecoder(KeycloakProperties props) {
        return NimbusJwtDecoder.withJwkSetUri(props.jwksUri())
                // Keycloak's logout_token carries typ=logout+jwt, not JWT. Nimbus's default
                // type verifier only accepts "JWT" (or no typ), so without this every real
                // logout_token fails with BadJwtException: Failed to validate the token.
                .jwtProcessorCustomizer(processor -> processor.setJWSTypeVerifier(
                        new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("logout+jwt"))))
                .build();
    }
}
