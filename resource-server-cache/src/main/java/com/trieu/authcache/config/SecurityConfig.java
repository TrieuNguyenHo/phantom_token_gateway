package com.trieu.authcache.config;

import com.trieu.authcache.introspection.IntrospectionCacheService;
import com.trieu.authcache.introspection.KeycloakIntrospectionClient;
import com.trieu.authcache.introspection.RedisCachedOpaqueTokenIntrospector;
import com.trieu.authcache.introspection.TokenHasher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    /**
     * This single bean is the entire integration point: Spring Security's OAuth2 resource
     * server support calls {@link OpaqueTokenIntrospector#introspect(String)} on every
     * bearer-token request. Swapping the framework default for
     * {@link RedisCachedOpaqueTokenIntrospector} is the only wiring change needed to get the
     * cache in front of every protected endpoint in the service.
     */
    @Bean
    public OpaqueTokenIntrospector opaqueTokenIntrospector(TokenHasher hasher,
                                                             IntrospectionCacheService cache,
                                                             KeycloakIntrospectionClient keycloakClient) {
        return new RedisCachedOpaqueTokenIntrospector(hasher, cache, keycloakClient);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, OpaqueTokenIntrospector introspector) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // stateless resource server, bearer tokens only
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health/**", "/backchannel-logout", "/internal/keycloak-events").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer((OAuth2ResourceServerConfigurer<HttpSecurity> oauth2) ->
                        oauth2.opaqueToken(opaque -> opaque.introspector(introspector)));
        return http.build();
    }
}
