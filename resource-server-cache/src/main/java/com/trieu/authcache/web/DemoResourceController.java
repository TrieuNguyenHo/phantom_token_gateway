package com.trieu.authcache.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * A stand-in for "any protected endpoint in the service" - it doesn't do anything interesting
 * itself, it just demonstrates that {@link com.trieu.authcache.introspection.RedisCachedOpaqueTokenIntrospector}
 * is transparently wired in: every call here goes cache-first before it reaches this handler.
 */
@RestController
public class DemoResourceController {

    @GetMapping("/api/whoami")
    public Map<String, Object> whoami(@AuthenticationPrincipal OAuth2IntrospectionAuthenticatedPrincipal principal) {
        return Map.of(
                "sub", principal.getName(),
                "scope", principal.getAttribute("scope"),
                "clientId", principal.getAttribute("client_id")
        );
    }
}
