package com.trieu.authcache.web;

import com.trieu.authcache.introspection.IntrospectionCacheService;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class KeycloakEventWebhookControllerTest {

    private final IntrospectionCacheService cache = mock(IntrospectionCacheService.class);
    private final KeycloakEventWebhookController controller = new KeycloakEventWebhookController(cache);

    @Test
    void wrongSharedSecret_isRejectedBeforeTouchingTheCache() {
        var response = controller.onKeycloakEvent("wrong-secret",
                new KeycloakEventWebhookController.KeycloakEvent("LOGOUT", "sid-1", "user-1"));

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        verifyNoInteractions(cache);
    }

    @Test
    void logoutEvent_evictsTheSession() {
        ResponseEntity<Void> response = controller.onKeycloakEvent("dev-shared-secret",
                new KeycloakEventWebhookController.KeycloakEvent("LOGOUT", "sid-1", "user-1"));

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        verify(cache).evictBySession(eq("sid-1"), any(Duration.class));
    }

    @Test
    void revokeGrantEvent_alsoEvictsTheSession() {
        controller.onKeycloakEvent("dev-shared-secret",
                new KeycloakEventWebhookController.KeycloakEvent("REVOKE_GRANT", "sid-2", "user-2"));

        verify(cache).evictBySession(eq("sid-2"), any(Duration.class));
    }

    @Test
    void unrelatedEventType_isAcknowledgedWithoutTouchingTheCache() {
        ResponseEntity<Void> response = controller.onKeycloakEvent("dev-shared-secret",
                new KeycloakEventWebhookController.KeycloakEvent("LOGIN", null, "user-1"));

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        verifyNoInteractions(cache);
    }

    @Test
    void logoutEventWithoutSid_isRejected() {
        ResponseEntity<Void> response = controller.onKeycloakEvent("dev-shared-secret",
                new KeycloakEventWebhookController.KeycloakEvent("LOGOUT", null, "user-1"));

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        verifyNoInteractions(cache);
    }
}
