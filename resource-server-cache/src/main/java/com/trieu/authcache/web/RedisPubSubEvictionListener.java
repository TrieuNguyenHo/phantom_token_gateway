package com.trieu.authcache.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.trieu.authcache.introspection.IntrospectionCacheService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.listener.adapter.MessageListenerAdapter;

import java.time.Duration;
import java.util.Map;

/**
 * Alternative transport for layer 2 (event-listener-driven eviction): instead of the Keycloak
 * SPI calling every service instance's HTTP endpoint directly (N calls, needs service
 * discovery), it publishes one message to a Redis Pub/Sub channel and every instance subscribed
 * here evicts its local knowledge in parallel. Same effect as
 * {@link KeycloakEventWebhookController}, different fan-out mechanism - worth mentioning as the
 * option that scales better with instance count, at the cost of Pub/Sub's at-most-once delivery
 * (a message is lost if a listener is down when it's published; the short TTL in layer 1 is the
 * safety net for that case).
 */
@Slf4j
@Configuration
public class RedisPubSubEvictionListener {

    public static final String CHANNEL = "auth-events";
    private static final Duration DENY_LIST_TTL = Duration.ofMinutes(5);

    @Bean
    public RedisMessageListenerContainer redisMessageListenerContainer(RedisConnectionFactory connectionFactory,
                                                                         IntrospectionCacheService cache,
                                                                         ObjectMapper objectMapper) {
        RedisMessageListenerContainer container = new RedisMessageListenerContainer();
        container.setConnectionFactory(connectionFactory);

        MessageListenerAdapter adapter = new MessageListenerAdapter();
        adapter.setDelegate(new EventDelegate(cache, objectMapper));
        adapter.setDefaultListenerMethod("onMessage");
        adapter.afterPropertiesSet();

        container.addMessageListener(adapter, new ChannelTopic(CHANNEL));
        return container;
    }

    /** Plain POJO delegate - keeps the message-parsing logic unit-testable without Redis wiring. */
    static class EventDelegate {
        private final IntrospectionCacheService cache;
        private final ObjectMapper objectMapper;

        EventDelegate(IntrospectionCacheService cache, ObjectMapper objectMapper) {
            this.cache = cache;
            this.objectMapper = objectMapper;
        }

        @SuppressWarnings("unused") // invoked reflectively by MessageListenerAdapter
        public void onMessage(String message) {
            try {
                Map<?, ?> event = objectMapper.readValue(message, Map.class);
                String type = String.valueOf(event.get("type"));
                String sid = (String) event.get("sid");
                if (sid != null && ("LOGOUT".equals(type) || "REVOKE_GRANT".equals(type))) {
                    cache.evictBySession(sid, DENY_LIST_TTL);
                    log.info("Evicted cache for sid={} via Pub/Sub event {}", sid, type);
                }
            } catch (Exception e) {
                log.warn("Failed to process auth-events Pub/Sub message: {}", message, e);
            }
        }
    }
}
