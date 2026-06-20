package com.watchtower.dashboard.kafka;

import com.watchtower.common.config.KafkaTopics;
import com.watchtower.common.event.SecurityAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Consumes security alerts from Kafka and pushes them to
 * WebSocket-connected clients in real time.
 */
@Component
public class AlertStreamConsumer {

    private static final Logger log = LoggerFactory.getLogger(AlertStreamConsumer.class);
    private final SimpMessagingTemplate messagingTemplate;

    // In-memory recent alerts buffer for new client connections
    private final CopyOnWriteArrayList<SecurityAlert> recentAlerts = new CopyOnWriteArrayList<>();
    private static final int MAX_RECENT = 100;

    public AlertStreamConsumer(SimpMessagingTemplate messagingTemplate) {
        this.messagingTemplate = messagingTemplate;
    }

    @KafkaListener(
            topics = KafkaTopics.SECURITY_ALERTS,
            groupId = KafkaTopics.DASHBOARD_GROUP,
            properties = {
                "spring.json.trusted.packages=com.watchtower.*",
                "spring.json.value.default.type=com.watchtower.common.event.SecurityAlert"
            }
    )
    public void onAlert(SecurityAlert alert) {
        log.info("Broadcasting alert {} to WebSocket clients", alert.alertId());

        // Buffer for late-joining clients
        recentAlerts.addFirst(alert);
        if (recentAlerts.size() > MAX_RECENT) {
            recentAlerts.removeLast();
        }

        // Push to all subscribers on /topic/alerts
        messagingTemplate.convertAndSend("/topic/alerts", alert);
    }

    public CopyOnWriteArrayList<SecurityAlert> getRecentAlerts() {
        return recentAlerts;
    }
}
