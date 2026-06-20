package com.watchtower.notification.kafka;

import com.watchtower.common.config.KafkaTopics;
import com.watchtower.common.event.SecurityAlert;
import com.watchtower.notification.service.NotificationRouter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Component
public class AlertConsumer {

    private static final Logger log = LoggerFactory.getLogger(AlertConsumer.class);
    private final NotificationRouter notificationRouter;

    public AlertConsumer(NotificationRouter notificationRouter) {
        this.notificationRouter = notificationRouter;
    }

    @KafkaListener(
            topics = KafkaTopics.SECURITY_ALERTS,
            groupId = KafkaTopics.NOTIFICATION_GROUP,
            properties = {
                "spring.json.trusted.packages=com.watchtower.*",
                "spring.json.value.default.type=com.watchtower.common.event.SecurityAlert"
            }
    )
    public void onAlert(SecurityAlert alert) {
        log.info("Received alert {} [{}] severity={}",
                alert.alertId(), alert.alertType(), alert.severity());
        notificationRouter.route(alert);
    }
}
