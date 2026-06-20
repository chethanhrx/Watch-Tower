package com.watchtower.detection.kafka;

import com.watchtower.common.config.KafkaTopics;
import com.watchtower.common.event.SecurityAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

/**
 * Publishes security alerts to the security-alerts Kafka topic.
 * Key: alertType + severity for partition grouping.
 */
@Component
public class AlertProducer {

    private static final Logger log = LoggerFactory.getLogger(AlertProducer.class);
    private final KafkaTemplate<String, SecurityAlert> kafkaTemplate;

    public AlertProducer(KafkaTemplate<String, SecurityAlert> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    public void publish(SecurityAlert alert) {
        String key = alert.alertType().name() + ":" + alert.severity().name();
        kafkaTemplate.send(KafkaTopics.SECURITY_ALERTS, key, alert)
                .whenComplete((result, ex) -> {
                    if (ex != null) {
                        log.error("Failed to publish alert {}: {}", alert.alertId(), ex.getMessage());
                    } else {
                        log.info("Published alert {} [{}] severity={} from {}",
                                alert.alertId(), alert.alertType(),
                                alert.severity(), alert.sourceIp());
                    }
                });
    }
}
