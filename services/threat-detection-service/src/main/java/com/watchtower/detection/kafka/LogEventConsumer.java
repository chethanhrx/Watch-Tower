package com.watchtower.detection.kafka;

import com.watchtower.common.config.KafkaTopics;
import com.watchtower.common.event.NormalizedLogEvent;
import com.watchtower.common.event.SecurityAlert;
import com.watchtower.detection.engine.AnomalyDetector;
import com.watchtower.detection.engine.RuleEngine;
import com.watchtower.detection.service.RedisDeduplicationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Consumes normalized log events from Kafka, runs them through the
 * rule engine and anomaly detectors, and publishes alerts.
 */
@Component
public class LogEventConsumer {

    private static final Logger log = LoggerFactory.getLogger(LogEventConsumer.class);

    private final RuleEngine ruleEngine;
    private final List<AnomalyDetector> anomalyDetectors;
    private final RedisDeduplicationService deduplication;
    private final AlertProducer alertProducer;

    public LogEventConsumer(RuleEngine ruleEngine,
                            List<AnomalyDetector> anomalyDetectors,
                            RedisDeduplicationService deduplication,
                            AlertProducer alertProducer) {
        this.ruleEngine = ruleEngine;
        this.anomalyDetectors = anomalyDetectors;
        this.deduplication = deduplication;
        this.alertProducer = alertProducer;
    }

    @KafkaListener(
            topics = KafkaTopics.RAW_LOGS,
            groupId = KafkaTopics.THREAT_DETECTION_GROUP,
            containerFactory = "logEventListenerFactory"
    )
    public void onLogEvent(NormalizedLogEvent event) {
        log.debug("Processing event {} [{}] from {}", event.eventId(),
                event.eventType(), event.sourceIp());

        // 1. Rule-based detection
        List<SecurityAlert> ruleAlerts = ruleEngine.evaluate(event);
        ruleAlerts.forEach(this::publishIfNotDuplicate);

        // 2. Anomaly detection (statistical + ML)
        for (AnomalyDetector detector : anomalyDetectors) {
            detector.analyze(event).ifPresent(this::publishIfNotDuplicate);
        }
    }

    private void publishIfNotDuplicate(SecurityAlert alert) {
        if (deduplication.tryAcquire(alert.alertType().name(), alert.sourceIp())) {
            alertProducer.publish(alert);
        }
    }
}
