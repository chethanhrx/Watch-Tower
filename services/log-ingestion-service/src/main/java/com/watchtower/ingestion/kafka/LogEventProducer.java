package com.watchtower.ingestion.kafka;

import com.watchtower.common.config.KafkaTopics;
import com.watchtower.common.event.NormalizedLogEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Component;

import java.util.concurrent.CompletableFuture;

/**
 * Publishes normalized log events to the raw-logs Kafka topic.
 * Partition key: sourceIp for per-IP ordering.
 */
@Component
public class LogEventProducer {

    private static final Logger log = LoggerFactory.getLogger(LogEventProducer.class);
    private final KafkaTemplate<String, NormalizedLogEvent> kafkaTemplate;

    public LogEventProducer(KafkaTemplate<String, NormalizedLogEvent> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    public CompletableFuture<SendResult<String, NormalizedLogEvent>> publish(NormalizedLogEvent event) {
        return kafkaTemplate.send(KafkaTopics.RAW_LOGS, event.sourceIp(), event)
                .whenComplete((result, ex) -> {
                    if (ex != null) {
                        log.error("Failed to publish event {}: {}", event.eventId(), ex.getMessage());
                    } else {
                        log.debug("Published event {} to partition {} offset {}",
                                event.eventId(),
                                result.getRecordMetadata().partition(),
                                result.getRecordMetadata().offset());
                    }
                });
    }
}
