package com.watchtower.ingestion.service;

import com.watchtower.common.event.NormalizedLogEvent;
import com.watchtower.ingestion.kafka.LogEventProducer;
import com.watchtower.ingestion.parser.LogParserFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;

/**
 * Core ingestion orchestrator — parses raw logs, publishes to Kafka,
 * and indexes to Elasticsearch.
 */
@Service
public class LogIngestionService {

    private static final Logger log = LoggerFactory.getLogger(LogIngestionService.class);

    private final LogParserFactory parserFactory;
    private final LogEventProducer kafkaProducer;
    private final ElasticsearchIndexService esIndexService;

    public LogIngestionService(LogParserFactory parserFactory,
                                LogEventProducer kafkaProducer,
                                ElasticsearchIndexService esIndexService) {
        this.parserFactory = parserFactory;
        this.kafkaProducer = kafkaProducer;
        this.esIndexService = esIndexService;
    }

    /**
     * Ingest a single raw log line.
     */
    public NormalizedLogEvent ingest(String rawLine, String format) {
        NormalizedLogEvent event;
        if (format != null && !format.isBlank()) {
            event = parserFactory.parse(rawLine, format);
        } else {
            event = parserFactory.autoDetectAndParse(rawLine);
        }

        if (event == null) {
            log.warn("Could not parse log line: {}", rawLine.substring(0, Math.min(80, rawLine.length())));
            return null;
        }

        // Publish to Kafka (async)
        kafkaProducer.publish(event);

        // Index to Elasticsearch (async)
        esIndexService.indexAsync(event);

        return event;
    }

    /**
     * Ingest a batch of raw log lines.
     */
    public List<NormalizedLogEvent> ingestBatch(List<String> rawLines, String format) {
        return rawLines.stream()
                .map(line -> ingest(line, format))
                .filter(Objects::nonNull)
                .toList();
    }
}
