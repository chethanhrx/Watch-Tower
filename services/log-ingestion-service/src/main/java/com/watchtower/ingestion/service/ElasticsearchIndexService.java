package com.watchtower.ingestion.service;

import com.watchtower.common.event.NormalizedLogEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.data.elasticsearch.core.mapping.IndexCoordinates;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

/**
 * Indexes normalized log events into Elasticsearch for forensic search.
 * Uses daily indices (watchtower-logs-YYYY-MM-DD) for efficient retention management.
 */
@Service
public class ElasticsearchIndexService {

    private static final Logger log = LoggerFactory.getLogger(ElasticsearchIndexService.class);
    private static final String INDEX_PREFIX = "watchtower-logs-";

    private final ElasticsearchOperations esOperations;

    public ElasticsearchIndexService(ElasticsearchOperations esOperations) {
        this.esOperations = esOperations;
    }

    @Async
    public void indexAsync(NormalizedLogEvent event) {
        try {
            String indexName = INDEX_PREFIX + LocalDate.now().format(DateTimeFormatter.ISO_LOCAL_DATE);
            esOperations.save(event, IndexCoordinates.of(indexName));
            log.debug("Indexed event {} to {}", event.eventId(), indexName);
        } catch (Exception e) {
            log.error("Failed to index event {}: {}", event.eventId(), e.getMessage());
        }
    }
}
