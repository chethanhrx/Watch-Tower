package com.watchtower.ingestion.controller;

import com.watchtower.common.event.NormalizedLogEvent;
import com.watchtower.ingestion.service.LogIngestionService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * REST API for log ingestion — accepts logs from Filebeat, Logstash, or any HTTP client.
 */
@RestController
@RequestMapping("/api/v1/logs")
public class LogIngestionController {

    private final LogIngestionService ingestionService;

    public LogIngestionController(LogIngestionService ingestionService) {
        this.ingestionService = ingestionService;
    }

    /**
     * Ingest a single log line.
     */
    @PostMapping("/ingest")
    public ResponseEntity<Map<String, Object>> ingest(@RequestBody IngestRequest request) {
        NormalizedLogEvent event = ingestionService.ingest(request.rawLog(), request.format());
        if (event == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "error", "message", "Could not parse log line"));
        }
        return ResponseEntity.ok(Map.of(
                "status", "accepted", "eventId", event.eventId(), "eventType", event.eventType()));
    }

    /**
     * Ingest a batch of log lines.
     */
    @PostMapping("/ingest/batch")
    public ResponseEntity<Map<String, Object>> ingestBatch(@RequestBody BatchIngestRequest request) {
        List<NormalizedLogEvent> events = ingestionService.ingestBatch(
                request.rawLogs(), request.format());
        return ResponseEntity.ok(Map.of(
                "status", "accepted",
                "total", request.rawLogs().size(),
                "parsed", events.size(),
                "failed", request.rawLogs().size() - events.size()));
    }

    public record IngestRequest(String rawLog, String format) {}
    public record BatchIngestRequest(List<String> rawLogs, String format) {}
}
