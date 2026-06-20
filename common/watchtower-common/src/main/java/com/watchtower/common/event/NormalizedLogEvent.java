package com.watchtower.common.event;

import com.watchtower.common.enums.EventType;
import com.watchtower.common.enums.Severity;

import java.time.Instant;
import java.util.Map;

/**
 * Normalized log event — the canonical format produced by the log ingestion service
 * and consumed by the threat detection engine.
 *
 * <p>All raw log formats (syslog, auth.log, nginx, Windows Event Log) are parsed
 * and normalized into this schema before being published to the {@code raw-logs}
 * Kafka topic.</p>
 *
 * @param eventId    Unique identifier (UUID v7 for time-ordered IDs)
 * @param timestamp  When the original event occurred
 * @param sourceIp   IP address of the event origin
 * @param sourceHost Hostname of the event origin
 * @param eventType  Normalized event category
 * @param severity   Assessed severity level
 * @param rawMessage The original unparsed log line
 * @param metadata   Flexible key-value pairs for format-specific fields
 *                   (e.g., user_agent, http_method, port, username)
 */
public record NormalizedLogEvent(
        String eventId,
        Instant timestamp,
        String sourceIp,
        String sourceHost,
        EventType eventType,
        Severity severity,
        String rawMessage,
        Map<String, String> metadata
) {
    /**
     * Returns the value of a metadata field, or a default if not present.
     */
    public String metadataOrDefault(String key, String defaultValue) {
        return metadata != null ? metadata.getOrDefault(key, defaultValue) : defaultValue;
    }
}
