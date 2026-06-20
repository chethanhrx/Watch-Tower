package com.watchtower.common.config;

/**
 * Centralized Kafka topic name constants.
 * Ensures all services reference the same topic names without string duplication.
 */
public final class KafkaTopics {

    private KafkaTopics() {
        // Utility class — no instantiation
    }

    /** Normalized log events from the ingestion service */
    public static final String RAW_LOGS = "raw-logs";

    /** Security alerts from the threat detection engine */
    public static final String SECURITY_ALERTS = "security-alerts";

    /** File integrity monitoring events */
    public static final String FIM_EVENTS = "fim-events";

    // ── Consumer Group IDs ──

    public static final String THREAT_DETECTION_GROUP = "threat-detection-group";
    public static final String NOTIFICATION_GROUP = "notification-group";
    public static final String DASHBOARD_GROUP = "dashboard-group";
}
