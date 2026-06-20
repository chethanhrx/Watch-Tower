package com.watchtower.common.event;

import com.watchtower.common.enums.AlertType;
import com.watchtower.common.enums.Severity;

import java.time.Instant;
import java.util.Map;

/**
 * Security alert — published to the {@code security-alerts} Kafka topic when
 * a threat is detected by either the rule engine or the anomaly detection layer.
 *
 * <p>Consumed by: notification-service (sends alerts), alert-dashboard-service
 * (pushes to WebSocket for real-time UI).</p>
 *
 * @param alertId         Unique identifier (UUID)
 * @param timestamp       When the alert was generated
 * @param alertType       Category of the detected threat
 * @param severity        Assessed severity
 * @param sourceIp        IP address associated with the threat
 * @param description     Human-readable description of what was detected
 * @param matchedRuleId   ID of the detection rule that triggered (null if ML-detected)
 * @param detectionMethod How the threat was detected: RULE, STATISTICAL, ML
 * @param confidenceScore Confidence level 0.0–1.0 (1.0 for rule matches)
 * @param triggeringEvent The log event that triggered this alert
 * @param context         Additional context (e.g., related IPs, usernames, geo data)
 */
public record SecurityAlert(
        String alertId,
        Instant timestamp,
        AlertType alertType,
        Severity severity,
        String sourceIp,
        String description,
        Long matchedRuleId,
        String detectionMethod,
        double confidenceScore,
        NormalizedLogEvent triggeringEvent,
        Map<String, String> context
) {}
