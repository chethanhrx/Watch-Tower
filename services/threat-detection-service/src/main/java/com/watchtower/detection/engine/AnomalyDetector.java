package com.watchtower.detection.engine;

import com.watchtower.common.event.NormalizedLogEvent;
import com.watchtower.common.event.SecurityAlert;

import java.util.Optional;

/**
 * Strategy interface for anomaly detection.
 * Implementations include statistical baselining and (future) ML models.
 */
public interface AnomalyDetector {

    String getDetectorId();

    /**
     * Analyze an event for anomalies.
     * @return SecurityAlert if anomaly detected, empty otherwise
     */
    Optional<SecurityAlert> analyze(NormalizedLogEvent event);
}
