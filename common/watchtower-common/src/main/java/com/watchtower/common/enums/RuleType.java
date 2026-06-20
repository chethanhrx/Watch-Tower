package com.watchtower.common.enums;

/**
 * Detection rule types supported by the threat detection engine.
 */
public enum RuleType {
    /** Fires when event count exceeds threshold within a time window */
    THRESHOLD,

    /** Fires when event fields match a regex pattern */
    PATTERN,

    /** Fires when a specific sequence of events occurs in order */
    SEQUENCE,

    /** Fires on geolocation-based anomalies (impossible travel) */
    GEO_ANOMALY
}
