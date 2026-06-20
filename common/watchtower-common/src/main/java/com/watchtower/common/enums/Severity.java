package com.watchtower.common.enums;

/**
 * Severity levels for log events and security alerts.
 * Ordered from lowest to highest impact.
 */
public enum Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    public boolean isHigherThan(Severity other) {
        return this.ordinal() > other.ordinal();
    }

    public boolean isAtLeast(Severity threshold) {
        return this.ordinal() >= threshold.ordinal();
    }
}
