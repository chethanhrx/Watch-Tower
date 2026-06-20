package com.watchtower.common.enums;

/**
 * Normalized event types produced by the log ingestion service.
 * Maps raw log formats into a unified taxonomy.
 */
public enum EventType {
    // Authentication events
    AUTH_SUCCESS,
    AUTH_FAILURE,
    AUTH_LOGOUT,
    PASSWORD_CHANGE,

    // Network events
    CONNECTION_ATTEMPT,
    CONNECTION_ESTABLISHED,
    CONNECTION_REFUSED,

    // HTTP events
    HTTP_REQUEST,
    HTTP_ERROR,

    // System events
    SYSTEM_EVENT,
    PROCESS_START,
    PROCESS_STOP,
    SERVICE_RESTART,

    // File events
    FILE_ACCESS,
    FILE_MODIFIED,
    FILE_CREATED,
    FILE_DELETED,
    PERMISSION_CHANGED,

    // Security events
    PRIVILEGE_ESCALATION,
    FIREWALL_BLOCK,
    MALWARE_DETECTED,

    // Catch-all
    UNKNOWN
}
