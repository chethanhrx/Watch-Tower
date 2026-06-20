package com.watchtower.common.event;

import java.time.Instant;

/**
 * File integrity monitoring event — published to the {@code fim-events} Kafka topic
 * when a monitored file is created, modified, deleted, or has its permissions changed.
 *
 * @param eventId        Unique identifier (UUID)
 * @param timestamp      When the change was detected
 * @param filePath       Absolute path of the affected file
 * @param changeType     Type of change: CREATED, MODIFIED, DELETED, PERMISSION_CHANGED
 * @param oldHash        Previous SHA-256 hash (null for CREATED)
 * @param newHash        New SHA-256 hash (null for DELETED)
 * @param oldPermissions Previous POSIX permissions string (null for CREATED)
 * @param newPermissions New POSIX permissions string (null for DELETED)
 * @param fileSize       Current file size in bytes
 * @param owner          File owner
 */
public record FileIntegrityEvent(
        String eventId,
        Instant timestamp,
        String filePath,
        String changeType,
        String oldHash,
        String newHash,
        String oldPermissions,
        String newPermissions,
        long fileSize,
        String owner
) {}
