package com.watchtower.ingestion.parser;

import com.watchtower.common.event.NormalizedLogEvent;

/**
 * Strategy interface for log parsers.
 *
 * <p>Each parser implementation handles a specific log format (syslog, auth.log,
 * nginx, etc.) and normalizes it into the canonical {@link NormalizedLogEvent} schema.
 * New formats can be added without modifying existing parsers (Open/Closed Principle).</p>
 */
public interface LogParser {

    /**
     * Returns the format identifier this parser handles.
     * Used by {@link LogParserFactory} for dispatch.
     */
    String getFormat();

    /**
     * Attempts to parse a raw log line into a normalized event.
     *
     * @param rawLine the raw log string
     * @return the normalized event, or null if the line cannot be parsed
     */
    NormalizedLogEvent parse(String rawLine);

    /**
     * Checks whether this parser can likely handle the given raw line.
     * Used for auto-detection when the format is not explicitly specified.
     */
    boolean canParse(String rawLine);
}
