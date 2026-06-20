package com.watchtower.ingestion.parser;

import com.watchtower.common.event.NormalizedLogEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Factory that dispatches raw log lines to the appropriate parser.
 *
 * <p>Supports two modes:
 * <ul>
 *   <li>Explicit format: caller specifies the format (e.g., "SYSLOG", "NGINX")</li>
 *   <li>Auto-detection: tries each registered parser's {@code canParse()} method</li>
 * </ul>
 *
 * <p>New parsers are automatically registered via Spring's component scanning —
 * just implement {@link LogParser} and annotate with {@code @Component}.</p>
 */
@Component
public class LogParserFactory {

    private static final Logger log = LoggerFactory.getLogger(LogParserFactory.class);

    private final List<LogParser> parsers;

    public LogParserFactory(List<LogParser> parsers) {
        this.parsers = parsers;
        log.info("Registered {} log parsers: {}", parsers.size(),
                parsers.stream().map(LogParser::getFormat).toList());
    }

    /**
     * Parse a raw log line using the specified format.
     */
    public NormalizedLogEvent parse(String rawLine, String format) {
        return parsers.stream()
                .filter(p -> p.getFormat().equalsIgnoreCase(format))
                .findFirst()
                .map(p -> p.parse(rawLine))
                .orElseGet(() -> {
                    log.warn("No parser found for format '{}', attempting auto-detection", format);
                    return autoDetectAndParse(rawLine);
                });
    }

    /**
     * Auto-detect the log format and parse.
     */
    public NormalizedLogEvent autoDetectAndParse(String rawLine) {
        // AuthLogParser should be checked before SyslogParser since auth logs are a subset of syslog
        for (LogParser parser : parsers) {
            if (parser.canParse(rawLine)) {
                NormalizedLogEvent event = parser.parse(rawLine);
                if (event != null) {
                    log.debug("Auto-detected format '{}' for log line", parser.getFormat());
                    return event;
                }
            }
        }
        log.warn("No parser could handle log line: {}", rawLine.substring(0, Math.min(100, rawLine.length())));
        return null;
    }
}
