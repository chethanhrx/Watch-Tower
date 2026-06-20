package com.watchtower.ingestion.parser;

import com.watchtower.common.enums.EventType;
import com.watchtower.common.enums.Severity;
import com.watchtower.common.event.NormalizedLogEvent;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses standard syslog format (RFC 3164).
 * Example: "Jun 15 10:30:45 webserver01 sshd[12345]: Failed password for user root from 192.168.1.100 port 22 ssh2"
 */
@Component
public class SyslogParser implements LogParser {

    // RFC 3164 syslog pattern: timestamp hostname process[pid]: message
    private static final Pattern SYSLOG_PATTERN = Pattern.compile(
            "^(\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+(\\S+)\\s+(\\S+?)(?:\\[(\\d+)])?:\\s+(.+)$"
    );

    private static final DateTimeFormatter SYSLOG_DATE = DateTimeFormatter.ofPattern(
            "MMM  d HH:mm:ss", Locale.ENGLISH
    );

    private static final DateTimeFormatter SYSLOG_DATE_SINGLE = DateTimeFormatter.ofPattern(
            "MMM d HH:mm:ss", Locale.ENGLISH
    );

    // Patterns for common security events
    private static final Pattern FAILED_AUTH = Pattern.compile(
            "(?i)(failed|invalid|error|denied).*(?:password|auth|login|key)"
    );
    private static final Pattern SUCCESS_AUTH = Pattern.compile(
            "(?i)(accepted|success).*(?:password|publickey|login)"
    );
    private static final Pattern IP_PATTERN = Pattern.compile(
            "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})"
    );

    @Override
    public String getFormat() {
        return "SYSLOG";
    }

    @Override
    public boolean canParse(String rawLine) {
        return SYSLOG_PATTERN.matcher(rawLine).matches();
    }

    @Override
    public NormalizedLogEvent parse(String rawLine) {
        Matcher matcher = SYSLOG_PATTERN.matcher(rawLine);
        if (!matcher.matches()) {
            return null;
        }

        String timestampStr = matcher.group(1);
        String hostname = matcher.group(2);
        String process = matcher.group(3);
        String pid = matcher.group(4);
        String message = matcher.group(5);

        Instant timestamp = parseSyslogTimestamp(timestampStr);
        String sourceIp = extractIp(message);
        EventType eventType = classifyEvent(message);
        Severity severity = assessSeverity(eventType, message);

        Map<String, String> metadata = new HashMap<>();
        metadata.put("process", process);
        if (pid != null) metadata.put("pid", pid);
        metadata.put("format", "SYSLOG");

        // Extract username if present
        extractUsername(message).ifPresent(u -> metadata.put("username", u));

        return new NormalizedLogEvent(
                UUID.randomUUID().toString(),
                timestamp,
                sourceIp != null ? sourceIp : "0.0.0.0",
                hostname,
                eventType,
                severity,
                rawLine,
                metadata
        );
    }

    private Instant parseSyslogTimestamp(String timestampStr) {
        try {
            // Syslog timestamps don't include year — assume current year
            int year = java.time.Year.now().getValue();
            String normalized = timestampStr.replaceAll("\\s+", " ");
            LocalDateTime ldt = LocalDateTime.parse(
                    normalized, SYSLOG_DATE_SINGLE
            ).withYear(year);
            return ldt.toInstant(ZoneOffset.UTC);
        } catch (Exception e) {
            return Instant.now();
        }
    }

    private String extractIp(String message) {
        Matcher matcher = IP_PATTERN.matcher(message);
        return matcher.find() ? matcher.group(1) : null;
    }

    private EventType classifyEvent(String message) {
        if (FAILED_AUTH.matcher(message).find()) return EventType.AUTH_FAILURE;
        if (SUCCESS_AUTH.matcher(message).find()) return EventType.AUTH_SUCCESS;
        if (message.toLowerCase().contains("sudo")) return EventType.PRIVILEGE_ESCALATION;
        if (message.toLowerCase().contains("session opened")) return EventType.AUTH_SUCCESS;
        if (message.toLowerCase().contains("session closed")) return EventType.AUTH_LOGOUT;
        return EventType.SYSTEM_EVENT;
    }

    private Severity assessSeverity(EventType eventType, String message) {
        return switch (eventType) {
            case AUTH_FAILURE -> Severity.MEDIUM;
            case PRIVILEGE_ESCALATION -> Severity.HIGH;
            case AUTH_SUCCESS -> Severity.INFO;
            case AUTH_LOGOUT -> Severity.INFO;
            default -> Severity.LOW;
        };
    }

    private java.util.Optional<String> extractUsername(String message) {
        Pattern userPattern = Pattern.compile("(?:for|user|by)\\s+(\\S+)", Pattern.CASE_INSENSITIVE);
        Matcher matcher = userPattern.matcher(message);
        if (matcher.find()) {
            String user = matcher.group(1);
            // Clean up common suffixes
            return java.util.Optional.of(user.replaceAll("[,;]$", ""));
        }
        return java.util.Optional.empty();
    }
}
