package com.watchtower.ingestion.parser;

import com.watchtower.common.enums.EventType;
import com.watchtower.common.enums.Severity;
import com.watchtower.common.event.NormalizedLogEvent;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses Linux auth.log / secure log entries.
 * Example: "Jun 15 10:30:45 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
 * Example: "Jun 15 10:30:45 server sudo: admin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash"
 */
@Component
public class AuthLogParser implements LogParser {

    private static final Pattern AUTH_LOG_PATTERN = Pattern.compile(
            "^(\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+(\\S+)\\s+(\\S+?)(?:\\[(\\d+)])?:\\s+(.+)$"
    );

    private static final Pattern FAILED_PASSWORD = Pattern.compile(
            "Failed password for (invalid user )?(\\S+) from (\\S+) port (\\d+)"
    );
    private static final Pattern ACCEPTED_PASSWORD = Pattern.compile(
            "Accepted (password|publickey) for (\\S+) from (\\S+) port (\\d+)"
    );
    private static final Pattern SUDO_COMMAND = Pattern.compile(
            "(\\S+) : TTY=(\\S+) ; PWD=(\\S+) ; USER=(\\S+) ; COMMAND=(.+)"
    );
    private static final Pattern INVALID_USER = Pattern.compile(
            "Invalid user (\\S+) from (\\S+)"
    );

    @Override
    public String getFormat() {
        return "AUTH_LOG";
    }

    @Override
    public boolean canParse(String rawLine) {
        if (!AUTH_LOG_PATTERN.matcher(rawLine).matches()) return false;
        // Distinguish from generic syslog by checking for auth-related processes
        String lower = rawLine.toLowerCase();
        return lower.contains("sshd") || lower.contains("sudo") || lower.contains("pam")
                || lower.contains("su[") || lower.contains("login");
    }

    @Override
    public NormalizedLogEvent parse(String rawLine) {
        Matcher baseMatcher = AUTH_LOG_PATTERN.matcher(rawLine);
        if (!baseMatcher.matches()) return null;

        String hostname = baseMatcher.group(2);
        String process = baseMatcher.group(3);
        String message = baseMatcher.group(5);

        Map<String, String> metadata = new HashMap<>();
        metadata.put("format", "AUTH_LOG");
        metadata.put("process", process);

        String sourceIp = "0.0.0.0";
        EventType eventType = EventType.SYSTEM_EVENT;
        Severity severity = Severity.INFO;

        // Check for failed password
        Matcher failedMatcher = FAILED_PASSWORD.matcher(message);
        if (failedMatcher.find()) {
            boolean invalidUser = failedMatcher.group(1) != null;
            metadata.put("username", failedMatcher.group(2));
            sourceIp = failedMatcher.group(3);
            metadata.put("port", failedMatcher.group(4));
            metadata.put("invalid_user", String.valueOf(invalidUser));
            eventType = EventType.AUTH_FAILURE;
            severity = invalidUser ? Severity.MEDIUM : Severity.MEDIUM;
        }

        // Check for accepted password/key
        Matcher acceptedMatcher = ACCEPTED_PASSWORD.matcher(message);
        if (acceptedMatcher.find()) {
            metadata.put("auth_method", acceptedMatcher.group(1));
            metadata.put("username", acceptedMatcher.group(2));
            sourceIp = acceptedMatcher.group(3);
            metadata.put("port", acceptedMatcher.group(4));
            eventType = EventType.AUTH_SUCCESS;
            severity = Severity.INFO;
        }

        // Check for sudo command
        Matcher sudoMatcher = SUDO_COMMAND.matcher(message);
        if (sudoMatcher.find()) {
            metadata.put("username", sudoMatcher.group(1));
            metadata.put("tty", sudoMatcher.group(2));
            metadata.put("pwd", sudoMatcher.group(3));
            metadata.put("target_user", sudoMatcher.group(4));
            metadata.put("command", sudoMatcher.group(5));
            eventType = EventType.PRIVILEGE_ESCALATION;
            severity = Severity.HIGH;
        }

        // Check for invalid user attempts
        Matcher invalidMatcher = INVALID_USER.matcher(message);
        if (invalidMatcher.find()) {
            metadata.put("username", invalidMatcher.group(1));
            sourceIp = invalidMatcher.group(2);
            eventType = EventType.AUTH_FAILURE;
            severity = Severity.MEDIUM;
        }

        return new NormalizedLogEvent(
                UUID.randomUUID().toString(),
                Instant.now(),
                sourceIp,
                hostname,
                eventType,
                severity,
                rawLine,
                metadata
        );
    }
}
