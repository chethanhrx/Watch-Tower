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
 * Parses Nginx/Apache combined log format.
 * Example: 192.168.1.50 - admin [15/Jun/2024:10:30:45 +0000] "GET /admin HTTP/1.1" 403 1234 "-" "Mozilla/5.0"
 */
@Component
public class NginxLogParser implements LogParser {

    // Combined log format pattern
    private static final Pattern NGINX_PATTERN = Pattern.compile(
            "^(\\S+)\\s+\\S+\\s+(\\S+)\\s+\\[([^]]+)]\\s+\"(\\S+)\\s+(\\S+)\\s+(\\S+)\"\\s+(\\d{3})\\s+(\\d+)\\s+\"([^\"]*)\"\\s+\"([^\"]*)\"$"
    );

    @Override
    public String getFormat() {
        return "NGINX";
    }

    @Override
    public boolean canParse(String rawLine) {
        return NGINX_PATTERN.matcher(rawLine).matches();
    }

    @Override
    public NormalizedLogEvent parse(String rawLine) {
        Matcher matcher = NGINX_PATTERN.matcher(rawLine);
        if (!matcher.matches()) {
            return null;
        }

        String clientIp = matcher.group(1);
        String remoteUser = matcher.group(2);
        String httpMethod = matcher.group(4);
        String requestUri = matcher.group(5);
        String protocol = matcher.group(6);
        int statusCode = Integer.parseInt(matcher.group(7));
        long bodyBytes = Long.parseLong(matcher.group(8));
        String referer = matcher.group(9);
        String userAgent = matcher.group(10);

        EventType eventType = classifyHttpEvent(statusCode);
        Severity severity = assessHttpSeverity(statusCode, requestUri, userAgent);

        Map<String, String> metadata = new HashMap<>();
        metadata.put("format", "NGINX");
        metadata.put("http_method", httpMethod);
        metadata.put("request_uri", requestUri);
        metadata.put("protocol", protocol);
        metadata.put("status_code", String.valueOf(statusCode));
        metadata.put("body_bytes", String.valueOf(bodyBytes));
        metadata.put("user_agent", userAgent);
        metadata.put("referer", referer);
        if (!"-".equals(remoteUser)) {
            metadata.put("username", remoteUser);
        }

        return new NormalizedLogEvent(
                UUID.randomUUID().toString(),
                Instant.now(),
                clientIp,
                clientIp,
                eventType,
                severity,
                rawLine,
                metadata
        );
    }

    private EventType classifyHttpEvent(int statusCode) {
        if (statusCode >= 200 && statusCode < 400) return EventType.HTTP_REQUEST;
        if (statusCode == 401 || statusCode == 403) return EventType.AUTH_FAILURE;
        return EventType.HTTP_ERROR;
    }

    private Severity assessHttpSeverity(int statusCode, String uri, String userAgent) {
        // Check for suspicious user agents
        String uaLower = userAgent.toLowerCase();
        if (uaLower.contains("sqlmap") || uaLower.contains("nikto") || uaLower.contains("nmap")
                || uaLower.contains("masscan") || uaLower.contains("dirbuster")) {
            return Severity.HIGH;
        }

        // Check for suspicious URIs
        String uriLower = uri.toLowerCase();
        if (uriLower.contains("../") || uriLower.contains("etc/passwd")
                || uriLower.contains("wp-admin") || uriLower.contains(".env")) {
            return Severity.HIGH;
        }

        if (statusCode >= 500) return Severity.MEDIUM;
        if (statusCode == 401 || statusCode == 403) return Severity.MEDIUM;
        return Severity.INFO;
    }
}
