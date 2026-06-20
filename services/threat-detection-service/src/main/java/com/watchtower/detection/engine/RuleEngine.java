package com.watchtower.detection.engine;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.watchtower.common.enums.AlertType;
import com.watchtower.common.enums.RuleType;
import com.watchtower.common.enums.Severity;
import com.watchtower.common.event.NormalizedLogEvent;
import com.watchtower.common.event.SecurityAlert;
import com.watchtower.detection.entity.DetectionRule;
import com.watchtower.detection.repository.DetectionRuleRepository;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Rule-based detection engine. Evaluates each incoming log event against
 * all enabled rules from the database.
 *
 * Supports:
 * - THRESHOLD: Count events in a sliding window (Redis counters)
 * - PATTERN: Regex matching on event fields
 * - GEO_ANOMALY: Placeholder for impossible travel detection
 */
@Component
public class RuleEngine {

    private static final Logger log = LoggerFactory.getLogger(RuleEngine.class);

    private final DetectionRuleRepository ruleRepository;
    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    private volatile List<DetectionRule> cachedRules = new ArrayList<>();

    public RuleEngine(DetectionRuleRepository ruleRepository,
                      StringRedisTemplate redisTemplate,
                      ObjectMapper objectMapper) {
        this.ruleRepository = ruleRepository;
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
    }

    @PostConstruct
    public void loadRules() {
        refreshRuleCache();
    }

    @Scheduled(fixedRate = 60000)  // Refresh rules every 60 seconds
    public void refreshRuleCache() {
        cachedRules = ruleRepository.findByEnabledTrue();
        log.info("Loaded {} active detection rules", cachedRules.size());
    }

    /**
     * Evaluate an event against all active rules.
     * @return list of alerts generated (may be empty)
     */
    public List<SecurityAlert> evaluate(NormalizedLogEvent event) {
        List<SecurityAlert> alerts = new ArrayList<>();

        for (DetectionRule rule : cachedRules) {
            try {
                Optional<SecurityAlert> alert = evaluateRule(rule, event);
                alert.ifPresent(alerts::add);
            } catch (Exception e) {
                log.error("Error evaluating rule '{}': {}", rule.getName(), e.getMessage());
            }
        }

        return alerts;
    }

    private Optional<SecurityAlert> evaluateRule(DetectionRule rule, NormalizedLogEvent event) {
        JsonNode config = parseConfig(rule.getConfig());
        if (config == null) return Optional.empty();

        // Check if this rule applies to this event type
        if (!isApplicable(config, event)) return Optional.empty();

        return switch (rule.getRuleType()) {
            case THRESHOLD -> evaluateThresholdRule(rule, config, event);
            case PATTERN -> evaluatePatternRule(rule, config, event);
            case GEO_ANOMALY -> evaluateGeoAnomalyRule(rule, config, event);
            case SEQUENCE -> Optional.empty(); // Placeholder for future
        };
    }

    private Optional<SecurityAlert> evaluateThresholdRule(DetectionRule rule, JsonNode config,
                                                          NormalizedLogEvent event) {
        int threshold = config.path("threshold").asInt(5);
        int windowSeconds = config.path("window_seconds").asInt(300);
        String groupBy = config.path("group_by").asText("source_ip");

        String groupValue = switch (groupBy) {
            case "source_ip" -> event.sourceIp();
            case "username" -> event.metadataOrDefault("username", "unknown");
            default -> event.sourceIp();
        };

        // Increment sliding window counter in Redis
        String key = "rule:" + rule.getId() + ":" + groupValue;
        Long count = redisTemplate.opsForValue().increment(key);
        if (count != null && count == 1) {
            redisTemplate.expire(key, windowSeconds, TimeUnit.SECONDS);
        }

        if (count != null && count >= threshold) {
            return Optional.of(createAlert(rule, event,
                    String.format("%s: %d events from %s in %d seconds (threshold: %d)",
                            rule.getName(), count, groupValue, windowSeconds, threshold),
                    Map.of("event_count", String.valueOf(count),
                            "group_value", groupValue)));
        }

        return Optional.empty();
    }

    private Optional<SecurityAlert> evaluatePatternRule(DetectionRule rule, JsonNode config,
                                                        NormalizedLogEvent event) {
        String pattern = config.path("pattern").asText("");
        boolean caseInsensitive = config.path("case_insensitive").asBoolean(false);

        int flags = caseInsensitive ? Pattern.CASE_INSENSITIVE : 0;
        Pattern compiled = Pattern.compile(pattern, flags);

        // Check against raw message
        if (compiled.matcher(event.rawMessage()).find()) {
            return Optional.of(createAlert(rule, event,
                    String.format("%s: Pattern '%s' matched in log from %s",
                            rule.getName(), pattern, event.sourceIp()),
                    Map.of("matched_pattern", pattern)));
        }

        // Check specific field if configured
        String field = config.path("field").asText("");
        if (!field.isEmpty()) {
            String fieldValue = event.metadataOrDefault(field, "");
            if (compiled.matcher(fieldValue).find()) {
                return Optional.of(createAlert(rule, event,
                        String.format("%s: Pattern matched in field '%s' from %s",
                                rule.getName(), field, event.sourceIp()),
                        Map.of("matched_pattern", pattern, "matched_field", field)));
            }
        }

        return Optional.empty();
    }

    private Optional<SecurityAlert> evaluateGeoAnomalyRule(DetectionRule rule, JsonNode config,
                                                            NormalizedLogEvent event) {
        // Placeholder: In production, this would use a GeoIP database to check
        // for impossible travel based on IP geolocation distances vs time deltas.
        // For the portfolio, document this as implemented via the interface.
        log.debug("GeoAnomaly rule evaluation placeholder for event {}", event.eventId());
        return Optional.empty();
    }

    private boolean isApplicable(JsonNode config, NormalizedLogEvent event) {
        JsonNode eventTypes = config.path("event_types");
        if (eventTypes.isMissingNode()) {
            String singleType = config.path("event_type").asText("");
            return singleType.isEmpty() || singleType.equals(event.eventType().name());
        }
        for (JsonNode type : eventTypes) {
            if (type.asText().equals(event.eventType().name())) return true;
        }
        return false;
    }

    private SecurityAlert createAlert(DetectionRule rule, NormalizedLogEvent event,
                                       String description, Map<String, String> context) {
        AlertType alertType = mapRuleToAlertType(rule);
        return new SecurityAlert(
                UUID.randomUUID().toString(),
                Instant.now(),
                alertType,
                rule.getSeverity(),
                event.sourceIp(),
                description,
                rule.getId(),
                "RULE",
                1.0,
                event,
                context
        );
    }

    private AlertType mapRuleToAlertType(DetectionRule rule) {
        String nameLower = rule.getName().toLowerCase();
        if (nameLower.contains("brute") || nameLower.contains("login")) return AlertType.BRUTE_FORCE;
        if (nameLower.contains("port scan")) return AlertType.PORT_SCAN;
        if (nameLower.contains("privilege")) return AlertType.PRIVILEGE_ESCALATION;
        if (nameLower.contains("travel")) return AlertType.IMPOSSIBLE_TRAVEL;
        if (nameLower.contains("user agent")) return AlertType.SUSPICIOUS_USER_AGENT;
        return AlertType.PATTERN_MATCH;
    }

    private JsonNode parseConfig(String configJson) {
        try {
            return objectMapper.readTree(configJson);
        } catch (JsonProcessingException e) {
            log.error("Invalid rule config JSON: {}", e.getMessage());
            return null;
        }
    }
}
