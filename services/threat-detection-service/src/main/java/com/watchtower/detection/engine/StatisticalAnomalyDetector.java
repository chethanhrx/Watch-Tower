package com.watchtower.detection.engine;

import com.watchtower.common.enums.AlertType;
import com.watchtower.common.enums.EventType;
import com.watchtower.common.enums.Severity;
import com.watchtower.common.event.NormalizedLogEvent;
import com.watchtower.common.event.SecurityAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Statistical anomaly detector — production-realistic approach.
 *
 * Detects:
 * 1. Login frequency anomaly: flags when login rate for a user/IP exceeds mean + 3σ
 * 2. Time-of-day anomaly: flags logins outside a user's normal activity hours
 *
 * Uses Redis for sliding window counters and in-memory stats for baselines.
 * Baselines are recalculated periodically via @Scheduled in the detection service.
 */
@Component
public class StatisticalAnomalyDetector implements AnomalyDetector {

    private static final Logger log = LoggerFactory.getLogger(StatisticalAnomalyDetector.class);
    private static final int FREQUENCY_WINDOW_SECONDS = 3600; // 1 hour
    private static final int FREQUENCY_THRESHOLD = 20; // initial threshold before baseline exists
    private static final double Z_SCORE_THRESHOLD = 3.0;

    private final StringRedisTemplate redisTemplate;

    // In-memory baselines (would be in a DB/cache in full production)
    private final ConcurrentHashMap<String, UserBaseline> baselines = new ConcurrentHashMap<>();

    public StatisticalAnomalyDetector(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public String getDetectorId() {
        return "statistical-baseline-v1";
    }

    @Override
    public Optional<SecurityAlert> analyze(NormalizedLogEvent event) {
        if (event.eventType() != EventType.AUTH_SUCCESS
                && event.eventType() != EventType.AUTH_FAILURE) {
            return Optional.empty();
        }

        // Check login frequency anomaly
        Optional<SecurityAlert> freqAlert = checkLoginFrequency(event);
        if (freqAlert.isPresent()) return freqAlert;

        // Check time-of-day anomaly
        return checkTimeOfDay(event);
    }

    private Optional<SecurityAlert> checkLoginFrequency(NormalizedLogEvent event) {
        String key = "stats:login_freq:" + event.sourceIp();

        // Increment counter in Redis with 1-hour sliding window
        Long count = redisTemplate.opsForValue().increment(key);
        if (count != null && count == 1) {
            redisTemplate.expire(key, FREQUENCY_WINDOW_SECONDS, TimeUnit.SECONDS);
        }

        if (count == null) return Optional.empty();

        // Check against baseline or static threshold
        UserBaseline baseline = baselines.get(event.sourceIp());
        boolean isAnomaly;
        double confidence;

        if (baseline != null && baseline.loginCountStdDev > 0) {
            double zScore = (count - baseline.meanLoginCountPerHour) / baseline.loginCountStdDev;
            isAnomaly = zScore > Z_SCORE_THRESHOLD;
            confidence = Math.min(1.0, zScore / (Z_SCORE_THRESHOLD * 2));
        } else {
            isAnomaly = count > FREQUENCY_THRESHOLD;
            confidence = 0.7; // Lower confidence without baseline
        }

        if (isAnomaly) {
            return Optional.of(new SecurityAlert(
                    UUID.randomUUID().toString(),
                    Instant.now(),
                    AlertType.ANOMALOUS_LOGIN_FREQUENCY,
                    Severity.HIGH,
                    event.sourceIp(),
                    String.format("Anomalous login frequency: %d attempts in the last hour from %s (threshold: %s)",
                            count, event.sourceIp(),
                            baseline != null ? String.format("%.1f + 3σ", baseline.meanLoginCountPerHour)
                                    : String.valueOf(FREQUENCY_THRESHOLD)),
                    null,
                    "STATISTICAL",
                    confidence,
                    event,
                    Map.of("login_count_1h", String.valueOf(count),
                            "detector", getDetectorId())
            ));
        }
        return Optional.empty();
    }

    private Optional<SecurityAlert> checkTimeOfDay(NormalizedLogEvent event) {
        if (event.eventType() != EventType.AUTH_SUCCESS) return Optional.empty();

        int hour = event.timestamp().atZone(java.time.ZoneOffset.UTC).getHour();

        // Flag logins between 1 AM and 5 AM UTC as potentially suspicious
        // (simple heuristic; real system would use per-user baselines)
        if (hour >= 1 && hour <= 5) {
            String username = event.metadataOrDefault("username", "unknown");
            return Optional.of(new SecurityAlert(
                    UUID.randomUUID().toString(),
                    Instant.now(),
                    AlertType.ANOMALOUS_LOGIN_TIME,
                    Severity.MEDIUM,
                    event.sourceIp(),
                    String.format("Unusual login time: user '%s' logged in at %02d:00 UTC from %s",
                            username, hour, event.sourceIp()),
                    null,
                    "STATISTICAL",
                    0.6,
                    event,
                    Map.of("login_hour_utc", String.valueOf(hour),
                            "username", username,
                            "detector", getDetectorId())
            ));
        }
        return Optional.empty();
    }

    /**
     * Update baseline for a source IP. Called periodically.
     */
    public void updateBaseline(String sourceIp, double meanLoginCount, double stdDev) {
        baselines.put(sourceIp, new UserBaseline(meanLoginCount, stdDev));
    }

    private record UserBaseline(double meanLoginCountPerHour, double loginCountStdDev) {}
}
