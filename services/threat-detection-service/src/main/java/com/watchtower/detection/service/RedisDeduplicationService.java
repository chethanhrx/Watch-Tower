package com.watchtower.detection.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * Redis-based alert deduplication.
 * Prevents alert storms by suppressing repeated alerts of the same type
 * from the same source within a configurable time window.
 *
 * Key format: alert:dedup:{alertType}:{sourceIp}
 * TTL: 5 minutes (configurable)
 */
@Service
public class RedisDeduplicationService {

    private static final Logger log = LoggerFactory.getLogger(RedisDeduplicationService.class);
    private static final String KEY_PREFIX = "alert:dedup:";
    private static final Duration DEFAULT_WINDOW = Duration.ofMinutes(5);

    private final StringRedisTemplate redisTemplate;

    public RedisDeduplicationService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * Check if this alert is a duplicate. If not, mark it as seen.
     *
     * @return true if this is a NEW alert (should be processed), false if duplicate
     */
    public boolean tryAcquire(String alertType, String sourceIp) {
        String key = KEY_PREFIX + alertType + ":" + sourceIp;
        // SET NX with TTL — atomic check-and-set
        Boolean isNew = redisTemplate.opsForValue()
                .setIfAbsent(key, "1", DEFAULT_WINDOW);

        if (Boolean.TRUE.equals(isNew)) {
            log.debug("New alert: {}:{} — processing", alertType, sourceIp);
            return true;
        } else {
            log.debug("Duplicate alert suppressed: {}:{}", alertType, sourceIp);
            return false;
        }
    }

    /**
     * Overload with custom window duration.
     */
    public boolean tryAcquire(String alertType, String sourceIp, Duration window) {
        String key = KEY_PREFIX + alertType + ":" + sourceIp;
        Boolean isNew = redisTemplate.opsForValue().setIfAbsent(key, "1", window);
        return Boolean.TRUE.equals(isNew);
    }
}
