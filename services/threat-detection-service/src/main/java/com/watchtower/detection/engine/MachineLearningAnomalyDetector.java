package com.watchtower.detection.engine;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.watchtower.common.enums.AlertType;
import com.watchtower.common.enums.Severity;
import com.watchtower.common.event.NormalizedLogEvent;
import com.watchtower.common.event.SecurityAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Component
public class MachineLearningAnomalyDetector implements AnomalyDetector {

    private static final Logger log = LoggerFactory.getLogger(MachineLearningAnomalyDetector.class);

    private final StringRedisTemplate redisTemplate;
    private final RestTemplate restTemplate;
    private final String mlServiceUrl;
    
    // We only send a subset of logs to ML to avoid overwhelming the model
    private static final double SAMPLING_RATE = 1.0;

    public MachineLearningAnomalyDetector(
            StringRedisTemplate redisTemplate,
            @Value("${ml.service.url:http://ml-scoring-service:8090}") String mlServiceUrl) {
        this.redisTemplate = redisTemplate;
        this.restTemplate = new RestTemplate();
        this.mlServiceUrl = mlServiceUrl;
    }

    @Override
    public String getDetectorId() {
        return "isolation-forest-v1";
    }

    @Override
    public Optional<SecurityAlert> analyze(NormalizedLogEvent event) {
        // Only sample a portion of events to send to the ML service to save resources
        if (Math.random() > SAMPLING_RATE) {
            return Optional.empty();
        }

        try {
            // 1. Gather features (In a real system, these come from Redis or Flink state)
            String ip = event.sourceIp();
            int loginCount1h = getCountFromRedis("stats:login_freq:" + ip);
            int loginCount24h = loginCount1h * 12; // Simulated for demo
            int uniqueIps24h = 1;
            int hourOfDay = event.timestamp().atZone(java.time.ZoneOffset.UTC).getHour();
            
            String bytesStr = event.metadataOrDefault("body_bytes", "5000");
            float bytesTransferred = Float.parseFloat(bytesStr);

            FeatureVector features = new FeatureVector(ip, loginCount1h, loginCount24h, uniqueIps24h, hourOfDay, bytesTransferred);

            // 2. Call the Python ML Sidecar
            ResponseEntity<ScoreResponse> response = restTemplate.postForEntity(
                    mlServiceUrl + "/api/v1/score",
                    features,
                    ScoreResponse.class
            );

            ScoreResponse score = response.getBody();

            // 3. Evaluate response
            if (score != null && score.isAnomaly() && score.confidence() > 0.2) {
                return Optional.of(new SecurityAlert(
                        UUID.randomUUID().toString(),
                        Instant.now(),
                        AlertType.ML_ANOMALY,
                        Severity.HIGH,
                        ip,
                        String.format("Machine Learning Anomaly Detected (Score: %.2f, Confidence: %.2f)", 
                            score.anomalyScore(), score.confidence()),
                        null,
                        getDetectorId(),
                        score.confidence(),
                        event,
                        Map.of(
                            "anomaly_score", String.valueOf(score.anomalyScore()),
                            "detector", getDetectorId()
                        )
                ));
            }
        } catch (Exception e) {
            log.warn("Failed to call ML scoring service: {}", e.getMessage());
        }

        return Optional.empty();
    }

    private int getCountFromRedis(String key) {
        String val = redisTemplate.opsForValue().get(key);
        if (val == null) return 0;
        try {
            return Integer.parseInt(val);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    // DTOs for ML Service Communication
    private record FeatureVector(
        @JsonProperty("source_ip") String sourceIp,
        @JsonProperty("login_count_1h") int loginCount1h,
        @JsonProperty("login_count_24h") int loginCount24h,
        @JsonProperty("unique_ips_24h") int uniqueIps24h,
        @JsonProperty("hour_of_day") int hourOfDay,
        @JsonProperty("bytes_transferred") float bytesTransferred
    ) {}

    private record ScoreResponse(
        @JsonProperty("anomaly_score") double anomalyScore,
        @JsonProperty("is_anomaly") boolean isAnomaly,
        @JsonProperty("confidence") double confidence
    ) {}
}
