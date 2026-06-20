package com.watchtower.dashboard.controller;

import com.watchtower.common.event.SecurityAlert;
import com.watchtower.dashboard.kafka.AlertStreamConsumer;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * REST API for alert aggregations and dashboard data.
 */
@RestController
@RequestMapping("/api/v1/alerts")
public class AlertController {

    private final AlertStreamConsumer alertStream;

    public AlertController(AlertStreamConsumer alertStream) {
        this.alertStream = alertStream;
    }

    /** Get recent alerts (in-memory buffer) */
    @GetMapping("/recent")
    public List<SecurityAlert> getRecentAlerts(
            @RequestParam(defaultValue = "50") int limit) {
        return alertStream.getRecentAlerts().stream()
                .limit(limit)
                .toList();
    }

    /** Aggregate alerts by severity */
    @GetMapping("/summary/by-severity")
    public Map<String, Long> alertsBySeverity() {
        return alertStream.getRecentAlerts().stream()
                .collect(Collectors.groupingBy(
                        a -> a.severity().name(),
                        Collectors.counting()));
    }

    /** Aggregate alerts by type */
    @GetMapping("/summary/by-type")
    public Map<String, Long> alertsByType() {
        return alertStream.getRecentAlerts().stream()
                .collect(Collectors.groupingBy(
                        a -> a.alertType().name(),
                        Collectors.counting()));
    }

    /** Top source IPs */
    @GetMapping("/summary/top-ips")
    public Map<String, Long> topSourceIps(@RequestParam(defaultValue = "10") int limit) {
        return alertStream.getRecentAlerts().stream()
                .collect(Collectors.groupingBy(
                        SecurityAlert::sourceIp,
                        Collectors.counting()))
                .entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(limit)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,
                        (a, b) -> a, java.util.LinkedHashMap::new));
    }
}
