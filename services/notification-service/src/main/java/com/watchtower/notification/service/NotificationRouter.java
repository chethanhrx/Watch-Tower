package com.watchtower.notification.service;

import com.watchtower.common.enums.Severity;
import com.watchtower.common.event.SecurityAlert;
import com.watchtower.notification.entity.NotificationHistory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;

/**
 * Severity-based notification routing.
 * CRITICAL → immediate email + Telegram
 * HIGH → immediate email
 * MEDIUM/LOW → logged for digest (scheduled batch)
 */
@Service
public class NotificationRouter {

    private static final Logger log = LoggerFactory.getLogger(NotificationRouter.class);

    private final JavaMailSender mailSender;

    @Value("${watchtower.notification.email.to:admin@watchtower.io}")
    private String defaultRecipient;

    @Value("${watchtower.notification.email.from:alerts@watchtower.io}")
    private String fromAddress;

    @PersistenceContext
    private EntityManager entityManager;

    public NotificationRouter(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Transactional
    public void route(SecurityAlert alert) {
        Severity severity = alert.severity();

        if (severity.isAtLeast(Severity.HIGH)) {
            sendEmail(alert);
        }

        if (severity == Severity.CRITICAL) {
            sendTelegram(alert);
        }

        // Always log to notification history
        saveHistory(alert, severity.isAtLeast(Severity.HIGH) ? "SENT" : "QUEUED");
    }

    private void sendEmail(SecurityAlert alert) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromAddress);
            message.setTo(defaultRecipient);
            message.setSubject(String.format("[WatchTower %s] %s — %s",
                    alert.severity(), alert.alertType(), alert.sourceIp()));
            message.setText(String.format("""
                    Security Alert Detected
                    
                    Type: %s
                    Severity: %s
                    Source IP: %s
                    Time: %s
                    
                    Description:
                    %s
                    
                    Detection Method: %s
                    Confidence: %.0f%%
                    
                    — WatchTower Threat Detection Platform
                    """,
                    alert.alertType(), alert.severity(), alert.sourceIp(),
                    alert.timestamp(), alert.description(),
                    alert.detectionMethod(), alert.confidenceScore() * 100));

            mailSender.send(message);
            log.info("Email sent for alert {} [{}]", alert.alertId(), alert.severity());
        } catch (Exception e) {
            log.error("Failed to send email for alert {}: {}", alert.alertId(), e.getMessage());
        }
    }

    private void sendTelegram(SecurityAlert alert) {
        // Placeholder: Telegram Bot API integration
        log.info("Telegram notification would be sent for CRITICAL alert {}", alert.alertId());
    }

    private void saveHistory(SecurityAlert alert, String status) {
        NotificationHistory history = new NotificationHistory();
        history.setAlertId(alert.alertId());
        history.setChannelType("EMAIL");
        history.setRecipient(defaultRecipient);
        history.setSeverity(alert.severity().name());
        history.setSubject(alert.alertType().name());
        history.setBody(alert.description());
        history.setStatus(status);
        if ("SENT".equals(status)) history.setSentAt(Instant.now());
        entityManager.persist(history);
    }
}
