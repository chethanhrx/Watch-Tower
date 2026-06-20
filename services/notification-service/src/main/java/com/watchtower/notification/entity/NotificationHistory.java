package com.watchtower.notification.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "notification_history")
public class NotificationHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "alert_id", nullable = false)
    private String alertId;

    @Column(name = "channel_id")
    private Long channelId;

    @Column(name = "channel_type", nullable = false)
    private String channelType;

    private String recipient;

    @Column(nullable = false)
    private String severity;

    private String subject;

    @Column(columnDefinition = "text")
    private String body;

    @Column(nullable = false)
    private String status = "PENDING";

    @Column(name = "error_message")
    private String errorMessage;

    @Column(name = "sent_at")
    private Instant sentAt;

    @Column(name = "created_at")
    private Instant createdAt;

    // ── Getters & Setters ──
    public Long getId() { return id; }
    public String getAlertId() { return alertId; }
    public void setAlertId(String alertId) { this.alertId = alertId; }
    public String getChannelType() { return channelType; }
    public void setChannelType(String channelType) { this.channelType = channelType; }
    public String getRecipient() { return recipient; }
    public void setRecipient(String recipient) { this.recipient = recipient; }
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    public String getSubject() { return subject; }
    public void setSubject(String subject) { this.subject = subject; }
    public String getBody() { return body; }
    public void setBody(String body) { this.body = body; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public void setErrorMessage(String msg) { this.errorMessage = msg; }
    public void setSentAt(Instant sentAt) { this.sentAt = sentAt; }
    public void setChannelId(Long channelId) { this.channelId = channelId; }

    @PrePersist
    protected void onCreate() { createdAt = Instant.now(); }
}
