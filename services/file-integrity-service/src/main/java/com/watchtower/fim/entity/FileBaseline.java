package com.watchtower.fim.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "file_baselines")
public class FileBaseline {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "directory_id", nullable = false)
    private Long directoryId;

    @Column(name = "file_path", unique = true, nullable = false)
    private String filePath;

    @Column(name = "sha256_hash", nullable = false, length = 64)
    private String sha256Hash;

    private String permissions;
    private String owner;

    @Column(name = "file_size")
    private long fileSize;

    @Column(name = "last_scanned")
    private Instant lastScanned;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    // ── Getters & Setters ──
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public Long getDirectoryId() { return directoryId; }
    public void setDirectoryId(Long directoryId) { this.directoryId = directoryId; }
    public String getFilePath() { return filePath; }
    public void setFilePath(String filePath) { this.filePath = filePath; }
    public String getSha256Hash() { return sha256Hash; }
    public void setSha256Hash(String sha256Hash) { this.sha256Hash = sha256Hash; }
    public String getPermissions() { return permissions; }
    public void setPermissions(String permissions) { this.permissions = permissions; }
    public String getOwner() { return owner; }
    public void setOwner(String owner) { this.owner = owner; }
    public long getFileSize() { return fileSize; }
    public void setFileSize(long fileSize) { this.fileSize = fileSize; }
    public Instant getLastScanned() { return lastScanned; }
    public void setLastScanned(Instant lastScanned) { this.lastScanned = lastScanned; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }

    @PrePersist
    protected void onCreate() { createdAt = updatedAt = Instant.now(); }
    @PreUpdate
    protected void onUpdate() { updatedAt = Instant.now(); }
}
