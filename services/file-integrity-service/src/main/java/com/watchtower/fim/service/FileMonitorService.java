package com.watchtower.fim.service;

import com.watchtower.common.config.KafkaTopics;
import com.watchtower.common.event.FileIntegrityEvent;
import com.watchtower.fim.entity.FileBaseline;
import com.watchtower.fim.repository.FileBaselineRepository;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Monitors directories for file changes using Java WatchService.
 * Computes SHA-256 hashes and publishes FileIntegrityEvents to Kafka.
 */
@Service
public class FileMonitorService {

    private static final Logger log = LoggerFactory.getLogger(FileMonitorService.class);

    @Value("${watchtower.fim.watch-path:/watch}")
    private String watchPath;

    private final FileBaselineRepository baselineRepository;
    private final KafkaTemplate<String, FileIntegrityEvent> kafkaTemplate;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private volatile boolean running = true;

    public FileMonitorService(FileBaselineRepository baselineRepository,
                               KafkaTemplate<String, FileIntegrityEvent> kafkaTemplate) {
        this.baselineRepository = baselineRepository;
        this.kafkaTemplate = kafkaTemplate;
    }

    @PostConstruct
    public void start() {
        executor.submit(this::watchDirectory);
        log.info("File integrity monitoring started for: {}", watchPath);
    }

    @PreDestroy
    public void stop() {
        running = false;
        executor.shutdownNow();
    }

    private void watchDirectory() {
        Path dir = Paths.get(watchPath);
        if (!Files.exists(dir)) {
            log.warn("Watch directory does not exist: {}. Creating it.", watchPath);
            try { Files.createDirectories(dir); } catch (IOException e) {
                log.error("Failed to create watch directory", e); return;
            }
        }

        try (WatchService watcher = FileSystems.getDefault().newWatchService()) {
            dir.register(watcher,
                    StandardWatchEventKinds.ENTRY_CREATE,
                    StandardWatchEventKinds.ENTRY_MODIFY,
                    StandardWatchEventKinds.ENTRY_DELETE);

            while (running) {
                WatchKey key = watcher.poll(1, java.util.concurrent.TimeUnit.SECONDS);
                if (key == null) continue;

                for (WatchEvent<?> watchEvent : key.pollEvents()) {
                    WatchEvent.Kind<?> kind = watchEvent.kind();
                    if (kind == StandardWatchEventKinds.OVERFLOW) continue;

                    Path changed = dir.resolve((Path) watchEvent.context());
                    processFileChange(changed, kind);
                }
                key.reset();
            }
        } catch (IOException | InterruptedException e) {
            if (running) log.error("WatchService error", e);
        }
    }

    private void processFileChange(Path filePath, WatchEvent.Kind<?> kind) {
        String absPath = filePath.toAbsolutePath().toString();
        String changeType = mapChangeType(kind);

        log.info("File change detected: {} [{}]", absPath, changeType);

        var existing = baselineRepository.findByFilePath(absPath).orElse(null);
        String oldHash = existing != null ? existing.getSha256Hash() : null;
        String oldPerms = existing != null ? existing.getPermissions() : null;
        String newHash = null;
        String newPerms = null;
        long fileSize = 0;
        String owner = "unknown";

        if (kind != StandardWatchEventKinds.ENTRY_DELETE && Files.exists(filePath)) {
            newHash = computeSha256(filePath);
            newPerms = getPermissions(filePath);
            try {
                fileSize = Files.size(filePath);
                owner = Files.getOwner(filePath).getName();
            } catch (IOException ignored) {}

            // Update or create baseline
            if (existing != null) {
                existing.setSha256Hash(newHash);
                existing.setPermissions(newPerms);
                existing.setFileSize(fileSize);
                existing.setOwner(owner);
                existing.setLastScanned(Instant.now());
                baselineRepository.save(existing);
            } else {
                FileBaseline baseline = new FileBaseline();
                baseline.setDirectoryId(1L);
                baseline.setFilePath(absPath);
                baseline.setSha256Hash(newHash);
                baseline.setPermissions(newPerms);
                baseline.setFileSize(fileSize);
                baseline.setOwner(owner);
                baseline.setLastScanned(Instant.now());
                baselineRepository.save(baseline);
            }
        } else if (kind == StandardWatchEventKinds.ENTRY_DELETE && existing != null) {
            baselineRepository.delete(existing);
        }

        // Publish event to Kafka
        FileIntegrityEvent event = new FileIntegrityEvent(
                UUID.randomUUID().toString(),
                Instant.now(),
                absPath, changeType,
                oldHash, newHash,
                oldPerms, newPerms,
                fileSize, owner
        );
        kafkaTemplate.send(KafkaTopics.FIM_EVENTS, watchPath, event);
    }

    private String mapChangeType(WatchEvent.Kind<?> kind) {
        if (kind == StandardWatchEventKinds.ENTRY_CREATE) return "CREATED";
        if (kind == StandardWatchEventKinds.ENTRY_MODIFY) return "MODIFIED";
        if (kind == StandardWatchEventKinds.ENTRY_DELETE) return "DELETED";
        return "UNKNOWN";
    }

    String computeSha256(Path path) {
        try (InputStream is = Files.newInputStream(path)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[8192];
            int read;
            while ((read = is.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (Exception e) {
            log.error("Failed to compute SHA-256 for {}", path, e);
            return "ERROR";
        }
    }

    private String getPermissions(Path path) {
        try {
            return PosixFilePermissions.toString(Files.getPosixFilePermissions(path));
        } catch (Exception e) {
            return "unknown";
        }
    }
}
