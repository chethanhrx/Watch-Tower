package com.watchtower.ingestion.simulator;

import com.watchtower.ingestion.service.LogIngestionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Log simulator for demo/development — generates realistic-looking
 * security events to exercise the full pipeline without real log sources.
 *
 * Activate with: --spring.profiles.active=simulator
 */
@Component
@Profile("simulator")
public class LogSimulator implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(LogSimulator.class);
    private final LogIngestionService ingestionService;
    private final Random random = new Random();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private static final List<String> ATTACKER_IPS = List.of(
            "203.0.113.42", "198.51.100.17", "192.0.2.99", "45.33.32.156",
            "185.220.101.1", "91.121.87.18"
    );
    private static final List<String> NORMAL_IPS = List.of(
            "10.0.1.50", "10.0.1.51", "10.0.2.30", "172.16.0.100", "192.168.1.10"
    );
    private static final List<String> USERNAMES = List.of(
            "admin", "root", "deploy", "jenkins", "postgres", "ubuntu", "john", "alice"
    );
    private static final List<String> HOSTS = List.of(
            "web-prod-01", "web-prod-02", "db-master", "api-server", "bastion-host"
    );
    private static final List<String> MALICIOUS_UAS = List.of(
            "sqlmap/1.5", "Nikto/2.1.6", "Nmap Scripting Engine",
            "Mozilla/5.0 (compatible; Googlebot/2.1)", "dirbuster/1.0"
    );

    public LogSimulator(LogIngestionService ingestionService) {
        this.ingestionService = ingestionService;
    }

    @Override
    public void run(String... args) {
        log.info("🔄 Log Simulator started — generating events every 2-5 seconds");
        scheduler.scheduleAtFixedRate(this::generateEvent, 1, 2, TimeUnit.SECONDS);
    }

    private void generateEvent() {
        try {
            String logLine = switch (random.nextInt(10)) {
                case 0, 1, 2 -> generateFailedLogin();
                case 3 -> generateSuccessLogin();
                case 4 -> generateSudoCommand();
                case 5, 6 -> generateNginxRequest();
                case 7 -> generateSuspiciousNginxRequest();
                case 8 -> generateBruteForce();
                case 9 -> generateSyslogEvent();
                default -> generateFailedLogin();
            };
            ingestionService.ingest(logLine, null);
        } catch (Exception e) {
            log.error("Simulator error: {}", e.getMessage());
        }
    }

    private String generateFailedLogin() {
        String ip = randomFrom(ATTACKER_IPS);
        String user = randomFrom(USERNAMES);
        String host = randomFrom(HOSTS);
        return String.format("%s %s sshd[%d]: Failed password for %s from %s port %d ssh2",
                syslogTimestamp(), host, random.nextInt(30000) + 1000,
                user, ip, random.nextInt(60000) + 1024);
    }

    private String generateSuccessLogin() {
        String ip = randomFrom(NORMAL_IPS);
        String user = randomFrom(List.of("deploy", "jenkins", "alice"));
        String host = randomFrom(HOSTS);
        return String.format("%s %s sshd[%d]: Accepted publickey for %s from %s port %d ssh2",
                syslogTimestamp(), host, random.nextInt(30000) + 1000,
                user, ip, random.nextInt(60000) + 1024);
    }

    private String generateSudoCommand() {
        String user = randomFrom(List.of("deploy", "ubuntu"));
        String host = randomFrom(HOSTS);
        return String.format("%s %s sudo: %s : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
                syslogTimestamp(), host, user);
    }

    private String generateNginxRequest() {
        String ip = randomFrom(NORMAL_IPS);
        String[] paths = {"/api/v1/users", "/dashboard", "/api/v1/health", "/login", "/static/app.js"};
        return String.format("%s - - [%s] \"GET %s HTTP/1.1\" 200 %d \"-\" \"Mozilla/5.0 (X11; Linux x86_64)\"",
                ip, nginxTimestamp(), randomFrom(List.of(paths)),
                random.nextInt(50000) + 100);
    }

    private String generateSuspiciousNginxRequest() {
        String ip = randomFrom(ATTACKER_IPS);
        String ua = randomFrom(MALICIOUS_UAS);
        String[] paths = {"/admin", "/../etc/passwd", "/.env", "/wp-login.php", "/api/v1/users?id=1 OR 1=1"};
        return String.format("%s - - [%s] \"GET %s HTTP/1.1\" 403 %d \"-\" \"%s\"",
                ip, nginxTimestamp(), randomFrom(List.of(paths)),
                random.nextInt(1000) + 100, ua);
    }

    private String generateBruteForce() {
        // Generate a burst of failed logins from one IP
        String ip = randomFrom(ATTACKER_IPS);
        String host = randomFrom(HOSTS);
        StringBuilder sb = new StringBuilder();
        String logLine = String.format(
                "%s %s sshd[%d]: Failed password for invalid user admin from %s port %d ssh2",
                syslogTimestamp(), host, random.nextInt(30000) + 1000,
                ip, random.nextInt(60000) + 1024);
        ingestionService.ingest(logLine, null);
        return String.format(
                "%s %s sshd[%d]: Failed password for root from %s port %d ssh2",
                syslogTimestamp(), host, random.nextInt(30000) + 1000,
                ip, random.nextInt(60000) + 1024);
    }

    private String generateSyslogEvent() {
        String host = randomFrom(HOSTS);
        return String.format("%s %s kernel[0]: TCP connection from %s port %d accepted",
                syslogTimestamp(), host, randomFrom(NORMAL_IPS),
                random.nextInt(60000) + 1024);
    }

    private String syslogTimestamp() {
        return LocalDateTime.now().format(
                DateTimeFormatter.ofPattern("MMM dd HH:mm:ss", Locale.ENGLISH));
    }

    private String nginxTimestamp() {
        return LocalDateTime.now().format(
                DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss +0000", Locale.ENGLISH));
    }

    private <T> T randomFrom(List<T> list) {
        return list.get(random.nextInt(list.size()));
    }
}
