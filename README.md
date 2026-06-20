# 🔭 WatchTower

**AI-Powered Cybersecurity Threat Detection Platform**

A production-grade microservices system demonstrating event-driven architecture, real-time security monitoring, and applied threat detection engineering.

## Features

- **Real-Time Log Ingestion** — Parses syslog, auth.log, and Nginx logs into a normalized schema
- **Rule-Based Detection** — Configurable rules: brute force, port scan, privilege escalation, suspicious user agents
- **Statistical Anomaly Detection** — Login frequency z-score analysis, time-of-day deviation detection
- **File Integrity Monitoring** — SHA-256 baseline tracking with Java WatchService
- **Live Alert Dashboard** — WebSocket-powered real-time alert feed with Recharts visualizations
- **Alert Deduplication** — Redis-based storm suppression (5-minute sliding window)
- **Severity-Based Notifications** — Email routing by alert severity

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for full details with diagrams.

```
WatchTower/
├── services/
│   ├── api-gateway/               # Spring Cloud Gateway — JWT, rate limiting
│   ├── log-ingestion-service/     # Log parsing, Kafka producer, ES indexing
│   ├── threat-detection-service/  # Rule engine, anomaly detection, Redis dedup
│   ├── file-integrity-service/    # WatchService, SHA-256 baselines
│   ├── notification-service/      # Email/Telegram notifications
│   └── alert-dashboard-service/   # REST + WebSocket BFF
├── common/watchtower-common/      # Shared DTOs, events, enums
├── frontend/                      # React dashboard
├── docker-compose.yml
└── ARCHITECTURE.md
```

## Tech Stack

Java 21 · Spring Boot 3.3 · Apache Kafka (KRaft) · PostgreSQL 16 · Redis 7 · Elasticsearch 8.13 · React 18 · Recharts · Docker

## Quick Start

```bash
# Build all services
mvn clean package -DskipTests

# Start everything
docker-compose up -d

# Open dashboard: http://localhost:3000
# Login: admin / admin123

# (Optional) Run log simulator for demo data
SPRING_PROFILES_ACTIVE=simulator mvn -pl services/log-ingestion-service spring-boot:run
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Kafka partitioned by `source_ip` | Enables per-IP threshold rules without distributed state |
| Redis SET NX for dedup | Atomic check-and-set with TTL for alert storm suppression |
| Statistical over ML | Honest engineering — z-score baselines cover 95% of real-world use cases |
| Per-service databases | No shared-DB anti-pattern — each service owns its data |
| Strategy pattern (parsers, detectors) | Open/Closed Principle — add formats without modifying existing code |

## License

MIT
