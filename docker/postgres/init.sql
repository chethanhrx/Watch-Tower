-- ============================================================
-- WatchTower — PostgreSQL Initialization Script
-- Creates per-service databases (no shared-DB anti-pattern)
-- ============================================================

-- Service databases
CREATE DATABASE gateway_db;
CREATE DATABASE ingestion_db;
CREATE DATABASE detection_db;
CREATE DATABASE fim_db;
CREATE DATABASE notification_db;

-- Grant full privileges to the watchtower user on each database
GRANT ALL PRIVILEGES ON DATABASE gateway_db TO watchtower;
GRANT ALL PRIVILEGES ON DATABASE ingestion_db TO watchtower;
GRANT ALL PRIVILEGES ON DATABASE detection_db TO watchtower;
GRANT ALL PRIVILEGES ON DATABASE fim_db TO watchtower;
GRANT ALL PRIVILEGES ON DATABASE notification_db TO watchtower;

-- ============================================================
-- Gateway DB: Users, API Keys
-- ============================================================
\connect gateway_db;

CREATE TABLE users (
    id              BIGSERIAL PRIMARY KEY,
    username        VARCHAR(50)  UNIQUE NOT NULL,
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    role            VARCHAR(20)  NOT NULL DEFAULT 'ANALYST',
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE refresh_tokens (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT       NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token           VARCHAR(512) UNIQUE NOT NULL,
    expires_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);

-- Seed a default admin user (password: admin123 — BCrypt hash)
INSERT INTO users (username, email, password_hash, role) VALUES
    ('admin', 'admin@watchtower.io', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 'ADMIN');

-- ============================================================
-- Ingestion DB: Source configs, ingestion stats
-- ============================================================
\connect ingestion_db;

CREATE TABLE log_sources (
    id              BIGSERIAL PRIMARY KEY,
    name            VARCHAR(100) NOT NULL,
    source_type     VARCHAR(30)  NOT NULL,  -- SYSLOG, AUTH_LOG, NGINX, WINDOWS_EVENT
    host            VARCHAR(255),
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE ingestion_stats (
    id              BIGSERIAL PRIMARY KEY,
    source_id       BIGINT REFERENCES log_sources(id),
    events_received BIGINT       NOT NULL DEFAULT 0,
    events_parsed   BIGINT       NOT NULL DEFAULT 0,
    events_failed   BIGINT       NOT NULL DEFAULT 0,
    window_start    TIMESTAMP WITH TIME ZONE NOT NULL,
    window_end      TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_ingestion_stats_window ON ingestion_stats(window_start, window_end);

-- ============================================================
-- Detection DB: Rules, detection history, ML model metadata
-- ============================================================
\connect detection_db;

CREATE TABLE detection_rules (
    id              BIGSERIAL PRIMARY KEY,
    name            VARCHAR(100) NOT NULL,
    description     TEXT,
    rule_type       VARCHAR(30)  NOT NULL,  -- THRESHOLD, PATTERN, SEQUENCE, GEO_ANOMALY
    severity        VARCHAR(20)  NOT NULL,  -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    config          JSONB        NOT NULL,  -- Rule-specific configuration
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE detection_history (
    id              BIGSERIAL PRIMARY KEY,
    alert_id        VARCHAR(36)  UNIQUE NOT NULL,
    rule_id         BIGINT REFERENCES detection_rules(id),
    alert_type      VARCHAR(50)  NOT NULL,
    severity        VARCHAR(20)  NOT NULL,
    source_ip       VARCHAR(45),
    description     TEXT,
    confidence      DOUBLE PRECISION DEFAULT 1.0,
    detection_method VARCHAR(20) NOT NULL,  -- RULE, ML, STATISTICAL
    raw_event       JSONB,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE ml_model_metadata (
    id              BIGSERIAL PRIMARY KEY,
    model_name      VARCHAR(100) NOT NULL,
    model_version   VARCHAR(20)  NOT NULL,
    model_type      VARCHAR(50)  NOT NULL,  -- ISOLATION_FOREST, STATISTICAL_BASELINE
    status          VARCHAR(20)  NOT NULL DEFAULT 'ACTIVE',
    accuracy_score  DOUBLE PRECISION,
    trained_at      TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_detection_history_source_ip ON detection_history(source_ip);
CREATE INDEX idx_detection_history_created_at ON detection_history(created_at);
CREATE INDEX idx_detection_history_severity ON detection_history(severity);

-- Seed default detection rules
INSERT INTO detection_rules (name, description, rule_type, severity, config) VALUES
    ('Brute Force Login',
     'Detects multiple failed login attempts from the same IP within a time window',
     'THRESHOLD',
     'HIGH',
     '{"event_type": "AUTH_FAILURE", "threshold": 5, "window_seconds": 300, "group_by": "source_ip"}'::jsonb),

    ('Port Scan Detection',
     'Detects connection attempts to multiple ports from a single source IP',
     'THRESHOLD',
     'MEDIUM',
     '{"event_type": "CONNECTION_ATTEMPT", "threshold": 20, "window_seconds": 60, "group_by": "source_ip"}'::jsonb),

    ('Privilege Escalation',
     'Detects sudo/su usage or privilege change events',
     'PATTERN',
     'CRITICAL',
     '{"pattern": "(sudo|su\\s|COMMAND=|privilege|escalat)", "event_types": ["AUTH_SUCCESS", "SYSTEM_EVENT"], "case_insensitive": true}'::jsonb),

    ('Suspicious User Agent',
     'Detects known malicious or unusual user agents in HTTP requests',
     'PATTERN',
     'MEDIUM',
     '{"pattern": "(sqlmap|nikto|nmap|masscan|zgrab|dirbuster)", "field": "user_agent", "event_types": ["HTTP_REQUEST"], "case_insensitive": true}'::jsonb),

    ('Impossible Travel',
     'Detects logins from geographically distant locations within an impossible timeframe',
     'GEO_ANOMALY',
     'HIGH',
     '{"max_speed_kmh": 900, "min_distance_km": 500, "window_seconds": 3600, "event_types": ["AUTH_SUCCESS"]}'::jsonb);

-- Seed ML model metadata
INSERT INTO ml_model_metadata (model_name, model_version, model_type, status) VALUES
    ('login-frequency-baseline', '1.0.0', 'STATISTICAL_BASELINE', 'ACTIVE'),
    ('time-of-day-anomaly', '1.0.0', 'STATISTICAL_BASELINE', 'ACTIVE');

-- ============================================================
-- FIM DB: File baselines, monitored directories
-- ============================================================
\connect fim_db;

CREATE TABLE monitored_directories (
    id              BIGSERIAL PRIMARY KEY,
    path            VARCHAR(512) UNIQUE NOT NULL,
    recursive       BOOLEAN      NOT NULL DEFAULT TRUE,
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE file_baselines (
    id              BIGSERIAL PRIMARY KEY,
    directory_id    BIGINT       NOT NULL REFERENCES monitored_directories(id) ON DELETE CASCADE,
    file_path       VARCHAR(512) UNIQUE NOT NULL,
    sha256_hash     VARCHAR(64)  NOT NULL,
    permissions     VARCHAR(20),
    owner           VARCHAR(100),
    file_size       BIGINT       NOT NULL DEFAULT 0,
    last_scanned    TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE file_change_history (
    id              BIGSERIAL PRIMARY KEY,
    baseline_id     BIGINT REFERENCES file_baselines(id),
    file_path       VARCHAR(512) NOT NULL,
    change_type     VARCHAR(20)  NOT NULL,  -- CREATED, MODIFIED, DELETED, PERMISSION_CHANGED
    old_hash        VARCHAR(64),
    new_hash        VARCHAR(64),
    old_permissions VARCHAR(20),
    new_permissions VARCHAR(20),
    detected_at     TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_file_baselines_path ON file_baselines(file_path);
CREATE INDEX idx_file_change_history_detected_at ON file_change_history(detected_at);

-- Seed a default monitored directory
INSERT INTO monitored_directories (path, recursive) VALUES ('/watch', TRUE);

-- ============================================================
-- Notification DB: History, channels, preferences
-- ============================================================
\connect notification_db;

CREATE TABLE notification_channels (
    id              BIGSERIAL PRIMARY KEY,
    channel_type    VARCHAR(20)  NOT NULL,  -- EMAIL, TELEGRAM, WEBHOOK
    config          JSONB        NOT NULL,  -- Channel-specific config (SMTP, bot token, etc.)
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE notification_history (
    id              BIGSERIAL PRIMARY KEY,
    alert_id        VARCHAR(36)  NOT NULL,
    channel_id      BIGINT REFERENCES notification_channels(id),
    channel_type    VARCHAR(20)  NOT NULL,
    recipient       VARCHAR(255),
    severity        VARCHAR(20)  NOT NULL,
    subject         VARCHAR(255),
    body            TEXT,
    status          VARCHAR(20)  NOT NULL DEFAULT 'PENDING',  -- PENDING, SENT, FAILED
    error_message   TEXT,
    sent_at         TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_notification_history_alert_id ON notification_history(alert_id);
CREATE INDEX idx_notification_history_status ON notification_history(status);
CREATE INDEX idx_notification_history_created_at ON notification_history(created_at);

-- Seed a default email channel (placeholder config)
INSERT INTO notification_channels (channel_type, config) VALUES
    ('EMAIL', '{"smtp_host": "smtp.gmail.com", "smtp_port": 587, "from": "alerts@watchtower.io"}'::jsonb);
