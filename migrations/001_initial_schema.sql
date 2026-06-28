-- SentinelMark v2 — Initial Database Schema

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     TEXT NOT NULL UNIQUE,
    display_name TEXT,
    email       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_users_user_id ON users (user_id);

CREATE TABLE IF NOT EXISTS devices (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id   TEXT NOT NULL,
    fingerprint TEXT,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, device_id)
);
CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices (user_id);

CREATE TABLE IF NOT EXISTS behavior_profiles (
    id                        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id                   TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE UNIQUE,
    known_devices             JSONB NOT NULL DEFAULT '[]',
    known_regions             JSONB NOT NULL DEFAULT '[]',
    avg_transaction_amount    DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    avg_login_hour            DOUBLE PRECISION,
    avg_session_duration_secs BIGINT,
    historical_trust_avg      DOUBLE PRECISION,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_behavior_profiles_user_id ON behavior_profiles (user_id);

CREATE TABLE IF NOT EXISTS telemetry_events (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id               TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id             TEXT NOT NULL,
    browser_fingerprint   TEXT NOT NULL DEFAULT '',
    ip_address            TEXT NOT NULL DEFAULT '',
    geo_region            TEXT NOT NULL DEFAULT '',
    action_type           TEXT NOT NULL,
    transaction_amount    DOUBLE PRECISION,
    session_duration_secs BIGINT,
    recorded_at           TIMESTAMPTZ NOT NULL,
    ingested_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_telemetry_user_id ON telemetry_events (user_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_recorded_at ON telemetry_events (recorded_at DESC);

CREATE TABLE IF NOT EXISTS evaluations (
    id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id            TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    telemetry_event_id UUID REFERENCES telemetry_events(id),
    risk_score         DOUBLE PRECISION NOT NULL,
    trust_score        DOUBLE PRECISION NOT NULL,
    decision           TEXT NOT NULL,
    requires_multi_sig BOOLEAN NOT NULL DEFAULT FALSE,
    risk_factors       JSONB NOT NULL DEFAULT '[]',
    explanation        TEXT NOT NULL DEFAULT '',
    evaluation_time_ms BIGINT,
    evaluated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_evaluations_user_id ON evaluations (user_id);
CREATE INDEX IF NOT EXISTS idx_evaluations_evaluated_at ON evaluations (evaluated_at DESC);

CREATE TABLE IF NOT EXISTS audit_logs (
    id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id            TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    evaluation_id      UUID REFERENCES evaluations(id),
    trust_score        DOUBLE PRECISION NOT NULL,
    risk_score         DOUBLE PRECISION NOT NULL,
    decision           TEXT NOT NULL,
    anomalies          JSONB NOT NULL DEFAULT '[]',
    policy_decision    TEXT NOT NULL,
    explanation        TEXT NOT NULL DEFAULT '',
    evaluation_time_ms BIGINT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at DESC);

CREATE TABLE IF NOT EXISTS sessions (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id       TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id     TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active',
    started_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at      TIMESTAMPTZ,
    last_activity TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions (status);
