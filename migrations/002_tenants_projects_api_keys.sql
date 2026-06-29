-- SentinelMark v2 — Multi-Tenant API Key Architecture
-- Hierarchy: Tenant → Project → API Key → Evaluations

-- ─── Tenants ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tenants (
    id         UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    name       TEXT        NOT NULL,
    status     TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants (status);

-- ─── Projects ────────────────────────────────────────────────────────────────
-- One tenant can have many projects (e.g. "Mobile App", "Web Portal")

CREATE TABLE IF NOT EXISTS projects (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT        NOT NULL,
    environment TEXT        NOT NULL DEFAULT 'live' CHECK (environment IN ('live', 'test', 'dev')),
    status      TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_projects_tenant_id  ON projects (tenant_id);
CREATE INDEX IF NOT EXISTS idx_projects_status     ON projects (status);

-- ─── API Keys ────────────────────────────────────────────────────────────────
-- Scoped to a project. key_hash is SHA-256 of the raw key (never stored plain).
-- prefix stores e.g. "sm_live_" for display only.

CREATE TABLE IF NOT EXISTS api_keys (
    id               UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id       UUID        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name             TEXT        NOT NULL DEFAULT 'Default Key',
    key_hash         TEXT        NOT NULL UNIQUE,
    key_prefix       TEXT        NOT NULL,   -- e.g. "sm_live_abc12" (first 16 chars, safe to display)
    is_active        BOOLEAN     NOT NULL DEFAULT TRUE,
    rate_limit_rpm   INTEGER     NOT NULL DEFAULT 60,  -- requests per minute
    last_used_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash   ON api_keys (key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_project_id ON api_keys (project_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_active     ON api_keys (is_active);

-- ─── Usage Records ───────────────────────────────────────────────────────────
-- Lightweight append-only log for billing and analytics

CREATE TABLE IF NOT EXISTS usage_records (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    api_key_id  UUID        NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    project_id  UUID        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tenant_id   UUID        NOT NULL REFERENCES tenants(id)  ON DELETE CASCADE,
    endpoint    TEXT        NOT NULL,
    status_code INTEGER     NOT NULL DEFAULT 200,
    latency_ms  BIGINT,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_usage_records_api_key_id  ON usage_records (api_key_id);
CREATE INDEX IF NOT EXISTS idx_usage_records_tenant_id   ON usage_records (tenant_id);
CREATE INDEX IF NOT EXISTS idx_usage_records_recorded_at ON usage_records (recorded_at DESC);

-- ─── Add tenant/project scoping to core tables ───────────────────────────────

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS tenant_id  UUID REFERENCES tenants(id),
    ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id);

ALTER TABLE evaluations
    ADD COLUMN IF NOT EXISTS tenant_id  UUID REFERENCES tenants(id),
    ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id);

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS tenant_id  UUID REFERENCES tenants(id),
    ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id);

ALTER TABLE telemetry_events
    ADD COLUMN IF NOT EXISTS tenant_id  UUID REFERENCES tenants(id),
    ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id);

-- ─── Backfill: Default Tenant & Project for existing demo data ────────────────

DO $$
DECLARE
    v_tenant_id  UUID;
    v_project_id UUID;
    v_key_id     UUID;
BEGIN
    -- Create default demo tenant
    INSERT INTO tenants (name, status)
    VALUES ('SentinelMark Demo', 'active')
    ON CONFLICT DO NOTHING
    RETURNING id INTO v_tenant_id;

    -- Handle case where tenant already exists
    IF v_tenant_id IS NULL THEN
        SELECT id INTO v_tenant_id FROM tenants WHERE name = 'SentinelMark Demo' LIMIT 1;
    END IF;

    -- Create default project under the demo tenant
    INSERT INTO projects (tenant_id, name, environment, status)
    VALUES (v_tenant_id, 'Demo Project', 'live', 'active')
    ON CONFLICT DO NOTHING
    RETURNING id INTO v_project_id;

    IF v_project_id IS NULL THEN
        SELECT id INTO v_project_id FROM projects WHERE tenant_id = v_tenant_id LIMIT 1;
    END IF;

    -- Create the seeded demo API key (hash of "sm_live_sentinelmark_demo_key_2024")
    -- SHA-256: use this raw key in your .env or API Explorer for testing
    INSERT INTO api_keys (project_id, name, key_hash, key_prefix, is_active, rate_limit_rpm)
    VALUES (
        v_project_id,
        'Demo Key',
        -- SHA-256 of: sm_live_sentinelmark_demo_key_2024
        'a3f8d2b1c9e4a7f6b2d3e8c1a9f4b7d2e3c8a1f6b9d4e7c2a8f1b3d6e9c4a7',
        'sm_live_sentim',
        TRUE,
        120
    )
    ON CONFLICT (key_hash) DO NOTHING
    RETURNING id INTO v_key_id;

    -- Backfill existing rows with default tenant/project
    UPDATE users           SET tenant_id = v_tenant_id, project_id = v_project_id WHERE tenant_id IS NULL;
    UPDATE evaluations     SET tenant_id = v_tenant_id, project_id = v_project_id WHERE tenant_id IS NULL;
    UPDATE audit_logs      SET tenant_id = v_tenant_id, project_id = v_project_id WHERE tenant_id IS NULL;
    UPDATE telemetry_events SET tenant_id = v_tenant_id, project_id = v_project_id WHERE tenant_id IS NULL;

    RAISE NOTICE 'Backfill complete. tenant_id=%, project_id=%', v_tenant_id, v_project_id;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_users_tenant_id            ON users (tenant_id);
CREATE INDEX IF NOT EXISTS idx_evaluations_tenant_id      ON evaluations (tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_id       ON audit_logs (tenant_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_events_tenant_id ON telemetry_events (tenant_id);
