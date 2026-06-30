-- SentinelMark Phase 5: Policy Engine

-- ─── Policy Variables ────────────────────────────────────────────────────────
-- Project-level constants (e.g. HIGH_RISK_THRESHOLD = 0.85)

CREATE TABLE IF NOT EXISTS policy_variables (
    id         UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name       VARCHAR(100) NOT NULL,
    value      JSONB       NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, name)
);

CREATE INDEX IF NOT EXISTS idx_policy_variables_project ON policy_variables(project_id);

-- ─── Policies ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS policies (
    id         UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id  UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id UUID        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name       VARCHAR(100) NOT NULL,
    description TEXT,
    status     VARCHAR(20) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'archived', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policies_project ON policies(project_id);

-- ─── Policy Versions ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS policy_versions (
    id             UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id      UUID        NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    version_number INT         NOT NULL,
    rules          JSONB       NOT NULL, -- The AST
    created_by     VARCHAR(255),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(policy_id, version_number)
);

-- Note: active_version_id references the currently active version.
ALTER TABLE policies ADD COLUMN IF NOT EXISTS active_version_id UUID REFERENCES policy_versions(id) ON DELETE SET NULL;

-- ─── Policy Simulations ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS policy_simulations (
    id                UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_version_id UUID        NOT NULL REFERENCES policy_versions(id) ON DELETE CASCADE,
    project_id        UUID        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    status            VARCHAR(20) NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed')),
    events_analyzed   INT         NOT NULL DEFAULT 0,
    results           JSONB       NOT NULL DEFAULT '{}',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at      TIMESTAMPTZ
);

-- ─── Rule Metrics ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS rule_metrics (
    id             UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id      UUID        NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    rule_id        VARCHAR(100) NOT NULL, -- The ID in the JSON AST
    evaluations    BIGINT      NOT NULL DEFAULT 0,
    matches        BIGINT      NOT NULL DEFAULT 0,
    actions_taken  JSONB       NOT NULL DEFAULT '{}',
    avg_latency_ms FLOAT       NOT NULL DEFAULT 0.0,
    last_matched   TIMESTAMPTZ,
    UNIQUE(policy_id, rule_id)
);
