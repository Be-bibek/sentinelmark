-- SentinelMark Phase 2: Developer Portal & Team Management

-- ─── Team Members ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS team_members (
    id         UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id  UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       VARCHAR(100) NOT NULL,
    email      VARCHAR(255) NOT NULL,
    role       VARCHAR(20) NOT NULL DEFAULT 'developer' CHECK (role IN ('owner', 'admin', 'developer', 'read_only')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);

CREATE INDEX IF NOT EXISTS idx_team_members_tenant ON team_members(tenant_id);

-- ─── Default Data Backfill ───────────────────────────────────────────────────

DO $$
DECLARE
    v_tenant_id UUID;
BEGIN
    -- Find the demo tenant created in 002
    SELECT id INTO v_tenant_id FROM tenants WHERE name = 'SentinelMark Demo' LIMIT 1;

    IF v_tenant_id IS NOT NULL THEN
        -- Insert a default owner
        INSERT INTO team_members (tenant_id, name, email, role)
        VALUES (v_tenant_id, 'Demo User', 'demo@sentinelmark.dev', 'owner')
        ON CONFLICT (tenant_id, email) DO NOTHING;
        
        RAISE NOTICE 'Added default owner to Demo Tenant.';
    END IF;
END;
$$;
