-- SentinelMark Phase 1: Plugin-based Architecture

-- ─── Products (Central Catalog) ───────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS products (
    id         UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    slug       VARCHAR(50) NOT NULL UNIQUE,
    name       VARCHAR(100) NOT NULL,
    category   VARCHAR(50) NOT NULL,
    adapter    VARCHAR(50) NOT NULL,
    version    VARCHAR(20) NOT NULL,
    enabled    BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Project Products (Registry Mapping) ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS project_products (
    id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id    UUID        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    product_id    UUID        NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
    configuration JSONB       NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, product_id)
);

-- ─── Unified Trust Events (Central Ledger) ────────────────────────────────────

CREATE TABLE IF NOT EXISTS trust_events (
    id               UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id        UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id       UUID        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    product_slug     VARCHAR(50) NOT NULL REFERENCES products(slug) ON DELETE CASCADE,
    event_type       VARCHAR(100) NOT NULL,
    protocol_version VARCHAR(20) NOT NULL,
    sdk_version      VARCHAR(20) NOT NULL,
    severity         VARCHAR(20) NOT NULL,
    raw_payload      JSONB       NOT NULL,
    risk_score       FLOAT       NOT NULL DEFAULT 0.0,
    trust_score      FLOAT       NOT NULL DEFAULT 100.0,
    action_taken     VARCHAR(50) NOT NULL DEFAULT 'ALLOW',
    metadata         JSONB       NOT NULL DEFAULT '{}',
    timestamp        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_trust_events_tenant_product ON trust_events(tenant_id, product_slug);

-- ─── Default Data Backfill ───────────────────────────────────────────────────

DO $$
DECLARE
    v_dicom_id UUID;
    v_proof_id UUID;
    v_stellar_id UUID;
    v_project_id UUID;
BEGIN
    -- Insert default products
    INSERT INTO products (slug, name, category, adapter, version, enabled)
    VALUES 
        ('dicom-trace', 'DICOM Trace', 'medical', 'DicomAdapter', '1.0', TRUE),
        ('prooftrace-5g', 'ProofTrace 5G', 'telecom', 'ProofTraceAdapter', '1.0', TRUE),
        ('stellarflow', 'Stellar Flow', 'fintech', 'StellarAdapter', '1.0', TRUE)
    ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name
    RETURNING id INTO v_dicom_id;

    -- Fetch the IDs if they already existed
    SELECT id INTO v_dicom_id FROM products WHERE slug = 'dicom-trace';
    SELECT id INTO v_proof_id FROM products WHERE slug = 'prooftrace-5g';
    SELECT id INTO v_stellar_id FROM products WHERE slug = 'stellarflow';

    -- Find the demo project created in 002
    SELECT id INTO v_project_id FROM projects WHERE name = 'Demo Project' LIMIT 1;

    -- Map products to the demo project
    IF v_project_id IS NOT NULL THEN
        INSERT INTO project_products (project_id, product_id, enabled)
        VALUES 
            (v_project_id, v_dicom_id, TRUE),
            (v_project_id, v_proof_id, TRUE),
            (v_project_id, v_stellar_id, TRUE)
        ON CONFLICT (project_id, product_id) DO NOTHING;
        
        RAISE NOTICE 'Mapped default products to Demo Project.';
    END IF;
END;
$$;
