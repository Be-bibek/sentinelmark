-- Migration: 005_idempotency.sql
-- Purpose: Store idempotency keys for safely retrying API requests without duplicating side effects.

CREATE TABLE idempotency_keys (
    idempotency_key VARCHAR(255) NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    response_body JSONB NOT NULL,
    response_status INT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (project_id, idempotency_key)
);

-- Index to quickly clean up expired keys
CREATE INDEX idx_idempotency_keys_expires_at ON idempotency_keys(expires_at);
