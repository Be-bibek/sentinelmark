-- SentinelMark v2 Schema

CREATE TABLE IF NOT EXISTS behavior_profiles (
    user_id VARCHAR(255) PRIMARY KEY,
    profile_data JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,
    trust_score DOUBLE PRECISION NOT NULL,
    decision VARCHAR(50) NOT NULL,
    reasons JSONB NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL
);
