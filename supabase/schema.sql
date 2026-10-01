"""
CyberSafe — Supabase schema migration
Run this SQL inside the Supabase SQL editor (Dashboard → SQL Editor → New Query).

All tables have Row Level Security enabled.
The service-role key (server-side only) bypasses RLS for inserts.
No table ever stores the raw suspicious URL.
"""

-- ─────────────────────────────────────────────────────────────────────────────
-- Extension: pgcrypto for gen_random_uuid()
-- ─────────────────────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─────────────────────────────────────────────────────────────────────────────
-- scan_history: one row per analysed URL (hashed for privacy)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_history (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at    TIMESTAMPTZ NOT NULL    DEFAULT now(),
    url_hash      TEXT        NOT NULL,          -- SHA-256 of original URL
    hostname      TEXT        NOT NULL DEFAULT '',
    scheme        TEXT        NOT NULL DEFAULT '',
    verdict       TEXT        NOT NULL,          -- SAFE | REVIEW | SUSPICIOUS
    risk_score    INTEGER     NOT NULL DEFAULT 0,
    confidence    TEXT        NOT NULL DEFAULT '',
    finding_count INTEGER     NOT NULL DEFAULT 0,
    source        TEXT        NOT NULL DEFAULT 'api'
);

ALTER TABLE scan_history ENABLE ROW LEVEL SECURITY;

-- Admins (service role) can insert; no one else can read via API
CREATE POLICY "service_role_insert_scan_history"
    ON scan_history FOR INSERT
    TO service_role
    WITH CHECK (true);

-- ─────────────────────────────────────────────────────────────────────────────
-- profiles: per-user profile data (linked to Supabase Auth uid)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS profiles (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at    TIMESTAMPTZ NOT NULL    DEFAULT now(),
    display_name  TEXT,
    email         TEXT,
    role          TEXT        NOT NULL DEFAULT 'user'  -- user | admin
);

ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

-- Users can read/update their own profile only
CREATE POLICY "users_read_own_profile"
    ON profiles FOR SELECT
    USING (auth.uid() = id);

CREATE POLICY "users_update_own_profile"
    ON profiles FOR UPDATE
    USING (auth.uid() = id);

-- ─────────────────────────────────────────────────────────────────────────────
-- trusted_domains: campus administrator allowlist
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS trusted_domains (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at  TIMESTAMPTZ NOT NULL    DEFAULT now(),
    domain      TEXT        NOT NULL UNIQUE,
    description TEXT,
    enabled     BOOLEAN     NOT NULL DEFAULT true
);

ALTER TABLE trusted_domains ENABLE ROW LEVEL SECURITY;

-- Authenticated users can read trusted domains; only admins (service role) can write
CREATE POLICY "authenticated_read_trusted_domains"
    ON trusted_domains FOR SELECT
    TO authenticated
    USING (enabled = true);

CREATE POLICY "service_role_manage_trusted_domains"
    ON trusted_domains FOR ALL
    TO service_role
    WITH CHECK (true);

-- ─────────────────────────────────────────────────────────────────────────────
-- scan_events: lightweight analytics (no URL content)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_events (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at  TIMESTAMPTZ NOT NULL    DEFAULT now(),
    verdict     TEXT,
    score       INTEGER,
    source      TEXT        NOT NULL DEFAULT 'api'
);

ALTER TABLE scan_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY "service_role_insert_scan_events"
    ON scan_events FOR INSERT
    TO service_role
    WITH CHECK (true);

-- ─────────────────────────────────────────────────────────────────────────────
-- Indexes for common queries
-- ─────────────────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS ix_scan_history_created_at  ON scan_history  (created_at DESC);
CREATE INDEX IF NOT EXISTS ix_scan_history_verdict      ON scan_history  (verdict);
CREATE INDEX IF NOT EXISTS ix_scan_history_url_hash     ON scan_history  (url_hash);
CREATE INDEX IF NOT EXISTS ix_scan_events_created_at    ON scan_events   (created_at DESC);
CREATE INDEX IF NOT EXISTS ix_trusted_domains_domain    ON trusted_domains (domain);

-- ─────────────────────────────────────────────────────────────────────────────
-- recon_history: stores Safe Recon scan results
-- result_json stores the full structured recon payload
-- No raw URL stored — only the hostname and a truncated target for display
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS recon_history (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at   TIMESTAMPTZ NOT NULL    DEFAULT now(),
    target_url   TEXT        NOT NULL,          -- truncated display URL (not full raw URL for privacy)
    hostname     TEXT        NOT NULL DEFAULT '',
    risk_score   INTEGER     NOT NULL DEFAULT 0,
    risk_level   TEXT        NOT NULL DEFAULT '',  -- SAFE | LOW | MEDIUM | HIGH | CRITICAL
    summary      TEXT        NOT NULL DEFAULT '',
    result_json  JSONB,
    source       TEXT        NOT NULL DEFAULT 'api'
);

ALTER TABLE recon_history ENABLE ROW LEVEL SECURITY;

CREATE POLICY "service_role_insert_recon_history"
    ON recon_history FOR INSERT
    TO service_role
    WITH CHECK (true);

CREATE INDEX IF NOT EXISTS ix_recon_history_created_at ON recon_history (created_at DESC);
CREATE INDEX IF NOT EXISTS ix_recon_history_hostname    ON recon_history (hostname);
