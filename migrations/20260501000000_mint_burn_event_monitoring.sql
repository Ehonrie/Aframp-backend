-- ============================================================================
-- MINT & BURN EVENT MONITORING SCHEMA
-- ============================================================================

-- ============================================================================
-- 1. PROCESSED_EVENTS TABLE
-- Deduplication + audit trail for all classified Stellar operations
-- ============================================================================
CREATE TABLE IF NOT EXISTS processed_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_hash    TEXT NOT NULL,
    operation_type      TEXT NOT NULL,
    ledger_id           BIGINT NOT NULL,
    created_at_chain    TIMESTAMPTZ NOT NULL,
    processed_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    asset_code          TEXT,
    asset_issuer        TEXT,
    amount              TEXT,
    source_account      TEXT NOT NULL,
    destination_account TEXT,
    raw_memo            TEXT,
    parsed_id           TEXT,
    CONSTRAINT uq_processed_events_tx_hash UNIQUE (transaction_hash)
);

CREATE INDEX IF NOT EXISTS idx_processed_events_ledger_id
    ON processed_events(ledger_id);

-- ============================================================================
-- 2. LEDGER_CURSOR TABLE
-- Single-row table for Horizon SSE stream resumption
-- ============================================================================
CREATE TABLE IF NOT EXISTS ledger_cursor (
    id          SERIAL PRIMARY KEY,
    cursor      TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed the singleton row
INSERT INTO ledger_cursor (cursor) VALUES ('now')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- 3. UNMATCHED_EVENTS TABLE
-- Operations whose memo could not be matched to a mint or redemption record
-- ============================================================================
CREATE TABLE IF NOT EXISTS unmatched_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_hash    TEXT NOT NULL,
    raw_memo            TEXT,
    raw_operation       JSONB NOT NULL,
    recorded_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_unmatched_events_recorded_at
    ON unmatched_events(recorded_at DESC);
