-- Peg Integrity Monitor Schema
-- Stores time-series deviation data for Peg Stability charts and
-- Transparency Report (#140). Tracks de-peg events and time-to-recovery.

CREATE TABLE IF NOT EXISTS peg_deviation_snapshots (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    captured_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    dex_price       NUMERIC(20, 10) NOT NULL,   -- cNGN/NGN price on Stellar DEX
    oracle_price    NUMERIC(20, 10) NOT NULL,   -- Reference oracle price
    deviation_bps   NUMERIC(10, 4) NOT NULL,    -- (dex - oracle) / oracle * 10000
    alert_level     SMALLINT NOT NULL DEFAULT 0 -- 0=ok, 1=yellow, 2=orange, 3=red
);

CREATE INDEX IF NOT EXISTS idx_peg_snapshots_time
    ON peg_deviation_snapshots (captured_at DESC);

-- De-peg events: opened when level >= 1, closed when back to 0
CREATE TABLE IF NOT EXISTS peg_depeg_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at          TIMESTAMPTZ NOT NULL,
    resolved_at         TIMESTAMPTZ,
    peak_deviation_bps  NUMERIC(10, 4) NOT NULL DEFAULT 0,
    max_alert_level     SMALLINT NOT NULL DEFAULT 1,
    time_to_recovery_secs BIGINT,   -- NULL until resolved
    is_open             BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_peg_events_open ON peg_depeg_events (is_open);
