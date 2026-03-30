-- Liquidity Pool Architecture Migration
-- Covers: pool records, segments, allocations, utilisation, and seed data

-- ── Pool records ─────────────────────────────────────────────────────────────

CREATE TYPE pool_type AS ENUM ('retail', 'wholesale', 'institutional');
CREATE TYPE pool_status AS ENUM ('active', 'paused', 'deactivated');

CREATE TABLE liquidity_pools (
    pool_id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    currency_pair            VARCHAR(20)    NOT NULL,          -- e.g. 'cNGN/NGN'
    pool_type                pool_type      NOT NULL,
    total_liquidity_depth    NUMERIC(28,8)  NOT NULL DEFAULT 0,
    available_liquidity      NUMERIC(28,8)  NOT NULL DEFAULT 0,
    reserved_liquidity       NUMERIC(28,8)  NOT NULL DEFAULT 0,
    min_liquidity_threshold  NUMERIC(28,8)  NOT NULL,
    target_liquidity_level   NUMERIC(28,8)  NOT NULL,
    max_liquidity_cap        NUMERIC(28,8)  NOT NULL,
    pool_status              pool_status    NOT NULL DEFAULT 'active',
    created_at               TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_liquidity_consistency
        CHECK (available_liquidity + reserved_liquidity <= total_liquidity_depth),
    CONSTRAINT chk_thresholds
        CHECK (min_liquidity_threshold <= target_liquidity_level
               AND target_liquidity_level <= max_liquidity_cap)
);

CREATE UNIQUE INDEX idx_liquidity_pools_pair_type
    ON liquidity_pools (currency_pair, pool_type);

-- ── Liquidity allocations ─────────────────────────────────────────────────────

CREATE TABLE liquidity_allocations (
    allocation_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pool_id                    UUID        NOT NULL REFERENCES liquidity_pools(pool_id),
    liquidity_provider_id      UUID        NOT NULL,
    allocated_amount           NUMERIC(28,8) NOT NULL,
    allocation_timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lock_period_seconds        BIGINT      NOT NULL DEFAULT 0,
    withdrawal_eligibility_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_liq_alloc_pool ON liquidity_allocations(pool_id);
CREATE INDEX idx_liq_alloc_provider ON liquidity_allocations(liquidity_provider_id);

-- ── Liquidity reservations ────────────────────────────────────────────────────

CREATE TYPE reservation_status AS ENUM ('active', 'consumed', 'released', 'timed_out');

CREATE TABLE liquidity_reservations (
    reservation_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pool_id          UUID           NOT NULL REFERENCES liquidity_pools(pool_id),
    transaction_id   UUID           NOT NULL,
    reserved_amount  NUMERIC(28,8)  NOT NULL,
    status           reservation_status NOT NULL DEFAULT 'active',
    reserved_at      TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ    NOT NULL,
    resolved_at      TIMESTAMPTZ
);

CREATE INDEX idx_liq_res_pool       ON liquidity_reservations(pool_id);
CREATE INDEX idx_liq_res_txn        ON liquidity_reservations(transaction_id);
CREATE INDEX idx_liq_res_status     ON liquidity_reservations(status);
CREATE INDEX idx_liq_res_expires    ON liquidity_reservations(expires_at)
    WHERE status = 'active';

-- ── Pool utilisation snapshots ────────────────────────────────────────────────

CREATE TABLE pool_utilisation (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pool_id                   UUID        NOT NULL REFERENCES liquidity_pools(pool_id),
    period                    VARCHAR(20) NOT NULL,   -- 'hourly' | 'daily'
    period_start              TIMESTAMPTZ NOT NULL,
    total_transaction_volume  NUMERIC(28,8) NOT NULL DEFAULT 0,
    peak_utilisation_pct      NUMERIC(5,2)  NOT NULL DEFAULT 0,
    avg_utilisation_pct       NUMERIC(5,2)  NOT NULL DEFAULT 0,
    liquidity_provider_count  INT           NOT NULL DEFAULT 0,
    created_at                TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_pool_util_pool_period ON pool_utilisation(pool_id, period_start DESC);

-- ── Pool health snapshots ─────────────────────────────────────────────────────

CREATE TABLE pool_health_snapshots (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pool_id                  UUID          NOT NULL REFERENCES liquidity_pools(pool_id),
    utilisation_pct          NUMERIC(5,2)  NOT NULL,
    available_depth          NUMERIC(28,8) NOT NULL,
    distance_from_min        NUMERIC(28,8) NOT NULL,
    distance_from_target     NUMERIC(28,8) NOT NULL,
    effective_depth          NUMERIC(28,8) NOT NULL,
    snapshotted_at           TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_pool_health_pool_time ON pool_health_snapshots(pool_id, snapshotted_at DESC);

-- ── Seed: initial pool configurations ────────────────────────────────────────
-- cNGN/NGN pools

INSERT INTO liquidity_pools
    (currency_pair, pool_type, min_liquidity_threshold, target_liquidity_level, max_liquidity_cap)
VALUES
    ('cNGN/NGN', 'retail',      500000,    2000000,   10000000),
    ('cNGN/NGN', 'wholesale',   2000000,   10000000,  50000000),
    ('cNGN/NGN', 'institutional',10000000, 50000000, 200000000),
    ('cNGN/KES', 'retail',      100000,    500000,    2000000),
    ('cNGN/KES', 'wholesale',   500000,    2000000,   10000000),
    ('cNGN/KES', 'institutional',2000000,  10000000,  50000000),
    ('cNGN/GHS', 'retail',      100000,    500000,    2000000),
    ('cNGN/GHS', 'wholesale',   500000,    2000000,   10000000),
    ('cNGN/GHS', 'institutional',2000000,  10000000,  50000000);
