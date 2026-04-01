-- migrate:up
-- Proof of Reserves: stores periodic snapshots of cNGN supply and reserve backing.

CREATE TABLE IF NOT EXISTS proof_of_reserves (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    total_supply    NUMERIC(36, 6) NOT NULL CHECK (total_supply >= 0),
    total_reserves  NUMERIC(36, 6) NOT NULL CHECK (total_reserves >= 0),
    collateral_ratio NUMERIC(10, 6) NOT NULL CHECK (collateral_ratio >= 0),
    audit_link      TEXT,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE proof_of_reserves IS 'Periodic snapshots of cNGN circulating supply and NGN reserve backing.';
COMMENT ON COLUMN proof_of_reserves.total_supply IS 'Total cNGN in circulation at snapshot time.';
COMMENT ON COLUMN proof_of_reserves.total_reserves IS 'Total NGN reserves held at snapshot time.';
COMMENT ON COLUMN proof_of_reserves.collateral_ratio IS 'Ratio of reserves to supply (1.0 = fully backed).';
COMMENT ON COLUMN proof_of_reserves.audit_link IS 'URL to the third-party audit report for this snapshot.';

CREATE INDEX IF NOT EXISTS idx_proof_of_reserves_recorded_at
    ON proof_of_reserves(recorded_at DESC);
