-- Collateral Verification Engine & Proof of Reserve (Issue #217)

-- Reserve accounts registered by ops team (from issue #118)
CREATE TABLE IF NOT EXISTS reserve_accounts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    provider    TEXT NOT NULL,          -- e.g. 'gtbank', 'zenith', 'manual'
    account_ref TEXT NOT NULL UNIQUE,   -- bank account number or external ref
    currency    TEXT NOT NULL DEFAULT 'NGN',
    is_active   BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Current balance snapshots per reserve account (updated by aggregator)
CREATE TABLE IF NOT EXISTS reserve_balances (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reserve_account_id  UUID NOT NULL REFERENCES reserve_accounts(id),
    balance             NUMERIC(36, 6) NOT NULL,
    in_transit          NUMERIC(36, 6) NOT NULL DEFAULT 0,
    fetched_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    source              TEXT NOT NULL DEFAULT 'manual'  -- 'api' | 'manual'
);

CREATE INDEX IF NOT EXISTS idx_reserve_balances_account_fetched
    ON reserve_balances (reserve_account_id, fetched_at DESC);

-- Historical PoR snapshots (append-only)
CREATE TABLE IF NOT EXISTS historical_verification (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    on_chain_supply     NUMERIC(36, 6) NOT NULL,
    fiat_reserves       NUMERIC(36, 6) NOT NULL,
    in_transit          NUMERIC(36, 6) NOT NULL DEFAULT 0,
    delta               NUMERIC(36, 6) NOT NULL,   -- fiat_reserves + in_transit - on_chain_supply
    collateral_ratio    NUMERIC(10, 6) NOT NULL,   -- (fiat_reserves + in_transit) / on_chain_supply
    is_collateralised   BOOLEAN NOT NULL,
    issuer_address      TEXT NOT NULL,
    asset_code          TEXT NOT NULL DEFAULT 'cNGN',
    snapshot_signature  TEXT,                      -- hex(SHA-256 of canonical JSON)
    snapshot_json       JSONB NOT NULL,
    triggered_by        TEXT NOT NULL DEFAULT 'scheduler',  -- 'scheduler' | 'api'
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_historical_verification_created
    ON historical_verification (created_at DESC);

-- Prevent updates/deletes — PoR records are immutable
CREATE OR REPLACE FUNCTION por_immutable() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'historical_verification is append-only';
END;
$$;

CREATE TRIGGER trg_por_no_update
    BEFORE UPDATE ON historical_verification
    FOR EACH ROW EXECUTE FUNCTION por_immutable();

CREATE TRIGGER trg_por_no_delete
    BEFORE DELETE ON historical_verification
    FOR EACH ROW EXECUTE FUNCTION por_immutable();
