-- Mint Request Submission & Validation System (Issue #220)

-- Confirmed fiat deposits — the source of truth for fiat_reference_id validation
CREATE TABLE IF NOT EXISTS confirmed_deposits (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reference_id    TEXT NOT NULL UNIQUE,   -- bank transfer / payment reference
    amount          NUMERIC(36, 7) NOT NULL CHECK (amount > 0),
    currency        TEXT NOT NULL DEFAULT 'NGN',
    depositor_name  TEXT,
    deposited_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_confirmed_deposits_reference
    ON confirmed_deposits (reference_id);

-- Mint request state machine
CREATE TYPE mint_request_status AS ENUM (
    'pending_validation',
    'validated',
    'approved',
    'rejected',
    'minting',
    'completed',
    'failed'
);

CREATE TABLE IF NOT EXISTS mint_requests (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    amount              NUMERIC(36, 7) NOT NULL CHECK (amount > 0),
    destination_address TEXT NOT NULL,
    fiat_reference_id   TEXT NOT NULL REFERENCES confirmed_deposits(reference_id),
    asset_code          TEXT NOT NULL DEFAULT 'cNGN',
    status              mint_request_status NOT NULL DEFAULT 'pending_validation',
    rejection_reason    TEXT,
    submitted_by        TEXT,               -- actor ID from auth context
    submitted_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_mint_requests_fiat_ref_active
    ON mint_requests (fiat_reference_id)
    WHERE status NOT IN ('rejected', 'failed');

CREATE INDEX IF NOT EXISTS idx_mint_requests_status
    ON mint_requests (status, submitted_at DESC);

CREATE INDEX IF NOT EXISTS idx_mint_requests_destination
    ON mint_requests (destination_address, submitted_at DESC);

CREATE OR REPLACE FUNCTION mint_requests_set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$;

CREATE TRIGGER trg_mint_requests_updated_at
    BEFORE UPDATE ON mint_requests
    FOR EACH ROW EXECUTE FUNCTION mint_requests_set_updated_at();
