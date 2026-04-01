-- ============================================================================
-- NIGERIA → GHANA CORRIDOR — Issue #2.05
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. Ghana E-Levy daily tracker (per sender wallet, per day).
--    GRA requires E-Levy to be collected and reported daily.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ghana_e_levy_log (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    transfer_id     UUID        NOT NULL,
    sender_wallet   VARCHAR(200) NOT NULL,
    ghs_gross       DECIMAL(20,4) NOT NULL,
    e_levy_amount   DECIMAL(20,4) NOT NULL,
    e_levy_rate     DECIMAL(6,4) NOT NULL DEFAULT 0.0100,
    date            DATE        NOT NULL DEFAULT CURRENT_DATE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_e_levy_wallet_date
    ON ghana_e_levy_log (sender_wallet, date DESC);

CREATE INDEX IF NOT EXISTS idx_e_levy_date
    ON ghana_e_levy_log (date DESC);

-- ---------------------------------------------------------------------------
-- 2. Daily reconciliation log (Aframp ledger vs Hubtel reporting).
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ghana_reconciliation_log (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    reconciliation_date DATE        NOT NULL,
    aframp_total_ghs    DECIMAL(20,4) NOT NULL DEFAULT 0,
    hubtel_total_ghs    DECIMAL(20,4) NOT NULL DEFAULT 0,
    discrepancy_ghs     DECIMAL(20,4) GENERATED ALWAYS AS (aframp_total_ghs - hubtel_total_ghs) STORED,
    aframp_tx_count     INTEGER     NOT NULL DEFAULT 0,
    hubtel_tx_count     INTEGER     NOT NULL DEFAULT 0,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'matched', 'discrepancy', 'resolved')),
    notes               TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_ghana_recon_date UNIQUE (reconciliation_date)
);

-- ---------------------------------------------------------------------------
-- 3. Fee structure seed for NG→GH corridor.
-- ---------------------------------------------------------------------------

INSERT INTO fee_structures (
    transaction_type, payment_provider, payment_method,
    min_amount, max_amount,
    provider_fee_percent, provider_fee_flat, provider_fee_cap,
    platform_fee_percent, is_active, effective_from
)
SELECT
    'ghana_corridor', 'hubtel_ghana', 'mobile_money',
    0, NULL,
    1.0,    -- 1% E-Levy (passed through to sender)
    0.50,   -- GHS 0.50 Hubtel flat fee
    NULL,
    1.5,    -- 1.5% platform corridor fee
    TRUE, NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM fee_structures
    WHERE transaction_type = 'ghana_corridor' AND payment_provider = 'hubtel_ghana'
);

-- ---------------------------------------------------------------------------
-- 4. Seed NG→GH corridor in compliance registry.
-- ---------------------------------------------------------------------------

INSERT INTO payment_corridors (
    source_country, destination_country,
    source_currency, destination_currency,
    status
)
SELECT 'NG', 'GH', 'NGN', 'GHS', 'active'
WHERE NOT EXISTS (
    SELECT 1 FROM payment_corridors
    WHERE source_country = 'NG' AND destination_country = 'GH'
      AND source_currency = 'NGN' AND destination_currency = 'GHS'
);

-- Seed routing metadata (corridor_router_schema columns).
UPDATE payment_corridors SET
    min_transfer_amount = 100,
    max_transfer_amount = 2000000,
    delivery_methods    = ARRAY['mobile_money', 'bank'],
    bridge_asset        = 'XLM',
    risk_score          = 40,
    required_kyc_tier   = 'basic',
    display_name        = 'Nigeria → Ghana',
    estimated_minutes   = 5,
    is_featured         = true,
    config              = '{"e_levy_rate": 0.01, "bog_reporting": true}'::jsonb
WHERE source_country = 'NG' AND destination_country = 'GH'
  AND source_currency = 'NGN' AND destination_currency = 'GHS';

-- Seed route hops: cNGN → XLM → GHS
INSERT INTO corridor_route_hops (corridor_id, hop_order, from_asset, to_asset, provider)
SELECT pc.id, 1, 'cNGN', 'XLM', 'stellar_dex'
FROM payment_corridors pc
WHERE pc.source_country = 'NG' AND pc.destination_country = 'GH'
  AND NOT EXISTS (
      SELECT 1 FROM corridor_route_hops h WHERE h.corridor_id = pc.id AND h.hop_order = 1
  );

INSERT INTO corridor_route_hops (corridor_id, hop_order, from_asset, to_asset, provider)
SELECT pc.id, 2, 'XLM', 'GHS', 'hubtel_ghana'
FROM payment_corridors pc
WHERE pc.source_country = 'NG' AND pc.destination_country = 'GH'
  AND NOT EXISTS (
      SELECT 1 FROM corridor_route_hops h WHERE h.corridor_id = pc.id AND h.hop_order = 2
  );

-- ---------------------------------------------------------------------------
-- 5. Seed NGN/GHS exchange rate placeholder.
-- ---------------------------------------------------------------------------

INSERT INTO exchange_rates (currency_pair, rate, source)
SELECT 'NGN/GHS', 0.0420, 'seed'
WHERE NOT EXISTS (
    SELECT 1 FROM exchange_rates WHERE currency_pair = 'NGN/GHS'
);
