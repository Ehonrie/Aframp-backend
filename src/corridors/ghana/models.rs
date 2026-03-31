//! Domain models for the Nigeria → Ghana corridor.

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Transfer request / response
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct GhanaTransferRequest {
    pub sender_wallet: String,
    pub cngn_amount: Decimal,
    /// Recipient MoMo phone (MTN, Telecel, AirtelTigo).
    pub recipient_phone: Option<String>,
    /// Recipient GIP bank account (alternative to MoMo).
    pub recipient_bank: Option<GhanaBankDetails>,
    pub recipient_name: String,
    /// Ghana Card number (required for transfers ≥ GHS 1,000 per BoG rules).
    pub recipient_ghana_card: Option<String>,
    pub idempotency_key: String,
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GhanaBankDetails {
    /// GIP bank code (e.g. "GCB" for Ghana Commercial Bank).
    pub bank_code: String,
    pub account_number: String,
    pub account_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GhanaTransferQuote {
    pub quote_id: Uuid,
    pub cngn_amount: Decimal,
    pub ngn_equivalent: Decimal,
    pub ngn_ghs_rate: Decimal,
    pub ghs_gross: Decimal,
    pub corridor_fee_ghs: Decimal,
    pub ghs_net: Decimal,
    pub fee_breakdown: GhanaFeeBreakdown,
    pub expires_at: DateTime<Utc>,
}

/// Ghana-specific fee breakdown including E-Levy.
#[derive(Debug, Clone, Serialize)]
pub struct GhanaFeeBreakdown {
    /// Platform corridor fee (bps on GHS gross).
    pub platform_fee_bps: u32,
    pub platform_fee_ghs: Decimal,
    /// Hubtel provider flat fee.
    pub provider_fee_ghs: Decimal,
    /// Ghana E-Levy: 1% on electronic transfers (GRA Act 1075, 2022).
    /// Applied on the GHS gross amount.
    pub e_levy_ghs: Decimal,
    pub e_levy_rate: Decimal,
    pub total_fee_ghs: Decimal,
}

#[derive(Debug, Clone, Serialize)]
pub struct GhanaTransferResponse {
    pub transfer_id: Uuid,
    pub status: GhanaTransferStatus,
    pub quote: GhanaTransferQuote,
    pub recipient_validated: bool,
    pub detected_network: Option<String>,
    pub compliance_tag_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Status state machine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum GhanaTransferStatus {
    PendingCngn,
    Converting,
    DisbursementPending,
    Completed,
    RefundInitiated,
    Refunded,
    Failed,
}

impl GhanaTransferStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            GhanaTransferStatus::PendingCngn => "pending_cngn",
            GhanaTransferStatus::Converting => "converting",
            GhanaTransferStatus::DisbursementPending => "disbursement_pending",
            GhanaTransferStatus::Completed => "completed",
            GhanaTransferStatus::RefundInitiated => "refund_initiated",
            GhanaTransferStatus::Refunded => "refunded",
            GhanaTransferStatus::Failed => "failed",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            GhanaTransferStatus::Completed
                | GhanaTransferStatus::Refunded
                | GhanaTransferStatus::Failed
        )
    }
}

// ---------------------------------------------------------------------------
// BoG / E-Levy constants
// ---------------------------------------------------------------------------

/// Bank of Ghana single-transaction MoMo cap (GHS).
pub fn bog_max_single_txn_ghs() -> Decimal {
    Decimal::new(10_000, 0)
}

/// BoG threshold above which Ghana Card is mandatory (GHS).
pub fn bog_ghana_card_threshold_ghs() -> Decimal {
    Decimal::new(1_000, 0)
}

/// Ghana E-Levy rate: 1% (GRA Act 1075, 2022).
pub fn e_levy_rate() -> Decimal {
    Decimal::new(1, 2) // 0.01
}
