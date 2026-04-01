use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct PegDeviationSnapshot {
    pub id: Uuid,
    pub captured_at: DateTime<Utc>,
    pub dex_price: sqlx::types::BigDecimal,
    pub oracle_price: sqlx::types::BigDecimal,
    pub deviation_bps: sqlx::types::BigDecimal,
    pub alert_level: i16,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct PegDepegEvent {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub peak_deviation_bps: sqlx::types::BigDecimal,
    pub max_alert_level: i16,
    pub time_to_recovery_secs: Option<i64>,
    pub is_open: bool,
}

/// Alert level thresholds in basis points.
pub const BPS_YELLOW: f64 = 20.0;
pub const BPS_ORANGE: f64 = 50.0;
pub const BPS_RED: f64 = 100.0;

/// Seconds the price must stay deviated before an alert fires (false-positive guard).
pub fn duration_threshold_secs() -> u64 {
    std::env::var("PEG_DURATION_THRESHOLD_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30)
}

pub fn poll_interval_secs() -> u64 {
    std::env::var("PEG_POLL_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10)
}

/// Classify deviation magnitude into an alert level (0–3).
pub fn alert_level(abs_bps: f64) -> i16 {
    if abs_bps >= BPS_RED {
        3
    } else if abs_bps >= BPS_ORANGE {
        2
    } else if abs_bps >= BPS_YELLOW {
        1
    } else {
        0
    }
}

// ── Public API response ───────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct PegHealthResponse {
    pub status: &'static str,       // "healthy" | "warning" | "critical"
    pub alert_level: i16,
    pub dex_price: String,
    pub oracle_price: String,
    pub deviation_bps: String,
    pub captured_at: DateTime<Utc>,
    pub open_depeg_event: Option<OpenDepegInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenDepegInfo {
    pub started_at: DateTime<Utc>,
    pub peak_deviation_bps: String,
    pub max_alert_level: i16,
}
