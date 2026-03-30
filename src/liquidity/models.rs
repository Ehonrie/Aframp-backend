use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::BigDecimal;
use uuid::Uuid;

// ── Enums ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "pool_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum PoolType {
    Retail,
    Wholesale,
    Institutional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "pool_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum PoolStatus {
    Active,
    Paused,
    Deactivated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "reservation_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Active,
    Consumed,
    Released,
    TimedOut,
}

// ── Core models ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LiquidityPool {
    pub pool_id: Uuid,
    pub currency_pair: String,
    pub pool_type: PoolType,
    pub total_liquidity_depth: BigDecimal,
    pub available_liquidity: BigDecimal,
    pub reserved_liquidity: BigDecimal,
    pub min_liquidity_threshold: BigDecimal,
    pub target_liquidity_level: BigDecimal,
    pub max_liquidity_cap: BigDecimal,
    pub pool_status: PoolStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LiquidityAllocation {
    pub allocation_id: Uuid,
    pub pool_id: Uuid,
    pub liquidity_provider_id: Uuid,
    pub allocated_amount: BigDecimal,
    pub allocation_timestamp: DateTime<Utc>,
    pub lock_period_seconds: i64,
    pub withdrawal_eligibility_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LiquidityReservation {
    pub reservation_id: Uuid,
    pub pool_id: Uuid,
    pub transaction_id: Uuid,
    pub reserved_amount: BigDecimal,
    pub status: ReservationStatus,
    pub reserved_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PoolUtilisation {
    pub id: Uuid,
    pub pool_id: Uuid,
    pub period: String,
    pub period_start: DateTime<Utc>,
    pub total_transaction_volume: BigDecimal,
    pub peak_utilisation_pct: BigDecimal,
    pub avg_utilisation_pct: BigDecimal,
    pub liquidity_provider_count: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PoolHealthSnapshot {
    pub id: Uuid,
    pub pool_id: Uuid,
    pub utilisation_pct: BigDecimal,
    pub available_depth: BigDecimal,
    pub distance_from_min: BigDecimal,
    pub distance_from_target: BigDecimal,
    pub effective_depth: BigDecimal,
    pub snapshotted_at: DateTime<Utc>,
}

// ── Segment thresholds ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SegmentThresholds {
    pub retail_max: BigDecimal,
    pub wholesale_max: BigDecimal,
}

impl Default for SegmentThresholds {
    fn default() -> Self {
        use std::str::FromStr;
        Self {
            retail_max: BigDecimal::from_str("100000").unwrap(),
            wholesale_max: BigDecimal::from_str("1000000").unwrap(),
        }
    }
}

impl SegmentThresholds {
    pub fn segment_for(&self, amount: &BigDecimal) -> PoolType {
        if amount <= &self.retail_max {
            PoolType::Retail
        } else if amount <= &self.wholesale_max {
            PoolType::Wholesale
        } else {
            PoolType::Institutional
        }
    }

    /// Adjacent segments in fallback order (primary first)
    pub fn fallback_order(primary: &PoolType) -> Vec<PoolType> {
        match primary {
            PoolType::Retail => vec![PoolType::Retail, PoolType::Wholesale, PoolType::Institutional],
            PoolType::Wholesale => vec![PoolType::Wholesale, PoolType::Retail, PoolType::Institutional],
            PoolType::Institutional => vec![PoolType::Institutional, PoolType::Wholesale, PoolType::Retail],
        }
    }
}

// ── Request / response DTOs ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreatePoolRequest {
    pub currency_pair: String,
    pub pool_type: PoolType,
    pub min_liquidity_threshold: BigDecimal,
    pub target_liquidity_level: BigDecimal,
    pub max_liquidity_cap: BigDecimal,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePoolRequest {
    pub min_liquidity_threshold: Option<BigDecimal>,
    pub target_liquidity_level: Option<BigDecimal>,
    pub max_liquidity_cap: Option<BigDecimal>,
}

#[derive(Debug, Serialize)]
pub struct PoolWithHealth {
    #[serde(flatten)]
    pub pool: LiquidityPool,
    pub utilisation_pct: f64,
    pub effective_depth: BigDecimal,
    pub health_status: PoolHealthStatus,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PoolHealthStatus {
    Healthy,
    BelowTarget,
    BelowMinimum,
    OverCap,
    HighUtilisation,
}

#[derive(Debug, Serialize)]
pub struct LiquidityDepthResponse {
    pub currency_pair: String,
    pub retail_depth: BigDecimal,
    pub wholesale_depth: BigDecimal,
    pub institutional_depth: BigDecimal,
    pub total_depth: BigDecimal,
}

#[derive(Debug, Serialize)]
pub struct InsufficientLiquidityError {
    pub error: &'static str,
    pub currency_pair: String,
    pub requested_amount: BigDecimal,
    pub estimated_availability_minutes: u64,
}
