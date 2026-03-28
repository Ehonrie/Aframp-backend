use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Enums ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "consumer_tier", rename_all = "snake_case")]
pub enum ConsumerTier {
    Free,
    Starter,
    Professional,
    Enterprise,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "snapshot_period", rename_all = "snake_case")]
pub enum SnapshotPeriod {
    Hourly,
    Daily,
    Weekly,
    Monthly,
}

impl SnapshotPeriod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hourly => "hourly",
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "health_trend", rename_all = "snake_case")]
pub enum HealthTrend {
    Improving,
    Stable,
    Declining,
}

// ── Core Models ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumerUsageSnapshot {
    pub id: Uuid,
    pub consumer_id: String,
    pub consumer_tier: ConsumerTier,
    pub snapshot_period: SnapshotPeriod,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_requests: i64,
    pub successful_requests: i64,
    pub failed_requests: i64,
    pub error_rate: f64,
    pub p50_response_time_ms: i32,
    pub p99_response_time_ms: i32,
    pub avg_response_time_ms: i32,
    pub rate_limit_breaches: i32,
    pub unique_endpoints: i32,
    pub snapshot_timestamp: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumerEndpointUsage {
    pub id: Uuid,
    pub consumer_id: String,
    pub endpoint_path: String,
    pub http_method: String,
    pub snapshot_period: SnapshotPeriod,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub request_count: i64,
    pub success_count: i64,
    pub error_count: i64,
    pub avg_latency_ms: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumerFeatureAdoption {
    pub id: Uuid,
    pub consumer_id: String,
    pub feature_name: String,
    pub first_used_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub total_usage_count: i64,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumerHealthScore {
    pub id: Uuid,
    pub consumer_id: String,
    pub health_score: i32,
    pub error_rate_score: i32,
    pub rate_limit_score: i32,
    pub auth_failure_score: i32,
    pub webhook_delivery_score: i32,
    pub activity_recency_score: i32,
    pub health_trend: HealthTrend,
    pub previous_score: Option<i32>,
    pub score_change: i32,
    pub is_at_risk: bool,
    pub risk_factors: Option<serde_json::Value>,
    pub score_timestamp: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumerRevenueAttribution {
    pub id: Uuid,
    pub consumer_id: String,
    pub snapshot_period: SnapshotPeriod,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_transaction_count: i64,
    pub total_transaction_volume: f64,
    pub total_fees_generated: f64,
    pub cngn_volume_transferred: f64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumerUsageAnomaly {
    pub id: Uuid,
    pub consumer_id: String,
    pub anomaly_type: String,
    pub severity: String,
    pub detected_value: Option<f64>,
    pub expected_value: Option<f64>,
    pub threshold_value: Option<f64>,
    pub deviation_percent: Option<f64>,
    pub detection_window: String,
    pub anomaly_context: Option<serde_json::Value>,
    pub is_resolved: bool,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolution_notes: Option<String>,
    pub detected_at: DateTime<Utc>,
    pub notified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformUsageReport {
    pub id: Uuid,
    pub report_type: String,
    pub report_period_start: DateTime<Utc>,
    pub report_period_end: DateTime<Utc>,
    pub total_api_requests: i64,
    pub platform_error_rate: f64,
    pub total_consumers: i32,
    pub active_consumers: i32,
    pub new_consumers: i32,
    pub at_risk_consumers: i32,
    pub feature_adoption_summary: Option<serde_json::Value>,
    pub top_consumers_by_volume: Option<serde_json::Value>,
    pub report_file_path: Option<String>,
    pub report_file_size_bytes: Option<i64>,
    pub generated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumerMonthlyReport {
    pub id: Uuid,
    pub consumer_id: String,
    pub report_month: chrono::NaiveDate,
    pub total_requests: i64,
    pub error_rate: f64,
    pub avg_response_time_ms: i32,
    pub health_score: i32,
    pub features_used: Option<serde_json::Value>,
    pub integration_health_summary: Option<String>,
    pub report_file_path: Option<String>,
    pub report_file_size_bytes: Option<i64>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub generated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthScoreConfig {
    pub id: Uuid,
    pub config_name: String,
    pub error_rate_weight: f64,
    pub rate_limit_weight: f64,
    pub auth_failure_weight: f64,
    pub webhook_delivery_weight: f64,
    pub activity_recency_weight: f64,
    pub at_risk_threshold: i32,
    pub critical_threshold: i32,
    pub trend_lookback_days: i32,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── Request/Response DTOs ────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct UsageSummaryQuery {
    pub period: Option<String>, // 'current_hour', 'today', 'this_week', 'this_month'
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageSummaryResponse {
    pub period: String,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_requests: i64,
    pub error_rate: f64,
    pub rate_limit_utilization: f64,
    pub active_features: Vec<String>,
    pub health_score: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequestHistoryQuery {
    pub endpoint: Option<String>,
    pub status_code: Option<i32>,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointUsageResponse {
    pub endpoint_path: String,
    pub http_method: String,
    pub request_count: i64,
    pub error_rate: f64,
    pub avg_latency_ms: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct FeatureAdoptionResponse {
    pub feature_name: String,
    pub first_used_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub total_usage_count: i64,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RateLimitStatusResponse {
    pub dimension: String,
    pub current_usage: i64,
    pub limit: i64,
    pub utilization_percent: f64,
    pub reset_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorBreakdownResponse {
    pub error_code: String,
    pub endpoint: String,
    pub count: i64,
    pub first_occurrence: DateTime<Utc>,
    pub last_occurrence: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConsumerAnalyticsQuery {
    pub tier: Option<ConsumerTier>,
    pub period_start: Option<DateTime<Utc>>,
    pub period_end: Option<DateTime<Utc>>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConsumerOverviewResponse {
    pub total_registered_consumers: i32,
    pub active_consumers_by_tier: serde_json::Value,
    pub new_consumers_this_period: i32,
    pub consumer_growth_trend: Vec<GrowthDataPoint>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GrowthDataPoint {
    pub period: String,
    pub count: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthScoreDistribution {
    pub score_band: String,
    pub consumer_count: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct AtRiskConsumer {
    pub consumer_id: String,
    pub health_score: i32,
    pub risk_factors: Vec<String>,
    pub last_activity: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FeatureAdoptionRate {
    pub feature_name: String,
    pub total_consumers: i32,
    pub active_consumers: i32,
    pub adoption_rate: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopConsumer {
    pub consumer_id: String,
    pub metric_value: f64,
    pub rank: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChurnedConsumer {
    pub consumer_id: String,
    pub last_activity: DateTime<Utc>,
    pub previous_request_count: i64,
    pub days_inactive: i32,
}
