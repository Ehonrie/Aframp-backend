use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Horizon deserialization target
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct HorizonOperation {
    pub id: String,
    pub paging_token: String,
    #[serde(rename = "type")]
    pub op_type: String,
    pub transaction_hash: String,
    pub ledger: i64,
    pub created_at: DateTime<Utc>,
    pub source_account: String,
    pub asset_code: Option<String>,
    pub asset_issuer: Option<String>,
    pub amount: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub account: Option<String>,
    pub transaction_memo: Option<String>,
    pub transaction_memo_type: Option<String>,
}

// ---------------------------------------------------------------------------
// Processed event (maps to processed_events table)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessedEvent {
    pub id: Uuid,
    pub transaction_hash: String,
    pub operation_type: String,
    pub ledger_id: i64,
    pub created_at_chain: DateTime<Utc>,
    pub processed_at: DateTime<Utc>,
    pub asset_code: Option<String>,
    pub asset_issuer: Option<String>,
    pub amount: Option<String>,
    pub source_account: String,
    pub destination_account: Option<String>,
    pub raw_memo: Option<String>,
    pub parsed_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Unmatched event (maps to unmatched_events table)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnmatchedEvent {
    pub id: Uuid,
    pub transaction_hash: String,
    pub raw_memo: Option<String>,
    pub raw_operation: Value,
    pub recorded_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct MintBurnConfig {
    pub issuer_id: String,
    pub horizon_base_url: String,
    #[serde(default = "default_heartbeat_timeout_secs")]
    pub heartbeat_timeout_secs: u64,
    #[serde(default = "default_reconnect_backoff_max_secs")]
    pub reconnect_backoff_max_secs: u64,
    #[serde(default = "default_reconnect_backoff_initial_secs")]
    pub reconnect_backoff_initial_secs: u64,
}

fn default_heartbeat_timeout_secs() -> u64 {
    30
}

fn default_reconnect_backoff_max_secs() -> u64 {
    60
}

fn default_reconnect_backoff_initial_secs() -> u64 {
    1
}

impl Default for MintBurnConfig {
    fn default() -> Self {
        Self {
            issuer_id: String::new(),
            horizon_base_url: String::new(),
            heartbeat_timeout_secs: default_heartbeat_timeout_secs(),
            reconnect_backoff_max_secs: default_reconnect_backoff_max_secs(),
            reconnect_backoff_initial_secs: default_reconnect_backoff_initial_secs(),
        }
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum MintBurnError {
    #[error("stream error: {0}")]
    StreamError(String),

    #[error("database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("missing required field: {0}")]
    MissingField(String),

    #[error("parse error: {0}")]
    ParseError(String),

    #[error("config error: {0}")]
    ConfigError(String),
}
