//! Transparency data service.
//!
//! Fetches the latest Proof-of-Reserves snapshot from the database and
//! signs the JSON payload with the platform's Ed25519 "Transparency Key"
//! so external aggregators can verify authenticity.
//!
//! # Signing scheme
//! The canonical bytes that are signed are the UTF-8 encoding of the
//! deterministic JSON object:
//!
//! ```json
//! {"total_supply":"...","total_reserves":"...","collateral_ratio":"...",
//!  "last_updated_timestamp":"...","audit_link":"..."}
//! ```
//!
//! The signature is a lowercase hex-encoded Ed25519 signature over those bytes.
//! The public key is returned in the response so consumers can verify offline.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum TransparencyError {
    #[error("No proof-of-reserves snapshot found")]
    NoSnapshot,
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Signing key not configured: {0}")]
    SigningKey(String),
    #[error("Signing failed: {0}")]
    Signing(String),
}

// ---------------------------------------------------------------------------
// DB row
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct ReserveRow {
    total_supply: sqlx::types::BigDecimal,
    total_reserves: sqlx::types::BigDecimal,
    collateral_ratio: sqlx::types::BigDecimal,
    audit_link: Option<String>,
    recorded_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Public response types
// ---------------------------------------------------------------------------

/// Signed Proof-of-Reserves payload returned by `GET /v1/public/transparency`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyResponse {
    /// Total cNGN in circulation (string to preserve precision).
    pub total_supply: String,
    /// Total NGN reserves held (string to preserve precision).
    pub total_reserves: String,
    /// Ratio of reserves to supply (1.0 = fully backed).
    pub collateral_ratio: String,
    /// ISO-8601 timestamp of the most recent snapshot.
    pub last_updated_timestamp: String,
    /// URL to the third-party audit report, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_link: Option<String>,
    /// Cryptographic signature over the canonical payload bytes.
    pub signature: String,
    /// Hex-encoded Ed25519 public key used to produce `signature`.
    pub signing_key: String,
}

/// A single historical data point for time-series endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReserveDataPoint {
    pub total_supply: String,
    pub total_reserves: String,
    pub collateral_ratio: String,
    pub timestamp: String,
}

/// Response for the historical time-series endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyHistoryResponse {
    pub period_days: u32,
    pub data_points: Vec<ReserveDataPoint>,
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

pub struct TransparencyService {
    pool: PgPool,
    signing_key: Arc<SigningKey>,
    verifying_key_hex: String,
}

impl TransparencyService {
    /// Create a new service.
    ///
    /// `transparency_key_hex` must be a 64-character lowercase hex string
    /// representing the 32-byte Ed25519 seed.  If `None` or empty a random
    /// ephemeral key is generated (useful for development).
    pub fn new(pool: PgPool, transparency_key_hex: Option<String>) -> Result<Self, TransparencyError> {
        let signing_key = match transparency_key_hex.as_deref() {
            Some(hex) if hex.len() == 64 => {
                let bytes = hex::decode(hex)
                    .map_err(|e| TransparencyError::SigningKey(e.to_string()))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| TransparencyError::SigningKey("key must be 32 bytes".into()))?;
                SigningKey::from_bytes(&arr)
            }
            _ => {
                tracing::warn!(
                    "TRANSPARENCY_SIGNING_KEY not set or invalid — using ephemeral key (not suitable for production)"
                );
                SigningKey::generate(&mut OsRng)
            }
        };

        let verifying_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

        Ok(Self {
            pool,
            signing_key: Arc::new(signing_key),
            verifying_key_hex,
        })
    }

    /// Fetch the latest snapshot and return a signed transparency payload.
    pub async fn get_latest(&self) -> Result<TransparencyResponse, TransparencyError> {
        let row: Option<ReserveRow> = sqlx::query_as(
            r#"
            SELECT total_supply, total_reserves, collateral_ratio, audit_link, recorded_at
            FROM proof_of_reserves
            ORDER BY recorded_at DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        let row = row.ok_or(TransparencyError::NoSnapshot)?;
        self.build_response(row)
    }

    /// Fetch historical snapshots for the given number of days.
    pub async fn get_history(&self, days: u32) -> Result<TransparencyHistoryResponse, TransparencyError> {
        let rows: Vec<ReserveRow> = sqlx::query_as(
            r#"
            SELECT total_supply, total_reserves, collateral_ratio, audit_link, recorded_at
            FROM proof_of_reserves
            WHERE recorded_at >= now() - make_interval(days => $1)
            ORDER BY recorded_at ASC
            "#,
        )
        .bind(days as i32)
        .fetch_all(&self.pool)
        .await?;

        let data_points = rows
            .into_iter()
            .map(|r| ReserveDataPoint {
                total_supply: r.total_supply.to_string(),
                total_reserves: r.total_reserves.to_string(),
                collateral_ratio: r.collateral_ratio.to_string(),
                timestamp: r.recorded_at.to_rfc3339(),
            })
            .collect();

        Ok(TransparencyHistoryResponse { period_days: days, data_points })
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    fn build_response(&self, row: ReserveRow) -> Result<TransparencyResponse, TransparencyError> {
        let total_supply = row.total_supply.to_string();
        let total_reserves = row.total_reserves.to_string();
        let collateral_ratio = row.collateral_ratio.to_string();
        let last_updated_timestamp = row.recorded_at.to_rfc3339();

        // Canonical bytes: deterministic JSON (sorted keys, no whitespace).
        let canonical = format!(
            r#"{{"audit_link":{},"collateral_ratio":"{}","last_updated_timestamp":"{}","total_reserves":"{}","total_supply":"{}"}}"#,
            match &row.audit_link {
                Some(l) => format!("\"{}\"", l),
                None => "null".to_string(),
            },
            collateral_ratio,
            last_updated_timestamp,
            total_reserves,
            total_supply,
        );

        let signature_bytes = self.signing_key.sign(canonical.as_bytes());
        let signature = hex::encode(signature_bytes.to_bytes());

        Ok(TransparencyResponse {
            total_supply,
            total_reserves,
            collateral_ratio,
            last_updated_timestamp,
            audit_link: row.audit_link,
            signature,
            signing_key: self.verifying_key_hex.clone(),
        })
    }
}
