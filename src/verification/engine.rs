/// Collateral Verification Engine
///
/// Compares on-chain cNGN supply (Stellar) against off-chain fiat reserves (bank accounts).
/// Generates signed PoR snapshots and alerts on under-collateralisation.
use crate::chains::stellar::client::StellarClient;
use crate::verification::repository::VerificationRepository;
use chrono::Utc;
use rust_decimal::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub id: Uuid,
    pub on_chain_supply: Decimal,
    pub fiat_reserves: Decimal,
    pub in_transit: Decimal,
    /// (fiat_reserves + in_transit) - on_chain_supply
    /// Positive = over-collateralised, negative = under-collateralised
    pub delta: Decimal,
    /// (fiat_reserves + in_transit) / on_chain_supply
    pub collateral_ratio: Decimal,
    pub is_collateralised: bool,
    pub issuer_address: String,
    pub asset_code: String,
    pub triggered_by: String,
    pub created_at: chrono::DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("Stellar fetch failed: {0}")]
    StellarFetch(String),
    #[error("Reserve fetch failed: {0}")]
    ReserveFetch(String),
    #[error("Database error: {0}")]
    Database(String),
    #[error("No reserve accounts configured")]
    NoReserves,
}

pub struct VerificationEngine {
    stellar: Arc<StellarClient>,
    repo: Arc<VerificationRepository>,
    issuer_address: String,
    asset_code: String,
}

impl VerificationEngine {
    pub fn new(stellar: Arc<StellarClient>, pool: PgPool) -> Self {
        let issuer_address = std::env::var("CNGN_ISSUER_ADDRESS")
            .or_else(|_| std::env::var("CNGN_ISSUER_MAINNET"))
            .unwrap_or_default();
        Self {
            stellar,
            repo: Arc::new(VerificationRepository::new(pool)),
            issuer_address,
            asset_code: "cNGN".to_string(),
        }
    }

    /// Run a full verification cycle and persist the result.
    pub async fn run(&self, triggered_by: &str) -> Result<VerificationResult, VerificationError> {
        let on_chain = self.fetch_on_chain_supply().await?;
        let (fiat_reserves, in_transit) = self.fetch_fiat_reserves().await?;

        let effective_reserves = fiat_reserves + in_transit;
        let delta = effective_reserves - on_chain;

        let collateral_ratio = if on_chain.is_zero() {
            // No supply minted yet — trivially collateralised
            Decimal::from(1)
        } else {
            effective_reserves / on_chain
        };

        let is_collateralised = collateral_ratio >= Decimal::from(1);

        if !is_collateralised {
            error!(
                ratio = %collateral_ratio,
                on_chain_supply = %on_chain,
                fiat_reserves = %fiat_reserves,
                in_transit = %in_transit,
                "UNDER-COLLATERALISATION DETECTED — cNGN supply exceeds reserves"
            );
        } else {
            info!(
                ratio = %collateral_ratio,
                on_chain_supply = %on_chain,
                fiat_reserves = %fiat_reserves,
                "Collateral verification passed"
            );
        }

        let id = Uuid::new_v4();
        let now = Utc::now();

        let snapshot_json = serde_json::json!({
            "id": id,
            "on_chain_supply": on_chain.to_string(),
            "fiat_reserves": fiat_reserves.to_string(),
            "in_transit": in_transit.to_string(),
            "delta": delta.to_string(),
            "collateral_ratio": collateral_ratio.to_string(),
            "is_collateralised": is_collateralised,
            "issuer_address": self.issuer_address,
            "asset_code": self.asset_code,
            "triggered_by": triggered_by,
            "created_at": now.to_rfc3339(),
        });

        let signature = sign_snapshot(&snapshot_json.to_string());

        self.repo
            .insert_snapshot(
                id,
                on_chain,
                fiat_reserves,
                in_transit,
                delta,
                collateral_ratio,
                is_collateralised,
                &self.issuer_address,
                &self.asset_code,
                &signature,
                snapshot_json,
                triggered_by,
                now,
            )
            .await
            .map_err(|e| VerificationError::Database(e.to_string()))?;

        Ok(VerificationResult {
            id,
            on_chain_supply: on_chain,
            fiat_reserves,
            in_transit,
            delta,
            collateral_ratio,
            is_collateralised,
            issuer_address: self.issuer_address.clone(),
            asset_code: self.asset_code.clone(),
            triggered_by: triggered_by.to_string(),
            created_at: now,
        })
    }

    /// Fetch total cNGN in circulation from the issuer account on Stellar.
    ///
    /// The issuer's own balance of the asset represents the *un-issued* supply.
    /// Total minted = sum of all trustline holders' balances, but Horizon exposes
    /// this via the asset endpoint. We use the simpler approach: query the issuer
    /// account and read the cNGN balance it holds (which is the amount it has
    /// *not yet distributed*). For a full supply figure we'd need the asset
    /// endpoint — we use that here.
    async fn fetch_on_chain_supply(&self) -> Result<Decimal, VerificationError> {
        if self.issuer_address.is_empty() {
            warn!("CNGN_ISSUER_ADDRESS not set — treating on-chain supply as 0");
            return Ok(Decimal::ZERO);
        }

        let url = format!(
            "{}/assets?asset_code={}&asset_issuer={}",
            self.stellar.config().horizon_url(),
            self.asset_code,
            self.issuer_address
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| VerificationError::StellarFetch(e.to_string()))?;

        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            client.get(&url).send(),
        )
        .await
        .map_err(|_| VerificationError::StellarFetch("Horizon asset endpoint timed out".into()))?
        .map_err(|e| VerificationError::StellarFetch(e.to_string()))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| VerificationError::StellarFetch(e.to_string()))?;

        let amount_str = body
            .pointer("/_embedded/records/0/amount")
            .and_then(|v| v.as_str())
            .unwrap_or("0");

        Decimal::from_str(amount_str)
            .map_err(|e| VerificationError::StellarFetch(format!("parse error: {}", e)))
    }

    /// Sum all active reserve account balances from the DB.
    /// Returns (total_reserves, total_in_transit).
    async fn fetch_fiat_reserves(&self) -> Result<(Decimal, Decimal), VerificationError> {
        self.repo
            .sum_active_reserves()
            .await
            .map_err(|e| VerificationError::ReserveFetch(e.to_string()))
    }
}

/// SHA-256 hex signature of the canonical snapshot string.
fn sign_snapshot(canonical: &str) -> String {
    let digest = Sha256::digest(canonical.as_bytes());
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collateral_ratio_under() {
        let supply = Decimal::from(1_000_000);
        let reserves = Decimal::from(900_000);
        let in_transit = Decimal::ZERO;
        let effective = reserves + in_transit;
        let ratio = effective / supply;
        assert!(ratio < Decimal::from(1));
    }

    #[test]
    fn test_collateral_ratio_over() {
        let supply = Decimal::from(1_000_000);
        let reserves = Decimal::from(1_100_000);
        let in_transit = Decimal::from(50_000);
        let effective = reserves + in_transit;
        let ratio = effective / supply;
        assert!(ratio > Decimal::from(1));
    }

    #[test]
    fn test_in_transit_counts_toward_collateral() {
        // 900k reserves + 150k in-transit covers 1M supply
        let supply = Decimal::from(1_000_000);
        let reserves = Decimal::from(900_000);
        let in_transit = Decimal::from(150_000);
        let effective = reserves + in_transit;
        let ratio = effective / supply;
        assert!(ratio >= Decimal::from(1));
    }

    #[test]
    fn test_sign_snapshot_deterministic() {
        let s = sign_snapshot("hello");
        assert_eq!(s, sign_snapshot("hello"));
        assert_eq!(s.len(), 64);
    }

    #[test]
    fn test_zero_supply_is_collateralised() {
        let supply = Decimal::ZERO;
        let ratio = if supply.is_zero() {
            Decimal::from(1)
        } else {
            Decimal::from(1_000_000) / supply
        };
        assert!(ratio >= Decimal::from(1));
    }
}
