use crate::database::error::DatabaseError;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

pub struct VerificationRepository {
    pool: PgPool,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct VerificationSnapshot {
    pub id: Uuid,
    pub on_chain_supply: sqlx::types::BigDecimal,
    pub fiat_reserves: sqlx::types::BigDecimal,
    pub in_transit: sqlx::types::BigDecimal,
    pub delta: sqlx::types::BigDecimal,
    pub collateral_ratio: sqlx::types::BigDecimal,
    pub is_collateralised: bool,
    pub issuer_address: String,
    pub asset_code: String,
    pub snapshot_signature: Option<String>,
    pub snapshot_json: serde_json::Value,
    pub triggered_by: String,
    pub created_at: DateTime<Utc>,
}

impl VerificationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_snapshot(
        &self,
        id: Uuid,
        on_chain_supply: Decimal,
        fiat_reserves: Decimal,
        in_transit: Decimal,
        delta: Decimal,
        collateral_ratio: Decimal,
        is_collateralised: bool,
        issuer_address: &str,
        asset_code: &str,
        signature: &str,
        snapshot_json: serde_json::Value,
        triggered_by: &str,
        created_at: DateTime<Utc>,
    ) -> Result<(), DatabaseError> {
        // Convert rust_decimal → bigdecimal for sqlx
        let to_bd = |d: Decimal| -> sqlx::types::BigDecimal {
            d.to_string().parse().unwrap_or_default()
        };

        sqlx::query!(
            r#"
            INSERT INTO historical_verification (
                id, on_chain_supply, fiat_reserves, in_transit, delta,
                collateral_ratio, is_collateralised, issuer_address, asset_code,
                snapshot_signature, snapshot_json, triggered_by, created_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
            "#,
            id,
            to_bd(on_chain_supply),
            to_bd(fiat_reserves),
            to_bd(in_transit),
            to_bd(delta),
            to_bd(collateral_ratio),
            is_collateralised,
            issuer_address,
            asset_code,
            signature,
            snapshot_json,
            triggered_by,
            created_at,
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    /// Latest snapshot — used by the API endpoint.
    pub async fn latest(&self) -> Result<Option<VerificationSnapshot>, DatabaseError> {
        sqlx::query_as!(
            VerificationSnapshot,
            r#"SELECT id, on_chain_supply, fiat_reserves, in_transit, delta,
                      collateral_ratio, is_collateralised, issuer_address, asset_code,
                      snapshot_signature, snapshot_json, triggered_by, created_at
               FROM historical_verification
               ORDER BY created_at DESC LIMIT 1"#
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Paginated history.
    pub async fn history(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<VerificationSnapshot>, DatabaseError> {
        sqlx::query_as!(
            VerificationSnapshot,
            r#"SELECT id, on_chain_supply, fiat_reserves, in_transit, delta,
                      collateral_ratio, is_collateralised, issuer_address, asset_code,
                      snapshot_signature, snapshot_json, triggered_by, created_at
               FROM historical_verification
               ORDER BY created_at DESC
               LIMIT $1 OFFSET $2"#,
            limit,
            offset,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Sum of latest balance per active reserve account.
    /// Returns (total_reserves, total_in_transit).
    pub async fn sum_active_reserves(&self) -> Result<(Decimal, Decimal), DatabaseError> {
        let row = sqlx::query!(
            r#"
            SELECT
                COALESCE(SUM(rb.balance),    0) AS "total_reserves!: sqlx::types::BigDecimal",
                COALESCE(SUM(rb.in_transit), 0) AS "total_in_transit!: sqlx::types::BigDecimal"
            FROM reserve_accounts ra
            JOIN LATERAL (
                SELECT balance, in_transit
                FROM reserve_balances
                WHERE reserve_account_id = ra.id
                ORDER BY fetched_at DESC
                LIMIT 1
            ) rb ON true
            WHERE ra.is_active = true
            "#
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        let parse = |bd: sqlx::types::BigDecimal| -> Decimal {
            bd.to_string().parse().unwrap_or(Decimal::ZERO)
        };

        Ok((
            parse(row.total_reserves),
            parse(row.total_in_transit),
        ))
    }
}
