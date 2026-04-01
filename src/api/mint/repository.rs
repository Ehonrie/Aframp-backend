use crate::database::error::DatabaseError;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::Type, serde::Serialize, serde::Deserialize, PartialEq)]
#[sqlx(type_name = "mint_request_status", rename_all = "snake_case")]
pub enum MintRequestStatus {
    PendingValidation,
    Validated,
    Approved,
    Rejected,
    Minting,
    Completed,
    Failed,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MintRequest {
    pub id: Uuid,
    pub amount: sqlx::types::BigDecimal,
    pub destination_address: String,
    pub fiat_reference_id: String,
    pub asset_code: String,
    pub status: MintRequestStatus,
    pub rejection_reason: Option<String>,
    pub submitted_by: Option<String>,
    pub submitted_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct MintRepository {
    pool: PgPool,
}

impl MintRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        amount: Decimal,
        destination_address: &str,
        fiat_reference_id: &str,
        asset_code: &str,
        submitted_by: Option<&str>,
    ) -> Result<MintRequest, DatabaseError> {
        let bd: sqlx::types::BigDecimal = amount.to_string().parse().unwrap_or_default();

        sqlx::query_as!(
            MintRequest,
            r#"INSERT INTO mint_requests
               (amount, destination_address, fiat_reference_id, asset_code, submitted_by)
               VALUES ($1, $2, $3, $4, $5)
               RETURNING id, amount, destination_address, fiat_reference_id, asset_code,
                         status as "status: MintRequestStatus", rejection_reason,
                         submitted_by, submitted_at, updated_at"#,
            bd,
            destination_address,
            fiat_reference_id,
            asset_code,
            submitted_by,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<MintRequest>, DatabaseError> {
        sqlx::query_as!(
            MintRequest,
            r#"SELECT id, amount, destination_address, fiat_reference_id, asset_code,
                      status as "status: MintRequestStatus", rejection_reason,
                      submitted_by, submitted_at, updated_at
               FROM mint_requests WHERE id = $1"#,
            id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Check if fiat_reference_id is already used in a non-terminal request.
    pub async fn fiat_ref_in_use(&self, fiat_reference_id: &str) -> Result<bool, DatabaseError> {
        let count: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM mint_requests
             WHERE fiat_reference_id = $1
               AND status NOT IN ('rejected', 'failed')",
            fiat_reference_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?
        .unwrap_or(0);

        Ok(count > 0)
    }

    /// Confirm the fiat reference exists in confirmed_deposits.
    pub async fn confirmed_deposit_exists(
        &self,
        reference_id: &str,
    ) -> Result<bool, DatabaseError> {
        let exists: bool = sqlx::query_scalar!(
            "SELECT EXISTS(SELECT 1 FROM confirmed_deposits WHERE reference_id = $1)",
            reference_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?
        .unwrap_or(false);

        Ok(exists)
    }

    pub async fn update_status(
        &self,
        id: Uuid,
        status: MintRequestStatus,
        rejection_reason: Option<&str>,
    ) -> Result<(), DatabaseError> {
        sqlx::query!(
            "UPDATE mint_requests SET status = $2, rejection_reason = $3 WHERE id = $1",
            id,
            status as MintRequestStatus,
            rejection_reason,
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }
}
