//! HTTP handlers for the Nigeria → Ghana corridor API.

use crate::corridors::ghana::models::*;
use crate::corridors::ghana::service::{GhanaCorridorError, GhanaCorridorService};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

pub struct GhanaCorridorState {
    pub service: Arc<GhanaCorridorService>,
    pub pool: Arc<PgPool>,
}

#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Serialize)]
pub struct ApiError {
    pub success: bool,
    pub error: String,
    pub code: &'static str,
}

fn ok<T: Serialize>(data: T) -> Json<ApiResponse<T>> {
    Json(ApiResponse { success: true, data, message: None })
}

fn err(status: StatusCode, msg: String, code: &'static str) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError { success: false, error: msg, code }))
}

fn map_err(e: GhanaCorridorError) -> (StatusCode, Json<ApiError>) {
    match &e {
        GhanaCorridorError::ComplianceDenied(_) => err(StatusCode::FORBIDDEN, e.to_string(), "COMPLIANCE_DENIED"),
        GhanaCorridorError::RecipientInvalid(_) => err(StatusCode::UNPROCESSABLE_ENTITY, e.to_string(), "RECIPIENT_INVALID"),
        GhanaCorridorError::LimitExceeded(_) => err(StatusCode::UNPROCESSABLE_ENTITY, e.to_string(), "LIMIT_EXCEEDED"),
        GhanaCorridorError::BogRequirement(_) => err(StatusCode::UNPROCESSABLE_ENTITY, e.to_string(), "BOG_REQUIREMENT"),
        GhanaCorridorError::FxUnavailable(_) => err(StatusCode::SERVICE_UNAVAILABLE, e.to_string(), "FX_UNAVAILABLE"),
        GhanaCorridorError::DisbursementFailed(_) => err(StatusCode::BAD_GATEWAY, e.to_string(), "DISBURSEMENT_FAILED"),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string(), "INTERNAL_ERROR"),
    }
}

#[derive(Deserialize)]
pub struct QuoteQuery {
    pub cngn_amount: Decimal,
}

/// GET /api/corridors/ghana/quote?cngn_amount=5000
pub async fn get_quote_handler(
    State(state): State<Arc<GhanaCorridorState>>,
    Query(params): Query<QuoteQuery>,
) -> Result<Json<ApiResponse<GhanaTransferQuote>>, (StatusCode, Json<ApiError>)> {
    state.service.get_quote(params.cngn_amount).await.map(ok).map_err(map_err)
}

/// POST /api/corridors/ghana/transfer
pub async fn initiate_transfer_handler(
    State(state): State<Arc<GhanaCorridorState>>,
    Json(req): Json<GhanaTransferRequest>,
) -> Result<(StatusCode, Json<ApiResponse<GhanaTransferResponse>>), (StatusCode, Json<ApiError>)> {
    state
        .service
        .initiate_transfer(&req)
        .await
        .map(|r| {
            (
                StatusCode::CREATED,
                Json(ApiResponse {
                    success: true,
                    data: r,
                    message: Some("Transfer initiated".to_string()),
                }),
            )
        })
        .map_err(map_err)
}

/// GET /api/corridors/ghana/transfer/:id
pub async fn get_transfer_handler(
    State(state): State<Arc<GhanaCorridorState>>,
    Path(transfer_id): Path<Uuid>,
) -> Result<Json<ApiResponse<serde_json::Value>>, (StatusCode, Json<ApiError>)> {
    let row = sqlx::query!(
        r#"
        SELECT transaction_id, status, from_amount, to_amount, metadata, created_at, updated_at
        FROM transactions
        WHERE transaction_id = $1 AND type = 'ghana_corridor'
        "#,
        transfer_id,
    )
    .fetch_optional(state.pool.as_ref())
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string(), "DATABASE_ERROR"))?;

    match row {
        Some(r) => Ok(ok(serde_json::json!({
            "transfer_id": r.transaction_id,
            "status": r.status,
            "cngn_amount": r.from_amount,
            "ghs_amount": r.to_amount,
            "metadata": r.metadata,
            "created_at": r.created_at,
            "updated_at": r.updated_at,
        }))),
        None => Err(err(StatusCode::NOT_FOUND, format!("Transfer {} not found", transfer_id), "NOT_FOUND")),
    }
}
