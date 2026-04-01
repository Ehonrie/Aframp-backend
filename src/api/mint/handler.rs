use crate::api::mint::{repository::MintRepository, validator::MintValidator};
use crate::chains::stellar::trustline::CngnTrustlineManager;
use crate::error::{AppError, AppErrorKind, ValidationError};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;

pub struct MintState {
    pub repo: Arc<MintRepository>,
    pub validator: Arc<MintValidator>,
}

// ── Request / Response ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct MintSubmitRequest {
    pub amount: String,
    pub destination_address: String,
    pub fiat_reference_id: String,
    #[serde(default = "default_asset_code")]
    pub asset_code: String,
}

fn default_asset_code() -> String {
    "cNGN".to_string()
}

#[derive(Debug, Serialize)]
pub struct MintSubmitResponse {
    pub mint_request_id: Uuid,
    pub status: String,
    pub destination_address: String,
    pub amount: String,
    pub asset_code: String,
    pub fiat_reference_id: String,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// POST /api/mint/requests
pub async fn submit_mint_request(
    State(state): State<Arc<MintState>>,
    req: axum::extract::Request,
) -> Result<impl IntoResponse, AppError> {
    // Extract actor from auth context (optional — system may call without auth)
    let submitted_by = req
        .extensions()
        .get::<crate::auth::OAuthTokenClaims>()
        .map(|c| c.sub.clone())
        .or_else(|| {
            req.extensions()
                .get::<crate::auth::jwt::TokenClaims>()
                .map(|c| c.sub.clone())
        });

    // Extract JSON body
    let Json(body): Json<MintSubmitRequest> = Json::from_request(req, &())
        .await
        .map_err(|_| {
            AppError::new(AppErrorKind::Validation(ValidationError::MissingField {
                field: "request body".to_string(),
            }))
        })?;

    if body.fiat_reference_id.trim().is_empty() {
        return Err(AppError::new(AppErrorKind::Validation(
            ValidationError::MissingField {
                field: "fiat_reference_id".to_string(),
            },
        )));
    }

    // Run all validation checks
    let amount = state
        .validator
        .validate(
            &body.amount,
            &body.destination_address,
            &body.fiat_reference_id,
            &body.asset_code,
        )
        .await?;

    // Persist in PENDING_VALIDATION state
    let record = state
        .repo
        .create(
            amount,
            &body.destination_address,
            &body.fiat_reference_id,
            &body.asset_code,
            submitted_by.as_deref(),
        )
        .await
        .map_err(|e| {
            AppError::new(AppErrorKind::Infrastructure(
                crate::error::InfrastructureError::Database {
                    message: e.to_string(),
                    is_retryable: true,
                },
            ))
        })?;

    info!(
        mint_request_id = %record.id,
        destination = %body.destination_address,
        amount = %body.amount,
        fiat_ref = %body.fiat_reference_id,
        "Mint request submitted"
    );

    Ok((
        StatusCode::CREATED,
        Json(MintSubmitResponse {
            mint_request_id: record.id,
            status: "pending_validation".to_string(),
            destination_address: record.destination_address,
            amount: record.amount.to_string(),
            asset_code: record.asset_code,
            fiat_reference_id: record.fiat_reference_id,
        }),
    ))
}

/// GET /api/mint/requests/:id
pub async fn get_mint_request(
    State(state): State<Arc<MintState>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let record = state.repo.get_by_id(id).await.map_err(|e| {
        AppError::new(AppErrorKind::Infrastructure(
            crate::error::InfrastructureError::Database {
                message: e.to_string(),
                is_retryable: true,
            },
        ))
    })?;

    match record {
        Some(r) => Ok((StatusCode::OK, Json(r)).into_response()),
        None => Err(AppError::new(AppErrorKind::Domain(
            crate::error::DomainError::TransactionNotFound {
                transaction_id: id.to_string(),
            },
        ))),
    }
}
