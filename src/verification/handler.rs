/// Internal API endpoints for the Collateral Verification Engine.
///
/// GET  /api/internal/verification/latest   — latest verified state
/// GET  /api/internal/verification/history  — paginated snapshot history
/// POST /api/internal/verification/trigger  — on-demand verification run
use crate::verification::engine::{VerificationEngine, VerificationError};
use crate::verification::repository::VerificationRepository;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

pub struct VerificationState {
    pub engine: Arc<VerificationEngine>,
    pub repo: Arc<VerificationRepository>,
}

pub async fn get_latest(State(s): State<Arc<VerificationState>>) -> impl IntoResponse {
    match s.repo.latest().await {
        Ok(Some(snap)) => (StatusCode::OK, Json(serde_json::json!({ "data": snap }))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "No verification snapshot found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn get_history(
    State(s): State<Arc<VerificationState>>,
    Query(q): Query<HistoryQuery>,
) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(20).clamp(1, 100);
    let offset = q.offset.unwrap_or(0).max(0);

    match s.repo.history(limit, offset).await {
        Ok(snaps) => (StatusCode::OK, Json(serde_json::json!({ "data": snaps }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn trigger_verification(State(s): State<Arc<VerificationState>>) -> impl IntoResponse {
    match s.engine.run("api").await {
        Ok(result) => (StatusCode::OK, Json(serde_json::json!({ "data": result }))).into_response(),
        Err(VerificationError::StellarFetch(msg)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "Stellar fetch failed — result not persisted to avoid false negative",
                "detail": msg
            })),
        )
            .into_response(),
        Err(VerificationError::ReserveFetch(msg)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "Reserve fetch failed — result not persisted to avoid false negative",
                "detail": msg
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}
