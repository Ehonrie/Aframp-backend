use super::models::*;
use super::repository::LiquidityRepository;
use super::service::LiquidityService;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

pub type LiquidityState = Arc<LiquidityHandlerState>;

pub struct LiquidityHandlerState {
    pub repo: Arc<LiquidityRepository>,
    pub service: Arc<LiquidityService>,
}

// ── Public ────────────────────────────────────────────────────────────────────

/// GET /api/liquidity/depth?currency_pair=cNGN/NGN
pub async fn get_depth(
    State(s): State<LiquidityState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let Some(pair) = params.get("currency_pair") else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error":"currency_pair required"}))).into_response();
    };
    match s.service.get_depth(pair).await {
        Ok(d) => (StatusCode::OK, Json(json!(d))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

// ── Admin ─────────────────────────────────────────────────────────────────────

/// GET /api/admin/liquidity/pools
pub async fn list_pools(State(s): State<LiquidityState>) -> impl IntoResponse {
    match s.repo.list_pools().await {
        Ok(pools) => {
            let out: Vec<_> = pools.into_iter().map(pool_with_health).collect();
            (StatusCode::OK, Json(json!(out))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

/// GET /api/admin/liquidity/pools/:pool_id
pub async fn get_pool(
    State(s): State<LiquidityState>,
    Path(pool_id): Path<Uuid>,
) -> impl IntoResponse {
    let pool = match s.repo.get_pool(pool_id).await {
        Ok(Some(p)) => p,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(json!({"error":"pool not found"}))).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };
    let allocations = s.repo.get_pool_allocations(pool_id).await.unwrap_or_default();
    let history = s.repo.get_utilisation_history(pool_id, 30).await.unwrap_or_default();
    (StatusCode::OK, Json(json!({
        "pool": pool_with_health(pool),
        "allocations": allocations,
        "utilisation_history": history,
    }))).into_response()
}

/// POST /api/admin/liquidity/pools
pub async fn create_pool(
    State(s): State<LiquidityState>,
    Json(req): Json<CreatePoolRequest>,
) -> impl IntoResponse {
    match s.repo.create_pool(&req).await {
        Ok(p) => (StatusCode::CREATED, Json(json!(p))).into_response(),
        Err(e) => (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

/// PATCH /api/admin/liquidity/pools/:pool_id
pub async fn update_pool(
    State(s): State<LiquidityState>,
    Path(pool_id): Path<Uuid>,
    Json(req): Json<UpdatePoolRequest>,
) -> impl IntoResponse {
    match s.repo.update_pool(pool_id, &req).await {
        Ok(Some(p)) => (StatusCode::OK, Json(json!(p))).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error":"pool not found"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

/// POST /api/admin/liquidity/pools/:pool_id/pause
pub async fn pause_pool(State(s): State<LiquidityState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    set_status(s, id, PoolStatus::Paused).await
}

/// POST /api/admin/liquidity/pools/:pool_id/resume
pub async fn resume_pool(State(s): State<LiquidityState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    set_status(s, id, PoolStatus::Active).await
}

/// POST /api/admin/liquidity/pools/:pool_id/deactivate
pub async fn deactivate_pool(State(s): State<LiquidityState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    set_status(s, id, PoolStatus::Deactivated).await
}

async fn set_status(s: LiquidityState, pool_id: Uuid, status: PoolStatus) -> impl IntoResponse {
    match s.repo.set_pool_status(pool_id, status.clone()).await {
        Ok(true) => {
            tracing::info!(pool_id = %pool_id, ?status, "Pool status changed");
            (StatusCode::OK, Json(json!({"pool_id": pool_id, "status": status}))).into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, Json(json!({"error":"pool not found"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn pool_with_health(pool: LiquidityPool) -> PoolWithHealth {
    use bigdecimal::ToPrimitive;
    let total = pool.total_liquidity_depth.to_f64().unwrap_or(0.0);
    let reserved = pool.reserved_liquidity.to_f64().unwrap_or(0.0);
    let utilisation_pct = if total > 0.0 { reserved / total * 100.0 } else { 0.0 };

    let factor = sqlx::types::BigDecimal::from_str("0.99").unwrap_or(sqlx::types::BigDecimal::from(1));
    let effective_depth = &pool.available_liquidity * &factor;

    let health_status = if pool.available_liquidity < pool.min_liquidity_threshold {
        PoolHealthStatus::BelowMinimum
    } else if pool.available_liquidity > pool.max_liquidity_cap {
        PoolHealthStatus::OverCap
    } else if utilisation_pct > crate::liquidity::HIGH_UTILISATION_THRESHOLD {
        PoolHealthStatus::HighUtilisation
    } else if pool.available_liquidity < pool.target_liquidity_level {
        PoolHealthStatus::BelowTarget
    } else {
        PoolHealthStatus::Healthy
    };

    PoolWithHealth { pool, utilisation_pct, effective_depth, health_status }
}
