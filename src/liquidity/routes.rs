use super::handlers::{
    create_pool, deactivate_pool, get_depth, get_pool, list_pools, pause_pool, resume_pool,
    update_pool, LiquidityState,
};
use axum::{
    routing::{get, patch, post},
    Router,
};

/// Public routes (consumer pre-flight depth check)
pub fn public_routes(state: LiquidityState) -> Router {
    Router::new()
        .route("/api/liquidity/depth", get(get_depth))
        .with_state(state)
}

/// Admin routes (require admin auth middleware applied by caller)
pub fn admin_routes(state: LiquidityState) -> Router {
    Router::new()
        .route("/api/admin/liquidity/pools", get(list_pools).post(create_pool))
        .route(
            "/api/admin/liquidity/pools/:pool_id",
            get(get_pool).patch(update_pool),
        )
        .route("/api/admin/liquidity/pools/:pool_id/pause", post(pause_pool))
        .route("/api/admin/liquidity/pools/:pool_id/resume", post(resume_pool))
        .route(
            "/api/admin/liquidity/pools/:pool_id/deactivate",
            post(deactivate_pool),
        )
        .with_state(state)
}
