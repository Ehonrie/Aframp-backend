//! Route definitions for the Nigeria → Ghana corridor.

use crate::corridors::ghana::handlers::*;
use crate::corridors::ghana::webhook::{handle_hubtel_ghana_webhook, GhanaWebhookState};
use axum::{routing::{get, post}, Router};
use std::sync::Arc;

pub fn ghana_corridor_router(state: Arc<GhanaCorridorState>) -> Router {
    Router::new()
        .route("/quote", get(get_quote_handler))
        .route("/transfer", post(initiate_transfer_handler))
        .route("/transfer/:id", get(get_transfer_handler))
        .with_state(state)
}

pub fn ghana_webhook_router(state: Arc<GhanaWebhookState>) -> Router {
    Router::new()
        .route("/hubtel_ghana", post(handle_hubtel_ghana_webhook))
        .with_state(state)
}
