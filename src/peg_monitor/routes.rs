use crate::peg_monitor::handlers::{
    get_depeg_events, get_peg_health, get_peg_history, PegMonitorState,
};
use axum::{routing::get, Router};

pub fn peg_monitor_routes(state: PegMonitorState) -> Router {
    Router::new()
        .route("/api/peg/health", get(get_peg_health))
        .route("/api/peg/history", get(get_peg_history))
        .route("/api/peg/events", get(get_depeg_events))
        .with_state(state)
}
