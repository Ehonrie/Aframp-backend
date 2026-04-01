use crate::peg_monitor::{
    models::{OpenDepegInfo, PegHealthResponse},
    repository::PegMonitorRepository,
};
use axum::{extract::State, http::StatusCode, Json};
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use std::sync::Arc;

pub type PegMonitorState = Arc<PegMonitorRepository>;

/// GET /api/peg/health — public peg health status for Transparency Page
pub async fn get_peg_health(
    State(repo): State<PegMonitorState>,
) -> Result<Json<PegHealthResponse>, StatusCode> {
    let snap = repo
        .latest_snapshot()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let open_event = repo
        .open_depeg_event()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let status = match snap.alert_level {
        0 => "healthy",
        1 | 2 => "warning",
        _ => "critical",
    };

    Ok(Json(PegHealthResponse {
        status,
        alert_level: snap.alert_level,
        dex_price: snap.dex_price.to_string(),
        oracle_price: snap.oracle_price.to_string(),
        deviation_bps: snap.deviation_bps.to_string(),
        captured_at: snap.captured_at,
        open_depeg_event: open_event.map(|e| OpenDepegInfo {
            started_at: e.started_at,
            peak_deviation_bps: e.peak_deviation_bps.to_string(),
            max_alert_level: e.max_alert_level,
        }),
    }))
}

/// GET /api/peg/history — time-series snapshots (last 24h by default)
pub async fn get_peg_history(
    State(repo): State<PegMonitorState>,
) -> Result<Json<Value>, StatusCode> {
    let since = Utc::now() - Duration::hours(24);
    let snapshots = repo
        .snapshots_since(since, 1440) // max 1 per minute × 24h
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(json!({ "data": snapshots })))
}

/// GET /api/peg/events — recent de-peg events with time-to-recovery
pub async fn get_depeg_events(
    State(repo): State<PegMonitorState>,
) -> Result<Json<Value>, StatusCode> {
    let events = repo
        .recent_depeg_events(50)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(json!({ "data": events })))
}
