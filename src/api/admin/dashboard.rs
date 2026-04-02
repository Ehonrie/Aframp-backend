//! Dashboard API for Circuit Breaker Status
//!
//! Provides real-time monitoring endpoints for system status and alerts

use crate::security::{AnomalyDetectionService, SystemStatus, CircuitBreakerState};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

// ---------------------------------------------------------------------------
// Request/Response Types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct DashboardStatusResponse {
    pub status: String,
    pub status_description: String,
    pub is_operational: bool,
    pub triggered_at: Option<String>,
    pub last_anomaly: Option<serde_json::Value>,
    pub audit_required: bool,
    pub uptime_percentage: f64,
    pub alerts_last_24h: u64,
    pub timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct SystemHealthResponse {
    pub healthy: bool,
    pub status: String,
    pub checks: Vec<HealthCheck>,
    pub timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct HealthCheck {
    pub name: String,
    pub status: String,
    pub message: Option<String>,
    pub response_time_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct AlertHistoryResponse {
    pub alerts: Vec<AlertEntry>,
    pub total_count: u64,
    pub last_24h: u64,
}

#[derive(Debug, Serialize)]
pub struct AlertEntry {
    pub id: String,
    pub timestamp: String,
    pub severity: String,
    pub title: String,
    pub message: String,
    pub anomaly_type: String,
    pub resolved: bool,
}

// ---------------------------------------------------------------------------
// API State
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DashboardApiState {
    pub anomaly_service: Arc<AnomalyDetectionService>,
}

// ---------------------------------------------------------------------------
// API Endpoints
// ---------------------------------------------------------------------------

/// GET /api/dashboard/status
/// 
/// Get current system status for dashboard display
pub async fn get_dashboard_status(
    State(state): State<Arc<DashboardApiState>>,
) -> Result<impl IntoResponse, crate::error::AppError> {
    let circuit_state = state.anomaly_service.get_circuit_breaker_state().await;
    let status = circuit_state.status.clone();
    
    let response = DashboardStatusResponse {
        status: status.to_string(),
        status_description: get_status_description(&status),
        is_operational: matches!(status, SystemStatus::Operational),
        triggered_at: circuit_state.triggered_at.map(|dt| dt.to_rfc3339()),
        last_anomaly: circuit_state.last_anomaly.map(|a| serde_json::to_value(a).unwrap_or_default()),
        audit_required: circuit_state.audit_required,
        uptime_percentage: calculate_uptime_percentage().await, // Would be calculated from historical data
        alerts_last_24h: get_alerts_last_24h().await, // Would be fetched from alert logs
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    
    Ok((StatusCode::OK, Json(response)))
}

/// GET /api/dashboard/health
/// 
/// Get comprehensive system health check
pub async fn get_system_health(
    State(state): State<Arc<DashboardApiState>>,
) -> Result<impl IntoResponse, crate::error::AppError> {
    let circuit_state = state.anomaly_service.get_circuit_breaker_state().await;
    let system_status = state.anomaly_service.get_system_status().await;
    
    let mut checks = Vec::new();
    
    // Circuit breaker health check
    checks.push(HealthCheck {
        name: "circuit_breaker".to_string(),
        status: if matches!(system_status, SystemStatus::Operational) {
            "healthy".to_string()
        } else {
            "critical".to_string()
        },
        message: Some(format!("Circuit breaker status: {}", system_status)),
        response_time_ms: Some(0), // Would measure actual response time
    });
    
    // Database health check
    checks.push(HealthCheck {
        name: "database".to_string(),
        status: "healthy".to_string(), // Would check actual DB connectivity
        message: None,
        response_time_ms: Some(5),
    });
    
    // Alert system health check
    checks.push(HealthCheck {
        name: "alert_system".to_string(),
        status: "healthy".to_string(), // Would check alert service connectivity
        message: None,
        response_time_ms: Some(10),
    });
    
    let overall_healthy = matches!(system_status, SystemStatus::Operational) 
        && checks.iter().all(|check| check.status == "healthy");
    
    let response = SystemHealthResponse {
        healthy: overall_healthy,
        status: system_status.to_string(),
        checks,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    
    let status_code = if overall_healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    
    Ok((status_code, Json(response)))
}

/// GET /api/dashboard/alerts
/// 
/// Get recent alert history
pub async fn get_alert_history(
    State(state): State<Arc<DashboardApiState>>,
    Query(params): Query<AlertHistoryParams>,
) -> Result<impl IntoResponse, crate::error::AppError> {
    let limit = params.limit.unwrap_or(50).min(100); // Cap at 100
    let offset = params.offset.unwrap_or(0);
    
    // This would fetch from actual alert storage
    let alerts = fetch_alert_history(limit, offset).await;
    let total_count = get_total_alert_count().await;
    let last_24h = get_alerts_last_24h().await;
    
    let response = AlertHistoryResponse {
        alerts,
        total_count,
        last_24h,
    };
    
    Ok((StatusCode::OK, Json(response)))
}

/// GET /api/dashboard/metrics
/// 
/// Get system metrics for monitoring
pub async fn get_system_metrics(
    State(state): State<Arc<DashboardApiState>>,
) -> Result<impl IntoResponse, crate::error::AppError> {
    let circuit_state = state.anomaly_service.get_circuit_breaker_state().await;
    
    let metrics = serde_json::json!({
        "system_status": circuit_state.status.to_string(),
        "audit_required": circuit_state.audit_required,
        "triggered_at": circuit_state.triggered_at,
        "last_anomaly": circuit_state.last_anomaly,
        "velocity_checks_24h": get_velocity_checks_count().await,
        "reserve_checks_24h": get_reserve_checks_count().await,
        "unknown_origin_mints_24h": get_unknown_origin_count().await,
        "transactions_halted_last_trigger": get_halted_transaction_count().await,
        "uptime_percentage": calculate_uptime_percentage().await,
        "timestamp": chrono::Utc::now().to_rfc3339()
    });
    
    Ok((StatusCode::OK, Json(metrics)))
}

// ---------------------------------------------------------------------------
// Query Parameters
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AlertHistoryParams {
    pub limit: Option<u64>,
    pub offset: Option<u64>,
    pub severity: Option<String>,
    pub resolved: Option<bool>,
}

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

fn get_status_description(status: &SystemStatus) -> String {
    match status {
        SystemStatus::Operational => 
            "🟢 System is operating normally. All minting and burning operations are functional.".to_string(),
        SystemStatus::PartialHalt => 
            "🟡 Some operations are halted due to security concerns. Critical functions remain active.".to_string(),
        SystemStatus::EmergencyStop => 
            "🔴 ALL OPERATIONS HALTED - Emergency mode activated. Manual audit required for recovery.".to_string(),
    }
}

// These would be implemented with actual data sources
async fn calculate_uptime_percentage() -> f64 {
    // Calculate from historical system_status data
    99.9 // Placeholder
}

async fn get_alerts_last_24h() -> u64 {
    // Query alert logs for last 24 hours
    0 // Placeholder
}

async fn fetch_alert_history(limit: u64, offset: u64) -> Vec<AlertEntry> {
    // Fetch from alert storage with pagination
    vec![] // Placeholder
}

async fn get_total_alert_count() -> u64 {
    // Get total count of alerts
    0 // Placeholder
}

async fn get_velocity_checks_count() -> u64 {
    // Count velocity checks in last 24h
    0 // Placeholder
}

async fn get_reserve_checks_count() -> u64 {
    // Count reserve ratio checks in last 24h
    0 // Placeholder
}

async fn get_unknown_origin_count() -> u64 {
    // Count unknown origin mints in last 24h
    0 // Placeholder
}

async fn get_halted_transaction_count() -> u64 {
    // Get count of transactions halted in last trigger
    0 // Placeholder
}

// ---------------------------------------------------------------------------
// Router Setup
// ---------------------------------------------------------------------------

pub fn create_router(
    anomaly_service: Arc<AnomalyDetectionService>,
) -> axum::Router {
    let state = Arc::new(DashboardApiState {
        anomaly_service,
    });
    
    axum::Router::new()
        .route("/status", axum::routing::get(get_dashboard_status))
        .route("/health", axum::routing::get(get_system_health))
        .route("/alerts", axum::routing::get(get_alert_history))
        .route("/metrics", axum::routing::get(get_system_metrics))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_description() {
        let operational_desc = get_status_description(&SystemStatus::Operational);
        assert!(operational_desc.contains("🟢"));
        assert!(operational_desc.contains("operating normally"));
        
        let emergency_desc = get_status_description(&SystemStatus::EmergencyStop);
        assert!(emergency_desc.contains("🔴"));
        assert!(emergency_desc.contains("ALL OPERATIONS HALTED"));
    }

    #[test]
    fn test_alert_history_params() {
        let params = AlertHistoryParams {
            limit: Some(10),
            offset: Some(5),
            severity: Some("critical".to_string()),
            resolved: Some(false),
        };
        
        assert_eq!(params.limit, Some(10));
        assert_eq!(params.offset, Some(5));
        assert_eq!(params.severity, Some("critical".to_string()));
        assert_eq!(params.resolved, Some(false));
    }
}
