//! Circuit Breaker API - Emergency System Controls
//!
//! Provides secure endpoints for manual emergency stop and system status monitoring

use crate::security::{AnomalyDetectionService, SystemStatus};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    middleware,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// Request/Response Types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct EmergencyStopRequest {
    /// Reason for emergency stop
    pub reason: String,
    /// Authorizing administrator identifier
    pub authorized_by: String,
    /// Multi-signature authorization codes (for enhanced security)
    pub auth_codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuditResetRequest {
    /// First auditor identifier
    pub auditor_1: String,
    /// Second auditor identifier  
    pub auditor_2: String,
    /// Reason for reset
    pub reset_reason: String,
    /// Audit verification codes
    pub audit_codes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SystemStatusResponse {
    pub status: String,
    pub triggered_at: Option<String>,
    pub last_anomaly: Option<serde_json::Value>,
    pub audit_required: bool,
    pub is_operational: bool,
}

#[derive(Debug, Serialize)]
pub struct EmergencyStopResponse {
    pub success: bool,
    pub status: String,
    pub message: String,
    pub triggered_at: String,
}

#[derive(Debug, Serialize)]
pub struct AuditResetResponse {
    pub success: bool,
    pub status: String,
    pub message: String,
    pub reset_at: String,
}

// ---------------------------------------------------------------------------
// API State
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct CircuitBreakerApiState {
    pub anomaly_service: Arc<AnomalyDetectionService>,
}

// ---------------------------------------------------------------------------
// API Endpoints
// ---------------------------------------------------------------------------

/// GET /api/admin/circuit-breaker/status
/// 
/// Get current circuit breaker status (requires admin access)
pub async fn get_system_status(
    State(state): State<Arc<CircuitBreakerApiState>>,
) -> Result<impl IntoResponse, crate::error::AppError> {
    let circuit_state = state.anomaly_service.get_circuit_breaker_state().await;
    
    let response = SystemStatusResponse {
        status: circuit_state.status.to_string(),
        triggered_at: circuit_state.triggered_at.map(|dt| dt.to_rfc3339()),
        last_anomaly: circuit_state.last_anomaly.map(|a| serde_json::to_value(a).unwrap_or_default()),
        audit_required: circuit_state.audit_required,
        is_operational: matches!(circuit_state.status, SystemStatus::Operational),
    };
    
    Ok((StatusCode::OK, Json(response)))
}

/// POST /api/admin/circuit-breaker/emergency-stop
/// 
/// Manual emergency stop with multi-sig protection
pub async fn emergency_stop(
    State(state): State<Arc<CircuitBreakerApiState>>,
    Json(req): Json<EmergencyStopRequest>,
) -> Result<impl IntoResponse, crate::error::AppError> {
    // Validate authorization codes
    if !validate_emergency_auth(&req.auth_codes) {
        return Err(crate::error::AppError::new(
            crate::error::AppErrorKind::Domain(
                crate::error::DomainError::Forbidden {
                    message: "Invalid authorization codes for emergency stop".to_string(),
                }
            )
        ));
    }
    
    // Check if system is already stopped
    let current_status = state.anomaly_service.get_system_status().await;
    if matches!(current_status, SystemStatus::EmergencyStop) {
        return Ok((StatusCode::OK, Json(EmergencyStopResponse {
            success: false,
            status: current_status.to_string(),
            message: "System already in emergency stop state".to_string(),
            triggered_at: chrono::Utc::now().to_rfc3339(),
        })));
    }
    
    // Trigger emergency stop
    state.anomaly_service
        .manual_emergency_stop(&req.reason, &req.authorized_by)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to trigger emergency stop");
            crate::error::AppError::new(
                crate::error::AppErrorKind::Infrastructure(
                    crate::error::InfrastructureError::Database {
                        message: e.to_string(),
                        is_retryable: false,
                    }
                )
            )
        })?;
    
    let new_status = state.anomaly_service.get_system_status().await;
    
    warn!(
        reason = %req.reason,
        authorized_by = %req.authorized_by,
        new_status = %new_status,
        "Emergency stop activated via API"
    );
    
    Ok((StatusCode::OK, Json(EmergencyStopResponse {
        success: true,
        status: new_status.to_string(),
        message: "Emergency stop activated successfully".to_string(),
        triggered_at: chrono::Utc::now().to_rfc3339(),
    })))
}

/// POST /api/admin/circuit-breaker/audit-reset
/// 
/// Reset system after manual audit by two authorized executives
pub async fn audit_reset(
    State(state): State<Arc<CircuitBreakerApiState>>,
    Json(req): Json<AuditResetRequest>,
) -> Result<impl IntoResponse, crate::error::AppError> {
    // Validate audit codes
    if !validate_audit_auth(&req.audit_codes) {
        return Err(crate::error::AppError::new(
            crate::error::AppErrorKind::Domain(
                crate::error::DomainError::Forbidden {
                    message: "Invalid audit authorization codes".to_string(),
                }
            )
        ));
    }
    
    // Verify auditors are different people
    if req.auditor_1 == req.auditor_2 {
        return Err(crate::error::AppError::new(
            crate::error::AppErrorKind::Domain(
                crate::error::DomainError::Forbidden {
                    message: "Auditor 1 and Auditor 2 must be different individuals".to_string(),
                }
            )
        ));
    }
    
    // Check if system requires audit
    let circuit_state = state.anomaly_service.get_circuit_breaker_state().await;
    if !circuit_state.audit_required {
        return Err(crate::error::AppError::new(
            crate::error::AppErrorKind::Domain(
                crate::error::DomainError::Forbidden {
                    message: "No audit required or system not halted".to_string(),
                }
            )
        ));
    }
    
    // Perform audit reset
    state.anomaly_service
        .audit_and_reset(&req.auditor_1, &req.auditor_2, &req.reset_reason)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to reset system after audit");
            crate::error::AppError::new(
                crate::error::AppErrorKind::Infrastructure(
                    crate::error::InfrastructureError::Database {
                        message: e.to_string(),
                        is_retryable: false,
                    }
                )
            )
        })?;
    
    let new_status = state.anomaly_service.get_system_status().await;
    
    info!(
        auditor_1 = %req.auditor_1,
        auditor_2 = %req.auditor_2,
        reason = %req.reset_reason,
        new_status = %new_status,
        "System reset after manual audit"
    );
    
    Ok((StatusCode::OK, Json(AuditResetResponse {
        success: true,
        status: new_status.to_string(),
        message: "System reset successfully after audit".to_string(),
        reset_at: chrono::Utc::now().to_rfc3339(),
    })))
}

/// GET /api/admin/circuit-breaker/health
/// 
/// Health check endpoint that includes circuit breaker status
pub async fn circuit_breaker_health(
    State(state): State<Arc<CircuitBreakerApiState>>,
) -> Result<impl IntoResponse, crate::error::AppError> {
    let status = state.anomaly_service.get_system_status().await;
    let circuit_state = state.anomaly_service.get_circuit_breaker_state().await;
    
    let health_response = serde_json::json!({
        "healthy": matches!(status, SystemStatus::Operational),
        "status": status.to_string(),
        "circuit_breaker": {
            "status": circuit_state.status.to_string(),
            "triggered_at": circuit_state.triggered_at.map(|dt| dt.to_rfc3339()),
            "audit_required": circuit_state.audit_required,
            "last_anomaly": circuit_state.last_anomaly
        },
        "timestamp": chrono::Utc::now().to_rfc3339()
    });
    
    let http_status = match status {
        SystemStatus::Operational => StatusCode::OK,
        SystemStatus::PartialHalt => StatusCode::SERVICE_UNAVAILABLE,
        SystemStatus::EmergencyStop => StatusCode::SERVICE_UNAVAILABLE,
    };
    
    Ok((http_status, Json(health_response)))
}

// ---------------------------------------------------------------------------
// Authorization Helpers
// ---------------------------------------------------------------------------

/// Validate emergency stop authorization codes
fn validate_emergency_auth(auth_codes: &[String]) -> bool {
    // In production, this would validate against secure multi-sig requirements
    // For now, we'll implement a basic check that requires at least 2 auth codes
    if auth_codes.len() < 2 {
        return false;
    }
    
    // Check against environment-stored valid codes (in production, use HSM)
    let valid_codes: Vec<String> = std::env::var("EMERGENCY_AUTH_CODES")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    
    if valid_codes.is_empty() {
        warn!("No emergency auth codes configured - allowing for development");
        return true; // Allow in development if no codes configured
    }
    
    auth_codes.iter().all(|code| valid_codes.contains(code))
}

/// Validate audit authorization codes
fn validate_audit_auth(audit_codes: &[String]) -> bool {
    // Similar to emergency auth but with different codes
    if audit_codes.len() < 2 {
        return false;
    }
    
    let valid_codes: Vec<String> = std::env::var("AUDIT_AUTH_CODES")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    
    if valid_codes.is_empty() {
        warn!("No audit auth codes configured - allowing for development");
        return true; // Allow in development if no codes configured
    }
    
    audit_codes.iter().all(|code| valid_codes.contains(code))
}

// ---------------------------------------------------------------------------
// Router Setup
// ---------------------------------------------------------------------------

pub fn create_router(
    anomaly_service: Arc<AnomalyDetectionService>,
) -> axum::Router {
    let state = Arc::new(CircuitBreakerApiState {
        anomaly_service,
    });
    
    axum::Router::new()
        .route("/status", axum::routing::get(get_system_status))
        .route("/emergency-stop", axum::routing::post(emergency_stop))
        .route("/audit-reset", axum::routing::post(audit_reset))
        .route("/health", axum::routing::get(circuit_breaker_health))
        .with_state(state)
        // Add admin authentication middleware in production
        // .layer(middleware::from_fn(admin_auth_middleware))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_emergency_auth_validation() {
        // Test with no codes configured (development mode)
        std::env::remove_var("EMERGENCY_AUTH_CODES");
        assert!(validate_emergency_auth(&["code1".to_string(), "code2".to_string()]));
        
        // Test with codes configured
        std::env::set_var("EMERGENCY_AUTH_CODES", "code1,code2,code3");
        assert!(validate_emergency_auth(&["code1".to_string(), "code2".to_string()]));
        assert!(!validate_emergency_auth(&["invalid".to_string(), "code2".to_string()]));
        assert!(!validate_emergency_auth(&["code1".to_string()])); // Only one code
        
        std::env::remove_var("EMERGENCY_AUTH_CODES");
    }
    
    #[test]
    fn test_audit_auth_validation() {
        // Test with no codes configured (development mode)
        std::env::remove_var("AUDIT_AUTH_CODES");
        assert!(validate_audit_auth(&["audit1".to_string(), "audit2".to_string()]));
        
        // Test with codes configured
        std::env::set_var("AUDIT_AUTH_CODES", "audit1,audit2,audit3");
        assert!(validate_audit_auth(&["audit1".to_string(), "audit2".to_string()]));
        assert!(!validate_audit_auth(&["invalid".to_string(), "audit2".to_string()]));
        
        std::env::remove_var("AUDIT_AUTH_CODES");
    }
}
