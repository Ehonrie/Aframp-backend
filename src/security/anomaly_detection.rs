//! Mint Anomaly Detection & Automated Circuit Breaker
//!
//! Implements real-time monitoring for minting anomalies and automatic system halting
//! to protect the 1:1 reserve ratio in high-speed stablecoin environments.

use crate::database::repository::Repository;
use crate::database::transaction_repository::TransactionRepository;
use crate::security::alerts::{ AlertService, AlertConfig };
use serde::{ Deserialize, Serialize };
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{ Duration, Instant };
use tokio::sync::RwLock;
use tracing::{ error, info, warn };
use uuid::Uuid;

// ---------------------------------------------------------------------------
// System Status Enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text")]
pub enum SystemStatus {
    /// Normal operations - all systems functional
    #[sqlx(rename = "OPERATIONAL")]
    Operational,
    /// Some operations halted - critical functions disabled
    #[sqlx(rename = "PARTIAL_HALT")]
    PartialHalt,
    /// Complete system shutdown - emergency stop activated
    #[sqlx(rename = "EMERGENCY_STOP")]
    EmergencyStop,
}

impl Default for SystemStatus {
    fn default() -> Self {
        SystemStatus::Operational
    }
}

impl std::fmt::Display for SystemStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SystemStatus::Operational => write!(f, "OPERATIONAL"),
            SystemStatus::PartialHalt => write!(f, "PARTIAL_HALT"),
            SystemStatus::EmergencyStop => write!(f, "EMERGENCY_STOP"),
        }
    }
}

// ---------------------------------------------------------------------------
// Anomaly Detection Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AnomalyDetectionConfig {
    /// Maximum cNGN amount that can be minted within 60 seconds (in NGN units)
    pub velocity_limit_ngn: u64,
    /// Velocity check window duration
    pub velocity_window: Duration,
    /// Maximum negative delta tolerance as percentage (0.01% = 0.0001)
    pub negative_delta_tolerance: f64,
    /// Alert recipients for security incidents
    pub alert_recipients: Vec<String>,
    /// PagerDuty integration key
    pub pagerduty_key: Option<String>,
    /// Slack webhook URL
    pub slack_webhook_url: Option<String>,
}

impl Default for AnomalyDetectionConfig {
    fn default() -> Self {
        Self {
            velocity_limit_ngn: 500_000_000, // 500M NGN
            velocity_window: Duration::from_secs(60),
            negative_delta_tolerance: 0.0001, // 0.01%
            alert_recipients: vec!["security-team@company.com".to_string()],
            pagerduty_key: std::env::var("PAGERDUTY_KEY").ok(),
            slack_webhook_url: std::env::var("SLACK_WEBHOOK_URL").ok(),
        }
    }
}

impl AnomalyDetectionConfig {
    pub fn from_env() -> Self {
        let mut cfg = Self::default();

        if let Ok(velocity) = std::env::var("MINT_VELOCITY_LIMIT_NGN") {
            if let Ok(v) = velocity.parse::<u64>() {
                cfg.velocity_limit_ngn = v;
            }
        }

        if let Ok(tolerance) = std::env::var("NEGATIVE_DELTA_TOLERANCE") {
            if let Ok(t) = tolerance.parse::<f64>() {
                cfg.negative_delta_tolerance = t;
            }
        }

        cfg
    }
}

// ---------------------------------------------------------------------------
// Anomaly Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyType {
    /// Excessive minting velocity within time window
    VelocityExceeded {
        amount: u64,
        window: Duration,
        limit: u64,
    },
    /// Bank reserves less than on-chain supply beyond tolerance
    NegativeDelta {
        bank_reserves: u64,
        on_chain_supply: u64,
        delta_percentage: f64,
    },
    /// On-chain mint without corresponding database approval
    UnknownOrigin {
        tx_hash: String,
        amount: u64,
        wallet: String,
    },
}

// ---------------------------------------------------------------------------
// Circuit Breaker State
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct CircuitBreakerState {
    pub status: SystemStatus,
    pub triggered_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_anomaly: Option<AnomalyType>,
    pub audit_required: bool,
}

impl Default for CircuitBreakerState {
    fn default() -> Self {
        Self {
            status: SystemStatus::Operational,
            triggered_at: None,
            last_anomaly: None,
            audit_required: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Main Anomaly Detection Service
// ---------------------------------------------------------------------------

pub struct AnomalyDetectionService {
    pool: PgPool,
    config: AnomalyDetectionConfig,
    state: Arc<RwLock<CircuitBreakerState>>,
    velocity_tracker: Arc<RwLock<HashMap<String, Vec<(Instant, u64)>>>>,
    alert_service: Arc<AlertService>,
}

impl AnomalyDetectionService {
    pub fn new(pool: PgPool, config: AnomalyDetectionConfig) -> Self {
        let alert_config = AlertConfig::default();
        let alert_service = Arc::new(AlertService::new(alert_config));

        Self {
            pool,
            config,
            state: Arc::new(RwLock::new(CircuitBreakerState::default())),
            velocity_tracker: Arc::new(RwLock::new(HashMap::new())),
            alert_service,
        }
    }

    /// Get current system status
    pub async fn get_system_status(&self) -> SystemStatus {
        self.state.read().await.status.clone()
    }

    /// Check if system is operational (can be used as middleware)
    pub async fn is_operational(&self) -> bool {
        matches!(self.state.read().await.status, SystemStatus::Operational)
    }

    /// Record a mint event for velocity tracking
    pub async fn record_mint_event(&self, amount: u64, wallet: &str) -> anyhow::Result<()> {
        let mut tracker = self.velocity_tracker.write().await;
        let now = Instant::now();

        let wallet_events = tracker.entry(wallet.to_string()).or_insert_with(Vec::new);
        wallet_events.push((now, amount));

        // Clean old events outside the window
        let cutoff = now - self.config.velocity_window;
        wallet_events.retain(|(timestamp, _)| *timestamp >= cutoff);

        // Check velocity limit
        let total_in_window: u64 = wallet_events
            .iter()
            .map(|(_, amount)| *amount)
            .sum();

        if total_in_window > self.config.velocity_limit_ngn {
            drop(tracker); // Release lock before triggering circuit breaker

            let anomaly = AnomalyType::VelocityExceeded {
                amount: total_in_window,
                window: self.config.velocity_window,
                limit: self.config.velocity_limit_ngn,
            };

            self.trigger_circuit_breaker(anomaly).await?;
        }

        Ok(())
    }

    /// Detect unknown origin mints (on-chain without DB approval)
    pub async fn detect_unknown_origin_mints(
        &self,
        on_chain_mints: Vec<OnChainMint>
    ) -> anyhow::Result<()> {
        let tx_repo = TransactionRepository::new(self.pool.clone());

        for mint in on_chain_mints {
            // Check if this mint has a corresponding APPROVED database record
            match tx_repo.find_by_transaction_hash(&mint.tx_hash).await {
                Ok(Some(tx)) if tx.status == "approved" => {
                    // This is a legitimate mint
                    continue;
                }
                Ok(_) | Err(_) => {
                    // Unknown origin - trigger circuit breaker
                    let anomaly = AnomalyType::UnknownOrigin {
                        tx_hash: mint.tx_hash.clone(),
                        amount: mint.amount,
                        wallet: mint.wallet,
                    };

                    self.trigger_circuit_breaker(anomaly).await?;
                    break; // One anomaly is enough to trigger
                }
            }
        }

        Ok(())
    }

    /// Check for negative delta between bank reserves and on-chain supply
    pub async fn check_reserve_ratio(
        &self,
        bank_reserves: u64,
        on_chain_supply: u64
    ) -> anyhow::Result<()> {
        if bank_reserves < on_chain_supply {
            let delta = (on_chain_supply as f64) - (bank_reserves as f64);
            let delta_percentage = delta / (on_chain_supply as f64);

            if delta_percentage > self.config.negative_delta_tolerance {
                let anomaly = AnomalyType::NegativeDelta {
                    bank_reserves,
                    on_chain_supply,
                    delta_percentage,
                };

                self.trigger_circuit_breaker(anomaly).await?;
            }
        }

        Ok(())
    }

    /// Trigger the circuit breaker and halt the system
    pub async fn trigger_circuit_breaker(&self, anomaly: AnomalyType) -> anyhow::Result<()> {
        let mut state = self.state.write().await;

        // Only allow escalation, not de-escalation
        let new_status = match (&state.status, &anomaly) {
            (SystemStatus::Operational, _) => SystemStatus::PartialHalt,
            (SystemStatus::PartialHalt, AnomalyType::UnknownOrigin { .. }) =>
                SystemStatus::EmergencyStop,
            (SystemStatus::PartialHalt, _) => SystemStatus::EmergencyStop,
            (SystemStatus::EmergencyStop, _) => SystemStatus::EmergencyStop, // Already at max
        };

        state.status = new_status.clone();
        state.triggered_at = Some(chrono::Utc::now());
        state.last_anomaly = Some(anomaly.clone());
        state.audit_required = true;

        // Persist state to database
        self.persist_system_status(&new_status).await?;

        // Send alerts
        self.send_alerts(&anomaly, &new_status).await?;

        error!(
            anomaly = ?anomaly,
            new_status = %new_status,
            "CIRCUIT BREAKER TRIGGERED - System halted"
        );

        // Halt all pending transactions
        if let Err(e) = self.halt_pending_transactions().await {
            error!(error = %e, "Failed to halt pending transactions after circuit breaker trigger");
        }

        Ok(())
    }

    /// Halt all pending transactions (called after circuit breaker triggers)
    pub async fn halt_pending_transactions(&self) -> anyhow::Result<u64> {
        let tx_repo = TransactionRepository::new(self.pool.clone());

        // Get all transactions that are not in final states
        let pending_transactions = tx_repo
            .find_all_by_status(&["pending", "processing", "pending_payment"]).await
            .map_err(|e| {
                error!(error = %e, "Failed to fetch pending transactions for halt");
                e
            })?;

        let mut halted_count = 0u64;

        for transaction in pending_transactions {
            let new_status = match transaction.status.as_str() {
                "pending" => "HALTED_PENDING",
                "processing" => "HALTED_IN_PROGRESS",
                "pending_payment" => "SYSTEM_HALTED",
                _ => "SYSTEM_HALTED",
            };

            // Update transaction status with halt metadata
            let halt_metadata =
                serde_json::json!({
                "halted_at": chrono::Utc::now().to_rfc3339(),
                "previous_status": transaction.status,
                "halt_reason": "Circuit breaker triggered",
                "system_status": self.get_system_status().await.to_string(),
            });

            if
                let Err(e) = tx_repo.update_status_with_metadata(
                    &transaction.transaction_id.to_string(),
                    new_status,
                    halt_metadata
                ).await
            {
                error!(
                    transaction_id = %transaction.transaction_id,
                    error = %e,
                    "Failed to halt transaction"
                );
                continue;
            }

            halted_count += 1;
        }

        info!(halted_count = halted_count, "Successfully halted pending transactions");

        Ok(halted_count)
    }

    /// Manual kill switch - requires high-level authorization
    pub async fn manual_emergency_stop(
        &self,
        reason: &str,
        authorized_by: &str
    ) -> anyhow::Result<()> {
        let mut state = self.state.write().await;

        state.status = SystemStatus::EmergencyStop;
        state.triggered_at = Some(chrono::Utc::now());
        state.last_anomaly = Some(AnomalyType::UnknownOrigin {
            tx_hash: "MANUAL_TRIGGER".to_string(),
            amount: 0,
            wallet: format!("authorized_by:{}", authorized_by),
        });
        state.audit_required = true;

        // Persist state
        self.persist_system_status(&SystemStatus::EmergencyStop).await?;

        // Send critical alerts
        let anomaly = state.last_anomaly.as_ref().unwrap();
        self.send_alerts(anomaly, &SystemStatus::EmergencyStop).await?;

        error!(
            reason = %reason,
            authorized_by = %authorized_by,
            "MANUAL EMERGENCY STOP ACTIVATED"
        );

        Ok(())
    }

    /// Reset system status after manual audit (cannot be done automatically)
    pub async fn audit_and_reset(
        &self,
        auditor_1: &str,
        auditor_2: &str,
        reset_reason: &str
    ) -> anyhow::Result<()> {
        let mut state = self.state.write().await;

        // Verify system is halted and audit is required
        if !state.audit_required {
            return Err(anyhow::anyhow!("No audit required or system not halted"));
        }

        // Reset to operational
        state.status = SystemStatus::Operational;
        state.triggered_at = None;
        state.last_anomaly = None;
        state.audit_required = false;

        // Persist state
        self.persist_system_status(&SystemStatus::Operational).await?;

        info!(
            auditor_1 = %auditor_1,
            auditor_2 = %auditor_2,
            reason = %reset_reason,
            "System reset to operational after audit"
        );

        Ok(())
    }

    /// Get current circuit breaker state for dashboard
    pub async fn get_circuit_breaker_state(&self) -> CircuitBreakerState {
        self.state.read().await.clone()
    }

    // ---------------------------------------------------------------------------
    // Private Helper Methods
    // ---------------------------------------------------------------------------

    async fn persist_system_status(&self, status: &SystemStatus) -> anyhow::Result<()> {
        sqlx
            ::query(
                r#"
            INSERT INTO system_status (status, updated_at)
            VALUES ($1, NOW())
            ON CONFLICT (id) DO UPDATE SET
                status = EXCLUDED.status,
                updated_at = EXCLUDED.updated_at
            "#,
                status.to_string()
            )
            .execute(&self.pool).await?;

        Ok(())
    }

    async fn send_alerts(
        &self,
        anomaly: &AnomalyType,
        status: &SystemStatus
    ) -> anyhow::Result<()> {
        // Use the integrated alert service
        self.alert_service.send_circuit_breaker_alert(anomaly, status).await
    }
}

// ---------------------------------------------------------------------------
// Supporting Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct OnChainMint {
    pub tx_hash: String,
    pub amount: u64,
    pub wallet: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// Middleware for API Endpoints
// ---------------------------------------------------------------------------

pub struct CircuitBreakerMiddleware {
    anomaly_service: Arc<AnomalyDetectionService>,
}

impl CircuitBreakerMiddleware {
    pub fn new(anomaly_service: Arc<AnomalyDetectionService>) -> Self {
        Self { anomaly_service }
    }

    /// Check if operations are allowed - used in mint/burn endpoints
    pub async fn check_operation_allowed(&self) -> Result<(), crate::error::AppError> {
        if !self.anomaly_service.is_operational().await {
            let status = self.anomaly_service.get_system_status().await;
            return Err(
                crate::error::AppError::new(
                    crate::error::AppErrorKind::Domain(crate::error::DomainError::SystemHalted {
                        status: status.to_string(),
                    })
                )
            );
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Database Migration Helper
// ---------------------------------------------------------------------------

pub async fn ensure_system_status_table(pool: &PgPool) -> anyhow::Result<()> {
    sqlx
        ::query(
            r#"
        CREATE TABLE IF NOT EXISTS system_status (
            id SERIAL PRIMARY KEY DEFAULT 1,
            status TEXT NOT NULL CHECK (status IN ('OPERATIONAL', 'PARTIAL_HALT', 'EMERGENCY_STOP')),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            triggered_at TIMESTAMP WITH TIME ZONE,
            last_anomaly JSONB,
            audit_required BOOLEAN NOT NULL DEFAULT FALSE,
            CONSTRAINT single_status CHECK (id = 1)
        );

        INSERT INTO system_status (id, status)
        VALUES (1, 'OPERATIONAL')
        ON CONFLICT (id) DO NOTHING;
        "#
        )
        .execute(pool).await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_status_display() {
        assert_eq!(SystemStatus::Operational.to_string(), "OPERATIONAL");
        assert_eq!(SystemStatus::PartialHalt.to_string(), "PARTIAL_HALT");
        assert_eq!(SystemStatus::EmergencyStop.to_string(), "EMERGENCY_STOP");
    }

    #[test]
    fn test_anomaly_detection_config_defaults() {
        let config = AnomalyDetectionConfig::default();
        assert_eq!(config.velocity_limit_ngn, 500_000_000);
        assert_eq!(config.velocity_window, Duration::from_secs(60));
        assert_eq!(config.negative_delta_tolerance, 0.0001);
    }

    #[test]
    fn test_circuit_breaker_state_defaults() {
        let state = CircuitBreakerState::default();
        assert_eq!(state.status, SystemStatus::Operational);
        assert!(state.triggered_at.is_none());
        assert!(state.last_anomaly.is_none());
        assert!(!state.audit_required);
    }
}
