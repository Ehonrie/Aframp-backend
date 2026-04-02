//! System Halted Queue Handler
//!
//! Handles transaction queue when circuit breaker is triggered.
//! Moves pending transactions to SYSTEM_HALTED status and prevents processing.

use crate::database::transaction_repository::TransactionRepository;
use crate::security::{AnomalyDetectionService, SystemStatus};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Transaction status for system halt scenarios
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text")]
pub enum HaltedTransactionStatus {
    /// Transaction was queued when system was halted
    #[sqlx(rename = "SYSTEM_HALTED")]
    SystemHalted,
    /// Transaction was in progress when system was halted
    #[sqlx(rename = "HALTED_IN_PROGRESS")]
    HaltedInProgress,
    /// Transaction was pending when system was halted
    #[sqlx(rename = "HALTED_PENDING")]
    HaltedPending,
}

impl std::fmt::Display for HaltedTransactionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HaltedTransactionStatus::SystemHalted => write!(f, "SYSTEM_HALTED"),
            HaltedTransactionStatus::HaltedInProgress => write!(f, "HALTED_IN_PROGRESS"),
            HaltedTransactionStatus::HaltedPending => write!(f, "HALTED_PENDING"),
        }
    }
}

/// Queue manager for system halt scenarios
pub struct SystemHaltQueueManager {
    pool: PgPool,
    anomaly_service: Arc<AnomalyDetectionService>,
}

impl SystemHaltQueueManager {
    pub fn new(pool: PgPool, anomaly_service: Arc<AnomalyDetectionService>) -> Self {
        Self {
            pool,
            anomaly_service,
        }
    }

    /// Move all pending/processing transactions to halted status when circuit breaker triggers
    pub async fn halt_all_pending_transactions(&self) -> anyhow::Result<u64> {
        let tx_repo = TransactionRepository::new(self.pool.clone());
        
        // Get all transactions that are not in final states
        let pending_transactions = tx_repo
            .find_all_by_status(&["pending", "processing", "pending_payment"])
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to fetch pending transactions for halt");
                e
            })?;

        let mut halted_count = 0u64;

        for transaction in pending_transactions {
            let new_status = match transaction.status.as_str() {
                "pending" => HaltedTransactionStatus::HaltedPending,
                "processing" => HaltedTransactionStatus::HaltedInProgress,
                "pending_payment" => HaltedTransactionStatus::SystemHalted,
                _ => HaltedTransactionStatus::SystemHalted,
            };

            // Update transaction status with halt metadata
            let halt_metadata = serde_json::json!({
                "halted_at": chrono::Utc::now().to_rfc3339(),
                "previous_status": transaction.status,
                "halt_reason": "Circuit breaker triggered",
                "system_status": self.anomaly_service.get_system_status().await.to_string(),
            });

            if let Err(e) = tx_repo
                .update_status_with_metadata(
                    &transaction.transaction_id.to_string(),
                    &new_status.to_string(),
                    halt_metadata,
                )
                .await
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

        info!(
            halted_count = halted_count,
            "Successfully halted pending transactions"
        );

        Ok(halted_count)
    }

    /// Check if new transactions should be queued (system is halted)
    pub async fn should_queue_new_transactions(&self) -> bool {
        !matches!(
            self.anomaly_service.get_system_status().await,
            SystemStatus::Operational
        )
    }

    /// Add a new transaction to halted queue (when system is not operational)
    pub async fn queue_halted_transaction(
        &self,
        transaction_id: &str,
        wallet_address: &str,
        transaction_type: &str,
        amount_ngn: Option<String>,
        amount_cngn: Option<String>,
    ) -> anyhow::Result<()> {
        let tx_repo = TransactionRepository::new(self.pool.clone());

        // Create transaction record with SYSTEM_HALTED status
        let metadata = serde_json::json!({
            "queued_at": chrono::Utc::now().to_rfc3339(),
            "queue_reason": "System was halted at time of request",
            "system_status": self.anomaly_service.get_system_status().await.to_string(),
        });

        // Note: This would need to be adapted to the actual transaction creation method
        // For now, we'll update an existing transaction if it exists
        if let Ok(Some(mut tx)) = tx_repo.find_by_id(transaction_id).await {
            tx.status = HaltedTransactionStatus::SystemHalted.to_string();
            tx.metadata = metadata;

            if let Err(e) = tx_repo.update_status_with_metadata(
                transaction_id,
                &tx.status,
                tx.metadata,
            ).await {
                error!(
                    transaction_id = %transaction_id,
                    error = %e,
                    "Failed to queue halted transaction"
                );
                return Err(e.into());
            }

            info!(
                transaction_id = %transaction_id,
                wallet_address = %wallet_address,
                "Transaction queued due to system halt"
            );
        } else {
            warn!(
                transaction_id = %transaction_id,
                "Transaction not found for halt queue"
            );
        }

        Ok(())
    }

    /// Resume processing of halted transactions after system reset
    pub async fn resume_halted_transactions(&self) -> anyhow::Result<u64> {
        let tx_repo = TransactionRepository::new(self.pool.clone());
        
        // Get all halted transactions
        let halted_transactions = tx_repo
            .find_all_by_status(&[
                "SYSTEM_HALTED",
                "HALTED_IN_PROGRESS", 
                "HALTED_PENDING"
            ])
            .await?;

        let mut resumed_count = 0u64;

        for transaction in halted_transactions {
            // Determine original status from metadata
            let original_status = transaction.metadata
                .get("previous_status")
                .and_then(|v| v.as_str())
                .unwrap_or("pending");

            // Remove halt metadata and restore original status
            let mut updated_metadata = transaction.metadata.clone();
            updated_metadata.as_object_mut()
                .map(|obj| {
                    obj.remove("halted_at");
                    obj.remove("halt_reason");
                    obj.remove("system_status");
                    obj.insert("resumed_at".to_string(), 
                        serde_json::Value::String(chrono::Utc::now().to_rfc3339()));
                });

            if let Err(e) = tx_repo
                .update_status_with_metadata(
                    &transaction.transaction_id.to_string(),
                    original_status,
                    updated_metadata,
                )
                .await
            {
                error!(
                    transaction_id = %transaction.transaction_id,
                    error = %e,
                    "Failed to resume halted transaction"
                );
                continue;
            }

            resumed_count += 1;
        }

        info!(
            resumed_count = resumed_count,
            "Successfully resumed halted transactions"
        );

        Ok(resumed_count)
    }

    /// Get statistics about halted transactions
    pub async fn get_halt_statistics(&self) -> anyhow::Result<HaltStatistics> {
        let tx_repo = TransactionRepository::new(self.pool.clone());

        let system_halted = tx_repo.count_by_status("SYSTEM_HALTED").await.unwrap_or(0);
        let halted_in_progress = tx_repo.count_by_status("HALTED_IN_PROGRESS").await.unwrap_or(0);
        let halted_pending = tx_repo.count_by_status("HALTED_PENDING").await.unwrap_or(0);

        Ok(HaltStatistics {
            system_halted,
            halted_in_progress,
            halted_pending,
            total_halted: system_halted + halted_in_progress + halted_pending,
            system_status: self.anomaly_service.get_system_status().await,
        })
    }
}

/// Statistics about halted transactions
#[derive(Debug, Serialize)]
pub struct HaltStatistics {
    pub system_halted: i64,
    pub halted_in_progress: i64,
    pub halted_pending: i64,
    pub total_halted: i64,
    pub system_status: SystemStatus,
}

/// Extension trait for TransactionRepository to support halted transactions
pub trait HaltedTransactionRepository {
    async fn find_all_by_status(&self, statuses: &[&str]) -> anyhow::Result<Vec<crate::database::transaction::Transaction>>;
    async fn count_by_status(&self, status: &str) -> anyhow::Result<i64>;
}

// Note: This would need to be implemented in the actual TransactionRepository
// For now, this is a placeholder showing the intended interface

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_halted_transaction_status_display() {
        assert_eq!(HaltedTransactionStatus::SystemHalted.to_string(), "SYSTEM_HALTED");
        assert_eq!(HaltedTransactionStatus::HaltedInProgress.to_string(), "HALTED_IN_PROGRESS");
        assert_eq!(HaltedTransactionStatus::HaltedPending.to_string(), "HALTED_PENDING");
    }

    #[test]
    fn test_halt_statistics_creation() {
        let stats = HaltStatistics {
            system_halted: 10,
            halted_in_progress: 5,
            halted_pending: 3,
            total_halted: 18,
            system_status: SystemStatus::EmergencyStop,
        };

        assert_eq!(stats.total_halted, 18);
        assert_eq!(stats.system_halted, 10);
        assert_eq!(stats.halted_in_progress, 5);
        assert_eq!(stats.halted_pending, 3);
    }
}
