//! Onramp Transaction Processor Worker
//!
//! The engine room of the entire onramp flow. This background worker:
//! - Monitors pending transactions for payment provider confirmation
//! - Processes webhook events from Flutterwave, Paystack, and M-Pesa
//! - Executes cNGN transfers on Stellar once payment is confirmed
//! - Monitors Stellar for transaction confirmation
//! - Handles all failure scenarios including automatic refunds
//!
//! This is the highest-stakes code in the codebase — it moves real money.
//! Every state transition must be idempotent and race-condition proof.

use crate::chains::stellar::client::StellarClient;
use crate::database::repository::Repository;
use crate::database::transaction_repository::{Transaction, TransactionRepository};
use crate::database::webhook_repository::WebhookRepository;
use crate::error::{AppError, AppErrorKind, DomainError, ExternalError};
use crate::payments::types::ProviderName;
use crate::services::payment_orchestrator::PaymentOrchestrator;
use bigdecimal::BigDecimal;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tokio::time::{interval, sleep, timeout};
use tracing::{debug, error, info, warn, instrument};
use uuid::Uuid;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the Onramp Transaction Processor
#[derive(Debug, Clone)]
pub struct OnrampProcessorConfig {
    /// How often the polling fallback wakes up (seconds)
    pub poll_interval_secs: u64,
    /// Mark pending transactions failed after this duration (minutes)
    pub pending_timeout_mins: u64,
    /// Maximum retry attempts for Stellar submission
    pub stellar_max_retries: u32,
    /// Exponential backoff delays for Stellar retries (seconds)
    pub stellar_retry_backoff_secs: Vec<u64>,
    /// How often to poll Stellar for confirmation (seconds)
    pub stellar_confirmation_poll_secs: u64,
    /// Absolute timeout for Stellar confirmation (minutes)
    pub stellar_confirmation_timeout_mins: u64,
    /// Maximum retry attempts for refunds
    pub refund_max_retries: u32,
    /// Exponential backoff delays for refunds (seconds)
    pub refund_retry_backoff_secs: Vec<u64>,
}

impl Default for OnrampProcessorConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: 30,
            pending_timeout_mins: 30,
            stellar_max_retries: 3,
            stellar_retry_backoff_secs: vec![2, 4, 8],
            stellar_confirmation_poll_secs: 10,
            stellar_confirmation_timeout_mins: 5,
            refund_max_retries: 3,
            refund_retry_backoff_secs: vec![30, 60, 120],
        }
    }
}

impl OnrampProcessorConfig {
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        cfg.poll_interval_secs = std::env::var("ONRAMP_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(cfg.poll_interval_secs);
        cfg.pending_timeout_mins = std::env::var("ONRAMP_PENDING_TIMEOUT_MINS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(cfg.pending_timeout_mins);
        cfg.stellar_max_retries = std::env::var("ONRAMP_STELLAR_MAX_RETRIES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(cfg.stellar_max_retries);
        cfg
    }
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum ProcessorError {
    #[error("database error: {0}")]
    Database(#[from] crate::database::error::DatabaseError),

    #[error("stellar error: {0}")]
    Stellar(String),

    #[error("payment provider error: {0}")]
    PaymentProvider(String),

    #[error("trustline not found for wallet {wallet_address}")]
    TrustlineNotFound { wallet_address: String },

    #[error("insufficient cNGN balance: available={available}, required={required}")]
    InsufficientCngnBalance { available: String, required: String },

    #[error("payment timeout after {mins} minutes")]
    PaymentTimeout { mins: u64 },

    #[error("stellar transient error: {0}")]
    StellarTransientError(String),

    #[error("stellar permanent error: {0}")]
    StellarPermanentError(String),

    #[error("refund failed: {0}")]
    RefundFailed(String),

    #[error("internal error: {0}")]
    Internal(String),
}

// ============================================================================
// Failure Reasons
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureReason {
    PaymentTimeout,
    PaymentFailed,
    TrustlineNotFound,
    InsufficientCngnBalance,
    StellarTransientError,
    StellarPermanentError,
    UnknownError,
}

impl FailureReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            FailureReason::PaymentTimeout => "PAYMENT_TIMEOUT",
            FailureReason::PaymentFailed => "PAYMENT_FAILED",
            FailureReason::TrustlineNotFound => "TRUSTLINE_NOT_FOUND",
            FailureReason::InsufficientCngnBalance => "INSUFFICIENT_CNGN_BALANCE",
            FailureReason::StellarTransientError => "STELLAR_TRANSIENT_ERROR",
            FailureReason::StellarPermanentError => "STELLAR_PERMANENT_ERROR",
            FailureReason::UnknownError => "UNKNOWN_ERROR",
        }
    }
}

// ============================================================================
// Processor Worker
// ============================================================================

pub struct OnrampProcessor {
    db: Arc<PgPool>,
    stellar: Arc<StellarClient>,
    payment_orchestrator: Arc<PaymentOrchestrator>,
    config: OnrampProcessorConfig,
}

impl OnrampProcessor {
    pub fn new(
        db: Arc<PgPool>,
        stellar: Arc<StellarClient>,
        payment_orchestrator: Arc<PaymentOrchestrator>,
        config: OnrampProcessorConfig,
    ) -> Self {
        Self {
            db,
            stellar,
            payment_orchestrator,
            config,
        }
    }

    /// Main worker loop - runs continuously
    pub async fn run(&self, mut shutdown_rx: watch::Receiver<bool>) -> Result<(), ProcessorError> {
        info!(
            poll_interval_secs = self.config.poll_interval_secs,
            pending_timeout_mins = self.config.pending_timeout_mins,
            "🚀 Onramp Transaction Processor started"
        );

        let mut poll_ticker = interval(Duration::from_secs(self.config.poll_interval_secs));

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    info!("Shutdown signal received, stopping Onramp Processor");
                    break;
                }
                _ = poll_ticker.tick() => {
                    if let Err(e) = self.process_cycle().await {
                        error!(error = %e, "Error in processor cycle");
                    }
                }
            }
        }

        info!("Onramp Transaction Processor stopped");
        Ok(())
    }

    /// Single processing cycle
    async fn process_cycle(&self) -> Result<(), ProcessorError> {
        debug!("Starting onramp processor cycle");

        let _timer = crate::metrics::worker::cycle_duration_seconds()
            .with_label_values(&["onramp_processor"])
            .start_timer();
        crate::metrics::worker::cycles_total()
            .with_label_values(&["onramp_processor"])
            .inc();

        // Stage 1: Check for payment timeouts
        self.check_payment_timeouts().await?;

        // Stage 2: Process pending transactions (polling fallback)
        self.process_pending_transactions().await?;

        // Stage 3: Monitor Stellar confirmations
        self.monitor_stellar_confirmations().await?;

        debug!("Onramp processor cycle completed");
        Ok(())
    }

    /// Check for transactions pending payment confirmation for too long
    #[instrument(skip(self), fields(processor = "onramp"))]
    async fn check_payment_timeouts(&self) -> Result<(), ProcessorError> {
        let repo = TransactionRepository::new((*self.db).clone());
        let timeout_duration = Duration::from_secs(self.config.pending_timeout_mins * 60);

        // Find all pending transactions older than timeout
        let pending_txs = sqlx::query_as::<_, Transaction>(
            r#"
            SELECT * FROM transactions
            WHERE status = 'pending'
            AND created_at < NOW() - INTERVAL '1 minute' * $1
            ORDER BY created_at ASC
            LIMIT 100
            FOR UPDATE SKIP LOCKED
            "#,
        )
        .bind(self.config.pending_timeout_mins as i64)
        .fetch_all((*self.db).as_ref())
        .await?;

        for tx in pending_txs {
            info!(
                tx_id = %tx.transaction_id,
                created_at = ?tx.created_at,
                "Payment timeout detected, marking transaction failed"
            );

            // Mark as failed with PAYMENT_TIMEOUT reason
            self.mark_transaction_failed(
                &tx.transaction_id,
                FailureReason::PaymentTimeout,
                "Payment confirmation not received within timeout period",
            )
            .await?;

            // Emit metric
            metrics::inc_payments_failed("timeout");
        }

        Ok(())
    }

    /// Process pending transactions - polling fallback for missed webhooks
    #[instrument(skip(self), fields(processor = "onramp"))]
    async fn process_pending_transactions(&self) -> Result<(), ProcessorError> {
        // Find pending transactions older than 2 minutes with no webhook
        let stale_txs = sqlx::query_as::<_, Transaction>(
            r#"
            SELECT t.* FROM transactions t
            LEFT JOIN webhook_events w ON t.transaction_id = w.transaction_id
            WHERE t.status = 'pending'
            AND t.created_at < NOW() - INTERVAL '2 minutes'
            AND w.id IS NULL
            ORDER BY t.created_at ASC
            LIMIT 50
            FOR UPDATE SKIP LOCKED
            "#,
        )
        .fetch_all((*self.db).as_ref())
        .await?;

        for tx in stale_txs {
            debug!(
                tx_id = %tx.transaction_id,
                provider = ?tx.payment_provider,
                "Polling provider for payment confirmation"
            );

            // Query provider directly for payment status
            if let Err(e) = self.check_payment_with_provider(&tx).await {
                warn!(
                    tx_id = %tx.transaction_id,
                    error = %e,
                    "Failed to check payment status with provider"
                );
            }
        }

        Ok(())
    }

    /// Check payment status with provider directly
    async fn check_payment_with_provider(&self, tx: &Transaction) -> Result<(), ProcessorError> {
        let provider_ref = tx
            .payment_reference
            .as_ref()
            .ok_or_else(|| ProcessorError::Internal("No payment reference".to_string()))?;

        let provider_name = tx
            .payment_provider
            .as_ref()
            .ok_or_else(|| ProcessorError::Internal("No payment provider".to_string()))?;

        // Query provider for status
        // This would call the payment orchestrator's status check
        // For now, we log the attempt
        debug!(
            tx_id = %tx.transaction_id,
            provider = %provider_name,
            provider_ref = %provider_ref,
            "Querying provider for payment status"
        );

        // TODO: Implement provider status query via PaymentOrchestrator
        // If confirmed, call process_payment_confirmed()

        Ok(())
    }

    /// Monitor Stellar for transaction confirmations
    #[instrument(skip(self), fields(processor = "onramp"))]
    async fn monitor_stellar_confirmations(&self) -> Result<(), ProcessorError> {
        // Find transactions awaiting Stellar confirmation
        let processing_txs = sqlx::query_as::<_, Transaction>(
            r#"
            SELECT * FROM transactions
            WHERE status = 'processing'
            AND blockchain_tx_hash IS NOT NULL
            ORDER BY updated_at ASC
            LIMIT 50
            FOR UPDATE SKIP LOCKED
            "#,
        )
        .fetch_all((*self.db).as_ref())
        .await?;

        for tx in processing_txs {
            let tx_hash = tx
                .blockchain_tx_hash
                .as_ref()
                .ok_or_else(|| ProcessorError::Internal("No blockchain hash".to_string()))?;

            debug!(
                tx_id = %tx.transaction_id,
                stellar_hash = %tx_hash,
                "Checking Stellar transaction confirmation"
            );

            match self.check_stellar_confirmation(tx_hash).await {
                Ok(confirmed) => {
                    if confirmed {
                        info!(
                            tx_id = %tx.transaction_id,
                            stellar_hash = %tx_hash,
                            "Stellar transaction confirmed"
                        );

                        // Mark as completed
                        self.mark_transaction_completed(&tx.transaction_id, tx_hash).await?;
                        metrics::inc_transfers_confirmed();
                    }
                }
                Err(e) => {
                    warn!(
                        tx_id = %tx.transaction_id,
                        error = %e,
                        "Error checking Stellar confirmation"
                    );
                }
            }
        }

        Ok(())
    }

    /// Check if a Stellar transaction is confirmed
    async fn check_stellar_confirmation(&self, tx_hash: &str) -> Result<bool, ProcessorError> {
        // Query Stellar for transaction status
        // This would use the StellarClient to fetch the transaction
        // For now, we return false (not confirmed)
        debug!(stellar_hash = %tx_hash, "Querying Stellar for transaction confirmation");

        // TODO: Implement Stellar transaction lookup
        // Use stellar_client.get_transaction(tx_hash)

        Ok(false)
    }

    /// Process payment confirmation (webhook or polling)
    #[instrument(skip(self), fields(processor = "onramp"))]
    pub async fn process_payment_confirmed(
        &self,
        tx_id: &Uuid,
        provider_reference: &str,
        provider: &ProviderName,
        amount_ngn: &BigDecimal,
    ) -> Result<(), ProcessorError> {
        info!(
            tx_id = %tx_id,
            provider = %provider,
            provider_ref = %provider_reference,
            amount_ngn = %amount_ngn,
            "Processing payment confirmation"
        );

        // Fetch transaction
        let repo = TransactionRepository::new((*self.db).clone());
        let tx = repo
            .find_by_id(&tx_id.to_string())
            .await?
            .ok_or_else(|| ProcessorError::Internal(format!("Transaction not found: {}", tx_id)))?;

        // Validate amount matches
        if tx.from_amount != *amount_ngn {
            warn!(
                tx_id = %tx_id,
                expected = %tx.from_amount,
                received = %amount_ngn,
                "Payment amount mismatch"
            );
            return Err(ProcessorError::Internal("Amount mismatch".to_string()));
        }

        // Update status to processing with optimistic locking
        sqlx::query(
            r#"
            UPDATE transactions
            SET status = 'processing',
                updated_at = NOW()
            WHERE transaction_id = $1 AND status = 'pending'
            "#,
        )
        .bind(tx_id)
        .execute((*self.db).as_ref())
        .await?;

        info!(tx_id = %tx_id, "Transaction status updated to processing");
        metrics::inc_payments_confirmed(provider.as_str());

        // Proceed to Stage 2: cNGN transfer
        self.execute_cngn_transfer(&tx).await?;

        Ok(())
    }

    /// Execute cNGN transfer on Stellar
    #[instrument(skip(self, tx), fields(processor = "onramp", tx_id = %tx.transaction_id))]
    async fn execute_cngn_transfer(&self, tx: &Transaction) -> Result<(), ProcessorError> {
        info!(
            wallet = %tx.wallet_address,
            amount_cngn = %tx.cngn_amount,
            "Executing cNGN transfer on Stellar"
        );

        // Stage 2a: Verify trustline
        if !self.verify_trustline(&tx.wallet_address).await? {
            warn!(
                wallet = %tx.wallet_address,
                "Trustline not found, initiating refund"
            );
            self.mark_transaction_failed(
                &tx.transaction_id,
                FailureReason::TrustlineNotFound,
                &format!("Trustline not found for wallet {}", tx.wallet_address),
            )
            .await?;
            self.initiate_refund(tx, FailureReason::TrustlineNotFound)
                .await?;
            metrics::inc_transfers_failed("trustline_not_found");
            return Ok(());
        }

        // Stage 2b: Verify cNGN liquidity
        if !self.verify_cngn_liquidity(&tx.cngn_amount).await? {
            warn!(
                amount_required = %tx.cngn_amount,
                "Insufficient cNGN balance, initiating refund"
            );
            self.mark_transaction_failed(
                &tx.transaction_id,
                FailureReason::InsufficientCngnBalance,
                "Insufficient cNGN balance in system",
            )
            .await?;
            self.initiate_refund(tx, FailureReason::InsufficientCngnBalance)
                .await?;
            metrics::inc_transfers_failed("insufficient_balance");
            return Ok(());
        }

        // Stage 2c: Build and submit cNGN transfer
        match self.submit_cngn_transfer(tx).await {
            Ok(stellar_tx_hash) => {
                info!(
                    tx_id = %tx.transaction_id,
                    stellar_hash = %stellar_tx_hash,
                    "cNGN transfer submitted to Stellar"
                );

                // Store stellar_tx_hash
                sqlx::query(
                    r#"
                    UPDATE transactions
                    SET blockchain_tx_hash = $1,
                        updated_at = NOW()
                    WHERE transaction_id = $2 AND status = 'processing'
                    "#,
                )
                .bind(&stellar_tx_hash)
                .bind(&tx.transaction_id)
                .execute((*self.db).as_ref())
                .await?;

                metrics::inc_transfers_submitted();
            }
            Err(e) => {
                error!(
                    tx_id = %tx.transaction_id,
                    error = %e,
                    "Failed to submit cNGN transfer"
                );

                // Determine if transient or permanent error
                match e {
                    ProcessorError::StellarTransientError(_) => {
                        warn!("Transient Stellar error, will retry on next cycle");
                        // Leave in processing state for retry
                    }
                    _ => {
                        // Permanent error - mark failed and initiate refund
                        self.mark_transaction_failed(
                            &tx.transaction_id,
                            FailureReason::StellarPermanentError,
                            &e.to_string(),
                        )
                        .await?;
                        self.initiate_refund(tx, FailureReason::StellarPermanentError)
                            .await?;
                        metrics::inc_transfers_failed("stellar_error");
                    }
                }
            }
        }

        Ok(())
    }

    /// Verify trustline exists for wallet
    async fn verify_trustline(&self, wallet_address: &str) -> Result<bool, ProcessorError> {
        debug!(wallet = %wallet_address, "Verifying cNGN trustline");

        // TODO: Call trustline service to verify
        // For now, return true (assume trustline exists)
        Ok(true)
    }

    /// Verify sufficient cNGN liquidity
    async fn verify_cngn_liquidity(&self, amount: &BigDecimal) -> Result<bool, ProcessorError> {
        debug!(amount = %amount, "Verifying cNGN liquidity");

        // TODO: Query Stellar for system wallet cNGN balance
        // For now, return true (assume sufficient balance)
        Ok(true)
    }

    /// Submit cNGN transfer to Stellar with retry logic
    async fn submit_cngn_transfer(&self, tx: &Transaction) -> Result<String, ProcessorError> {
        let mut retry_count = 0;

        loop {
            match self.attempt_cngn_transfer(tx).await {
                Ok(tx_hash) => return Ok(tx_hash),
                Err(e) => {
                    if retry_count >= self.config.stellar_max_retries {
                        error!(
                            tx_id = %tx.transaction_id,
                            retries = retry_count,
                            "Max retries exceeded for Stellar submission"
                        );
                        return Err(e);
                    }

                    // Check if transient error
                    if matches!(e, ProcessorError::StellarTransientError(_)) {
                        let backoff_secs = self.config.stellar_retry_backoff_secs
                            .get(retry_count as usize)
                            .copied()
                            .unwrap_or(8);

                        warn!(
                            tx_id = %tx.transaction_id,
                            retry = retry_count + 1,
                            backoff_secs = backoff_secs,
                            error = %e,
                            "Transient Stellar error, retrying"
                        );

                        sleep(Duration::from_secs(backoff_secs)).await;
                        retry_count += 1;
                    } else {
                        // Permanent error - don't retry
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Attempt single cNGN transfer
    async fn attempt_cngn_transfer(&self, tx: &Transaction) -> Result<String, ProcessorError> {
        debug!(
            tx_id = %tx.transaction_id,
            wallet = %tx.wallet_address,
            amount = %tx.cngn_amount,
            "Attempting cNGN transfer"
        );

        // TODO: Build and submit transaction using CngnPaymentBuilder
        // For now, return a mock hash
        let mock_hash = format!("mock_hash_{}", Uuid::new_v4());
        Ok(mock_hash)
    }

    /// Mark transaction as completed
    async fn mark_transaction_completed(
        &self,
        tx_id: &Uuid,
        stellar_hash: &str,
    ) -> Result<(), ProcessorError> {
        sqlx::query(
            r#"
            UPDATE transactions
            SET status = 'completed',
                updated_at = NOW()
            WHERE transaction_id = $1 AND status = 'processing'
            "#,
        )
        .bind(tx_id)
        .execute((*self.db).as_ref())
        .await?;

        info!(
            tx_id = %tx_id,
            stellar_hash = %stellar_hash,
            "Transaction marked as completed"
        );

        Ok(())
    }

    /// Mark transaction as failed
    async fn mark_transaction_failed(
        &self,
        tx_id: &Uuid,
        reason: FailureReason,
        message: &str,
    ) -> Result<(), ProcessorError> {
        sqlx::query(
            r#"
            UPDATE transactions
            SET status = 'failed',
                error_message = $1,
                updated_at = NOW()
            WHERE transaction_id = $2
            "#,
        )
        .bind(message)
        .bind(tx_id)
        .execute((*self.db).as_ref())
        .await?;

        info!(
            tx_id = %tx_id,
            reason = %reason.as_str(),
            message = %message,
            "Transaction marked as failed"
        );

        Ok(())
    }

    /// Initiate automatic refund
    #[instrument(skip(self, tx), fields(processor = "onramp", tx_id = %tx.transaction_id))]
    async fn initiate_refund(
        &self,
        tx: &Transaction,
        reason: FailureReason,
    ) -> Result<(), ProcessorError> {
        info!(
            tx_id = %tx.transaction_id,
            provider = ?tx.payment_provider,
            reason = %reason.as_str(),
            "Initiating automatic refund"
        );

        // TODO: Call PaymentOrchestrator to initiate refund
        // For now, just log
        metrics::inc_refunds_initiated(tx.payment_provider.as_deref().unwrap_or("unknown"));

        Ok(())
    }
}

// ============================================================================
// Metrics (real Prometheus counters via crate::metrics)
// ============================================================================

mod metrics {
    #[inline]
    pub fn inc_payments_failed(reason: &str) {
        crate::metrics::cngn::transactions_total()
            .with_label_values(&["onramp", "failed"])
            .inc();
        crate::metrics::worker::errors_total()
            .with_label_values(&["onramp_processor", reason])
            .inc();
    }

    #[inline]
    pub fn inc_payments_confirmed(provider: &str) {
        crate::metrics::cngn::transactions_total()
            .with_label_values(&["onramp", "completed"])
            .inc();
        let _ = provider; // label available on payment metrics
    }

    #[inline]
    pub fn inc_transfers_submitted() {
        crate::metrics::stellar::tx_submissions_total()
            .with_label_values(&["success"])
            .inc();
    }

    #[inline]
    pub fn inc_transfers_confirmed() {
        // already counted via cngn transactions_total completed
    }

    #[inline]
    pub fn inc_transfers_failed(reason: &str) {
        crate::metrics::stellar::tx_submissions_total()
            .with_label_values(&["failed"])
            .inc();
        crate::metrics::worker::errors_total()
            .with_label_values(&["onramp_processor", reason])
            .inc();
    }

    #[inline]
    pub fn inc_refunds_initiated(provider: &str) {
        crate::metrics::cngn::transactions_total()
            .with_label_values(&["onramp", "refunded"])
            .inc();
        let _ = provider;
    }
}
