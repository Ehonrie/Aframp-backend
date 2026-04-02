//! Security Module - Anomaly Detection & Circuit Breaker
//!
//! This module provides comprehensive security monitoring and automated response
//! for the cNGN stablecoin system.

pub mod anomaly_detection;
pub mod halt_queue;
pub mod alerts;

#[cfg(test)]
pub mod tests;

pub use anomaly_detection::{
    AnomalyDetectionService,
    AnomalyDetectionConfig,
    SystemStatus,
    CircuitBreakerState,
    CircuitBreakerMiddleware,
    OnChainMint,
    ensure_system_status_table,
};
pub use halt_queue::{
    SystemHaltQueueManager,
    HaltedTransactionStatus,
    HaltStatistics,
    HaltedTransactionRepository,
};
pub use alerts::{ AlertService, AlertConfig, AlertMessage, AlertSeverity, AlertChannel };
