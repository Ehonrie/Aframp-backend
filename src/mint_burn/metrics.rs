//! Prometheus metrics for the Mint & Burn Event Monitoring Worker.
//!
//! Exposes counters, gauges, and a histogram as required by Requirements 8.1, 8.2, and 8.3.
//! All metrics are registered with the supplied registry via `MintBurnMetrics::new`.

use prometheus::{
    register_counter_with_registry, register_gauge_with_registry, Counter, Gauge, Histogram,
    HistogramOpts, Registry,
};

use crate::mint_burn::models::MintBurnError;

// ---------------------------------------------------------------------------
// MintBurnMetrics struct
// ---------------------------------------------------------------------------

/// Holds all Prometheus metric handles for the Mint & Burn worker subsystem.
///
/// Construct via `MintBurnMetrics::new(registry)` and share as `Arc<MintBurnMetrics>`.
#[derive(Clone)]
pub struct MintBurnMetrics {
    // Counters (Requirement 8.1)
    pub operations_received_total: Counter,
    pub mint_events_total: Counter,
    pub burn_events_total: Counter,
    pub clawback_events_total: Counter,
    pub duplicates_skipped_total: Counter,
    pub unmatched_events_total: Counter,

    // Gauges (Requirement 8.2)
    /// 1.0 = connected, 0.0 = disconnected
    pub stream_connected: Gauge,
    pub seconds_since_last_message: Gauge,
    pub reconnect_attempts_total: Gauge,

    // Histogram (Requirement 8.3)
    /// End-to-end processing latency: chain `created_at` → DB commit
    pub processing_latency_seconds: Histogram,
}

impl MintBurnMetrics {
    /// Create and register all Mint & Burn worker metrics with the given registry.
    pub fn new(registry: &Registry) -> Result<Self, MintBurnError> {
        // --- Counters ---
        let operations_received_total = register_counter_with_registry!(
            "mb_operations_received_total",
            "Total Horizon operations received by the Mint & Burn worker",
            registry
        )
        .map_err(|e| MintBurnError::ConfigError(e.to_string()))?;

        let mint_events_total = register_counter_with_registry!(
            "mb_mint_events_total",
            "Total Mint events processed",
            registry
        )
        .map_err(|e| MintBurnError::ConfigError(e.to_string()))?;

        let burn_events_total = register_counter_with_registry!(
            "mb_burn_events_total",
            "Total Burn events processed",
            registry
        )
        .map_err(|e| MintBurnError::ConfigError(e.to_string()))?;

        let clawback_events_total = register_counter_with_registry!(
            "mb_clawback_events_total",
            "Total Clawback events processed",
            registry
        )
        .map_err(|e| MintBurnError::ConfigError(e.to_string()))?;

        let duplicates_skipped_total = register_counter_with_registry!(
            "mb_duplicates_skipped_total",
            "Total duplicate operations skipped",
            registry
        )
        .map_err(|e| MintBurnError::ConfigError(e.to_string()))?;

        let unmatched_events_total = register_counter_with_registry!(
            "mb_unmatched_events_total",
            "Total operations with unmatched or unparseable memos",
            registry
        )
        .map_err(|e| MintBurnError::ConfigError(e.to_string()))?;

        // --- Gauges ---
        let stream_connected = register_gauge_with_registry!(
            "mb_stream_connected",
            "Horizon stream connection status: 1.0 = connected, 0.0 = disconnected",
            registry
        )
        .map_err(|e| MintBurnError::ConfigError(e.to_string()))?;

        let seconds_since_last_message = register_gauge_with_registry!(
            "mb_seconds_since_last_message",
            "Seconds elapsed since the last message was received from the Horizon stream",
            registry
        )
        .map_err(|e| MintBurnError::ConfigError(e.to_string()))?;

        let reconnect_attempts_total = register_gauge_with_registry!(
            "mb_reconnect_attempts_total",
            "Total reconnection attempts since worker startup",
            registry
        )
        .map_err(|e| MintBurnError::ConfigError(e.to_string()))?;

        // --- Histogram ---
        let processing_latency_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "mb_processing_latency_seconds",
                "End-to-end processing latency from chain created_at to DB commit",
            )
            .buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
        )
        .map_err(|e| MintBurnError::ConfigError(e.to_string()))?;

        registry
            .register(Box::new(processing_latency_seconds.clone()))
            .map_err(|e| MintBurnError::ConfigError(e.to_string()))?;

        Ok(Self {
            operations_received_total,
            mint_events_total,
            burn_events_total,
            clawback_events_total,
            duplicates_skipped_total,
            unmatched_events_total,
            stream_connected,
            seconds_since_last_message,
            reconnect_attempts_total,
            processing_latency_seconds,
        })
    }
}
