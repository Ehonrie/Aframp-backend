pub mod handlers;
pub mod metrics;
pub mod models;
pub mod repository;
pub mod routes;
pub mod service;
pub mod worker;

#[cfg(test)]
mod tests;

// ── Module-level constants (all configurable via env at startup) ──────────────

/// Seconds before an active reservation is automatically released.
pub const RESERVATION_TIMEOUT_SECS: i64 = 300; // 5 minutes

/// Fraction of available liquidity that can be consumed before slippage is
/// considered excessive (1 % default).
pub const SLIPPAGE_TOLERANCE: f64 = 0.01;

/// Utilisation percentage above which a high-utilisation alert fires.
pub const HIGH_UTILISATION_THRESHOLD: f64 = 80.0;
