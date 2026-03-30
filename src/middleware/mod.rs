//! Middleware modules for Aframp backend

#[cfg(feature = "database")]
pub mod api_key;

#[cfg(feature = "database")]
pub mod error;

#[cfg(feature = "database")]
pub mod geo_restriction;

#[cfg(feature = "database")]
pub mod hmac_signing;

#[cfg(feature = "database")]
pub mod ip_blocking;

#[cfg(feature = "database")]
pub mod replay_prevention;

#[cfg(feature = "database")]
pub mod scope_middleware;

#[cfg(feature = "database")]
pub mod logging;

pub mod metrics;

#[cfg(feature = "database")]
pub mod rate_limit;

pub mod rate_limit_metrics;

#[cfg(feature = "database")]
pub mod request_integrity;

pub mod cors;
pub mod security;
