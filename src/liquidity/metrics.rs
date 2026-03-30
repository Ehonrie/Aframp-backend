use prometheus::{
    register_counter_vec_with_registry, register_gauge_vec_with_registry,
    CounterVec, GaugeVec, Registry,
};
use std::sync::OnceLock;

static AVAILABLE_LIQUIDITY: OnceLock<GaugeVec> = OnceLock::new();
static RESERVED_LIQUIDITY: OnceLock<GaugeVec> = OnceLock::new();
static UTILISATION_PCT: OnceLock<GaugeVec> = OnceLock::new();
static EFFECTIVE_DEPTH: OnceLock<GaugeVec> = OnceLock::new();
static RESERVATION_EVENTS: OnceLock<CounterVec> = OnceLock::new();
static RELEASE_EVENTS: OnceLock<CounterVec> = OnceLock::new();
static TIMEOUT_RELEASES: OnceLock<CounterVec> = OnceLock::new();
static INSUFFICIENT_REJECTIONS: OnceLock<CounterVec> = OnceLock::new();

pub fn register(r: &Registry) {
    AVAILABLE_LIQUIDITY.set(register_gauge_vec_with_registry!(
        "aframp_liquidity_available", "Available liquidity per pool",
        &["pool_id", "currency_pair", "pool_type"], r).unwrap()).ok();

    RESERVED_LIQUIDITY.set(register_gauge_vec_with_registry!(
        "aframp_liquidity_reserved", "Reserved liquidity per pool",
        &["pool_id", "currency_pair", "pool_type"], r).unwrap()).ok();

    UTILISATION_PCT.set(register_gauge_vec_with_registry!(
        "aframp_liquidity_utilisation_pct", "Utilisation percentage per pool",
        &["pool_id", "currency_pair", "pool_type"], r).unwrap()).ok();

    EFFECTIVE_DEPTH.set(register_gauge_vec_with_registry!(
        "aframp_liquidity_effective_depth", "Effective depth per currency pair",
        &["currency_pair"], r).unwrap()).ok();

    RESERVATION_EVENTS.set(register_counter_vec_with_registry!(
        "aframp_liquidity_reservations_total", "Reservation events per pool",
        &["pool_id", "currency_pair", "pool_type"], r).unwrap()).ok();

    RELEASE_EVENTS.set(register_counter_vec_with_registry!(
        "aframp_liquidity_releases_total", "Release events per pool",
        &["pool_id", "currency_pair", "pool_type", "reason"], r).unwrap()).ok();

    TIMEOUT_RELEASES.set(register_counter_vec_with_registry!(
        "aframp_liquidity_timeout_releases_total", "Timeout releases per pool",
        &["pool_id"], r).unwrap()).ok();

    INSUFFICIENT_REJECTIONS.set(register_counter_vec_with_registry!(
        "aframp_liquidity_insufficient_rejections_total", "Insufficient liquidity rejections",
        &["currency_pair"], r).unwrap()).ok();
}

pub fn available_liquidity() -> &'static GaugeVec {
    AVAILABLE_LIQUIDITY.get().expect("liquidity metrics not initialised")
}
pub fn reserved_liquidity() -> &'static GaugeVec {
    RESERVED_LIQUIDITY.get().expect("liquidity metrics not initialised")
}
pub fn utilisation_pct() -> &'static GaugeVec {
    UTILISATION_PCT.get().expect("liquidity metrics not initialised")
}
pub fn effective_depth() -> &'static GaugeVec {
    EFFECTIVE_DEPTH.get().expect("liquidity metrics not initialised")
}
pub fn reservation_events() -> &'static CounterVec {
    RESERVATION_EVENTS.get().expect("liquidity metrics not initialised")
}
pub fn release_events() -> &'static CounterVec {
    RELEASE_EVENTS.get().expect("liquidity metrics not initialised")
}
pub fn timeout_releases() -> &'static CounterVec {
    TIMEOUT_RELEASES.get().expect("liquidity metrics not initialised")
}
pub fn insufficient_rejections() -> &'static CounterVec {
    INSUFFICIENT_REJECTIONS.get().expect("liquidity metrics not initialised")
}
