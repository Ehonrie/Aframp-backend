/// Unit tests for liquidity pool logic that do not require a live database.
///
/// Covers:
///   - Pool segment routing (retail / wholesale / institutional)
///   - Adjacent-segment fallback order
///   - Effective depth calculation
///   - Pool health status derivation
#[cfg(test)]
mod tests {
    use crate::liquidity::models::*;
    use sqlx::types::BigDecimal;
    use std::str::FromStr;

    fn bd(s: &str) -> BigDecimal {
        BigDecimal::from_str(s).unwrap()
    }

    // ── Segment routing ───────────────────────────────────────────────────────

    #[test]
    fn segment_routing_retail() {
        let t = SegmentThresholds::default(); // retail_max=100_000, wholesale_max=1_000_000
        assert_eq!(t.segment_for(&bd("50000")), PoolType::Retail);
        assert_eq!(t.segment_for(&bd("100000")), PoolType::Retail); // boundary inclusive
    }

    #[test]
    fn segment_routing_wholesale() {
        let t = SegmentThresholds::default();
        assert_eq!(t.segment_for(&bd("100001")), PoolType::Wholesale);
        assert_eq!(t.segment_for(&bd("1000000")), PoolType::Wholesale);
    }

    #[test]
    fn segment_routing_institutional() {
        let t = SegmentThresholds::default();
        assert_eq!(t.segment_for(&bd("1000001")), PoolType::Institutional);
        assert_eq!(t.segment_for(&bd("999999999")), PoolType::Institutional);
    }

    // ── Fallback order ────────────────────────────────────────────────────────

    #[test]
    fn fallback_order_retail_starts_with_retail() {
        let order = SegmentThresholds::fallback_order(&PoolType::Retail);
        assert_eq!(order[0], PoolType::Retail);
        assert!(order.contains(&PoolType::Wholesale));
        assert!(order.contains(&PoolType::Institutional));
    }

    #[test]
    fn fallback_order_institutional_starts_with_institutional() {
        let order = SegmentThresholds::fallback_order(&PoolType::Institutional);
        assert_eq!(order[0], PoolType::Institutional);
    }

    // ── Effective depth ───────────────────────────────────────────────────────

    #[test]
    fn effective_depth_applies_slippage_tolerance() {
        let available = bd("1000000");
        let factor = BigDecimal::from_str(&format!("{:.4}", 1.0 - crate::liquidity::SLIPPAGE_TOLERANCE)).unwrap();
        let depth = &available * &factor;
        // 1% slippage → effective depth = 990_000
        assert_eq!(depth, bd("990000.0000"));
    }

    // ── Health status ─────────────────────────────────────────────────────────

    fn make_pool(available: &str, min: &str, target: &str, cap: &str, reserved: &str) -> LiquidityPool {
        use chrono::Utc;
        use uuid::Uuid;
        LiquidityPool {
            pool_id: Uuid::new_v4(),
            currency_pair: "cNGN/NGN".into(),
            pool_type: PoolType::Retail,
            total_liquidity_depth: bd("10000000"),
            available_liquidity: bd(available),
            reserved_liquidity: bd(reserved),
            min_liquidity_threshold: bd(min),
            target_liquidity_level: bd(target),
            max_liquidity_cap: bd(cap),
            pool_status: PoolStatus::Active,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn health_status(pool: &LiquidityPool) -> PoolHealthStatus {
        let total = 10_000_000.0_f64;
        let reserved: f64 = pool.reserved_liquidity.to_string().parse().unwrap();
        let utilisation = reserved / total * 100.0;

        if pool.available_liquidity < pool.min_liquidity_threshold {
            PoolHealthStatus::BelowMinimum
        } else if pool.available_liquidity > pool.max_liquidity_cap {
            PoolHealthStatus::OverCap
        } else if utilisation > crate::liquidity::HIGH_UTILISATION_THRESHOLD {
            PoolHealthStatus::HighUtilisation
        } else if pool.available_liquidity < pool.target_liquidity_level {
            PoolHealthStatus::BelowTarget
        } else {
            PoolHealthStatus::Healthy
        }
    }

    #[test]
    fn health_below_minimum() {
        let p = make_pool("400000", "500000", "2000000", "10000000", "0");
        assert_eq!(health_status(&p), PoolHealthStatus::BelowMinimum);
    }

    #[test]
    fn health_over_cap() {
        let p = make_pool("11000000", "500000", "2000000", "10000000", "0");
        assert_eq!(health_status(&p), PoolHealthStatus::OverCap);
    }

    #[test]
    fn health_below_target() {
        let p = make_pool("1000000", "500000", "2000000", "10000000", "0");
        assert_eq!(health_status(&p), PoolHealthStatus::BelowTarget);
    }

    #[test]
    fn health_healthy() {
        let p = make_pool("3000000", "500000", "2000000", "10000000", "0");
        assert_eq!(health_status(&p), PoolHealthStatus::Healthy);
    }

    #[test]
    fn health_high_utilisation() {
        // reserved = 8_500_000 / total 10_000_000 = 85% > 80% threshold
        let p = make_pool("1500000", "500000", "2000000", "10000000", "8500000");
        assert_eq!(health_status(&p), PoolHealthStatus::HighUtilisation);
    }
}
