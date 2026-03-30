use super::models::*;
use super::repository::LiquidityRepository;
use super::{metrics, RESERVATION_TIMEOUT_SECS, SLIPPAGE_TOLERANCE};
use crate::cache::RedisPool;
use anyhow::{anyhow, Result};
use bigdecimal::ToPrimitive;
use redis::AsyncCommands;
use sqlx::types::BigDecimal;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

pub struct LiquidityService {
    repo: Arc<LiquidityRepository>,
    redis: RedisPool,
    thresholds: SegmentThresholds,
}

impl LiquidityService {
    pub fn new(repo: Arc<LiquidityRepository>, redis: RedisPool) -> Self {
        Self { repo, redis, thresholds: SegmentThresholds::default() }
    }

    // ── Reservation ───────────────────────────────────────────────────────────

    /// Reserve liquidity for a transaction. Tries the primary segment first,
    /// then falls back to adjacent segments.
    pub async fn reserve(
        &self,
        currency_pair: &str,
        transaction_id: Uuid,
        amount: &BigDecimal,
    ) -> Result<LiquidityReservation> {
        let primary = self.thresholds.segment_for(amount);
        let order = SegmentThresholds::fallback_order(&primary);

        for segment in &order {
            let Some(pool) = self.repo.get_pool_by_pair_and_type(currency_pair, segment).await? else {
                continue;
            };
            if pool.pool_status != PoolStatus::Active {
                continue;
            }
            if &pool.available_liquidity < &pool.min_liquidity_threshold {
                continue;
            }

            if let Some(reservation) = self
                .repo
                .reserve_liquidity(pool.pool_id, transaction_id, amount, RESERVATION_TIMEOUT_SECS)
                .await?
            {
                let pid = pool.pool_id.to_string();
                let pt = format!("{:?}", pool.pool_type).to_lowercase();

                // Update Redis
                let new_avail = &pool.available_liquidity - amount;
                let new_res = &pool.reserved_liquidity + amount;
                self.set_redis_f64(&format!("liquidity:available:{}", pid), new_avail.to_f64().unwrap_or(0.0)).await;
                self.set_redis_f64(&format!("liquidity:reserved:{}", pid), new_res.to_f64().unwrap_or(0.0)).await;

                // Prometheus
                metrics::available_liquidity().with_label_values(&[&pid, currency_pair, &pt]).set(new_avail.to_f64().unwrap_or(0.0));
                metrics::reserved_liquidity().with_label_values(&[&pid, currency_pair, &pt]).set(new_res.to_f64().unwrap_or(0.0));
                metrics::reservation_events().with_label_values(&[&pid, currency_pair, &pt]).inc();

                info!(pool_id = %pool.pool_id, %transaction_id, %amount, segment = ?segment, "Liquidity reserved");
                return Ok(reservation);
            }
        }

        metrics::insufficient_rejections().with_label_values(&[currency_pair]).inc();
        warn!(currency_pair, %amount, "Insufficient liquidity across all segments");
        Err(anyhow!("insufficient_liquidity"))
    }

    /// Release a reservation back to available (failure / refund).
    pub async fn release(&self, reservation_id: Uuid) -> Result<()> {
        if self.repo.release_reservation(reservation_id, ReservationStatus::Released).await? {
            info!(reservation_id = %reservation_id, "Reservation released");
        }
        Ok(())
    }

    /// Mark a reservation as consumed (transaction completed successfully).
    pub async fn consume(&self, reservation_id: Uuid) -> Result<()> {
        if self.repo.release_reservation(reservation_id, ReservationStatus::Consumed).await? {
            info!(reservation_id = %reservation_id, "Reservation consumed");
        }
        Ok(())
    }

    // ── Depth ─────────────────────────────────────────────────────────────────

    pub async fn get_depth(&self, currency_pair: &str) -> Result<LiquidityDepthResponse> {
        let pools = self.repo.list_pools().await?;
        let factor = BigDecimal::from_str(&format!("{:.4}", 1.0 - SLIPPAGE_TOLERANCE))?;

        let depth_for = |pt: &PoolType| -> BigDecimal {
            pools.iter()
                .find(|p| p.currency_pair == currency_pair && &p.pool_type == pt && p.pool_status == PoolStatus::Active)
                .map(|p| &p.available_liquidity * &factor)
                .unwrap_or_else(|| BigDecimal::from(0))
        };

        let retail = depth_for(&PoolType::Retail);
        let wholesale = depth_for(&PoolType::Wholesale);
        let institutional = depth_for(&PoolType::Institutional);
        let total = &retail + &wholesale + &institutional;

        // Update Redis + Prometheus
        let total_f = total.to_f64().unwrap_or(0.0);
        metrics::effective_depth().with_label_values(&[currency_pair]).set(total_f);
        self.set_redis_f64(&format!("liquidity:depth:{}", currency_pair), total_f).await;

        Ok(LiquidityDepthResponse {
            currency_pair: currency_pair.to_string(),
            retail_depth: retail,
            wholesale_depth: wholesale,
            institutional_depth: institutional,
            total_depth: total,
        })
    }

    // ── Redis helper ──────────────────────────────────────────────────────────

    async fn set_redis_f64(&self, key: &str, value: f64) {
        if let Ok(mut conn) = self.redis.get().await {
            let _: Result<(), _> = conn.set_ex(key, value.to_string(), 300).await;
        }
    }
}
