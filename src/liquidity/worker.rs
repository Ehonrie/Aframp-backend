use super::models::*;
use super::repository::LiquidityRepository;
use super::{metrics, HIGH_UTILISATION_THRESHOLD};
use bigdecimal::ToPrimitive;
use chrono::Utc;
use sqlx::types::BigDecimal;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};
use uuid::Uuid;

pub struct LiquidityHealthWorker {
    repo: Arc<LiquidityRepository>,
    check_interval_secs: u64,
}

impl LiquidityHealthWorker {
    pub fn new(repo: Arc<LiquidityRepository>, check_interval_secs: u64) -> Self {
        Self { repo, check_interval_secs }
    }

    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) {
        let mut ticker = interval(Duration::from_secs(self.check_interval_secs));
        info!("Liquidity health worker started");
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.tick().await {
                        error!(error = %e, "Liquidity health tick failed");
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Liquidity health worker shutting down");
                        break;
                    }
                }
            }
        }
    }

    async fn tick(&self) -> anyhow::Result<()> {
        // Expire stale reservations first
        let expired = self.repo.expire_stale_reservations().await?;
        for rid in &expired {
            metrics::timeout_releases()
                .with_label_values(&[&rid.to_string()])
                .inc();
            warn!(reservation_id = %rid, "Reservation timed out and released");
        }

        let pools = self.repo.list_pools().await?;
        for pool in pools {
            if let Err(e) = self.snapshot_pool(&pool).await {
                error!(pool_id = %pool.pool_id, error = %e, "Health snapshot failed");
            }
        }
        Ok(())
    }

    async fn snapshot_pool(&self, pool: &LiquidityPool) -> anyhow::Result<()> {
        let total = pool.total_liquidity_depth.to_f64().unwrap_or(0.0);
        let reserved = pool.reserved_liquidity.to_f64().unwrap_or(0.0);
        let available = pool.available_liquidity.to_f64().unwrap_or(0.0);

        let utilisation = if total > 0.0 { reserved / total * 100.0 } else { 0.0 };

        let distance_from_min = &pool.available_liquidity - &pool.min_liquidity_threshold;
        let distance_from_target = &pool.available_liquidity - &pool.target_liquidity_level;
        let factor = BigDecimal::from_str("0.99")?;
        let effective_depth = &pool.available_liquidity * &factor;

        let snap = PoolHealthSnapshot {
            id: Uuid::new_v4(),
            pool_id: pool.pool_id,
            utilisation_pct: BigDecimal::try_from(utilisation).unwrap_or_default(),
            available_depth: pool.available_liquidity.clone(),
            distance_from_min,
            distance_from_target,
            effective_depth: effective_depth.clone(),
            snapshotted_at: Utc::now(),
        };
        self.repo.insert_health_snapshot(&snap).await?;

        // Prometheus
        let pid = pool.pool_id.to_string();
        let pair = &pool.currency_pair;
        let pt = format!("{:?}", pool.pool_type).to_lowercase();

        metrics::available_liquidity().with_label_values(&[&pid, pair, &pt]).set(available);
        metrics::reserved_liquidity().with_label_values(&[&pid, pair, &pt]).set(reserved);
        metrics::utilisation_pct().with_label_values(&[&pid, pair, &pt]).set(utilisation);
        metrics::effective_depth().with_label_values(&[pair]).set(effective_depth.to_f64().unwrap_or(0.0));

        // Alerts
        if pool.available_liquidity < pool.min_liquidity_threshold {
            warn!(
                pool_id = %pool.pool_id, currency_pair = %pair, pool_type = ?pool.pool_type,
                available = %pool.available_liquidity, minimum = %pool.min_liquidity_threshold,
                "ALERT: Pool below minimum liquidity threshold"
            );
        }
        if utilisation > HIGH_UTILISATION_THRESHOLD {
            warn!(pool_id = %pool.pool_id, utilisation_pct = utilisation, "ALERT: Pool high utilisation");
        }
        if pool.available_liquidity > pool.max_liquidity_cap {
            warn!(
                pool_id = %pool.pool_id, available = %pool.available_liquidity,
                cap = %pool.max_liquidity_cap, "ALERT: Pool exceeds maximum liquidity cap"
            );
        }

        Ok(())
    }
}
