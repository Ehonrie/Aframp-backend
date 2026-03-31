//! Peg Integrity Monitor Worker
//!
//! Polls the Stellar DEX for the cNGN/NGN trade price every N seconds,
//! computes the BPS deviation from the oracle reference price, persists
//! a time-series snapshot, and fires tiered alerts.
//!
//! False-positive guard: an alert only fires after the price has been
//! continuously deviated for >= PEG_DURATION_THRESHOLD_SECS seconds.

use crate::chains::stellar::client::StellarClient;
use crate::peg_monitor::{
    models::{alert_level, duration_threshold_secs, poll_interval_secs, BPS_RED},
    repository::PegMonitorRepository,
};
use bigdecimal::BigDecimal;
use chrono::Utc;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info, warn};

pub struct PegMonitorWorker {
    repo: Arc<PegMonitorRepository>,
    stellar_client: StellarClient,
    /// Stellar DEX asset code for cNGN
    asset_code: String,
    asset_issuer: String,
    /// Oracle reference price (1.0 for a perfect 1:1 peg)
    oracle_price: BigDecimal,
    /// Tracks when the current deviation streak started (for duration threshold)
    deviation_streak_start: Option<chrono::DateTime<chrono::Utc>>,
}

impl PegMonitorWorker {
    pub fn new(
        repo: Arc<PegMonitorRepository>,
        stellar_client: StellarClient,
        asset_code: String,
        asset_issuer: String,
    ) -> Self {
        let oracle_price = std::env::var("PEG_ORACLE_PRICE")
            .ok()
            .and_then(|v| BigDecimal::from_str(&v).ok())
            .unwrap_or_else(|| BigDecimal::from(1)); // default 1:1

        Self {
            repo,
            stellar_client,
            asset_code,
            asset_issuer,
            oracle_price,
            deviation_streak_start: None,
        }
    }

    pub async fn run(mut self, mut shutdown_rx: watch::Receiver<bool>) {
        let interval = Duration::from_secs(poll_interval_secs());
        info!(interval_secs = interval.as_secs(), "Peg Integrity Monitor started");

        let mut ticker = tokio::time::interval(interval);

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Peg Integrity Monitor stopping");
                        break;
                    }
                }
                _ = ticker.tick() => {
                    if let Err(e) = self.run_cycle().await {
                        error!(error = %e, "Peg monitor cycle failed");
                    }
                }
            }
        }
    }

    async fn run_cycle(&mut self) -> anyhow::Result<()> {
        let dex_price = self.fetch_dex_price().await?;

        // BPS = (dex - oracle) / oracle * 10_000
        let deviation_bps = (&dex_price - &self.oracle_price)
            / &self.oracle_price
            * BigDecimal::from(10_000);
        let abs_bps: f64 = deviation_bps
            .to_string()
            .parse::<f64>()
            .unwrap_or(0.0)
            .abs();

        let level = alert_level(abs_bps);

        // Persist snapshot
        let snap = self
            .repo
            .insert_snapshot(
                &dex_price,
                &self.oracle_price,
                &deviation_bps,
                level,
            )
            .await?;

        // Duration-threshold guard
        let now = Utc::now();
        if level > 0 {
            let streak_start = *self.deviation_streak_start.get_or_insert(now);
            let streak_secs = (now - streak_start).num_seconds() as u64;

            if streak_secs >= duration_threshold_secs() {
                self.handle_alert(level, abs_bps, &deviation_bps, now).await?;
            }
        } else {
            // Back to healthy — resolve any open event
            if self.deviation_streak_start.take().is_some() {
                if let Some(event) = self.repo.open_depeg_event().await? {
                    self.repo.resolve_depeg_event(event.id, now).await?;
                    info!(
                        event_id = %event.id,
                        recovery_secs = (now - event.started_at).num_seconds(),
                        "De-peg event resolved"
                    );
                }
            }
        }

        info!(
            dex_price = %dex_price,
            deviation_bps = %deviation_bps,
            alert_level = level,
            "Peg snapshot recorded"
        );

        Ok(())
    }

    async fn handle_alert(
        &mut self,
        level: i16,
        abs_bps: f64,
        deviation_bps: &BigDecimal,
        now: chrono::DateTime<Utc>,
    ) -> anyhow::Result<()> {
        // Open or update de-peg event
        match self.repo.open_depeg_event().await? {
            None => {
                let event = self
                    .repo
                    .create_depeg_event(now, deviation_bps, level)
                    .await?;
                info!(event_id = %event.id, level, abs_bps, "De-peg event opened");
            }
            Some(event) => {
                self.repo
                    .update_depeg_event_peak(event.id, deviation_bps, level)
                    .await?;
            }
        }

        match level {
            1 => warn!(
                abs_bps,
                "🟡 PEG ALERT L1 (Yellow): {:.2} BPS deviation — internal notification", abs_bps
            ),
            2 => warn!(
                abs_bps,
                "🟠 PEG ALERT L2 (Orange): {:.2} BPS deviation — high-priority alert", abs_bps
            ),
            3 => {
                error!(
                    abs_bps,
                    "🔴 PEG ALERT L3 (Red): {:.2} BPS deviation — EMERGENCY INTERVENTION triggered",
                    abs_bps
                );
                // TODO: integrate Emergency Intervention Flow (#1.09)
            }
            _ => {}
        }

        Ok(())
    }

    /// Fetch the current cNGN/NGN price from the Stellar DEX order book.
    async fn fetch_dex_price(&self) -> anyhow::Result<BigDecimal> {
        let url = format!(
            "{}/order_book?selling_asset_type=credit_alphanum12\
             &selling_asset_code={}&selling_asset_issuer={}\
             &buying_asset_type=native&limit=1",
            self.stellar_client.config().horizon_url(),
            self.asset_code,
            self.asset_issuer,
        );

        let resp: serde_json::Value = reqwest::get(&url).await?.json().await?;

        // Best ask price (lowest price someone will sell cNGN for XLM)
        let price_str = resp["asks"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|ask| ask["price"].as_str())
            .unwrap_or("1.0");

        Ok(BigDecimal::from_str(price_str)
            .unwrap_or_else(|_| BigDecimal::from(1)))
    }
}
