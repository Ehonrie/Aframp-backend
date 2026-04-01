/// Background worker that runs the verification engine every 24 hours
/// (configurable via VERIFICATION_INTERVAL_SECS env var).
use crate::verification::engine::{VerificationEngine, VerificationError};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info};

pub struct VerificationWorker {
    engine: Arc<VerificationEngine>,
    interval: Duration,
}

impl VerificationWorker {
    pub fn new(engine: Arc<VerificationEngine>) -> Self {
        let secs: u64 = std::env::var("VERIFICATION_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(86_400); // 24 hours
        Self {
            engine,
            interval: Duration::from_secs(secs),
        }
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        info!(
            interval_secs = self.interval.as_secs(),
            "Collateral verification worker started"
        );

        // Run once immediately on startup
        self.run_once().await;

        let mut ticker = tokio::time::interval(self.interval);
        ticker.tick().await; // consume the immediate tick

        loop {
            tokio::select! {
                _ = ticker.tick() => self.run_once().await,
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Collateral verification worker shutting down");
                        break;
                    }
                }
            }
        }
    }

    async fn run_once(&self) {
        match self.engine.run("scheduler").await {
            Ok(r) => info!(
                collateral_ratio = %r.collateral_ratio,
                is_collateralised = r.is_collateralised,
                "Verification cycle complete"
            ),
            Err(VerificationError::StellarFetch(e)) => {
                error!(error = %e, "Verification skipped — Stellar fetch failed (no false negative written)");
            }
            Err(VerificationError::ReserveFetch(e)) => {
                error!(error = %e, "Verification skipped — reserve fetch failed (no false negative written)");
            }
            Err(e) => error!(error = %e, "Verification cycle failed"),
        }
    }
}
