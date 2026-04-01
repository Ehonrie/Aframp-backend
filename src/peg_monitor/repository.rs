use crate::peg_monitor::models::{PegDepegEvent, PegDeviationSnapshot};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

pub type RepoResult<T> = Result<T, sqlx::Error>;

pub struct PegMonitorRepository {
    pool: PgPool,
}

impl PegMonitorRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn insert_snapshot(
        &self,
        dex_price: &sqlx::types::BigDecimal,
        oracle_price: &sqlx::types::BigDecimal,
        deviation_bps: &sqlx::types::BigDecimal,
        alert_level: i16,
    ) -> RepoResult<PegDeviationSnapshot> {
        sqlx::query_as::<_, PegDeviationSnapshot>(
            "INSERT INTO peg_deviation_snapshots
             (dex_price, oracle_price, deviation_bps, alert_level)
             VALUES ($1, $2, $3, $4)
             RETURNING id, captured_at, dex_price, oracle_price, deviation_bps, alert_level",
        )
        .bind(dex_price)
        .bind(oracle_price)
        .bind(deviation_bps)
        .bind(alert_level)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn latest_snapshot(&self) -> RepoResult<Option<PegDeviationSnapshot>> {
        sqlx::query_as::<_, PegDeviationSnapshot>(
            "SELECT id, captured_at, dex_price, oracle_price, deviation_bps, alert_level
             FROM peg_deviation_snapshots
             ORDER BY captured_at DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn snapshots_since(
        &self,
        since: DateTime<Utc>,
        limit: i64,
    ) -> RepoResult<Vec<PegDeviationSnapshot>> {
        sqlx::query_as::<_, PegDeviationSnapshot>(
            "SELECT id, captured_at, dex_price, oracle_price, deviation_bps, alert_level
             FROM peg_deviation_snapshots
             WHERE captured_at >= $1
             ORDER BY captured_at DESC LIMIT $2",
        )
        .bind(since)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    // ── De-peg events ─────────────────────────────────────────────────────────

    pub async fn open_depeg_event(&self) -> RepoResult<Option<PegDepegEvent>> {
        sqlx::query_as::<_, PegDepegEvent>(
            "SELECT id, started_at, resolved_at, peak_deviation_bps,
                    max_alert_level, time_to_recovery_secs, is_open
             FROM peg_depeg_events WHERE is_open = TRUE
             ORDER BY started_at DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn create_depeg_event(
        &self,
        started_at: DateTime<Utc>,
        deviation_bps: &sqlx::types::BigDecimal,
        alert_level: i16,
    ) -> RepoResult<PegDepegEvent> {
        sqlx::query_as::<_, PegDepegEvent>(
            "INSERT INTO peg_depeg_events (started_at, peak_deviation_bps, max_alert_level)
             VALUES ($1, $2, $3)
             RETURNING id, started_at, resolved_at, peak_deviation_bps,
                       max_alert_level, time_to_recovery_secs, is_open",
        )
        .bind(started_at)
        .bind(deviation_bps)
        .bind(alert_level)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn update_depeg_event_peak(
        &self,
        event_id: Uuid,
        deviation_bps: &sqlx::types::BigDecimal,
        alert_level: i16,
    ) -> RepoResult<()> {
        sqlx::query(
            "UPDATE peg_depeg_events
             SET peak_deviation_bps = GREATEST(peak_deviation_bps, $2),
                 max_alert_level    = GREATEST(max_alert_level, $3)
             WHERE id = $1",
        )
        .bind(event_id)
        .bind(deviation_bps)
        .bind(alert_level)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn resolve_depeg_event(&self, event_id: Uuid, now: DateTime<Utc>) -> RepoResult<()> {
        sqlx::query(
            "UPDATE peg_depeg_events
             SET is_open = FALSE,
                 resolved_at = $2,
                 time_to_recovery_secs = EXTRACT(EPOCH FROM ($2 - started_at))::BIGINT
             WHERE id = $1",
        )
        .bind(event_id)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn recent_depeg_events(&self, limit: i64) -> RepoResult<Vec<PegDepegEvent>> {
        sqlx::query_as::<_, PegDepegEvent>(
            "SELECT id, started_at, resolved_at, peak_deviation_bps,
                    max_alert_level, time_to_recovery_secs, is_open
             FROM peg_depeg_events
             ORDER BY started_at DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }
}
