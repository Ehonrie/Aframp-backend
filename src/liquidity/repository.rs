use super::models::*;
use chrono::Utc;
use sqlx::types::BigDecimal;
use sqlx::PgPool;
use uuid::Uuid;

pub struct LiquidityRepository {
    pool: PgPool,
}

impl LiquidityRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ── Pool CRUD ─────────────────────────────────────────────────────────────

    pub async fn list_pools(&self) -> Result<Vec<LiquidityPool>, sqlx::Error> {
        sqlx::query_as!(
            LiquidityPool,
            r#"SELECT pool_id, currency_pair,
                      pool_type AS "pool_type: PoolType",
                      total_liquidity_depth, available_liquidity, reserved_liquidity,
                      min_liquidity_threshold, target_liquidity_level, max_liquidity_cap,
                      pool_status AS "pool_status: PoolStatus",
                      created_at, updated_at
               FROM liquidity_pools
               ORDER BY currency_pair, pool_type"#
        )
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_pool(&self, pool_id: Uuid) -> Result<Option<LiquidityPool>, sqlx::Error> {
        sqlx::query_as!(
            LiquidityPool,
            r#"SELECT pool_id, currency_pair,
                      pool_type AS "pool_type: PoolType",
                      total_liquidity_depth, available_liquidity, reserved_liquidity,
                      min_liquidity_threshold, target_liquidity_level, max_liquidity_cap,
                      pool_status AS "pool_status: PoolStatus",
                      created_at, updated_at
               FROM liquidity_pools WHERE pool_id = $1"#,
            pool_id
        )
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn get_pool_by_pair_and_type(
        &self,
        currency_pair: &str,
        pool_type: &PoolType,
    ) -> Result<Option<LiquidityPool>, sqlx::Error> {
        sqlx::query_as!(
            LiquidityPool,
            r#"SELECT pool_id, currency_pair,
                      pool_type AS "pool_type: PoolType",
                      total_liquidity_depth, available_liquidity, reserved_liquidity,
                      min_liquidity_threshold, target_liquidity_level, max_liquidity_cap,
                      pool_status AS "pool_status: PoolStatus",
                      created_at, updated_at
               FROM liquidity_pools
               WHERE currency_pair = $1 AND pool_type = $2"#,
            currency_pair,
            pool_type as &PoolType
        )
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn create_pool(
        &self,
        req: &CreatePoolRequest,
    ) -> Result<LiquidityPool, sqlx::Error> {
        sqlx::query_as!(
            LiquidityPool,
            r#"INSERT INTO liquidity_pools
                   (currency_pair, pool_type, min_liquidity_threshold,
                    target_liquidity_level, max_liquidity_cap)
               VALUES ($1, $2, $3, $4, $5)
               RETURNING pool_id, currency_pair,
                         pool_type AS "pool_type: PoolType",
                         total_liquidity_depth, available_liquidity, reserved_liquidity,
                         min_liquidity_threshold, target_liquidity_level, max_liquidity_cap,
                         pool_status AS "pool_status: PoolStatus",
                         created_at, updated_at"#,
            req.currency_pair,
            req.pool_type as &PoolType,
            req.min_liquidity_threshold,
            req.target_liquidity_level,
            req.max_liquidity_cap,
        )
        .fetch_one(&self.pool)
        .await
    }

    pub async fn update_pool(
        &self,
        pool_id: Uuid,
        req: &UpdatePoolRequest,
    ) -> Result<Option<LiquidityPool>, sqlx::Error> {
        sqlx::query_as!(
            LiquidityPool,
            r#"UPDATE liquidity_pools SET
                   min_liquidity_threshold = COALESCE($2, min_liquidity_threshold),
                   target_liquidity_level  = COALESCE($3, target_liquidity_level),
                   max_liquidity_cap       = COALESCE($4, max_liquidity_cap),
                   updated_at              = NOW()
               WHERE pool_id = $1
               RETURNING pool_id, currency_pair,
                         pool_type AS "pool_type: PoolType",
                         total_liquidity_depth, available_liquidity, reserved_liquidity,
                         min_liquidity_threshold, target_liquidity_level, max_liquidity_cap,
                         pool_status AS "pool_status: PoolStatus",
                         created_at, updated_at"#,
            pool_id,
            req.min_liquidity_threshold,
            req.target_liquidity_level,
            req.max_liquidity_cap,
        )
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn set_pool_status(
        &self,
        pool_id: Uuid,
        status: PoolStatus,
    ) -> Result<bool, sqlx::Error> {
        let rows = sqlx::query!(
            "UPDATE liquidity_pools SET pool_status = $2, updated_at = NOW() WHERE pool_id = $1",
            pool_id,
            status as PoolStatus
        )
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(rows > 0)
    }

    // ── Atomic reservation ────────────────────────────────────────────────────

    /// Reserve liquidity atomically. Returns the new reservation or None if
    /// insufficient available liquidity or pool is not active.
    pub async fn reserve_liquidity(
        &self,
        pool_id: Uuid,
        transaction_id: Uuid,
        amount: &BigDecimal,
        timeout_seconds: i64,
    ) -> Result<Option<LiquidityReservation>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        // Lock the pool row and check availability atomically
        let updated = sqlx::query!(
            r#"UPDATE liquidity_pools
               SET available_liquidity = available_liquidity - $2,
                   reserved_liquidity  = reserved_liquidity  + $2,
                   updated_at          = NOW()
               WHERE pool_id = $1
                 AND pool_status = 'active'
                 AND available_liquidity >= $2
               RETURNING pool_id"#,
            pool_id,
            amount,
        )
        .fetch_optional(&mut *tx)
        .await?;

        if updated.is_none() {
            tx.rollback().await?;
            return Ok(None);
        }

        let reservation = sqlx::query_as!(
            LiquidityReservation,
            r#"INSERT INTO liquidity_reservations
                   (pool_id, transaction_id, reserved_amount, expires_at)
               VALUES ($1, $2, $3, NOW() + ($4 || ' seconds')::interval)
               RETURNING reservation_id, pool_id, transaction_id, reserved_amount,
                         status AS "status: ReservationStatus",
                         reserved_at, expires_at, resolved_at"#,
            pool_id,
            transaction_id,
            amount,
            timeout_seconds.to_string(),
        )
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(Some(reservation))
    }

    /// Release a reservation back to available (on failure/refund).
    pub async fn release_reservation(
        &self,
        reservation_id: Uuid,
        new_status: ReservationStatus,
    ) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        let res = sqlx::query!(
            r#"UPDATE liquidity_reservations
               SET status = $2, resolved_at = NOW()
               WHERE reservation_id = $1 AND status = 'active'
               RETURNING pool_id, reserved_amount"#,
            reservation_id,
            new_status as ReservationStatus,
        )
        .fetch_optional(&mut *tx)
        .await?;

        let Some(r) = res else {
            tx.rollback().await?;
            return Ok(false);
        };

        // Only return to available on release/timeout; consumed means it was spent
        if new_status == ReservationStatus::Released || new_status == ReservationStatus::TimedOut {
            sqlx::query!(
                r#"UPDATE liquidity_pools
                   SET available_liquidity = available_liquidity + $2,
                       reserved_liquidity  = reserved_liquidity  - $2,
                       updated_at          = NOW()
                   WHERE pool_id = $1"#,
                r.pool_id,
                r.reserved_amount,
            )
            .execute(&mut *tx)
            .await?;
        } else {
            // consumed: deduct from total depth
            sqlx::query!(
                r#"UPDATE liquidity_pools
                   SET total_liquidity_depth = total_liquidity_depth - $2,
                       reserved_liquidity    = reserved_liquidity    - $2,
                       updated_at            = NOW()
                   WHERE pool_id = $1"#,
                r.pool_id,
                r.reserved_amount,
            )
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(true)
    }

    /// Expire all active reservations past their expiry time.
    pub async fn expire_stale_reservations(&self) -> Result<Vec<Uuid>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        let stale = sqlx::query!(
            r#"UPDATE liquidity_reservations
               SET status = 'timed_out', resolved_at = NOW()
               WHERE status = 'active' AND expires_at < NOW()
               RETURNING reservation_id, pool_id, reserved_amount"#
        )
        .fetch_all(&mut *tx)
        .await?;

        for row in &stale {
            sqlx::query!(
                r#"UPDATE liquidity_pools
                   SET available_liquidity = available_liquidity + $2,
                       reserved_liquidity  = reserved_liquidity  - $2,
                       updated_at          = NOW()
                   WHERE pool_id = $1"#,
                row.pool_id,
                row.reserved_amount,
            )
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(stale.iter().map(|r| r.reservation_id).collect())
    }

    // ── Health snapshots ──────────────────────────────────────────────────────

    pub async fn insert_health_snapshot(
        &self,
        snap: &PoolHealthSnapshot,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"INSERT INTO pool_health_snapshots
                   (id, pool_id, utilisation_pct, available_depth,
                    distance_from_min, distance_from_target, effective_depth)
               VALUES ($1,$2,$3,$4,$5,$6,$7)"#,
            snap.id,
            snap.pool_id,
            snap.utilisation_pct,
            snap.available_depth,
            snap.distance_from_min,
            snap.distance_from_target,
            snap.effective_depth,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_pool_allocations(
        &self,
        pool_id: Uuid,
    ) -> Result<Vec<LiquidityAllocation>, sqlx::Error> {
        sqlx::query_as!(
            LiquidityAllocation,
            "SELECT * FROM liquidity_allocations WHERE pool_id = $1 ORDER BY allocation_timestamp DESC",
            pool_id
        )
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_utilisation_history(
        &self,
        pool_id: Uuid,
        limit: i64,
    ) -> Result<Vec<PoolUtilisation>, sqlx::Error> {
        sqlx::query_as!(
            PoolUtilisation,
            "SELECT * FROM pool_utilisation WHERE pool_id = $1 ORDER BY period_start DESC LIMIT $2",
            pool_id,
            limit
        )
        .fetch_all(&self.pool)
        .await
    }
}
