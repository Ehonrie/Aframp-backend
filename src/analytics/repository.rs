use super::models::*;
use crate::database::error::DatabaseError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

pub struct AnalyticsRepository {
    pool: PgPool,
}

impl AnalyticsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ── Usage Snapshots ──────────────────────────────────────────────────────

    pub async fn insert_usage_snapshot(
        &self,
        snapshot: &ConsumerUsageSnapshot,
    ) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"
            INSERT INTO consumer_usage_snapshots (
                id, consumer_id, consumer_tier, snapshot_period, period_start, period_end,
                total_requests, successful_requests, failed_requests, error_rate,
                p50_response_time_ms, p99_response_time_ms, avg_response_time_ms,
                rate_limit_breaches, unique_endpoints, snapshot_timestamp
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
            ON CONFLICT (consumer_id, snapshot_period, period_start) 
            DO UPDATE SET
                total_requests = EXCLUDED.total_requests,
                successful_requests = EXCLUDED.successful_requests,
                failed_requests = EXCLUDED.failed_requests,
                error_rate = EXCLUDED.error_rate,
                p50_response_time_ms = EXCLUDED.p50_response_time_ms,
                p99_response_time_ms = EXCLUDED.p99_response_time_ms,
                avg_response_time_ms = EXCLUDED.avg_response_time_ms,
                rate_limit_breaches = EXCLUDED.rate_limit_breaches,
                unique_endpoints = EXCLUDED.unique_endpoints,
                snapshot_timestamp = EXCLUDED.snapshot_timestamp
            "#,
            snapshot.id,
            snapshot.consumer_id,
            snapshot.consumer_tier as ConsumerTier,
            snapshot.snapshot_period as SnapshotPeriod,
            snapshot.period_start,
            snapshot.period_end,
            snapshot.total_requests,
            snapshot.successful_requests,
            snapshot.failed_requests,
            snapshot.error_rate,
            snapshot.p50_response_time_ms,
            snapshot.p99_response_time_ms,
            snapshot.avg_response_time_ms,
            snapshot.rate_limit_breaches,
            snapshot.unique_endpoints,
            snapshot.snapshot_timestamp,
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    pub async fn get_consumer_snapshots(
        &self,
        consumer_id: &str,
        period: SnapshotPeriod,
        limit: i64,
    ) -> Result<Vec<ConsumerUsageSnapshot>, DatabaseError> {
        let rows = sqlx::query_as!(
            ConsumerUsageSnapshot,
            r#"
            SELECT 
                id, consumer_id, consumer_tier as "consumer_tier: ConsumerTier",
                snapshot_period as "snapshot_period: SnapshotPeriod",
                period_start, period_end, total_requests, successful_requests,
                failed_requests, error_rate as "error_rate: f64",
                p50_response_time_ms, p99_response_time_ms, avg_response_time_ms,
                rate_limit_breaches, unique_endpoints, snapshot_timestamp, created_at
            FROM consumer_usage_snapshots
            WHERE consumer_id = $1 AND snapshot_period = $2
            ORDER BY period_start DESC
            LIMIT $3
            "#,
            consumer_id,
            period as SnapshotPeriod,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(rows)
    }

    // ── Endpoint Usage ───────────────────────────────────────────────────────

    pub async fn insert_endpoint_usage(
        &self,
        usage: &ConsumerEndpointUsage,
    ) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"
            INSERT INTO consumer_endpoint_usage (
                id, consumer_id, endpoint_path, http_method, snapshot_period,
                period_start, period_end, request_count, success_count,
                error_count, avg_latency_ms
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (consumer_id, endpoint_path, http_method, snapshot_period, period_start)
            DO UPDATE SET
                request_count = EXCLUDED.request_count,
                success_count = EXCLUDED.success_count,
                error_count = EXCLUDED.error_count,
                avg_latency_ms = EXCLUDED.avg_latency_ms
            "#,
            usage.id,
            usage.consumer_id,
            usage.endpoint_path,
            usage.http_method,
            usage.snapshot_period as SnapshotPeriod,
            usage.period_start,
            usage.period_end,
            usage.request_count,
            usage.success_count,
            usage.error_count,
            usage.avg_latency_ms,
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    pub async fn get_consumer_endpoint_usage(
        &self,
        consumer_id: &str,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> Result<Vec<ConsumerEndpointUsage>, DatabaseError> {
        let rows = sqlx::query_as!(
            ConsumerEndpointUsage,
            r#"
            SELECT 
                id, consumer_id, endpoint_path, http_method,
                snapshot_period as "snapshot_period: SnapshotPeriod",
                period_start, period_end, request_count, success_count,
                error_count, avg_latency_ms, created_at
            FROM consumer_endpoint_usage
            WHERE consumer_id = $1 
              AND period_start >= $2 
              AND period_end <= $3
            ORDER BY request_count DESC
            "#,
            consumer_id,
            period_start,
            period_end
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(rows)
    }

    // ── Feature Adoption ─────────────────────────────────────────────────────

    pub async fn upsert_feature_adoption(
        &self,
        consumer_id: &str,
        feature_name: &str,
    ) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"
            INSERT INTO consumer_feature_adoption (
                id, consumer_id, feature_name, first_used_at, last_used_at, total_usage_count
            ) VALUES ($1, $2, $3, now(), now(), 1)
            ON CONFLICT (consumer_id, feature_name)
            DO UPDATE SET
                last_used_at = now(),
                total_usage_count = consumer_feature_adoption.total_usage_count + 1,
                is_active = true,
                updated_at = now()
            "#,
            Uuid::new_v4(),
            consumer_id,
            feature_name
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    pub async fn get_consumer_feature_adoption(
        &self,
        consumer_id: &str,
    ) -> Result<Vec<ConsumerFeatureAdoption>, DatabaseError> {
        let rows = sqlx::query_as!(
            ConsumerFeatureAdoption,
            r#"
            SELECT id, consumer_id, feature_name, first_used_at, last_used_at,
                   total_usage_count, is_active, created_at, updated_at
            FROM consumer_feature_adoption
            WHERE consumer_id = $1
            ORDER BY last_used_at DESC
            "#,
            consumer_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(rows)
    }

    // ── Health Scores ────────────────────────────────────────────────────────

    pub async fn insert_health_score(
        &self,
        score: &ConsumerHealthScore,
    ) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"
            INSERT INTO consumer_health_scores (
                id, consumer_id, health_score, error_rate_score, rate_limit_score,
                auth_failure_score, webhook_delivery_score, activity_recency_score,
                health_trend, previous_score, score_change, is_at_risk, risk_factors,
                score_timestamp
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            "#,
            score.id,
            score.consumer_id,
            score.health_score,
            score.error_rate_score,
            score.rate_limit_score,
            score.auth_failure_score,
            score.webhook_delivery_score,
            score.activity_recency_score,
            score.health_trend as HealthTrend,
            score.previous_score,
            score.score_change,
            score.is_at_risk,
            score.risk_factors,
            score.score_timestamp,
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    pub async fn get_latest_health_score(
        &self,
        consumer_id: &str,
    ) -> Result<Option<ConsumerHealthScore>, DatabaseError> {
        let row = sqlx::query_as!(
            ConsumerHealthScore,
            r#"
            SELECT 
                id, consumer_id, health_score, error_rate_score, rate_limit_score,
                auth_failure_score, webhook_delivery_score, activity_recency_score,
                health_trend as "health_trend: HealthTrend", previous_score, score_change,
                is_at_risk, risk_factors, score_timestamp, created_at
            FROM consumer_health_scores
            WHERE consumer_id = $1
            ORDER BY score_timestamp DESC
            LIMIT 1
            "#,
            consumer_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(row)
    }

    pub async fn get_at_risk_consumers(
        &self,
        limit: i64,
    ) -> Result<Vec<ConsumerHealthScore>, DatabaseError> {
        let rows = sqlx::query_as!(
            ConsumerHealthScore,
            r#"
            SELECT DISTINCT ON (consumer_id)
                id, consumer_id, health_score, error_rate_score, rate_limit_score,
                auth_failure_score, webhook_delivery_score, activity_recency_score,
                health_trend as "health_trend: HealthTrend", previous_score, score_change,
                is_at_risk, risk_factors, score_timestamp, created_at
            FROM consumer_health_scores
            WHERE is_at_risk = true
            ORDER BY consumer_id, score_timestamp DESC
            LIMIT $1
            "#,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(rows)
    }

    // ── Revenue Attribution ──────────────────────────────────────────────────

    pub async fn insert_revenue_attribution(
        &self,
        revenue: &ConsumerRevenueAttribution,
    ) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"
            INSERT INTO consumer_revenue_attribution (
                id, consumer_id, snapshot_period, period_start, period_end,
                total_transaction_count, total_transaction_volume,
                total_fees_generated, cngn_volume_transferred
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (consumer_id, snapshot_period, period_start)
            DO UPDATE SET
                total_transaction_count = EXCLUDED.total_transaction_count,
                total_transaction_volume = EXCLUDED.total_transaction_volume,
                total_fees_generated = EXCLUDED.total_fees_generated,
                cngn_volume_transferred = EXCLUDED.cngn_volume_transferred
            "#,
            revenue.id,
            revenue.consumer_id,
            revenue.snapshot_period as SnapshotPeriod,
            revenue.period_start,
            revenue.period_end,
            revenue.total_transaction_count,
            revenue.total_transaction_volume,
            revenue.total_fees_generated,
            revenue.cngn_volume_transferred,
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    // ── Anomalies ────────────────────────────────────────────────────────────

    pub async fn insert_anomaly(
        &self,
        anomaly: &ConsumerUsageAnomaly,
    ) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"
            INSERT INTO consumer_usage_anomalies (
                id, consumer_id, anomaly_type, severity, detected_value,
                expected_value, threshold_value, deviation_percent,
                detection_window, anomaly_context, detected_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
            anomaly.id,
            anomaly.consumer_id,
            anomaly.anomaly_type,
            anomaly.severity,
            anomaly.detected_value,
            anomaly.expected_value,
            anomaly.threshold_value,
            anomaly.deviation_percent,
            anomaly.detection_window,
            anomaly.anomaly_context,
            anomaly.detected_at,
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    pub async fn get_unresolved_anomalies(
        &self,
        limit: i64,
    ) -> Result<Vec<ConsumerUsageAnomaly>, DatabaseError> {
        let rows = sqlx::query_as!(
            ConsumerUsageAnomaly,
            r#"
            SELECT 
                id, consumer_id, anomaly_type, severity,
                detected_value as "detected_value: f64",
                expected_value as "expected_value: f64",
                threshold_value as "threshold_value: f64",
                deviation_percent as "deviation_percent: f64",
                detection_window, anomaly_context, is_resolved,
                resolved_at, resolution_notes, detected_at, notified_at, created_at
            FROM consumer_usage_anomalies
            WHERE is_resolved = false
            ORDER BY detected_at DESC
            LIMIT $1
            "#,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(rows)
    }

    // ── Reports ──────────────────────────────────────────────────────────────

    pub async fn insert_platform_report(
        &self,
        report: &PlatformUsageReport,
    ) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"
            INSERT INTO platform_usage_reports (
                id, report_type, report_period_start, report_period_end,
                total_api_requests, platform_error_rate, total_consumers,
                active_consumers, new_consumers, at_risk_consumers,
                feature_adoption_summary, top_consumers_by_volume,
                report_file_path, report_file_size_bytes, generated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            "#,
            report.id,
            report.report_type,
            report.report_period_start,
            report.report_period_end,
            report.total_api_requests,
            report.platform_error_rate,
            report.total_consumers,
            report.active_consumers,
            report.new_consumers,
            report.at_risk_consumers,
            report.feature_adoption_summary,
            report.top_consumers_by_volume,
            report.report_file_path,
            report.report_file_size_bytes,
            report.generated_at,
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    pub async fn get_platform_reports(
        &self,
        report_type: Option<&str>,
        limit: i64,
    ) -> Result<Vec<PlatformUsageReport>, DatabaseError> {
        let rows = if let Some(rtype) = report_type {
            sqlx::query_as!(
                PlatformUsageReport,
                r#"
                SELECT 
                    id, report_type, report_period_start, report_period_end,
                    total_api_requests, platform_error_rate as "platform_error_rate: f64",
                    total_consumers, active_consumers, new_consumers, at_risk_consumers,
                    feature_adoption_summary, top_consumers_by_volume,
                    report_file_path, report_file_size_bytes, generated_at, created_at
                FROM platform_usage_reports
                WHERE report_type = $1
                ORDER BY report_period_start DESC
                LIMIT $2
                "#,
                rtype,
                limit
            )
            .fetch_all(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?
        } else {
            sqlx::query_as!(
                PlatformUsageReport,
                r#"
                SELECT 
                    id, report_type, report_period_start, report_period_end,
                    total_api_requests, platform_error_rate as "platform_error_rate: f64",
                    total_consumers, active_consumers, new_consumers, at_risk_consumers,
                    feature_adoption_summary, top_consumers_by_volume,
                    report_file_path, report_file_size_bytes, generated_at, created_at
                FROM platform_usage_reports
                ORDER BY report_period_start DESC
                LIMIT $1
                "#,
                limit
            )
            .fetch_all(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?
        };
        Ok(rows)
    }

    // ── Health Score Config ──────────────────────────────────────────────────

    pub async fn get_active_health_config(&self) -> Result<HealthScoreConfig, DatabaseError> {
        let row = sqlx::query_as!(
            HealthScoreConfig,
            r#"
            SELECT 
                id, config_name,
                error_rate_weight as "error_rate_weight: f64",
                rate_limit_weight as "rate_limit_weight: f64",
                auth_failure_weight as "auth_failure_weight: f64",
                webhook_delivery_weight as "webhook_delivery_weight: f64",
                activity_recency_weight as "activity_recency_weight: f64",
                at_risk_threshold, critical_threshold, trend_lookback_days,
                is_active, created_at, updated_at
            FROM health_score_config
            WHERE is_active = true
            LIMIT 1
            "#
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(row)
    }

    // ── Snapshot Generation Log ──────────────────────────────────────────────

    pub async fn log_snapshot_generation(
        &self,
        period: SnapshotPeriod,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
        consumers_processed: i32,
        snapshots_created: i32,
        duration_ms: i64,
        status: &str,
        error_message: Option<&str>,
        started_at: DateTime<Utc>,
    ) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"
            INSERT INTO snapshot_generation_log (
                id, snapshot_period, period_start, period_end,
                consumers_processed, snapshots_created, computation_duration_ms,
                status, error_message, started_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
            Uuid::new_v4(),
            period as SnapshotPeriod,
            period_start,
            period_end,
            consumers_processed,
            snapshots_created,
            duration_ms,
            status,
            error_message,
            started_at,
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }
}
