use super::models::*;
use super::repository::AnalyticsRepository;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use chrono::{Duration, Utc};
use serde_json::json;
use std::sync::Arc;
use tracing::error;

pub type AnalyticsState = Arc<AnalyticsRepository>;

pub async fn get_usage_summary(
    State(repo): State<AnalyticsState>,
    consumer_id: String, // Extracted from auth middleware
    Query(query): Query<UsageSummaryQuery>,
) -> Result<Json<UsageSummaryResponse>, (StatusCode, String)> {
    let (period_start, period_end, period_name) = match query.period.as_deref() {
        Some("current_hour") => {
            let now = Utc::now();
            let start = now - Duration::hours(1);
            (start, now, "current_hour")
        }
        Some("today") => {
            let now = Utc::now();
            let start = now.date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc();
            (start, now, "today")
        }
        Some("this_week") => {
            let now = Utc::now();
            let start = now - Duration::days(7);
            (start, now, "this_week")
        }
        _ => {
            let now = Utc::now();
            let start = now - Duration::days(30);
            (start, now, "this_month")
        }
    };

    let snapshots = repo
        .get_consumer_snapshots(&consumer_id, SnapshotPeriod::Daily, 30)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let total_requests: i64 = snapshots.iter().map(|s| s.total_requests).sum();
    let failed_requests: i64 = snapshots.iter().map(|s| s.failed_requests).sum();
    let error_rate = if total_requests > 0 {
        failed_requests as f64 / total_requests as f64
    } else {
        0.0
    };

    let features = repo
        .get_consumer_feature_adoption(&consumer_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let active_features: Vec<String> = features
        .into_iter()
        .filter(|f| f.is_active)
        .map(|f| f.feature_name)
        .collect();

    let health_score = repo
        .get_latest_health_score(&consumer_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map(|s| s.health_score);

    Ok(Json(UsageSummaryResponse {
        period: period_name.to_string(),
        period_start,
        period_end,
        total_requests,
        error_rate,
        rate_limit_utilization: 0.0, // Placeholder
        active_features,
        health_score,
    }))
}

pub async fn get_endpoint_usage(
    State(repo): State<AnalyticsState>,
    consumer_id: String,
) -> Result<Json<Vec<EndpointUsageResponse>>, (StatusCode, String)> {
    let period_end = Utc::now();
    let period_start = period_end - Duration::days(30);

    let usage = repo
        .get_consumer_endpoint_usage(&consumer_id, period_start, period_end)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let response: Vec<EndpointUsageResponse> = usage
        .into_iter()
        .map(|u| {
            let error_rate = if u.request_count > 0 {
                u.error_count as f64 / u.request_count as f64
            } else {
                0.0
            };
            EndpointUsageResponse {
                endpoint_path: u.endpoint_path,
                http_method: u.http_method,
                request_count: u.request_count,
                error_rate,
                avg_latency_ms: u.avg_latency_ms,
            }
        })
        .collect();

    Ok(Json(response))
}

pub async fn get_feature_adoption(
    State(repo): State<AnalyticsState>,
    consumer_id: String,
) -> Result<Json<Vec<FeatureAdoptionResponse>>, (StatusCode, String)> {
    let features = repo
        .get_consumer_feature_adoption(&consumer_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let response: Vec<FeatureAdoptionResponse> = features
        .into_iter()
        .map(|f| FeatureAdoptionResponse {
            feature_name: f.feature_name,
            first_used_at: f.first_used_at,
            last_used_at: f.last_used_at,
            total_usage_count: f.total_usage_count,
            is_active: f.is_active,
        })
        .collect();

    Ok(Json(response))
}

// ── Admin endpoints ──────────────────────────────────────────────────────────

pub async fn get_consumer_overview(
    State(repo): State<AnalyticsState>,
) -> Result<Json<ConsumerOverviewResponse>, (StatusCode, String)> {
    // Placeholder implementation
    Ok(Json(ConsumerOverviewResponse {
        total_registered_consumers: 0,
        active_consumers_by_tier: json!({}),
        new_consumers_this_period: 0,
        consumer_growth_trend: vec![],
    }))
}

pub async fn get_at_risk_consumers(
    State(repo): State<AnalyticsState>,
) -> Result<Json<Vec<AtRiskConsumer>>, (StatusCode, String)> {
    let scores = repo
        .get_at_risk_consumers(100)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let response: Vec<AtRiskConsumer> = scores
        .into_iter()
        .map(|s| {
            let risk_factors: Vec<String> = s
                .risk_factors
                .as_ref()
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            AtRiskConsumer {
                consumer_id: s.consumer_id,
                health_score: s.health_score,
                risk_factors,
                last_activity: s.score_timestamp,
            }
        })
        .collect();

    Ok(Json(response))
}

pub async fn get_platform_reports(
    State(repo): State<AnalyticsState>,
) -> Result<Json<Vec<PlatformUsageReport>>, (StatusCode, String)> {
    let reports = repo
        .get_platform_reports(None, 50)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(reports))
}

pub async fn get_consumer_detail(
    State(repo): State<AnalyticsState>,
    Path(consumer_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let snapshots = repo
        .get_consumer_snapshots(&consumer_id, SnapshotPeriod::Daily, 30)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let health_score = repo
        .get_latest_health_score(&consumer_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let features = repo
        .get_consumer_feature_adoption(&consumer_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({
        "consumer_id": consumer_id,
        "snapshots": snapshots,
        "health_score": health_score,
        "features": features
    })))

}
