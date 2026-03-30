use super::handlers::*;
use super::repository::AnalyticsRepository;
use axum::{routing::get, Router};
use std::sync::Arc;

pub fn analytics_routes() -> Router<Arc<AnalyticsRepository>> {
    Router::new()
        .route("/usage/summary", get(get_usage_summary))
        .route("/usage/endpoints", get(get_endpoint_usage))
        .route("/usage/features", get(get_feature_adoption))
        .route("/consumers/overview", get(get_consumer_overview))
        .route("/consumers/health", get(get_at_risk_consumers))
        .route("/consumers/:consumer_id/detail", get(get_consumer_detail))
        .route("/reports", get(get_platform_reports))
}
