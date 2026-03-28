use super::handlers::*;
use axum::{
    routing::get,
    Router,
};
use std::sync::Arc;

pub fn consumer_analytics_routes() -> Router<Arc<AnalyticsRepository>> {
    Router::new()
        .route("/usage/summary", get(get_usage_summary))
        .route("/usage/endpoints", get(get_endpoint_usage))
        .route("/usage/features", get(get_feature_adoption))
}

pub fn admin_analytics_routes() -> Router<Arc<AnalyticsRepository>> {
    Router::new()
        .route("/consumers/overview", get(get_consumer_overview))
        .route("/consumers/health", get(get_at_risk_consumers))
        .route("/consumers/:consumer_id/detail", get(get_consumer_detail))
        .route("/reports", get(get_platform_reports))
}
