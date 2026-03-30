//! Consumer Usage Analytics & Reporting System

pub mod models;
pub mod repository;
pub mod snapshot;
pub mod health;
pub mod anomaly;
pub mod reports;
pub mod handlers;
pub mod routes;
pub mod metrics;
pub mod worker;
pub mod cache;
mod tests;

pub use models::*;
pub use repository::AnalyticsRepository;
pub use handlers::*;
pub use routes::analytics_routes;
pub use snapshot::SnapshotGenerator;
pub use health::HealthScoreCalculator;
pub use anomaly::AnomalyDetector;
pub use reports::ReportGenerator;
