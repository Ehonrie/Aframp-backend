//! Alert System Integration
//!
//! Provides integration with external alerting services (SMS, PagerDuty, Slack)
//! for critical security incidents.

use crate::security::{AnomalyType, SystemStatus};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{error, info, warn};

/// Alert severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Critical => write!(f, "CRITICAL"),
            AlertSeverity::High => write!(f, "HIGH"),
            AlertSeverity::Medium => write!(f, "MEDIUM"),
            AlertSeverity::Low => write!(f, "LOW"),
        }
    }
}

/// Alert message structure
#[derive(Debug, Serialize)]
pub struct AlertMessage {
    pub title: String,
    pub message: String,
    pub severity: AlertSeverity,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source: String,
    pub metadata: HashMap<String, String>,
}

/// Alert service configuration
#[derive(Debug, Clone)]
pub struct AlertConfig {
    pub pagerduty_integration_key: Option<String>,
    pub slack_webhook_url: Option<String>,
    pub sms_recipients: Vec<String>,
    pub email_recipients: Vec<String>,
    pub enabled_channels: Vec<AlertChannel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertChannel {
    PagerDuty,
    Slack,
    SMS,
    Email,
}

/// Alert service for external integrations
pub struct AlertService {
    config: AlertConfig,
    http_client: reqwest::Client,
}

impl AlertService {
    pub fn new(config: AlertConfig) -> Self {
        Self {
            config,
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Send alert for circuit breaker trigger
    pub async fn send_circuit_breaker_alert(
        &self,
        anomaly: &AnomalyType,
        system_status: &SystemStatus,
    ) -> anyhow::Result<()> {
        let (severity, title, message) = self.format_circuit_breaker_alert(anomaly, system_status);
        
        let alert = AlertMessage {
            title,
            message,
            severity,
            timestamp: chrono::Utc::now(),
            source: "circuit-breaker".to_string(),
            metadata: self.extract_anomaly_metadata(anomaly, system_status),
        };

        // Send to all enabled channels
        let mut errors = Vec::new();
        
        for channel in &self.config.enabled_channels {
            if let Err(e) = self.send_to_channel(&alert, channel).await {
                warn!(channel = ?channel, error = %e, "Failed to send alert to channel");
                errors.push((channel.clone(), e));
            }
        }

        if errors.is_empty() {
            info!("Successfully sent circuit breaker alert to all channels");
        } else {
            error!(
                errors = ?errors,
                "Failed to send some circuit breaker alerts"
            );
        }

        Ok(())
    }

    /// Send test alert (for verification)
    pub async fn send_test_alert(&self) -> anyhow::Result<()> {
        let alert = AlertMessage {
            title: "Circuit Breaker Test Alert".to_string(),
            message: "This is a test alert from the cNGN circuit breaker system".to_string(),
            severity: AlertSeverity::Medium,
            timestamp: chrono::Utc::now(),
            source: "circuit-breaker-test".to_string(),
            metadata: HashMap::new(),
        };

        info!("Sending test alert to verify alert channels");

        for channel in &self.config.enabled_channels {
            if let Err(e) = self.send_to_channel(&alert, channel).await {
                warn!(channel = ?channel, error = %e, "Failed to send test alert to channel");
            }
        }

        Ok(())
    }

    // ---------------------------------------------------------------------------
    // Private Methods
    // ---------------------------------------------------------------------------

    fn format_circuit_breaker_alert(
        &self,
        anomaly: &AnomalyType,
        system_status: &SystemStatus,
    ) -> (AlertSeverity, String, String) {
        let (severity, title, message) = match anomaly {
            AnomalyType::VelocityExceeded { amount, window, limit } => {
                (
                    AlertSeverity::High,
                    "⚡ MINT VELOCITY ANOMALY DETECTED".to_string(),
                    format!(
                        "Minting velocity exceeded: {} NGN in {:?} (limit: {} NGN). System status: {}",
                        amount, window, limit, system_status
                    ),
                )
            }
            AnomalyType::NegativeDelta { bank_reserves, on_chain_supply, delta_percentage } => {
                (
                    AlertSeverity::Critical,
                    "🚨 RESERVE RATIO BREACH DETECTED".to_string(),
                    format!(
                        "Critical: Bank reserves ({}) < On-chain supply ({}). Delta: {:.4}%. System status: {}",
                        bank_reserves, on_chain_supply, delta_percentage * 100.0, system_status
                    ),
                )
            }
            AnomalyType::UnknownOrigin { tx_hash, amount, wallet } => {
                (
                    AlertSeverity::Critical,
                    "🚨 UNKNOWN ORIGIN MINT DETECTED".to_string(),
                    format!(
                        "Ghost mint detected! TX: {}, Amount: {}, Wallet: {}. System status: {}",
                        tx_hash, amount, wallet, system_status
                    ),
                )
            }
        };

        (severity, title, message)
    }

    fn extract_anomaly_metadata(
        &self,
        anomaly: &AnomalyType,
        system_status: &SystemStatus,
    ) -> HashMap<String, String> {
        let mut metadata = HashMap::new();
        metadata.insert("system_status".to_string(), system_status.to_string());
        metadata.insert("alert_type".to_string(), "circuit_breaker".to_string());

        match anomaly {
            AnomalyType::VelocityExceeded { amount, window, limit } => {
                metadata.insert("anomaly_type".to_string(), "velocity_exceeded".to_string());
                metadata.insert("amount".to_string(), amount.to_string());
                metadata.insert("window_seconds".to_string(), window.as_secs().to_string());
                metadata.insert("limit".to_string(), limit.to_string());
            }
            AnomalyType::NegativeDelta { bank_reserves, on_chain_supply, delta_percentage } => {
                metadata.insert("anomaly_type".to_string(), "negative_delta".to_string());
                metadata.insert("bank_reserves".to_string(), bank_reserves.to_string());
                metadata.insert("on_chain_supply".to_string(), on_chain_supply.to_string());
                metadata.insert("delta_percentage".to_string(), format!("{:.6}", delta_percentage));
            }
            AnomalyType::UnknownOrigin { tx_hash, amount, wallet } => {
                metadata.insert("anomaly_type".to_string(), "unknown_origin".to_string());
                metadata.insert("transaction_hash".to_string(), tx_hash.clone());
                metadata.insert("amount".to_string(), amount.to_string());
                metadata.insert("wallet".to_string(), wallet.clone());
            }
        }

        metadata
    }

    async fn send_to_channel(
        &self,
        alert: &AlertMessage,
        channel: &AlertChannel,
    ) -> anyhow::Result<()> {
        match channel {
            AlertChannel::PagerDuty => self.send_pagerduty_alert(alert).await,
            AlertChannel::Slack => self.send_slack_alert(alert).await,
            AlertChannel::SMS => self.send_sms_alert(alert).await,
            AlertChannel::Email => self.send_email_alert(alert).await,
        }
    }

    async fn send_pagerduty_alert(&self, alert: &AlertMessage) -> anyhow::Result<()> {
        let key = match &self.config.pagerduty_integration_key {
            Some(k) => k,
            None => {
                warn!("PagerDuty integration key not configured");
                return Ok(());
            }
        };

        let payload = serde_json::json!({
            "routing_key": key,
            "event_action": "trigger",
            "payload": {
                "summary": alert.title,
                "source": alert.source,
                "severity": match alert.severity {
                    AlertSeverity::Critical => "critical",
                    AlertSeverity::High => "error",
                    AlertSeverity::Medium => "warning",
                    AlertSeverity::Low => "info",
                },
                "timestamp": alert.timestamp.to_rfc3339(),
                "custom_details": {
                    "message": alert.message,
                    "metadata": alert.metadata
                }
            }
        });

        let response = self
            .http_client
            .post("https://events.pagerduty.com/v2/enqueue")
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            info!("PagerDuty alert sent successfully");
        } else {
            warn!(
                status = response.status(),
                "PagerDuty alert failed with status"
            );
        }

        Ok(())
    }

    async fn send_slack_alert(&self, alert: &AlertMessage) -> anyhow::Result<()> {
        let webhook_url = match &self.config.slack_webhook_url {
            Some(url) => url,
            None => {
                warn!("Slack webhook URL not configured");
                return Ok(());
            }
        };

        let color = match alert.severity {
            AlertSeverity::Critical => "#ff0000",      // Red
            AlertSeverity::High => "#ff6600",        // Orange
            AlertSeverity::Medium => "#ffaa00",       // Yellow
            AlertSeverity::Low => "#00ff00",          // Green
        };

        let payload = serde_json::json!({
            "text": format!("🚨 *{}*", alert.title),
            "attachments": [{
                "color": color,
                "fields": [
                    {
                        "title": "Message",
                        "value": alert.message,
                        "short": false
                    },
                    {
                        "title": "Severity",
                        "value": alert.severity.to_string(),
                        "short": true
                    },
                    {
                        "title": "Source",
                        "value": alert.source,
                        "short": true
                    },
                    {
                        "title": "Timestamp",
                        "value": alert.timestamp.to_rfc3339(),
                        "short": true
                    }
                ]
            }]
        });

        let response = self
            .http_client
            .post(webhook_url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            info!("Slack alert sent successfully");
        } else {
            warn!(
                status = response.status(),
                "Slack alert failed with status"
            );
        }

        Ok(())
    }

    async fn send_sms_alert(&self, alert: &AlertMessage) -> anyhow::Result<()> {
        if self.config.sms_recipients.is_empty() {
            warn!("No SMS recipients configured");
            return Ok(());
        }

        // This would integrate with an SMS service like Twilio, AWS SNS, etc.
        // For now, we'll just log the SMS that would be sent
        for recipient in &self.config.sms_recipients {
            warn!(
                recipient = %recipient,
                message = %alert.message,
                "SMS ALERT (not sent - integration needed)"
            );
        }

        info!("SMS alerts logged (integration needed)");
        Ok(())
    }

    async fn send_email_alert(&self, alert: &AlertMessage) -> anyhow::Result<()> {
        if self.config.email_recipients.is_empty() {
            warn!("No email recipients configured");
            return Ok(());
        }

        // This would integrate with an email service like SendGrid, AWS SES, etc.
        // For now, we'll just log the email that would be sent
        for recipient in &self.config.email_recipients {
            warn!(
                recipient = %recipient,
                subject = %alert.title,
                message = %alert.message,
                "EMAIL ALERT (not sent - integration needed)"
            );
        }

        info!("Email alerts logged (integration needed)");
        Ok(())
    }
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            pagerduty_integration_key: std::env::var("PAGERDUTY_INTEGRATION_KEY").ok(),
            slack_webhook_url: std::env::var("SLACK_WEBHOOK_URL").ok(),
            sms_recipients: vec![],
            email_recipients: vec![],
            enabled_channels: vec![AlertChannel::Slack], // Default to Slack only
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_severity_display() {
        assert_eq!(AlertSeverity::Critical.to_string(), "CRITICAL");
        assert_eq!(AlertSeverity::High.to_string(), "HIGH");
        assert_eq!(AlertSeverity::Medium.to_string(), "MEDIUM");
        assert_eq!(AlertSeverity::Low.to_string(), "LOW");
    }

    #[test]
    fn test_alert_config_default() {
        let config = AlertConfig::default();
        assert!(config.enabled_channels.contains(&AlertChannel::Slack));
        assert_eq!(config.enabled_channels.len(), 1);
    }

    #[test]
    fn test_alert_message_creation() {
        let alert = AlertMessage {
            title: "Test Alert".to_string(),
            message: "Test message".to_string(),
            severity: AlertSeverity::High,
            timestamp: chrono::Utc::now(),
            source: "test".to_string(),
            metadata: HashMap::new(),
        };

        assert_eq!(alert.title, "Test Alert");
        assert_eq!(alert.severity, AlertSeverity::High);
    }
}
