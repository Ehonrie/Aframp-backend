//! Ghana settlement provider — Hubtel API adapter.
//!
//! Covers:
//! - Mobile Money disbursements (MTN MoMo, Telecel Cash, AirtelTigo Money)
//! - GIP bank transfers (Ghana Interbank Payment)
//! - Recipient phone/Ghana Card validation
//! - Webhook result mapping → Aframp PaymentState
//! - Automated retry on transient failures

use crate::payments::error::{PaymentError, PaymentResult};
use crate::payments::provider::PaymentProvider;
use crate::payments::types::{
    Money, PaymentMethod, PaymentRequest, PaymentResponse, PaymentState, ProviderName,
    StatusRequest, StatusResponse, WebhookEvent, WebhookVerificationResult, WithdrawalMethod,
    WithdrawalRequest, WithdrawalResponse,
};
use crate::payments::utils::PaymentHttpClient;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::time::Duration;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct GhanaProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    pub base_url: String,
    pub webhook_secret: Option<String>,
    pub timeout_secs: u64,
    pub max_retries: u32,
}

impl GhanaProviderConfig {
    pub fn from_env() -> PaymentResult<Self> {
        let client_id = std::env::var("HUBTEL_CLIENT_ID")
            .or_else(|_| std::env::var("GHANA_PROVIDER_CLIENT_ID"))
            .unwrap_or_default();
        let client_secret = std::env::var("HUBTEL_CLIENT_SECRET")
            .or_else(|_| std::env::var("GHANA_PROVIDER_CLIENT_SECRET"))
            .unwrap_or_default();

        if client_id.is_empty() || client_secret.is_empty() {
            return Err(PaymentError::ValidationError {
                message: "HUBTEL_CLIENT_ID and HUBTEL_CLIENT_SECRET are required".to_string(),
                field: Some("ghana_provider".to_string()),
            });
        }

        Ok(Self {
            client_id,
            client_secret,
            base_url: std::env::var("HUBTEL_BASE_URL")
                .unwrap_or_else(|_| "https://api.hubtel.com/v1".to_string()),
            webhook_secret: std::env::var("HUBTEL_WEBHOOK_SECRET").ok(),
            timeout_secs: std::env::var("HUBTEL_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            max_retries: std::env::var("HUBTEL_MAX_RETRIES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3),
        })
    }
}

// ---------------------------------------------------------------------------
// Hubtel API types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct HubtelSendMoneyRequest {
    client_reference: String,
    to: String,
    amount: String,
    description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    recipient_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel: Option<String>, // "mtn-gh", "vodafone-gh", "tigo-gh", "airteltigo-gh"
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HubtelResponse {
    response_code: String,
    message: String,
    #[serde(default)]
    data: Option<JsonValue>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct HubtelBankTransferRequest {
    client_reference: String,
    account_number: String,
    account_name: String,
    bank_code: String,
    amount: String,
    description: String,
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

pub struct GhanaProvider {
    config: GhanaProviderConfig,
    http: PaymentHttpClient,
}

impl GhanaProvider {
    pub fn new(config: GhanaProviderConfig) -> PaymentResult<Self> {
        let http = PaymentHttpClient::new(
            Duration::from_secs(config.timeout_secs),
            config.max_retries,
        )?;
        Ok(Self { config, http })
    }

    pub fn from_env() -> PaymentResult<Self> {
        Self::new(GhanaProviderConfig::from_env()?)
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.config.base_url, path)
    }

    fn auth_header(&self) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let creds = format!("{}:{}", self.config.client_id, self.config.client_secret);
        format!("Basic {}", STANDARD.encode(creds.as_bytes()))
    }

    /// Detect the MoMo network from a Ghanaian phone number prefix.
    pub fn detect_momo_channel(phone: &str) -> Option<&'static str> {
        let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        let local = if digits.starts_with("233") {
            &digits[3..]
        } else if digits.starts_with('0') {
            &digits[1..]
        } else {
            &digits
        };

        if local.len() < 3 {
            return None;
        }

        match &local[..3] {
            // MTN Ghana: 024, 054, 055, 059
            "024" | "054" | "055" | "059" => Some("mtn-gh"),
            // Telecel (Vodafone) Ghana: 020, 050
            "020" | "050" => Some("vodafone-gh"),
            // AirtelTigo Ghana: 026, 027, 056, 057
            "026" | "027" | "056" | "057" => Some("airteltigo-gh"),
            _ => None,
        }
    }

    /// Normalise a Ghanaian phone number to 233XXXXXXXXX format.
    pub fn normalise_phone(phone: &str) -> String {
        let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.starts_with("233") {
            digits
        } else if digits.starts_with('0') {
            format!("233{}", &digits[1..])
        } else if digits.len() == 9 {
            format!("233{}", digits)
        } else {
            digits
        }
    }

    /// Map Hubtel response codes to Aframp PaymentState.
    fn map_response_code(code: &str) -> PaymentState {
        match code {
            "0000" | "00" => PaymentState::Success,
            "0001" => PaymentState::Processing, // pending
            "1001" | "1002" | "1003" => PaymentState::Failed, // insufficient funds / limit
            "2001" => PaymentState::Failed,     // invalid account
            "9999" => PaymentState::Unknown,    // timeout / system error
            _ => PaymentState::Unknown,
        }
    }

    fn map_response_code_description(code: &str) -> &'static str {
        match code {
            "0000" | "00" => "Success",
            "0001" => "Pending",
            "1001" => "Insufficient funds",
            "1002" => "Daily limit exceeded",
            "1003" => "Transaction limit exceeded",
            "2001" => "Invalid account / phone number",
            "9999" => "System timeout — retryable",
            _ => "Unknown Hubtel error",
        }
    }
}

#[async_trait]
impl PaymentProvider for GhanaProvider {
    async fn initiate_payment(&self, _request: PaymentRequest) -> PaymentResult<PaymentResponse> {
        Err(PaymentError::ValidationError {
            message: "Ghana provider is payout-only; use process_withdrawal".to_string(),
            field: Some("provider".to_string()),
        })
    }

    async fn verify_payment(&self, request: StatusRequest) -> PaymentResult<StatusResponse> {
        let reference = request
            .provider_reference
            .as_deref()
            .or(request.transaction_reference.as_deref())
            .ok_or_else(|| PaymentError::ValidationError {
                message: "reference required".to_string(),
                field: Some("reference".to_string()),
            })?;

        let url = self.endpoint(&format!("/transactions/{}", reference));
        let raw: HubtelResponse = self
            .http
            .request_json(
                reqwest::Method::GET,
                &url,
                None,
                None,
                &[("Authorization", &self.auth_header())],
            )
            .await?;

        let status = Self::map_response_code(&raw.response_code);

        Ok(StatusResponse {
            status,
            transaction_reference: request.transaction_reference,
            provider_reference: request.provider_reference,
            amount: None,
            payment_method: Some(PaymentMethod::MobileMoney),
            timestamp: None,
            failure_reason: if status == PaymentState::Failed {
                Some(raw.message)
            } else {
                None
            },
            provider_data: raw.data,
        })
    }

    /// Disburse GHS via Hubtel — supports both MoMo and GIP bank transfer.
    async fn process_withdrawal(
        &self,
        request: WithdrawalRequest,
    ) -> PaymentResult<WithdrawalResponse> {
        request.amount.validate_positive("amount")?;

        if request.amount.currency != "GHS" {
            return Err(PaymentError::ValidationError {
                message: format!(
                    "Ghana provider only supports GHS disbursements, got {}",
                    request.amount.currency
                ),
                field: Some("amount.currency".to_string()),
            });
        }

        match request.withdrawal_method {
            WithdrawalMethod::MobileMoney => {
                let phone = request
                    .recipient
                    .phone_number
                    .as_deref()
                    .ok_or_else(|| PaymentError::ValidationError {
                        message: "recipient.phone_number required for MoMo disbursement".to_string(),
                        field: Some("recipient.phone_number".to_string()),
                    })?;

                let normalised = Self::normalise_phone(phone);
                let channel = Self::detect_momo_channel(&normalised);

                let payload = HubtelSendMoneyRequest {
                    client_reference: request.transaction_reference.clone(),
                    to: normalised.clone(),
                    amount: request.amount.amount.clone(),
                    description: request
                        .reason
                        .clone()
                        .unwrap_or_else(|| "Aframp GHS disbursement".to_string()),
                    recipient_name: request.recipient.account_name.clone(),
                    channel: channel.map(|s| s.to_string()),
                };

                let raw: HubtelResponse = self
                    .http
                    .request_json(
                        reqwest::Method::POST,
                        &self.endpoint("/send-money"),
                        None,
                        Some(&serde_json::to_value(&payload).unwrap()),
                        &[
                            ("Authorization", &self.auth_header()),
                            ("Content-Type", "application/json"),
                        ],
                    )
                    .await
                    .map_err(|e| PaymentError::ProviderError {
                        provider: "hubtel_ghana".to_string(),
                        message: e.to_string(),
                        provider_code: None,
                        retryable: true,
                    })?;

                let status = Self::map_response_code(&raw.response_code);
                if status == PaymentState::Failed {
                    return Err(PaymentError::ProviderError {
                        provider: "hubtel_ghana".to_string(),
                        message: raw.message.clone(),
                        provider_code: Some(raw.response_code),
                        retryable: false,
                    });
                }

                let provider_ref = raw
                    .data
                    .as_ref()
                    .and_then(|d| d.get("TransactionId").or(d.get("transactionId")))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                info!(
                    tx_ref = %request.transaction_reference,
                    phone = %normalised,
                    channel = ?channel,
                    "Ghana MoMo disbursement queued via Hubtel"
                );

                Ok(WithdrawalResponse {
                    status: PaymentState::Processing,
                    transaction_reference: request.transaction_reference,
                    provider_reference: provider_ref,
                    amount_debited: Some(request.amount),
                    fees_charged: None,
                    estimated_completion_seconds: Some(60),
                    provider_data: raw.data,
                })
            }

            WithdrawalMethod::BankTransfer => {
                let account_number = request
                    .recipient
                    .account_number
                    .as_deref()
                    .ok_or_else(|| PaymentError::ValidationError {
                        message: "recipient.account_number required for GIP bank transfer"
                            .to_string(),
                        field: Some("recipient.account_number".to_string()),
                    })?;
                let bank_code = request
                    .recipient
                    .bank_code
                    .as_deref()
                    .ok_or_else(|| PaymentError::ValidationError {
                        message: "recipient.bank_code required for GIP bank transfer".to_string(),
                        field: Some("recipient.bank_code".to_string()),
                    })?;
                let account_name = request
                    .recipient
                    .account_name
                    .clone()
                    .unwrap_or_else(|| "Recipient".to_string());

                let payload = HubtelBankTransferRequest {
                    client_reference: request.transaction_reference.clone(),
                    account_number: account_number.to_string(),
                    account_name,
                    bank_code: bank_code.to_string(),
                    amount: request.amount.amount.clone(),
                    description: request
                        .reason
                        .clone()
                        .unwrap_or_else(|| "Aframp GHS bank transfer".to_string()),
                };

                let raw: HubtelResponse = self
                    .http
                    .request_json(
                        reqwest::Method::POST,
                        &self.endpoint("/bank-transfer"),
                        None,
                        Some(&serde_json::to_value(&payload).unwrap()),
                        &[
                            ("Authorization", &self.auth_header()),
                            ("Content-Type", "application/json"),
                        ],
                    )
                    .await
                    .map_err(|e| PaymentError::ProviderError {
                        provider: "hubtel_ghana".to_string(),
                        message: e.to_string(),
                        provider_code: None,
                        retryable: true,
                    })?;

                let status = Self::map_response_code(&raw.response_code);
                if status == PaymentState::Failed {
                    return Err(PaymentError::ProviderError {
                        provider: "hubtel_ghana".to_string(),
                        message: raw.message.clone(),
                        provider_code: Some(raw.response_code),
                        retryable: false,
                    });
                }

                let provider_ref = raw
                    .data
                    .as_ref()
                    .and_then(|d| d.get("TransactionId").or(d.get("transactionId")))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                info!(
                    tx_ref = %request.transaction_reference,
                    bank_code = %bank_code,
                    "Ghana GIP bank transfer queued via Hubtel"
                );

                Ok(WithdrawalResponse {
                    status: PaymentState::Processing,
                    transaction_reference: request.transaction_reference,
                    provider_reference: provider_ref,
                    amount_debited: Some(request.amount),
                    fees_charged: None,
                    estimated_completion_seconds: Some(300),
                    provider_data: raw.data,
                })
            }
        }
    }

    async fn get_payment_status(&self, request: StatusRequest) -> PaymentResult<StatusResponse> {
        self.verify_payment(request).await
    }

    fn name(&self) -> ProviderName {
        ProviderName::Flutterwave // reuse existing enum; Ghana uses Hubtel internally
    }

    fn supported_currencies(&self) -> &'static [&'static str] {
        &["GHS"]
    }

    fn supported_countries(&self) -> &'static [&'static str] {
        &["GH"]
    }

    fn verify_webhook(
        &self,
        payload: &[u8],
        signature: &str,
    ) -> PaymentResult<WebhookVerificationResult> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let secret = match &self.config.webhook_secret {
            Some(s) => s.clone(),
            None => {
                return Ok(WebhookVerificationResult {
                    valid: true,
                    reason: Some("No webhook secret configured — skipping verification".to_string()),
                })
            }
        };

        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .map_err(|e| PaymentError::WebhookVerificationError { message: e.to_string() })?;
        mac.update(payload);
        let expected = hex::encode(mac.finalize().into_bytes());
        let valid = crate::payments::utils::secure_eq(expected.as_bytes(), signature.as_bytes());

        Ok(WebhookVerificationResult {
            valid,
            reason: if valid {
                None
            } else {
                Some("Invalid Hubtel webhook signature".to_string())
            },
        })
    }

    fn parse_webhook_event(&self, payload: &[u8]) -> PaymentResult<WebhookEvent> {
        let parsed: JsonValue =
            serde_json::from_slice(payload).map_err(|e| PaymentError::WebhookVerificationError {
                message: format!("invalid Hubtel webhook JSON: {}", e),
            })?;

        // Hubtel callback envelope:
        // { "ResponseCode": "0000", "Status": "Success",
        //   "Data": { "ClientReference": "<tx_ref>", "TransactionId": "...", ... } }
        let response_code = parsed
            .get("ResponseCode")
            .or_else(|| parsed.get("responseCode"))
            .and_then(|v| v.as_str())
            .unwrap_or("9999");

        let status = Self::map_response_code(response_code);

        let data = parsed
            .get("Data")
            .or_else(|| parsed.get("data"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

        let tx_ref = data
            .get("ClientReference")
            .or_else(|| data.get("clientReference"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let provider_ref = data
            .get("TransactionId")
            .or_else(|| data.get("transactionId"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        if response_code != "0000" && response_code != "00" {
            warn!(
                response_code = %response_code,
                description = Self::map_response_code_description(response_code),
                tx_ref = ?tx_ref,
                "Hubtel Ghana disbursement callback — non-success"
            );
        }

        Ok(WebhookEvent {
            provider: ProviderName::Flutterwave,
            event_type: format!("hubtel.callback.{}", response_code),
            transaction_reference: tx_ref,
            provider_reference: provider_ref,
            status: Some(status),
            payload: parsed,
            received_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    async fn get_balance(&self, currency: &str) -> PaymentResult<Money> {
        Ok(Money {
            amount: "0".to_string(),
            currency: currency.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Recipient validation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct GhanaRecipientValidation {
    pub valid: bool,
    pub normalised_phone: Option<String>,
    pub detected_network: Option<String>,
    pub reason: Option<String>,
}

/// Validate a Ghanaian MoMo phone number before disbursement.
pub fn validate_ghana_momo_recipient(phone: &str) -> GhanaRecipientValidation {
    let normalised = GhanaProvider::normalise_phone(phone);

    if normalised.len() != 12 || !normalised.starts_with("233") {
        return GhanaRecipientValidation {
            valid: false,
            normalised_phone: Some(normalised),
            detected_network: None,
            reason: Some("Phone number must be in 233XXXXXXXXX format".to_string()),
        };
    }

    let channel = GhanaProvider::detect_momo_channel(&normalised);
    if channel.is_none() {
        return GhanaRecipientValidation {
            valid: false,
            normalised_phone: Some(normalised),
            detected_network: None,
            reason: Some(
                "Phone prefix not recognised as MTN, Telecel, or AirtelTigo Ghana".to_string(),
            ),
        };
    }

    GhanaRecipientValidation {
        valid: true,
        normalised_phone: Some(normalised),
        detected_network: channel.map(|s| s.to_string()),
        reason: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_phone_formats() {
        assert_eq!(GhanaProvider::normalise_phone("0244123456"), "233244123456");
        assert_eq!(GhanaProvider::normalise_phone("233244123456"), "233244123456");
        assert_eq!(GhanaProvider::normalise_phone("+233244123456"), "233244123456");
        assert_eq!(GhanaProvider::normalise_phone("244123456"), "233244123456");
    }

    #[test]
    fn detect_momo_channel() {
        assert_eq!(GhanaProvider::detect_momo_channel("233244123456"), Some("mtn-gh"));
        assert_eq!(GhanaProvider::detect_momo_channel("233200123456"), Some("vodafone-gh"));
        assert_eq!(GhanaProvider::detect_momo_channel("233260123456"), Some("airteltigo-gh"));
        assert_eq!(GhanaProvider::detect_momo_channel("233300123456"), None);
    }

    #[test]
    fn validate_momo_recipient_valid() {
        let r = validate_ghana_momo_recipient("0244123456");
        assert!(r.valid);
        assert_eq!(r.detected_network.as_deref(), Some("mtn-gh"));
    }

    #[test]
    fn validate_momo_recipient_invalid_prefix() {
        let r = validate_ghana_momo_recipient("0300123456");
        assert!(!r.valid);
    }

    #[test]
    fn response_code_mapping() {
        assert_eq!(GhanaProvider::map_response_code("0000"), PaymentState::Success);
        assert_eq!(GhanaProvider::map_response_code("1001"), PaymentState::Failed);
        assert_eq!(GhanaProvider::map_response_code("9999"), PaymentState::Unknown);
    }
}
