//! Ghana corridor service — orchestrates the full NG→GH transfer flow.

use crate::compliance_registry::repository::ComplianceRegistryRepository;
use crate::corridors::ghana::models::*;
use crate::payments::providers::ghana::{
    validate_ghana_momo_recipient, GhanaProvider, GhanaProviderConfig,
};
use crate::payments::provider::PaymentProvider;
use crate::payments::types::{Money, WithdrawalMethod, WithdrawalRecipient, WithdrawalRequest};
use crate::services::exchange_rate::ExchangeRateService;
use crate::services::fee_calculation::FeeCalculationService;
use chrono::Utc;
use rust_decimal::Decimal;
use sqlx::PgPool;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum GhanaCorridorError {
    #[error("compliance check failed: {0}")]
    ComplianceDenied(String),

    #[error("recipient validation failed: {0}")]
    RecipientInvalid(String),

    #[error("FX rate unavailable: {0}")]
    FxUnavailable(String),

    #[error("transaction limit exceeded: {0}")]
    LimitExceeded(String),

    #[error("BoG requirement not met: {0}")]
    BogRequirement(String),

    #[error("disbursement failed: {0}")]
    DisbursementFailed(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("internal error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

pub struct GhanaCorridorService {
    pool: PgPool,
    compliance_repo: Arc<ComplianceRegistryRepository>,
    exchange_rate_svc: Arc<ExchangeRateService>,
    #[allow(dead_code)]
    fee_svc: Arc<FeeCalculationService>,
    provider_config: GhanaProviderConfig,
    corridor_id: Uuid,
}

impl GhanaCorridorService {
    pub fn new(
        pool: PgPool,
        compliance_repo: Arc<ComplianceRegistryRepository>,
        exchange_rate_svc: Arc<ExchangeRateService>,
        fee_svc: Arc<FeeCalculationService>,
        provider_config: GhanaProviderConfig,
        corridor_id: Uuid,
    ) -> Self {
        Self {
            pool,
            compliance_repo,
            exchange_rate_svc,
            fee_svc,
            provider_config,
            corridor_id,
        }
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    pub async fn get_quote(
        &self,
        cngn_amount: Decimal,
    ) -> Result<GhanaTransferQuote, GhanaCorridorError> {
        let (rate, ghs_gross, fee_breakdown) = self.calculate_ghs_output(cngn_amount).await?;
        let ghs_net = ghs_gross - fee_breakdown.total_fee_ghs;

        Ok(GhanaTransferQuote {
            quote_id: Uuid::new_v4(),
            cngn_amount,
            ngn_equivalent: cngn_amount,
            ngn_ghs_rate: rate,
            ghs_gross,
            corridor_fee_ghs: fee_breakdown.total_fee_ghs,
            ghs_net,
            fee_breakdown,
            expires_at: Utc::now() + chrono::Duration::seconds(300),
        })
    }

    pub async fn initiate_transfer(
        &self,
        req: &GhanaTransferRequest,
    ) -> Result<GhanaTransferResponse, GhanaCorridorError> {
        // 1. Compliance gate.
        let compliance = self
            .compliance_repo
            .check_compliance(self.corridor_id, req.cngn_amount, "NGN")
            .await
            .map_err(|e| GhanaCorridorError::Database(e.to_string()))?;

        if !compliance.allowed {
            return Err(GhanaCorridorError::ComplianceDenied(
                compliance.denial_reason.unwrap_or_else(|| "Compliance check failed".to_string()),
            ));
        }

        // 2. FX + fee calculation.
        let (rate, ghs_gross, fee_breakdown) =
            self.calculate_ghs_output(req.cngn_amount).await?;
        let ghs_net = ghs_gross - fee_breakdown.total_fee_ghs;

        // 3. BoG limits + Ghana Card requirement.
        self.enforce_limits(ghs_net, req)?;

        // 4. Recipient validation.
        let (recipient_validated, detected_network) = self.validate_recipient(req)?;

        // 5. Quote snapshot.
        let quote = GhanaTransferQuote {
            quote_id: Uuid::new_v4(),
            cngn_amount: req.cngn_amount,
            ngn_equivalent: req.cngn_amount,
            ngn_ghs_rate: rate,
            ghs_gross,
            corridor_fee_ghs: fee_breakdown.total_fee_ghs,
            ghs_net,
            fee_breakdown,
            expires_at: Utc::now() + chrono::Duration::seconds(300),
        };

        // 6. Persist.
        let transfer_id = Uuid::new_v4();
        self.persist_transfer(transfer_id, req, &quote).await?;

        // 7. Compliance tag.
        let compliance_tag = self
            .compliance_repo
            .tag_transaction(
                transfer_id,
                self.corridor_id,
                compliance.license_id,
                compliance.ruleset_id,
            )
            .await
            .map_err(|e| GhanaCorridorError::Database(e.to_string()))?;

        // 8. Disburse GHS.
        let disburse_result = self.disburse_ghs(transfer_id, req, &quote).await;

        match disburse_result {
            Ok(provider_ref) => {
                self.update_status(
                    transfer_id,
                    GhanaTransferStatus::DisbursementPending,
                    Some(provider_ref),
                    None,
                )
                .await?;

                info!(
                    transfer_id = %transfer_id,
                    ghs_net = %ghs_net,
                    "Ghana corridor disbursement queued"
                );

                Ok(GhanaTransferResponse {
                    transfer_id,
                    status: GhanaTransferStatus::DisbursementPending,
                    quote,
                    recipient_validated,
                    detected_network,
                    compliance_tag_id: Some(compliance_tag.id),
                    created_at: Utc::now(),
                    message: "GHS disbursement queued via Hubtel".to_string(),
                })
            }
            Err(e) => {
                error!(
                    transfer_id = %transfer_id,
                    error = %e,
                    "Ghana corridor disbursement failed — initiating cNGN refund"
                );

                self.update_status(
                    transfer_id,
                    GhanaTransferStatus::RefundInitiated,
                    None,
                    Some(e.to_string()),
                )
                .await?;

                let _ = self.initiate_cngn_refund(transfer_id, req).await;

                Err(GhanaCorridorError::DisbursementFailed(e.to_string()))
            }
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    async fn calculate_ghs_output(
        &self,
        cngn_amount: Decimal,
    ) -> Result<(Decimal, Decimal, GhanaFeeBreakdown), GhanaCorridorError> {
        let rate_bd = self
            .exchange_rate_svc
            .get_rate("NGN", "GHS")
            .await
            .map_err(|e| GhanaCorridorError::FxUnavailable(e.to_string()))?;

        let rate = Decimal::from_str(&rate_bd.to_string())
            .map_err(|e| GhanaCorridorError::Internal(e.to_string()))?;

        let ghs_gross = cngn_amount * rate;

        // Platform fee: 1.5%
        let platform_fee_bps: u32 = 150;
        let platform_fee_ghs = ghs_gross * Decimal::new(platform_fee_bps as i64, 4);

        // Hubtel flat fee: GHS 0.50
        let provider_fee_ghs = Decimal::new(50, 2);

        // Ghana E-Levy: 1% on gross (GRA Act 1075, 2022)
        let e_levy_rate = e_levy_rate();
        let e_levy_ghs = ghs_gross * e_levy_rate;

        let total_fee_ghs = platform_fee_ghs + provider_fee_ghs + e_levy_ghs;

        Ok((
            rate,
            ghs_gross,
            GhanaFeeBreakdown {
                platform_fee_bps,
                platform_fee_ghs,
                provider_fee_ghs,
                e_levy_ghs,
                e_levy_rate,
                total_fee_ghs,
            },
        ))
    }

    fn enforce_limits(
        &self,
        ghs_net: Decimal,
        req: &GhanaTransferRequest,
    ) -> Result<(), GhanaCorridorError> {
        // BoG MoMo single-transaction cap: GHS 10,000.
        let bog_cap = bog_max_single_txn_ghs();
        if ghs_net > bog_cap {
            return Err(GhanaCorridorError::LimitExceeded(format!(
                "GHS {ghs_net} exceeds BoG single-transaction limit of GHS 10,000"
            )));
        }

        // Ghana Card required for transfers ≥ GHS 1,000.
        let card_threshold = bog_ghana_card_threshold_ghs();
        if ghs_net >= card_threshold && req.recipient_ghana_card.is_none() {
            return Err(GhanaCorridorError::BogRequirement(
                "Recipient Ghana Card number is required for transfers of GHS 1,000 or more (BoG regulation)".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_recipient(
        &self,
        req: &GhanaTransferRequest,
    ) -> Result<(bool, Option<String>), GhanaCorridorError> {
        if let Some(phone) = &req.recipient_phone {
            let result = validate_ghana_momo_recipient(phone);
            if !result.valid {
                return Err(GhanaCorridorError::RecipientInvalid(
                    result.reason.unwrap_or_else(|| "Phone validation failed".to_string()),
                ));
            }
            return Ok((true, result.detected_network));
        }

        if req.recipient_bank.is_some() {
            return Ok((true, None));
        }

        Err(GhanaCorridorError::RecipientInvalid(
            "Either recipient_phone or recipient_bank must be provided".to_string(),
        ))
    }

    async fn disburse_ghs(
        &self,
        transfer_id: Uuid,
        req: &GhanaTransferRequest,
        quote: &GhanaTransferQuote,
    ) -> Result<String, GhanaCorridorError> {
        let provider = GhanaProvider::new(self.provider_config.clone())
            .map_err(|e| GhanaCorridorError::Internal(e.to_string()))?;

        let (withdrawal_method, recipient) = if let Some(phone) = &req.recipient_phone {
            (
                WithdrawalMethod::MobileMoney,
                WithdrawalRecipient {
                    account_name: Some(req.recipient_name.clone()),
                    account_number: None,
                    bank_code: None,
                    phone_number: Some(phone.clone()),
                },
            )
        } else if let Some(bank) = &req.recipient_bank {
            (
                WithdrawalMethod::BankTransfer,
                WithdrawalRecipient {
                    account_name: Some(bank.account_name.clone()),
                    account_number: Some(bank.account_number.clone()),
                    bank_code: Some(bank.bank_code.clone()),
                    phone_number: None,
                },
            )
        } else {
            return Err(GhanaCorridorError::Internal(
                "No recipient details for disbursement".to_string(),
            ));
        };

        let wd_req = WithdrawalRequest {
            amount: Money {
                amount: quote.ghs_net.to_string(),
                currency: "GHS".to_string(),
            },
            recipient,
            withdrawal_method,
            transaction_reference: transfer_id.to_string(),
            reason: req.purpose.clone(),
            metadata: Some(serde_json::json!({
                "corridor": "NG-GH",
                "sender_wallet": req.sender_wallet,
                "recipient_ghana_card": req.recipient_ghana_card,
                "bog_reference": format!("BOG-{}", transfer_id),
                "e_levy_ghs": quote.fee_breakdown.e_levy_ghs.to_string(),
            })),
        };

        let resp = provider
            .process_withdrawal(wd_req)
            .await
            .map_err(|e| GhanaCorridorError::DisbursementFailed(e.to_string()))?;

        Ok(resp.provider_reference.unwrap_or_else(|| transfer_id.to_string()))
    }

    async fn persist_transfer(
        &self,
        transfer_id: Uuid,
        req: &GhanaTransferRequest,
        quote: &GhanaTransferQuote,
    ) -> Result<(), GhanaCorridorError> {
        let metadata = serde_json::json!({
            "corridor": "NG-GH",
            "idempotency_key": req.idempotency_key,
            "recipient_phone": req.recipient_phone,
            "recipient_bank": req.recipient_bank,
            "recipient_ghana_card": req.recipient_ghana_card,
            "purpose": req.purpose,
            "ngn_ghs_rate": quote.ngn_ghs_rate.to_string(),
            "ghs_gross": quote.ghs_gross.to_string(),
            "e_levy_ghs": quote.fee_breakdown.e_levy_ghs.to_string(),
            "corridor_fee_ghs": quote.corridor_fee_ghs.to_string(),
            "ghs_net": quote.ghs_net.to_string(),
            "bog_reference": format!("BOG-{}", transfer_id),
        });

        sqlx::query!(
            r#"
            INSERT INTO transactions (
                transaction_id, wallet_address, type,
                from_currency, to_currency,
                from_amount, to_amount,
                status, metadata, created_at, updated_at
            ) VALUES (
                $1, $2, 'ghana_corridor',
                'cNGN', 'GHS',
                $3, $4,
                'pending_cngn', $5, NOW(), NOW()
            )
            ON CONFLICT (transaction_id) DO NOTHING
            "#,
            transfer_id,
            req.sender_wallet,
            req.cngn_amount as Decimal,
            quote.ghs_net as Decimal,
            metadata,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| GhanaCorridorError::Database(e.to_string()))?;

        Ok(())
    }

    async fn update_status(
        &self,
        transfer_id: Uuid,
        status: GhanaTransferStatus,
        provider_reference: Option<String>,
        error_message: Option<String>,
    ) -> Result<(), GhanaCorridorError> {
        sqlx::query!(
            r#"
            UPDATE transactions
            SET status = $2,
                payment_reference = COALESCE($3, payment_reference),
                error_message = COALESCE($4, error_message),
                updated_at = NOW()
            WHERE transaction_id = $1
            "#,
            transfer_id,
            status.as_str(),
            provider_reference,
            error_message,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| GhanaCorridorError::Database(e.to_string()))?;

        Ok(())
    }

    async fn initiate_cngn_refund(
        &self,
        transfer_id: Uuid,
        req: &GhanaTransferRequest,
    ) -> Result<(), GhanaCorridorError> {
        warn!(
            transfer_id = %transfer_id,
            sender_wallet = %req.sender_wallet,
            cngn_amount = %req.cngn_amount,
            "Initiating cNGN refund for failed Ghana corridor transfer"
        );

        sqlx::query!(
            r#"
            UPDATE transactions
            SET status = 'refund_initiated',
                metadata = metadata || $2::jsonb,
                updated_at = NOW()
            WHERE transaction_id = $1
            "#,
            transfer_id,
            serde_json::json!({ "refund_reason": "ghana_disbursement_failed" }),
        )
        .execute(&self.pool)
        .await
        .map_err(|e| GhanaCorridorError::Database(e.to_string()))?;

        Ok(())
    }
}
