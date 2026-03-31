//! Hubtel Ghana webhook handler — maps Hubtel callback codes to Aframp states
//! and triggers cNGN refunds on disbursement failure.

use crate::corridors::ghana::models::GhanaTransferStatus;
use crate::payments::providers::ghana::GhanaProvider;
use crate::payments::provider::PaymentProvider;
use crate::payments::types::PaymentState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

pub struct GhanaWebhookState {
    pub pool: Arc<PgPool>,
    pub provider: Arc<GhanaProvider>,
}

/// POST /webhooks/hubtel_ghana
pub async fn handle_hubtel_ghana_webhook(
    State(state): State<Arc<GhanaWebhookState>>,
    body: String,
) -> impl IntoResponse {
    let event = match state.provider.parse_webhook_event(body.as_bytes()) {
        Ok(e) => e,
        Err(e) => {
            error!(error = %e, "Failed to parse Hubtel Ghana webhook");
            return (StatusCode::OK, Json(serde_json::json!({"status":"ok"}))).into_response();
        }
    };

    let tx_ref = match &event.transaction_reference {
        Some(r) => r.clone(),
        None => {
            warn!("Hubtel Ghana webhook missing ClientReference");
            return (StatusCode::OK, Json(serde_json::json!({"status":"ok"}))).into_response();
        }
    };

    let transfer_id = match Uuid::parse_str(&tx_ref) {
        Ok(id) => id,
        Err(_) => {
            warn!(tx_ref = %tx_ref, "Hubtel Ghana webhook tx_ref is not a UUID");
            return (StatusCode::OK, Json(serde_json::json!({"status":"ok"}))).into_response();
        }
    };

    let new_status = match event.status {
        Some(PaymentState::Success) => GhanaTransferStatus::Completed,
        Some(PaymentState::Failed) => GhanaTransferStatus::RefundInitiated,
        Some(PaymentState::Unknown) => {
            warn!(transfer_id = %transfer_id, "Hubtel Ghana timeout — leaving as disbursement_pending");
            return (StatusCode::OK, Json(serde_json::json!({"status":"ok"}))).into_response();
        }
        _ => {
            warn!(transfer_id = %transfer_id, "Hubtel Ghana webhook unknown status");
            return (StatusCode::OK, Json(serde_json::json!({"status":"ok"}))).into_response();
        }
    };

    let result = sqlx::query!(
        r#"
        UPDATE transactions
        SET status = $2,
            payment_reference = COALESCE($3, payment_reference),
            metadata = metadata || $4::jsonb,
            updated_at = NOW()
        WHERE transaction_id = $1
          AND type = 'ghana_corridor'
        "#,
        transfer_id,
        new_status.as_str(),
        event.provider_reference,
        serde_json::json!({
            "hubtel_event_type": event.event_type,
            "hubtel_provider_ref": event.provider_reference,
        }),
    )
    .execute(state.pool.as_ref())
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            info!(
                transfer_id = %transfer_id,
                status = %new_status.as_str(),
                "Ghana corridor transfer updated from Hubtel webhook"
            );

            if new_status == GhanaTransferStatus::RefundInitiated {
                let _ = sqlx::query!(
                    r#"
                    UPDATE transactions
                    SET metadata = metadata || $2::jsonb
                    WHERE transaction_id = $1
                    "#,
                    transfer_id,
                    serde_json::json!({ "refund_reason": "hubtel_disbursement_failed" }),
                )
                .execute(state.pool.as_ref())
                .await;

                warn!(transfer_id = %transfer_id, "Hubtel disbursement failed — cNGN refund queued");
            }
        }
        Ok(_) => warn!(transfer_id = %transfer_id, "Hubtel Ghana webhook: no matching transfer"),
        Err(e) => error!(transfer_id = %transfer_id, error = %e, "Failed to update from Hubtel webhook"),
    }

    (StatusCode::OK, Json(serde_json::json!({"status":"ok"}))).into_response()
}
