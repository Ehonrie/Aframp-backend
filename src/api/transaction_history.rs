//! Transaction history endpoint
//!
//! GET  /api/transactions         — paginated history with filtering & sorting
//! GET  /api/transactions/export  — CSV export of filtered history

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{types::BigDecimal, FromRow, PgPool};
use std::sync::Arc;
use tracing::{debug, error};
use uuid::Uuid;

use crate::cache::cache::{Cache as CacheTrait, RedisCache};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_PAGE_SIZE: i64 = 20;
const MAX_PAGE_SIZE: i64 = 100;
const MAX_DATE_RANGE_DAYS: i64 = 365;
const MAX_EXPORT_ROWS: i64 = 10_000;
/// Redis TTL for paginated history responses (30 seconds)
const HISTORY_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(30);

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TransactionHistoryState {
    pub pool: Arc<PgPool>,
    pub cache: Option<Arc<RedisCache>>,
}

// ---------------------------------------------------------------------------
// Cursor
// ---------------------------------------------------------------------------

/// Opaque cursor encodes (created_at, transaction_id) for stable keyset pagination.
#[derive(Debug, Serialize, Deserialize)]
struct CursorPayload {
    pub created_at: DateTime<Utc>,
    pub id: Uuid,
}

fn encode_cursor(created_at: DateTime<Utc>, id: Uuid) -> String {
    let payload = CursorPayload { created_at, id };
    let json = serde_json::to_vec(&payload).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(&json)
}

fn decode_cursor(cursor: &str) -> Option<CursorPayload> {
    let bytes = URL_SAFE_NO_PAD.decode(cursor).ok()?;
    serde_json::from_slice(&bytes).ok()
}

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    /// Wallet address — enforces ownership
    pub wallet_address: String,
    /// Opaque cursor from previous response
    pub cursor: Option<String>,
    /// Page size (1–100, default 20)
    pub limit: Option<i64>,
    /// Filter: onramp | offramp | bill_payment
    pub tx_type: Option<String>,
    /// Filter: pending | processing | completed | failed | refunded
    pub status: Option<String>,
    /// Filter: ISO-8601 start date
    pub date_from: Option<DateTime<Utc>>,
    /// Filter: ISO-8601 end date
    pub date_to: Option<DateTime<Utc>>,
    /// Filter: from_currency
    pub from_currency: Option<String>,
    /// Filter: to_currency
    pub to_currency: Option<String>,
    /// Sort: created_asc | created_desc | amount_asc | amount_desc (default: created_desc)
    pub sort: Option<String>,
}

// ---------------------------------------------------------------------------
// DB row
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, FromRow)]
struct TxRow {
    pub transaction_id: Uuid,
    pub wallet_address: String,
    pub r#type: String,
    pub from_currency: String,
    pub to_currency: String,
    pub from_amount: BigDecimal,
    pub to_amount: BigDecimal,
    pub cngn_amount: BigDecimal,
    pub status: String,
    pub payment_provider: Option<String>,
    pub payment_reference: Option<String>,
    pub blockchain_tx_hash: Option<String>,
    pub error_message: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Clone)]
pub struct TransactionRecord {
    pub id: String,
    pub wallet_address: String,
    pub tx_type: String,
    pub from_currency: String,
    pub to_currency: String,
    pub from_amount: String,
    pub to_amount: String,
    pub cngn_amount: String,
    pub status: String,
    pub payment_provider: Option<String>,
    pub payment_reference: Option<String>,
    pub blockchain_tx_hash: Option<String>,
    pub error_message: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Clone)]
pub struct HistoryResponse {
    pub data: Vec<TransactionRecord>,
    pub total: i64,
    pub next_cursor: Option<String>,
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    pub code: String,
    pub message: String,
}

fn err(status: StatusCode, code: &str, msg: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorBody {
            code: code.to_string(),
            message: msg.into(),
        }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

fn map_row(r: TxRow) -> TransactionRecord {
    TransactionRecord {
        id: r.transaction_id.to_string(),
        wallet_address: r.wallet_address,
        tx_type: r.r#type,
        from_currency: r.from_currency,
        to_currency: r.to_currency,
        from_amount: r.from_amount.to_string(),
        to_amount: r.to_amount.to_string(),
        cngn_amount: r.cngn_amount.to_string(),
        status: r.status,
        payment_provider: r.payment_provider,
        payment_reference: r.payment_reference,
        blockchain_tx_hash: r.blockchain_tx_hash,
        error_message: r.error_message,
        metadata: r.metadata,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn validate_query(q: &HistoryQuery) -> Result<i64, Response> {
    let limit = q.limit.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);

    if let Some(ref t) = q.tx_type {
        if !["onramp", "offramp", "bill_payment"].contains(&t.as_str()) {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "INVALID_TYPE",
                "tx_type must be onramp, offramp, or bill_payment",
            ));
        }
    }

    if let Some(ref s) = q.status {
        if !["pending", "processing", "completed", "failed", "refunded"].contains(&s.as_str()) {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "INVALID_STATUS",
                "status must be pending, processing, completed, failed, or refunded",
            ));
        }
    }

    if let (Some(from), Some(to)) = (q.date_from, q.date_to) {
        if from > to {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "INVALID_DATE_RANGE",
                "date_from must be before date_to",
            ));
        }
        if (to - from) > Duration::days(MAX_DATE_RANGE_DAYS) {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "DATE_RANGE_TOO_LARGE",
                format!("date range cannot exceed {} days", MAX_DATE_RANGE_DAYS),
            ));
        }
    }

    if let Some(ref sort) = q.sort {
        if !["created_asc", "created_desc", "amount_asc", "amount_desc"].contains(&sort.as_str()) {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "INVALID_SORT",
                "sort must be created_asc, created_desc, amount_asc, or amount_desc",
            ));
        }
    }

    Ok(limit)
}

// ---------------------------------------------------------------------------
// DB query
// ---------------------------------------------------------------------------

async fn fetch_history(
    pool: &PgPool,
    q: &HistoryQuery,
    limit: i64,
    for_export: bool,
) -> Result<(Vec<TxRow>, i64), sqlx::Error> {
    let cursor_payload = q.cursor.as_deref().and_then(decode_cursor);
    let sort = q.sort.as_deref().unwrap_or("created_desc");
    let effective_limit = if for_export {
        MAX_EXPORT_ROWS + 1
    } else {
        limit + 1 // fetch one extra to detect next page
    };

    // Determine sort direction
    let (order_col, order_dir) = match sort {
        "created_asc" => ("created_at", "ASC"),
        "amount_asc" => ("from_amount", "ASC"),
        "amount_desc" => ("from_amount", "DESC"),
        _ => ("created_at", "DESC"), // created_desc default
    };

    // Build cursor condition based on sort
    let cursor_condition = if let Some(ref cp) = cursor_payload {
        match sort {
            "created_asc" => format!(
                "AND (created_at, transaction_id) > ('{}', '{}')",
                cp.created_at.to_rfc3339(),
                cp.id
            ),
            "amount_asc" | "amount_desc" => {
                // For amount sort, fall back to created_at cursor for stability
                format!(
                    "AND (created_at, transaction_id) < ('{}', '{}')",
                    cp.created_at.to_rfc3339(),
                    cp.id
                )
            }
            _ => format!(
                "AND (created_at, transaction_id) < ('{}', '{}')",
                cp.created_at.to_rfc3339(),
                cp.id
            ),
        }
    } else {
        String::new()
    };

    let rows = sqlx::query_as::<_, TxRow>(&format!(
        r#"
        SELECT transaction_id, wallet_address, type, from_currency, to_currency,
               from_amount, to_amount, cngn_amount, status, payment_provider,
               payment_reference, blockchain_tx_hash, error_message, metadata,
               created_at, updated_at
        FROM transactions
        WHERE wallet_address = $1
          {cursor}
          AND ($2::text IS NULL OR type = $2)
          AND ($3::text IS NULL OR status = $3)
          AND ($4::timestamptz IS NULL OR created_at >= $4)
          AND ($5::timestamptz IS NULL OR created_at <= $5)
          AND ($6::text IS NULL OR from_currency = $6)
          AND ($7::text IS NULL OR to_currency = $7)
        ORDER BY {col} {dir}, transaction_id {dir}
        LIMIT $8
        "#,
        cursor = cursor_condition,
        col = order_col,
        dir = order_dir,
    ))
    .bind(&q.wallet_address)
    .bind(q.tx_type.as_deref())
    .bind(q.status.as_deref())
    .bind(q.date_from)
    .bind(q.date_to)
    .bind(q.from_currency.as_deref())
    .bind(q.to_currency.as_deref())
    .bind(effective_limit)
    .fetch_all(pool)
    .await?;

    // Count query (same filters, no cursor, no limit)
    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM transactions
        WHERE wallet_address = $1
          AND ($2::text IS NULL OR type = $2)
          AND ($3::text IS NULL OR status = $3)
          AND ($4::timestamptz IS NULL OR created_at >= $4)
          AND ($5::timestamptz IS NULL OR created_at <= $5)
          AND ($6::text IS NULL OR from_currency = $6)
          AND ($7::text IS NULL OR to_currency = $7)
        "#,
    )
    .bind(&q.wallet_address)
    .bind(q.tx_type.as_deref())
    .bind(q.status.as_deref())
    .bind(q.date_from)
    .bind(q.date_to)
    .bind(q.from_currency.as_deref())
    .bind(q.to_currency.as_deref())
    .fetch_one(pool)
    .await?;

    Ok((rows, total))
}

// ---------------------------------------------------------------------------
// Cache key
// ---------------------------------------------------------------------------

fn history_cache_key(q: &HistoryQuery, limit: i64) -> String {
    format!(
        "v1:tx:history:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        q.wallet_address,
        q.cursor.as_deref().unwrap_or(""),
        limit,
        q.tx_type.as_deref().unwrap_or(""),
        q.status.as_deref().unwrap_or(""),
        q.date_from.map(|d| d.timestamp()).unwrap_or(0),
        q.date_to.map(|d| d.timestamp()).unwrap_or(0),
        q.from_currency.as_deref().unwrap_or(""),
        q.sort.as_deref().unwrap_or("created_desc"),
    )
}

// ---------------------------------------------------------------------------
// GET /api/transactions
// ---------------------------------------------------------------------------

pub async fn get_transaction_history(
    State(state): State<Arc<TransactionHistoryState>>,
    Query(q): Query<HistoryQuery>,
) -> Response {
    if q.wallet_address.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "MISSING_WALLET",
            "wallet_address is required",
        );
    }

    let limit = match validate_query(&q) {
        Ok(l) => l,
        Err(e) => return e,
    };

    let cache_key = history_cache_key(&q, limit);

    // Try cache
    if let Some(ref cache) = state.cache {
        match cache.get::<HistoryResponse>(&cache_key).await {
            Ok(Some(cached)) => {
                debug!(wallet = %q.wallet_address, "Transaction history cache hit");
                return Json(cached).into_response();
            }
            Ok(None) => {}
            Err(e) => debug!(error = %e, "Cache get error (degraded)"),
        }
    }

    let (mut rows, total) = match fetch_history(&state.pool, &q, limit, false).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "Failed to fetch transaction history");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "failed to fetch history",
            );
        }
    };

    let has_more = rows.len() as i64 > limit;
    if has_more {
        rows.truncate(limit as usize);
    }

    let next_cursor = if has_more {
        rows.last()
            .map(|r| encode_cursor(r.created_at, r.transaction_id))
    } else {
        None
    };

    let response = HistoryResponse {
        total,
        next_cursor,
        truncated: false,
        data: rows.into_iter().map(map_row).collect(),
    };

    // Populate cache
    if let Some(ref cache) = state.cache {
        if let Err(e) = cache
            .set(&cache_key, &response, Some(HISTORY_CACHE_TTL))
            .await
        {
            debug!(error = %e, "Cache set error (degraded)");
        }
    }

    Json(response).into_response()
}

// ---------------------------------------------------------------------------
// GET /api/transactions/export
// ---------------------------------------------------------------------------

pub async fn export_transaction_history(
    State(state): State<Arc<TransactionHistoryState>>,
    Query(q): Query<HistoryQuery>,
) -> Response {
    if q.wallet_address.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "MISSING_WALLET",
            "wallet_address is required",
        );
    }

    let limit = match validate_query(&q) {
        Ok(l) => l,
        Err(e) => return e,
    };

    let (mut rows, _total) = match fetch_history(&state.pool, &q, limit, true).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "Failed to fetch transactions for export");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "failed to fetch transactions",
            );
        }
    };

    let truncated = rows.len() as i64 > MAX_EXPORT_ROWS;
    if truncated {
        rows.truncate(MAX_EXPORT_ROWS as usize);
    }

    // Build CSV
    let mut wtr = csv::Writer::from_writer(vec![]);

    // Header
    wtr.write_record(&[
        "id",
        "type",
        "status",
        "from_currency",
        "to_currency",
        "from_amount",
        "to_amount",
        "cngn_amount",
        "payment_provider",
        "payment_reference",
        "blockchain_tx_hash",
        "created_at",
        "updated_at",
    ])
    .ok();

    for row in &rows {
        wtr.write_record(&[
            row.transaction_id.to_string(),
            row.r#type.clone(),
            row.status.clone(),
            row.from_currency.clone(),
            row.to_currency.clone(),
            row.from_amount.to_string(),
            row.to_amount.to_string(),
            row.cngn_amount.to_string(),
            row.payment_provider.clone().unwrap_or_default(),
            row.payment_reference.clone().unwrap_or_default(),
            row.blockchain_tx_hash.clone().unwrap_or_default(),
            row.created_at.to_rfc3339(),
            row.updated_at.to_rfc3339(),
        ])
        .ok();
    }

    let csv_bytes = wtr.into_inner().unwrap_or_default();

    let truncation_note = if truncated {
        format!(
            "; truncated=true; max_rows={}",
            MAX_EXPORT_ROWS
        )
    } else {
        String::new()
    };

    let disposition = format!(
        "attachment; filename=\"transactions_{}.csv\"{}",
        q.wallet_address, truncation_note
    );

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                disposition.as_str(),
            ),
        ],
        csv_bytes,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_cursor_roundtrip() {
        let ts = Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();
        let id = Uuid::new_v4();
        let encoded = encode_cursor(ts, id);
        let decoded = decode_cursor(&encoded).unwrap();
        assert_eq!(decoded.created_at, ts);
        assert_eq!(decoded.id, id);
    }

    #[test]
    fn test_cursor_invalid_base64() {
        assert!(decode_cursor("not-valid-base64!!!").is_none());
    }

    #[test]
    fn test_cursor_invalid_json() {
        let bad = URL_SAFE_NO_PAD.encode(b"not json");
        assert!(decode_cursor(&bad).is_none());
    }

    #[test]
    fn test_validate_query_defaults() {
        let q = HistoryQuery {
            wallet_address: "GTEST".to_string(),
            cursor: None,
            limit: None,
            tx_type: None,
            status: None,
            date_from: None,
            date_to: None,
            from_currency: None,
            to_currency: None,
            sort: None,
        };
        let limit = validate_query(&q).unwrap();
        assert_eq!(limit, DEFAULT_PAGE_SIZE);
    }

    #[test]
    fn test_validate_query_clamps_limit() {
        let q = HistoryQuery {
            wallet_address: "GTEST".to_string(),
            cursor: None,
            limit: Some(9999),
            tx_type: None,
            status: None,
            date_from: None,
            date_to: None,
            from_currency: None,
            to_currency: None,
            sort: None,
        };
        let limit = validate_query(&q).unwrap();
        assert_eq!(limit, MAX_PAGE_SIZE);
    }

    #[test]
    fn test_validate_query_invalid_type() {
        let q = HistoryQuery {
            wallet_address: "GTEST".to_string(),
            cursor: None,
            limit: None,
            tx_type: Some("invalid".to_string()),
            status: None,
            date_from: None,
            date_to: None,
            from_currency: None,
            to_currency: None,
            sort: None,
        };
        assert!(validate_query(&q).is_err());
    }

    #[test]
    fn test_validate_query_date_range_too_large() {
        let from = Utc::now() - Duration::days(400);
        let to = Utc::now();
        let q = HistoryQuery {
            wallet_address: "GTEST".to_string(),
            cursor: None,
            limit: None,
            tx_type: None,
            status: None,
            date_from: Some(from),
            date_to: Some(to),
            from_currency: None,
            to_currency: None,
            sort: None,
        };
        assert!(validate_query(&q).is_err());
    }

    #[test]
    fn test_history_cache_key_stable() {
        let q = HistoryQuery {
            wallet_address: "GTEST".to_string(),
            cursor: None,
            limit: Some(20),
            tx_type: Some("onramp".to_string()),
            status: None,
            date_from: None,
            date_to: None,
            from_currency: None,
            to_currency: None,
            sort: None,
        };
        let k1 = history_cache_key(&q, 20);
        let k2 = history_cache_key(&q, 20);
        assert_eq!(k1, k2);
    }
}
