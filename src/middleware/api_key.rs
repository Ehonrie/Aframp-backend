//! API key authentication and scope enforcement middleware (Issue #131 / #132).
//!
//! Verification flow:
//!   1. Extract `Authorization: Bearer <key>` or `X-API-Key: <key>` header.
//!   2. Derive the 8-char prefix from the raw key for fast index lookup.
//!   3. Fetch all active keys sharing that prefix + environment from DB.
//!   4. Verify the raw key against each candidate's Argon2id hash.
//!   5. Reject keys scoped to the wrong environment.
//!   6. Check required scope is granted.
//!   7. Update last_used_at asynchronously (non-blocking).
//!   8. Inject `AuthenticatedKey` into request extensions.
//!
//! Security guarantees:
//!   - 401 is returned for any verification failure — never reveals whether
//!     the key ID exists.
//!   - Plaintext key is never logged at any level.
//!   - last_used_at update is fire-and-forget (does not block the request).

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::api_keys::{generator::verify_api_key, repository::ApiKeyRepository};

// ─── Error Responses ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct AuthError {
    error: AuthErrorDetail,
}

#[derive(Serialize)]
struct AuthErrorDetail {
    code: String,
    message: String,
}

fn unauthorized(code: &str, message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(AuthError {
            error: AuthErrorDetail {
                code: code.to_string(),
                message: message.to_string(),
            },
        }),
    )
        .into_response()
}

fn forbidden(scope: &str, endpoint: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(AuthError {
            error: AuthErrorDetail {
                code: "INSUFFICIENT_SCOPE".to_string(),
                message: format!(
                    "API key does not have the required scope '{}' for endpoint '{}'",
                    scope, endpoint
                ),
            },
        }),
    )
        .into_response()
}

// ─── Resolved Key Context ─────────────────────────────────────────────────────

/// Injected into request extensions after successful authentication.
#[derive(Clone, Debug)]
pub struct AuthenticatedKey {
    pub key_id: Uuid,
    pub consumer_id: Uuid,
    pub consumer_type: String,
    pub environment: String,
    pub scopes: Vec<String>,
}

// ─── Key Extraction ───────────────────────────────────────────────────────────

/// Extract the raw API key from `Authorization: Bearer <key>` or `X-API-Key: <key>`.
fn extract_raw_key(headers: &HeaderMap) -> Option<String> {
    // Prefer Authorization: Bearer
    if let Some(bearer) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        return Some(bearer.to_string());
    }
    // Fall back to X-API-Key
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

// ─── Key Resolution ───────────────────────────────────────────────────────────

/// Resolve a raw API key against the database using Argon2id verification.
///
/// Returns `None` if the key is invalid, expired, revoked, or environment-mismatched.
/// Never reveals which specific check failed to the caller.
pub async fn resolve_api_key(
    pool: &PgPool,
    raw_key: &str,
    expected_environment: &str,
) -> Option<AuthenticatedKey> {
    if raw_key.len() < 8 {
        return None;
    }

    // Derive prefix for fast index lookup (first 8 chars of the full key)
    let key_prefix: String = raw_key.chars().take(8).collect();

    let repo = ApiKeyRepository::new(pool.clone());

    // Fetch candidates by prefix + environment (uses idx_api_keys_prefix_status)
    let candidates = repo
        .find_active_by_prefix(&key_prefix, expected_environment)
        .await
        .ok()?;

    // Argon2id verify against each candidate (usually just one)
    let matched = candidates
        .into_iter()
        .find(|k| verify_api_key(raw_key, &k.key_hash))?;

    // Environment double-check (belt-and-suspenders — already filtered in query)
    if matched.environment != expected_environment {
        warn!(
            key_id = %matched.id,
            key_env = %matched.environment,
            expected_env = %expected_environment,
            "Environment mismatch on API key"
        );
        return None;
    }

    // Fetch granted scopes
    let scopes: Vec<String> = sqlx::query_scalar!(
        "SELECT scope_name FROM key_scopes WHERE api_key_id = $1 ORDER BY scope_name",
        matched.id
    )
    .fetch_all(pool)
    .await
    .ok()
    .unwrap_or_default();

    // Fetch consumer type
    let consumer_type: String = sqlx::query_scalar!(
        "SELECT consumer_type FROM consumers WHERE id = $1",
        matched.consumer_id
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .unwrap_or_default();

    // Update last_used_at asynchronously — does not block the request
    let pool_clone = pool.clone();
    let key_id = matched.id;
    tokio::spawn(async move {
        let _ = sqlx::query!(
            "UPDATE api_keys SET last_used_at = now() WHERE id = $1",
            key_id
        )
        .execute(&pool_clone)
        .await;
    });

    Some(AuthenticatedKey {
        key_id: matched.id,
        consumer_id: matched.consumer_id,
        consumer_type,
        environment: matched.environment,
        scopes,
    })
}

// ─── Middleware ───────────────────────────────────────────────────────────────

/// Axum middleware that enforces API key authentication and a required scope.
///
/// State: `(Arc<PgPool>, &'static str /* required_scope */, &'static str /* environment */)`
pub async fn scope_guard(
    State((pool, required_scope, environment)): State<(Arc<PgPool>, &'static str, &'static str)>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let endpoint = req.uri().path().to_string();

    let raw_key = match extract_raw_key(req.headers()) {
        Some(k) => k,
        None => {
            debug!(endpoint = %endpoint, "No API key on request");
            return unauthorized(
                "MISSING_API_KEY",
                "Authorization header with Bearer token or X-API-Key header is required",
            );
        }
    };

    let auth = match resolve_api_key(&pool, &raw_key, environment).await {
        Some(a) => a,
        None => {
            // Generic 401 — never reveal whether the key exists
            warn!(endpoint = %endpoint, "Invalid, expired, or wrong-environment API key");
            return unauthorized("INVALID_API_KEY", "Invalid or expired API key");
        }
    };

    if !auth.scopes.contains(&required_scope.to_string()) {
        warn!(
            consumer_id = %auth.consumer_id,
            key_id = %auth.key_id,
            required_scope = %required_scope,
            endpoint = %endpoint,
            "Scope denied"
        );

        // Audit denial asynchronously
        let pool_clone = pool.clone();
        let key_id = auth.key_id;
        let consumer_id = auth.consumer_id;
        let scope = required_scope.to_string();
        let ep = endpoint.clone();
        let env = environment.to_string();
        tokio::spawn(async move {
            let _ = sqlx::query!(
                r#"
                INSERT INTO api_key_audit_log
                    (event_type, api_key_id, consumer_id, environment, endpoint, rejection_reason)
                VALUES ('rejected', $1, $2, $3, $4, $5)
                "#,
                key_id,
                consumer_id,
                env,
                ep,
                format!("missing scope: {}", scope),
            )
            .execute(&pool_clone)
            .await;
        });

        return forbidden(required_scope, &endpoint);
    }

    info!(
        consumer_id = %auth.consumer_id,
        key_id = %auth.key_id,
        scope = %required_scope,
        environment = %environment,
        endpoint = %endpoint,
        "API key authorized"
    );

    req.extensions_mut().insert(auth);
    next.run(req).await
}

// ─── Helper ───────────────────────────────────────────────────────────────────

/// Validate that an already-resolved `AuthenticatedKey` holds ALL of the given scopes.
pub fn require_all_scopes(
    auth: &AuthenticatedKey,
    scopes: &[&str],
    endpoint: &str,
) -> Result<(), Response> {
    for scope in scopes {
        if !auth.scopes.contains(&scope.to_string()) {
            return Err(forbidden(scope, endpoint));
        }
    }
    Ok(())
}
