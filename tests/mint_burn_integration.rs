//! Integration tests for the Mint & Burn Event Monitoring Worker.
//!
//! These tests exercise the full replay sequence and cursor restoration
//! workflows using a real PostgreSQL database.
//!
//! Run with:
//!   DATABASE_URL=postgres://... cargo test --test mint_burn_integration --features integration -- --nocapture
//!
//! Tests are gated behind the `integration` feature flag so they are skipped
//! in normal CI unless explicitly enabled.
//!
//! Requirements: 11.4, 11.5

#![cfg(feature = "integration")]

use std::sync::Arc;

use chrono::Utc;
use prometheus::Registry;
use sqlx::PgPool;
use uuid::Uuid;

use Bitmesh_backend::mint_burn::{
    models::MintBurnConfig,
    metrics::MintBurnMetrics,
    worker::MintBurnWorker,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ISSUER_ID: &str = "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGZWM9CQJUQE3QLQNZJQE";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn test_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set for integration tests");
    PgPool::connect(&url).await.expect("db pool")
}

fn test_metrics() -> Arc<MintBurnMetrics> {
    let registry = Registry::new();
    Arc::new(MintBurnMetrics::new(&registry).expect("metrics"))
}

fn test_config() -> MintBurnConfig {
    MintBurnConfig {
        issuer_id: ISSUER_ID.to_owned(),
        horizon_base_url: "https://horizon-testnet.stellar.org".to_owned(),
        heartbeat_timeout_secs: 30,
        reconnect_backoff_max_secs: 60,
        reconnect_backoff_initial_secs: 1,
    }
}

fn make_worker(pool: PgPool) -> MintBurnWorker {
    let (worker, _tx) = MintBurnWorker::new(test_config(), pool, test_metrics());
    worker
}

/// Ensure the tables required by the mint_burn worker exist in the test DB.
/// This is idempotent — safe to call multiple times.
async fn ensure_schema(pool: &PgPool) {
    // processed_events
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS processed_events (
            id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            transaction_hash    TEXT NOT NULL,
            operation_type      TEXT NOT NULL,
            ledger_id           BIGINT NOT NULL,
            created_at_chain    TIMESTAMPTZ NOT NULL,
            processed_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            asset_code          TEXT,
            asset_issuer        TEXT,
            amount              TEXT,
            source_account      TEXT NOT NULL,
            destination_account TEXT,
            raw_memo            TEXT,
            parsed_id           TEXT,
            CONSTRAINT uq_processed_events_tx_hash UNIQUE (transaction_hash)
        )
        "#,
    )
    .execute(pool)
    .await
    .expect("create processed_events");

    // ledger_cursor
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ledger_cursor (
            id          SERIAL PRIMARY KEY,
            cursor      TEXT NOT NULL,
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        "#,
    )
    .execute(pool)
    .await
    .expect("create ledger_cursor");

    // Seed the singleton row if absent
    sqlx::query(
        "INSERT INTO ledger_cursor (cursor) SELECT 'now' WHERE NOT EXISTS (SELECT 1 FROM ledger_cursor)",
    )
    .execute(pool)
    .await
    .expect("seed ledger_cursor");

    // unmatched_events
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS unmatched_events (
            id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            transaction_hash    TEXT NOT NULL,
            raw_memo            TEXT,
            raw_operation       JSONB NOT NULL,
            recorded_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        "#,
    )
    .execute(pool)
    .await
    .expect("create unmatched_events");

    // mints — referenced by confirm_mint in repository.rs
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS mints (
            id           TEXT PRIMARY KEY,
            status       TEXT NOT NULL DEFAULT 'PENDING',
            ledger_id    BIGINT,
            confirmed_at TIMESTAMPTZ,
            created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        "#,
    )
    .execute(pool)
    .await
    .expect("create mints");

    // redemptions — referenced by confirm_redemption in repository.rs
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS redemptions (
            id           TEXT PRIMARY KEY,
            status       TEXT NOT NULL DEFAULT 'PENDING',
            ledger_id    BIGINT,
            confirmed_at TIMESTAMPTZ,
            created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        "#,
    )
    .execute(pool)
    .await
    .expect("create redemptions");
}

/// Remove all rows inserted by a test run, identified by a unique test-run tag
/// embedded in the transaction hashes.
async fn cleanup(pool: &PgPool, tx_hashes: &[&str]) {
    for hash in tx_hashes {
        sqlx::query("DELETE FROM processed_events WHERE transaction_hash = $1")
            .bind(hash)
            .execute(pool)
            .await
            .ok();
    }
}

async fn cleanup_mints(pool: &PgPool, mint_ids: &[&str]) {
    for id in mint_ids {
        sqlx::query("DELETE FROM mints WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
    }
}

async fn cleanup_redemptions(pool: &PgPool, redemption_ids: &[&str]) {
    for id in redemption_ids {
        sqlx::query("DELETE FROM redemptions WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
    }
}

/// Build a JSON payload that mimics a Horizon SSE `data:` line for a `payment`
/// operation (Mint: issuer → recipient).
fn mint_payload(
    tx_hash: &str,
    paging_token: &str,
    ledger: i64,
    mint_id: &str,
    recipient: &str,
) -> String {
    let created_at = Utc::now().to_rfc3339();
    format!(
        r#"{{
            "id": "{tx_hash}",
            "paging_token": "{paging_token}",
            "type": "payment",
            "transaction_hash": "{tx_hash}",
            "ledger": {ledger},
            "created_at": "{created_at}",
            "source_account": "{issuer}",
            "from": "{issuer}",
            "to": "{recipient}",
            "asset_code": "cNGN",
            "asset_issuer": "{issuer}",
            "amount": "100.0000000",
            "transaction_memo": "mint_id:{mint_id}",
            "transaction_memo_type": "text"
        }}"#,
        tx_hash = tx_hash,
        paging_token = paging_token,
        ledger = ledger,
        mint_id = mint_id,
        recipient = recipient,
        issuer = ISSUER_ID,
    )
}

/// Build a JSON payload for a `payment` operation (Burn: recipient → issuer).
fn burn_payload(
    tx_hash: &str,
    paging_token: &str,
    ledger: i64,
    redemption_id: &str,
    sender: &str,
) -> String {
    let created_at = Utc::now().to_rfc3339();
    format!(
        r#"{{
            "id": "{tx_hash}",
            "paging_token": "{paging_token}",
            "type": "payment",
            "transaction_hash": "{tx_hash}",
            "ledger": {ledger},
            "created_at": "{created_at}",
            "source_account": "{sender}",
            "from": "{sender}",
            "to": "{issuer}",
            "asset_code": "cNGN",
            "asset_issuer": "{issuer}",
            "amount": "50.0000000",
            "transaction_memo": "redemption_id:{redemption_id}",
            "transaction_memo_type": "text"
        }}"#,
        tx_hash = tx_hash,
        paging_token = paging_token,
        ledger = ledger,
        redemption_id = redemption_id,
        sender = sender,
        issuer = ISSUER_ID,
    )
}

// ---------------------------------------------------------------------------
// 10.1 Replay sequence integration test
// ---------------------------------------------------------------------------

/// Requirements: 11.4
///
/// Replays a fixed sequence of 5 operations from a known cursor against the
/// test database. Verifies that:
///   - All 5 operations are processed (no errors).
///   - `processed_events` contains exactly one row per transaction hash.
///   - The corresponding `mints` / `redemptions` records have status
///     `ON_CHAIN_CONFIRMED`.
///   - The `ledger_cursor` is advanced to the paging token of the last
///     processed operation.
#[tokio::test]
async fn replay_sequence_processes_all_five_operations() {
    let pool = test_pool().await;
    ensure_schema(&pool).await;

    // ── Fixed test-run ID to avoid collisions with other test runs ───────────
    let run_id = Uuid::new_v4().to_string();
    let run_id = &run_id[..8]; // short prefix for readability

    // ── Fixed transaction hashes ─────────────────────────────────────────────
    let tx_hashes = [
        format!("replay_seq_{run_id}_tx1"),
        format!("replay_seq_{run_id}_tx2"),
        format!("replay_seq_{run_id}_tx3"),
        format!("replay_seq_{run_id}_tx4"),
        format!("replay_seq_{run_id}_tx5"),
    ];

    // ── Fixed paging tokens (cursor values) ──────────────────────────────────
    let paging_tokens = [
        format!("cursor_{run_id}_1"),
        format!("cursor_{run_id}_2"),
        format!("cursor_{run_id}_3"),
        format!("cursor_{run_id}_4"),
        format!("cursor_{run_id}_5"),
    ];

    // ── Mint IDs for operations 1, 2, 3 ─────────────────────────────────────
    let mint_ids = [
        format!("mint_{run_id}_1"),
        format!("mint_{run_id}_2"),
        format!("mint_{run_id}_3"),
    ];

    // ── Redemption IDs for operations 4, 5 ──────────────────────────────────
    let redemption_ids = [
        format!("redemption_{run_id}_4"),
        format!("redemption_{run_id}_5"),
    ];

    let recipient = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";

    // ── Pre-insert mint and redemption records ────────────────────────────────
    for mint_id in &mint_ids {
        sqlx::query("INSERT INTO mints (id, status) VALUES ($1, 'PENDING')")
            .bind(mint_id)
            .execute(&pool)
            .await
            .expect("insert mint record");
    }
    for redemption_id in &redemption_ids {
        sqlx::query("INSERT INTO redemptions (id, status) VALUES ($1, 'PENDING')")
            .bind(redemption_id)
            .execute(&pool)
            .await
            .expect("insert redemption record");
    }

    // ── Build the 5 SSE payloads ──────────────────────────────────────────────
    let payloads = [
        mint_payload(&tx_hashes[0], &paging_tokens[0], 1001, &mint_ids[0], recipient),
        mint_payload(&tx_hashes[1], &paging_tokens[1], 1002, &mint_ids[1], recipient),
        mint_payload(&tx_hashes[2], &paging_tokens[2], 1003, &mint_ids[2], recipient),
        burn_payload(&tx_hashes[3], &paging_tokens[3], 1004, &redemption_ids[0], recipient),
        burn_payload(&tx_hashes[4], &paging_tokens[4], 1005, &redemption_ids[1], recipient),
    ];

    // ── Process all 5 operations ──────────────────────────────────────────────
    let worker = make_worker(pool.clone());
    for payload in &payloads {
        worker
            .process_event(payload)
            .await
            .expect("process_event should succeed");
    }

    // ── Assert: all 5 hashes are in processed_events ─────────────────────────
    for tx_hash in &tx_hashes {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM processed_events WHERE transaction_hash = $1",
        )
        .bind(tx_hash)
        .fetch_one(&pool)
        .await
        .expect("query processed_events");

        assert_eq!(
            count, 1,
            "processed_events must contain exactly one row for tx_hash={tx_hash}"
        );
    }

    // ── Assert: mint records have status ON_CHAIN_CONFIRMED ───────────────────
    for mint_id in &mint_ids {
        let status: String =
            sqlx::query_scalar("SELECT status FROM mints WHERE id = $1")
                .bind(mint_id)
                .fetch_one(&pool)
                .await
                .expect("query mints");

        assert_eq!(
            status, "ON_CHAIN_CONFIRMED",
            "mint record {mint_id} must have status ON_CHAIN_CONFIRMED"
        );
    }

    // ── Assert: redemption records have status ON_CHAIN_CONFIRMED ────────────
    for redemption_id in &redemption_ids {
        let status: String =
            sqlx::query_scalar("SELECT status FROM redemptions WHERE id = $1")
                .bind(redemption_id)
                .fetch_one(&pool)
                .await
                .expect("query redemptions");

        assert_eq!(
            status, "ON_CHAIN_CONFIRMED",
            "redemption record {redemption_id} must have status ON_CHAIN_CONFIRMED"
        );
    }

    // ── Assert: ledger_cursor is advanced to the last paging token ────────────
    let cursor: String =
        sqlx::query_scalar("SELECT cursor FROM ledger_cursor ORDER BY id LIMIT 1")
            .fetch_one(&pool)
            .await
            .expect("query ledger_cursor");

    assert_eq!(
        cursor, paging_tokens[4],
        "ledger_cursor must be advanced to the last paging token after replaying 5 operations"
    );

    // ── Cleanup ───────────────────────────────────────────────────────────────
    let hash_refs: Vec<&str> = tx_hashes.iter().map(String::as_str).collect();
    cleanup(&pool, &hash_refs).await;

    let mint_id_refs: Vec<&str> = mint_ids.iter().map(String::as_str).collect();
    cleanup_mints(&pool, &mint_id_refs).await;

    let redemption_id_refs: Vec<&str> = redemption_ids.iter().map(String::as_str).collect();
    cleanup_redemptions(&pool, &redemption_id_refs).await;
}

// ---------------------------------------------------------------------------
// 10.2 Worker restart and cursor restoration integration test
// ---------------------------------------------------------------------------

/// Requirements: 11.5, 5.2, 5.3
///
/// Simulates a worker restart mid-sequence. Verifies that:
///   - After processing 3 operations, the cursor is persisted at paging token 3.
///   - A new worker instance (simulating a restart) loads the cursor from DB.
///   - The new worker processes 2 more operations without re-processing the first 3.
///   - All 5 tx hashes are in `processed_events` exactly once each.
///   - The cursor is advanced to the 5th paging token after the second worker finishes.
///   - None of the first 3 operations were processed twice (count = 1 each).
#[tokio::test]
async fn worker_restart_restores_cursor_and_processes_remaining_operations() {
    let pool = test_pool().await;
    ensure_schema(&pool).await;

    // ── Fixed test-run ID to avoid collisions with other test runs ───────────
    let run_id = Uuid::new_v4().to_string();
    let run_id = &run_id[..8];

    // ── Transaction hashes: 3 mints + 2 burns ────────────────────────────────
    let tx_hashes = [
        format!("restart_{run_id}_tx1"),
        format!("restart_{run_id}_tx2"),
        format!("restart_{run_id}_tx3"),
        format!("restart_{run_id}_tx4"),
        format!("restart_{run_id}_tx5"),
    ];

    // ── Paging tokens ─────────────────────────────────────────────────────────
    let paging_tokens = [
        format!("restart_cursor_{run_id}_1"),
        format!("restart_cursor_{run_id}_2"),
        format!("restart_cursor_{run_id}_3"),
        format!("restart_cursor_{run_id}_4"),
        format!("restart_cursor_{run_id}_5"),
    ];

    // ── Mint IDs for operations 1–3 ──────────────────────────────────────────
    let mint_ids = [
        format!("restart_mint_{run_id}_1"),
        format!("restart_mint_{run_id}_2"),
        format!("restart_mint_{run_id}_3"),
    ];

    // ── Redemption IDs for operations 4–5 ────────────────────────────────────
    let redemption_ids = [
        format!("restart_redemption_{run_id}_4"),
        format!("restart_redemption_{run_id}_5"),
    ];

    let recipient = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";

    // ── Pre-insert mint and redemption records ────────────────────────────────
    for mint_id in &mint_ids {
        sqlx::query("INSERT INTO mints (id, status) VALUES ($1, 'PENDING')")
            .bind(mint_id)
            .execute(&pool)
            .await
            .expect("insert mint record");
    }
    for redemption_id in &redemption_ids {
        sqlx::query("INSERT INTO redemptions (id, status) VALUES ($1, 'PENDING')")
            .bind(redemption_id)
            .execute(&pool)
            .await
            .expect("insert redemption record");
    }

    // ── Build payloads ────────────────────────────────────────────────────────
    let mint_payloads = [
        mint_payload(&tx_hashes[0], &paging_tokens[0], 2001, &mint_ids[0], recipient),
        mint_payload(&tx_hashes[1], &paging_tokens[1], 2002, &mint_ids[1], recipient),
        mint_payload(&tx_hashes[2], &paging_tokens[2], 2003, &mint_ids[2], recipient),
    ];
    let burn_payloads = [
        burn_payload(&tx_hashes[3], &paging_tokens[3], 2004, &redemption_ids[0], recipient),
        burn_payload(&tx_hashes[4], &paging_tokens[4], 2005, &redemption_ids[1], recipient),
    ];

    // ── FIRST WORKER: process 3 mints ─────────────────────────────────────────
    let worker1 = make_worker(pool.clone());
    for payload in &mint_payloads {
        worker1
            .process_event(payload)
            .await
            .expect("worker1 process_event should succeed");
    }

    // ── Assert: cursor is persisted at paging token 3 after first worker ──────
    let cursor_after_first: String =
        sqlx::query_scalar("SELECT cursor FROM ledger_cursor ORDER BY id LIMIT 1")
            .fetch_one(&pool)
            .await
            .expect("query ledger_cursor after first worker");

    assert_eq!(
        cursor_after_first, paging_tokens[2],
        "cursor must be at paging token 3 after first worker processes 3 operations"
    );

    // ── SECOND WORKER: simulates restart — new instance, same pool ────────────
    // The new worker will load the cursor from DB on its own when run() is called,
    // but process_event() is called directly here (as in the existing test pattern).
    // The key property being tested is that the second worker does NOT re-process
    // the first 3 operations (idempotency via processed_events table), and DOES
    // process the 2 new burn operations.
    let worker2 = make_worker(pool.clone());

    // Verify the cursor is loadable by the new worker (simulates what run() does)
    let repo = Bitmesh_backend::mint_burn::repository::MintBurnRepository::new(pool.clone());
    let loaded_cursor = repo
        .load_cursor()
        .await
        .expect("load_cursor should succeed")
        .expect("cursor should be present after first worker");

    assert_eq!(
        loaded_cursor, paging_tokens[2],
        "new worker must load cursor at paging token 3 from DB"
    );

    // ── Attempt to re-process the first 3 operations (should be skipped) ──────
    for payload in &mint_payloads {
        worker2
            .process_event(payload)
            .await
            .expect("worker2 re-processing first 3 ops should not error (idempotent)");
    }

    // ── Process the 2 new burn operations ────────────────────────────────────
    for payload in &burn_payloads {
        worker2
            .process_event(payload)
            .await
            .expect("worker2 process burn should succeed");
    }

    // ── Assert: all 5 tx hashes are in processed_events exactly once ──────────
    for tx_hash in &tx_hashes {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM processed_events WHERE transaction_hash = $1",
        )
        .bind(tx_hash)
        .fetch_one(&pool)
        .await
        .expect("query processed_events");

        assert_eq!(
            count, 1,
            "processed_events must contain exactly one row for tx_hash={tx_hash} (no duplicates, none missed)"
        );
    }

    // ── Assert: first 3 operations were NOT processed twice (count = 1 each) ──
    // (Already covered above, but explicitly re-stated for clarity per task spec)
    for tx_hash in &tx_hashes[..3] {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM processed_events WHERE transaction_hash = $1",
        )
        .bind(tx_hash)
        .fetch_one(&pool)
        .await
        .expect("query processed_events for first 3");

        assert_eq!(
            count, 1,
            "first 3 operations must not be processed twice: tx_hash={tx_hash}"
        );
    }

    // ── Assert: cursor is at the 5th paging token ─────────────────────────────
    let final_cursor: String =
        sqlx::query_scalar("SELECT cursor FROM ledger_cursor ORDER BY id LIMIT 1")
            .fetch_one(&pool)
            .await
            .expect("query ledger_cursor after second worker");

    assert_eq!(
        final_cursor, paging_tokens[4],
        "cursor must be at paging token 5 after second worker processes 2 burn operations"
    );

    // ── Cleanup ───────────────────────────────────────────────────────────────
    let hash_refs: Vec<&str> = tx_hashes.iter().map(String::as_str).collect();
    cleanup(&pool, &hash_refs).await;

    let mint_id_refs: Vec<&str> = mint_ids.iter().map(String::as_str).collect();
    cleanup_mints(&pool, &mint_id_refs).await;

    let redemption_id_refs: Vec<&str> = redemption_ids.iter().map(String::as_str).collect();
    cleanup_redemptions(&pool, &redemption_id_refs).await;
}
