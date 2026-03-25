/// Database query benchmark tests.
///
/// These tests connect to a real PostgreSQL instance (DATABASE_URL env var) and
/// assert that critical queries complete within defined latency budgets at scale.
///
/// Run with:
///   DATABASE_URL=postgres://... cargo test --test db_query_benchmarks --features database -- --nocapture
///
/// The tests are gated behind the `integration` feature flag so they are skipped
/// in unit-test runs that do not have a database available.
#[cfg(feature = "integration")]
mod db_benchmarks {
    use sqlx::PgPool;
    use std::time::{Duration, Instant};

    /// Connect to the database using DATABASE_URL from the environment.
    async fn pool() -> PgPool {
        let url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set for integration tests");
        PgPool::connect(&url)
            .await
            .expect("Failed to connect to database")
    }

    /// Assert that `elapsed` is within `budget`. Prints timing regardless.
    fn assert_within(label: &str, elapsed: Duration, budget: Duration) {
        println!("[BENCH] {}: {:.2}ms (budget: {}ms)",
            label,
            elapsed.as_secs_f64() * 1000.0,
            budget.as_millis());
        assert!(
            elapsed <= budget,
            "{} exceeded budget: {:.2}ms > {}ms",
            label,
            elapsed.as_secs_f64() * 1000.0,
            budget.as_millis()
        );
    }

    // -------------------------------------------------------------------------
    // Q1: Transaction lookup by ID (PK scan)
    // Budget: 5 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_transaction_by_id() {
        let pool = pool().await;

        // Pick a real transaction_id from the table
        let row: Option<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT transaction_id FROM transactions LIMIT 1"
        )
        .fetch_optional(&pool)
        .await
        .unwrap();

        let Some((id,)) = row else {
            println!("[BENCH] bench_transaction_by_id: skipped (no data)");
            return;
        };

        let start = Instant::now();
        let _: Option<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT transaction_id FROM transactions WHERE transaction_id = $1"
        )
        .bind(id)
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert_within("transaction_by_id", start.elapsed(), Duration::from_millis(5));
    }

    // -------------------------------------------------------------------------
    // Q2: Worker polling — pending/processing transactions (hot path)
    // Budget: 20 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_worker_polling_pending() {
        let pool = pool().await;
        let start = Instant::now();
        let _: Vec<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT transaction_id
             FROM transactions
             WHERE status IN ('pending', 'processing', 'pending_payment')
               AND created_at > NOW() - INTERVAL '24 hours'
             ORDER BY created_at ASC
             LIMIT 100"
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_within("worker_polling_pending", start.elapsed(), Duration::from_millis(20));
    }

    // -------------------------------------------------------------------------
    // Q3: Offramp worker polling
    // Budget: 20 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_offramp_polling() {
        let pool = pool().await;
        let start = Instant::now();
        let _: Vec<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT transaction_id
             FROM transactions
             WHERE status = 'pending' AND type = 'offramp'
             ORDER BY created_at ASC
             LIMIT 50"
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_within("offramp_polling", start.elapsed(), Duration::from_millis(20));
    }

    // -------------------------------------------------------------------------
    // Q4: Transaction history — cursor-based pagination (first page)
    // Budget: 15 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_history_cursor_first_page() {
        let pool = pool().await;

        let row: Option<(String,)> = sqlx::query_as(
            "SELECT wallet_address FROM wallets WHERE wallet_address LIKE 'G%' LIMIT 1"
        )
        .fetch_optional(&pool)
        .await
        .unwrap();

        let Some((wallet,)) = row else {
            println!("[BENCH] bench_history_cursor_first_page: skipped (no data)");
            return;
        };

        let start = Instant::now();
        let _: Vec<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT transaction_id
             FROM transactions
             WHERE wallet_address = $1
             ORDER BY created_at DESC, transaction_id DESC
             LIMIT 20"
        )
        .bind(&wallet)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_within("history_cursor_first_page", start.elapsed(), Duration::from_millis(15));
    }

    // -------------------------------------------------------------------------
    // Q5: Transaction history — cursor-based pagination (deep page)
    // Budget: 15 ms  (must not degrade with offset)
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_history_cursor_deep_page() {
        let pool = pool().await;

        // Get a cursor from ~500 rows in
        let row: Option<(chrono::DateTime<chrono::Utc>, uuid::Uuid)> = sqlx::query_as(
            "SELECT created_at, transaction_id
             FROM transactions
             WHERE wallet_address = (
                 SELECT wallet_address FROM wallets WHERE wallet_address LIKE 'G%' LIMIT 1
             )
             ORDER BY created_at DESC, transaction_id DESC
             OFFSET 500 LIMIT 1"
        )
        .fetch_optional(&pool)
        .await
        .unwrap();

        let Some((cursor_ts, cursor_id)) = row else {
            println!("[BENCH] bench_history_cursor_deep_page: skipped (insufficient data)");
            return;
        };

        let wallet: (String,) = sqlx::query_as(
            "SELECT wallet_address FROM wallets WHERE wallet_address LIKE 'G%' LIMIT 1"
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let start = Instant::now();
        let _: Vec<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT transaction_id
             FROM transactions
             WHERE wallet_address = $1
               AND (created_at, transaction_id) < ($2, $3)
             ORDER BY created_at DESC, transaction_id DESC
             LIMIT 20"
        )
        .bind(&wallet.0)
        .bind(cursor_ts)
        .bind(cursor_id)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_within("history_cursor_deep_page", start.elapsed(), Duration::from_millis(15));
    }

    // -------------------------------------------------------------------------
    // Q6: Payment reference lookup
    // Budget: 5 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_payment_reference_lookup() {
        let pool = pool().await;

        let row: Option<(String,)> = sqlx::query_as(
            "SELECT payment_reference FROM transactions
             WHERE payment_reference IS NOT NULL LIMIT 1"
        )
        .fetch_optional(&pool)
        .await
        .unwrap();

        let Some((reference,)) = row else {
            println!("[BENCH] bench_payment_reference_lookup: skipped (no data)");
            return;
        };

        let start = Instant::now();
        let _: Option<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT transaction_id FROM transactions WHERE payment_reference = $1"
        )
        .bind(&reference)
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert_within("payment_reference_lookup", start.elapsed(), Duration::from_millis(5));
    }

    // -------------------------------------------------------------------------
    // Q7: Settlement aggregation — daily volume (materialised view)
    // Budget: 10 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_daily_volume_mv() {
        let pool = pool().await;
        let start = Instant::now();
        let _: Vec<(chrono::NaiveDate, String, i64)> = sqlx::query_as(
            "SELECT day, type, tx_count
             FROM mv_daily_transaction_volume
             WHERE day >= CURRENT_DATE - INTERVAL '30 days'
             ORDER BY day DESC"
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_within("daily_volume_mv", start.elapsed(), Duration::from_millis(10));
    }

    // -------------------------------------------------------------------------
    // Q8: Provider performance summary (materialised view)
    // Budget: 10 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_provider_performance_mv() {
        let pool = pool().await;
        let start = Instant::now();
        let _: Vec<(String, f64)> = sqlx::query_as(
            "SELECT payment_provider, AVG(success_rate_pct) as avg_success
             FROM mv_provider_performance
             WHERE hour >= NOW() - INTERVAL '24 hours'
             GROUP BY payment_provider"
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_within("provider_performance_mv", start.elapsed(), Duration::from_millis(10));
    }

    // -------------------------------------------------------------------------
    // Q9: Stellar confirmation worker — active txns with hash
    // Budget: 10 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_stellar_confirmation_polling() {
        let pool = pool().await;
        let start = Instant::now();
        let _: Vec<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT transaction_id
             FROM transactions
             WHERE status IN ('pending', 'processing')
               AND stellar_tx_hash IS NOT NULL
             LIMIT 100"
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_within("stellar_confirmation_polling", start.elapsed(), Duration::from_millis(10));
    }

    // -------------------------------------------------------------------------
    // Q10: Reconciliation — completed transactions by provider in date range
    // Budget: 30 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_reconciliation_by_provider() {
        let pool = pool().await;
        let start = Instant::now();
        let _: Vec<(String, i64, sqlx::types::BigDecimal)> = sqlx::query_as(
            "SELECT payment_provider, COUNT(*) as count, SUM(from_amount) as volume
             FROM transactions
             WHERE status = 'completed'
               AND created_at >= NOW() - INTERVAL '7 days'
             GROUP BY payment_provider"
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_within("reconciliation_by_provider", start.elapsed(), Duration::from_millis(30));
    }
}
