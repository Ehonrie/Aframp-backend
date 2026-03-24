# Dedicated Load Test Environment

This environment must mirror production infrastructure while remaining isolated from real user traffic and data.

## Topology Requirements

- same application image/build as production
- same PostgreSQL major version and migration set
- same Redis version and eviction config
- same worker process types and concurrency settings
- same ingress/load balancer class

## Isolation Requirements

- separate VPC/network namespace from production
- separate database and Redis instances (no shared storage)
- separate API keys, secrets, and wallets dedicated to test data
- synthetic seeded data only
- restricted access (engineering + CI service account)

## Provisioning Checklist

- [ ] Deploy backend service with production-equivalent settings
- [ ] Apply migrations to dedicated load database
- [ ] Provision dedicated Redis and verify connectivity
- [ ] Enable all workers used in production
- [ ] Configure observability dashboards (CPU, RAM, DB connections, queue depth, p95)
- [ ] Seed deterministic fixture records for load scenarios
- [ ] Configure DNS endpoint and TLS cert for load environment
- [ ] Create CI secrets:
  - `LOAD_TEST_BASE_URL`
  - `LOAD_TEST_API_KEY`
  - `LOAD_TEST_WALLET_ADDRESS`
  - `LOAD_TEST_TX_ID`

## Validation Before Running Tests

- [ ] `/health` reports healthy
- [ ] critical endpoints return expected non-error responses with fixture payloads
- [ ] background workers process queue messages
- [ ] database and Redis metrics visible in monitoring
