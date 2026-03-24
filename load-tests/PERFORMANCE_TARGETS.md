# Performance Targets

These are the committed pass/fail targets for critical APIs under load.

| Endpoint | Method | p95 Target | Max Throughput Target |
|---|---|---:|---:|
| `/api/onramp/quote` | POST | <= 450ms | <= 120 req/s |
| `/api/onramp/initiate` | POST | <= 700ms | <= 70 req/s |
| `/api/onramp/status/:tx_id` | GET | <= 250ms | <= 180 req/s |
| `/api/offramp/quote` | POST | <= 500ms | <= 100 req/s |
| `/api/offramp/initiate` | POST | <= 850ms | <= 60 req/s |
| `/api/bills/pay` | POST | <= 900ms | <= 40 req/s |
| `/api/rates` | GET | <= 200ms | <= 250 req/s |

## Global Constraints

- max error rate: `< 2%`
- scenario results must include p50, p95, p99, error rate, throughput

The source-of-truth used by k6 is `load-tests/config/targets.json`.
