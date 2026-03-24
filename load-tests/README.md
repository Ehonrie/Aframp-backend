# Load Testing (k6)

This project uses `k6` as the primary load testing tool.

## Why k6

- Scriptable scenarios in JavaScript for realistic user flows.
- Easy CI integration with deterministic pass/fail thresholds.
- Strong metric primitives (p50/p95/p99 latency, error rate, throughput).

## Structure

```text
load-tests/
  config/
    targets.json             # Endpoint performance targets and error budget
  environments/
    load.env.example         # Dedicated load environment variables
  lib/
    config.js                # Base URL, thresholds, shared options
    http.js                  # Endpoint request helpers and tagged metrics
    report.js                # Summary markdown generation
  scenarios/
    sustained.js             # 30-minute average traffic profile
    spike.js                 # 10x quote/initiate traffic surge
    stress.js                # Ramp to failure/throughput ceiling
    soak.js                  # 2-hour moderate traffic profile
  results/
    baseline/                # Committed baseline reports
    runs/                    # Timestamped local/CI run outputs
  run.sh                     # Scenario runner wrapper
  run-all.sh                 # Runs all scenarios for baseline capture
```

## Dedicated Load Environment

Load tests must run against an isolated environment that mirrors production topology:

- same backend build and configuration profile as production
- same Postgres engine/version and schema migrations
- same Redis topology and settings
- same worker processes and queue settings
- isolated datasets and credentials (never production user data)

Use a separate network, DNS entry, and secrets namespace for load testing.

Reference variables are in `load-tests/environments/load.env.example`.

## Endpoint Targets

Targets live in `load-tests/config/targets.json` and define p95 latency + max throughput per endpoint:

- `POST /api/onramp/quote`
- `POST /api/onramp/initiate`
- `GET /api/onramp/status/:tx_id`
- `POST /api/offramp/quote`
- `POST /api/offramp/initiate`
- `POST /api/bills/pay`
- `GET /api/rates`

Human-readable target table: `load-tests/PERFORMANCE_TARGETS.md`.

The suite enforces:

- endpoint p95 thresholds
- endpoint throughput ceilings
- global max error-rate budget
- endpoint check success rate

## Run Locally

1) Install `k6`.
2) Export env vars:

```bash
set -a
source load-tests/environments/load.env.example
set +a
```

3) Run a scenario:

```bash
./load-tests/run.sh sustained
./load-tests/run.sh spike
./load-tests/run.sh stress
./load-tests/run.sh soak
./load-tests/run-all.sh
```

Results are written to `load-tests/results/runs/<timestamp>-<scenario>/`:

- `summary.json`
- `metrics.json`
- `summary.md`
- `stdout.log`

## CI Execution

### Standalone workflow

- Workflow: `.github/workflows/load-tests.yml`
- Trigger: manual dispatch
- Inputs:
  - `scenario`: sustained | spike | stress | soak
  - `enforce_thresholds`: fail on threshold breach
- Artifacts: uploaded scenario reports under `load-tests/results/runs/**`

### Optional gate before production deployment

`ci-cd.yml` supports manual inputs:

- `run_load_tests` (boolean)
- `enforce_load_test_gate` (boolean)

When enabled, the sustained scenario runs after staging deploy and can gate production.

## Pass/Fail Thresholds

- **Sustained:** all endpoint p95 and error-rate thresholds must pass.
- **Spike:** temporary latency degradation is acceptable, but no crash and error budget should remain below threshold.
- **Stress:** records throughput ceiling and first dominant failure mode.
- **Soak:** 2h run completes with stable error rate and no resource exhaustion symptoms.

## Baseline

Baseline reports should be stored in `load-tests/results/baseline/`.
Use the template file in that folder to capture the current build's sustained/spike/stress/soak results for regression comparisons.

Recommended baseline workflow:

```bash
./load-tests/run-all.sh
```

This executes all four scenarios and writes a baseline run index file under `load-tests/results/baseline/`.
