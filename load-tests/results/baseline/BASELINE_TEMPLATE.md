# Performance Baseline Template

Date: YYYY-MM-DD  
Commit: <git sha>  
Environment: <isolated load test environment URL/name>

## Sustained (30m)

- p50:
- p95:
- p99:
- error rate:
- throughput:
- pass/fail:

## Spike (10x burst)

- p50:
- p95:
- p99:
- error rate:
- throughput:
- graceful degradation observations:
- pass/fail:

## Stress (ramp-to-failure)

- max stable throughput:
- first failure threshold:
- dominant failure mode (timeouts, 5xx, queue saturation, db pool exhaustion, etc.):
- pass/fail:

## Soak (2h)

- p50:
- p95:
- p99:
- error rate:
- throughput:
- memory/resource observations:
- pass/fail:
