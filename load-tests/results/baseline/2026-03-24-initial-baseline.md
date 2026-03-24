# Initial Baseline Record

Date: 2026-03-24  
Commit: pending-local  
Environment: isolated load environment (to be provided)

## Status

Baseline execution is prepared but not yet executed in this repository state because a dedicated isolated load test environment URL and credentials are not configured in the workspace.

Once `BASE_URL`, API credentials, and fixture identifiers are set, run:

```bash
./load-tests/run.sh sustained
./load-tests/run.sh spike
./load-tests/run.sh stress
./load-tests/run.sh soak
```

Then copy the generated metrics into `BASELINE_TEMPLATE.md` format and commit the measured values for regression tracking.
