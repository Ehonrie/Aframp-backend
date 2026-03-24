# Load Testing Guide

This document provides comprehensive guidance on setting up, running, and maintaining load tests for the Aframp backend service.

## Overview

The load testing framework uses **k6** as the primary load testing tool and is designed to validate the performance, reliability, and scalability of critical API endpoints under various load conditions.

## Architecture

### Load Testing Environment

The load testing environment is completely isolated from production and staging environments:

- **Database**: Dedicated PostgreSQL instance with test data
- **Redis**: Separate Redis cluster for caching
- **Workers**: Isolated worker processes
- **Network**: Separate VPC/subnet
- **DNS**: Dedicated domain (api-load-test.aframp.com)
- **Credentials**: Test-only API keys and secrets

### Test Data Strategy

- **Wallet Addresses**: Test Stellar wallets with no real funds
- **Transaction IDs**: Synthetic transaction identifiers
- **User Data**: Generated test user accounts
- **Provider Data**: Mock bill payment provider responses

## Performance Targets

### Critical Endpoints

| Endpoint | P95 Target | Max Throughput | Error Rate |
|----------|------------|----------------|------------|
| POST /api/onramp/quote | 450ms | 120 RPS | <2% |
| POST /api/onramp/initiate | 700ms | 70 RPS | <2% |
| GET /api/onramp/status/:tx_id | 250ms | 180 RPS | <2% |
| POST /api/offramp/quote | 500ms | 100 RPS | <2% |
| POST /api/offramp/initiate | 850ms | 60 RPS | <2% |
| POST /api/bills/pay | 900ms | 40 RPS | <2% |
| GET /api/rates | 200ms | 250 RPS | <2% |

### Global Thresholds

- **Global Error Rate**: <2%
- **Memory Usage**: No leaks detected during soak tests
- **CPU Usage**: <80% average during sustained load
- **Response Time**: P99 < 2x P95

## Test Scenarios

### 1. Sustained Load Test

**Purpose**: Validate system performance under expected average daily traffic

**Duration**: 30 minutes
**Load Pattern**: Constant arrival rate of 45 RPS
**Distribution**:
- 24% onramp quotes
- 15% onramp initiations  
- 17% onramp status checks
- 17% offramp quotes
- 11% offramp initiations
- 7% bill payments
- 9% rate queries

**Success Criteria**:
- All endpoints meet P95 targets
- Error rate < 2%
- No resource exhaustion
- Stable response times throughout

### 2. Spike Load Test

**Purpose**: Test graceful degradation under sudden traffic surges

**Duration**: 14 minutes
**Load Pattern**: Ramp from 25 to 250 RPS over 3 minutes
**Focus**: Quote and initiation endpoints (10x surge)

**Success Criteria**:
- No system crashes
- Graceful degradation (some latency increase acceptable)
- Error rate remains < 5% during peak
- Quick recovery after spike

### 3. Stress Test

**Purpose**: Find system breaking point and failure modes

**Duration**: 25 minutes
**Load Pattern**: Gradual ramp from 20 to 320 RPS
**Success Criteria**:
- Document throughput ceiling
- Identify primary failure mode
- Validate error handling
- Ensure no data corruption

### 4. Soak Test

**Purpose**: Detect memory leaks and resource exhaustion over time

**Duration**: 2 hours
**Load Pattern**: Moderate constant load of 25 RPS
**Success Criteria**:
- No memory leaks
- Stable response times
- No resource exhaustion
- No connection pool exhaustion

## Setup Instructions

### Prerequisites

1. **k6 Installation**
   ```bash
   # Ubuntu/Debian
   sudo gpg -k
   sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
   echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
   sudo apt-get update
   sudo apt-get install k6

   # macOS
   brew install k6

   # Windows
   choco install k6
   ```

2. **Environment Configuration**
   ```bash
   # Copy environment template
   cp load-tests/environments/load.env.example load-tests/environments/load.env

   # Edit with your load testing environment details
   nano load-tests/environments/load.env
   ```

3. **Dependencies**
   - Node.js (for some test utilities)
   - Docker (optional, for containerized execution)

### Environment Setup

1. **Load Testing Environment Provisioning**
   ```bash
   # Terraform or CloudFormation scripts would go here
   # Provision:
   # - PostgreSQL database
   # - Redis cluster
   # - Application servers
   # - Load balancer
   # - Monitoring stack
   ```

2. **Test Data Preparation**
   ```bash
   # Seed test database with synthetic data
   ./scripts/seed-load-test-data.sh

   # Create test Stellar wallets
   ./scripts/create-test-wallets.sh

   # Configure mock external services
   ./scripts/setup-mock-services.sh
   ```

## Running Tests

### Local Execution

1. **Load Environment Variables**
   ```bash
   set -a
   source load-tests/environments/load.env
   set +a
   ```

2. **Run Individual Scenarios**
   ```bash
   # Sustained load test
   ./load-tests/run.sh sustained

   # Spike load test
   ./load-tests/run.sh spike

   # Stress test
   ./load-tests/run.sh stress

   # Soak test
   ./load-tests/run.sh soak
   ```

3. **Run All Scenarios**
   ```bash
   ./load-tests/run-all.sh
   ```

### Containerized Execution

```bash
# Build load testing container
docker build -t aframp-load-tests .

# Run tests in container
docker run --env-file load-tests/environments/load.env aframp-load-tests sustained
```

### CI/CD Integration

1. **GitHub Actions Workflow**
   ```yaml
   # .github/workflows/load-tests.yml
   name: Load Tests
   on:
     workflow_dispatch:
       inputs:
         scenario:
           description: 'Test scenario to run'
           required: true
           default: 'sustained'
           type: choice
           options:
           - sustained
           - spike
           - stress
           - soak
           - all
         enforce_thresholds:
           description: 'Fail if thresholds are breached'
           required: false
           default: true
           type: boolean
   ```

2. **Manual Trigger**
   ```bash
   # Trigger via GitHub CLI
   gh workflow run load-tests.yml -f scenario=sustained -f enforce_thresholds=true
   ```

## Results Analysis

### Output Files

Each test run generates:

- `summary.json`: Detailed metrics and thresholds
- `metrics.json`: Raw time-series data
- `summary.md`: Human-readable report
- `stdout.log`: Console output and errors

### Key Metrics

1. **Response Time Percentiles**
   - P50 (median)
   - P95 (95th percentile)
   - P99 (99th percentile)
   - Max response time

2. **Throughput**
   - Requests per second (RPS)
   - Total requests
   - Successful vs failed requests

3. **Error Analysis**
   - Error rate by endpoint
   - Error types and patterns
   - Error timing correlation

4. **Resource Utilization**
   - CPU usage
   - Memory consumption
   - Database connection pool usage
   - Redis memory usage

### Performance Baseline

Baseline results are stored in `load-tests/results/baseline/`:

```bash
# View latest baseline
cat load-tests/results/baseline/latest-summary.md

# Compare with previous baseline
./scripts/compare-baselines.sh v1.0 v1.1
```

## Troubleshooting

### Common Issues

1. **Connection Timeouts**
   - Check network connectivity to load testing environment
   - Verify API keys and authentication
   - Increase k6 connection timeout settings

2. **High Error Rates**
   - Check application logs for errors
   - Verify test data validity
   - Review rate limiting configurations

3. **Memory Leaks**
   - Monitor memory usage during soak tests
   - Check for connection pool exhaustion
   - Review garbage collection patterns

4. **Inconsistent Results**
   - Ensure consistent test environment state
   - Clear caches between test runs
   - Use same test data across runs

### Debug Mode

```bash
# Enable debug logging
export K6_LOG_LEVEL=debug
./load-tests/run.sh sustained

# Run with fewer VUs for debugging
K6_VUS=10 ./load-tests/run.sh sustained
```

## Maintenance

### Regular Tasks

1. **Update Test Data**
   - Refresh test wallets monthly
   - Update provider configurations
   - Clean up old test transactions

2. **Review Thresholds**
   - Analyze performance trends
   - Adjust thresholds based on capacity changes
   - Validate against SLA requirements

3. **Environment Health**
   - Monitor load testing infrastructure
   - Update dependencies and tools
   - Review security configurations

### Performance Regression Detection

1. **Automated Alerts**
   - Set up monitoring for threshold breaches
   - Alert on significant performance degradation
   - Track trends over time

2. **Baseline Updates**
   - Update baselines after major releases
   - Document performance improvements
   - Track capacity growth

## Security Considerations

1. **Test Data Security**
   - Never use production data
   - Use synthetic test data only
   - Secure test credentials properly

2. **Environment Isolation**
   - Separate network from production
   - Use dedicated credentials
   - Implement proper access controls

3. **Data Privacy**
   - Anonymize any user data used in tests
   - Comply with data protection regulations
   - Secure test result storage

## Best Practices

1. **Test Design**
   - Use realistic traffic patterns
   - Include think time between requests
   - Test both happy path and error scenarios

2. **Resource Management**
   - Monitor resource usage during tests
   - Clean up test data after runs
   - Use appropriate VU counts

3. **Documentation**
   - Document test scenarios clearly
   - Maintain up-to-date configuration
   - Share results with stakeholders

4. **Continuous Improvement**
   - Regularly review and update tests
   - Incorporate lessons learned
   - Stay updated with k6 features

## Support

For questions or issues:

1. Check the troubleshooting section
2. Review k6 documentation: https://k6.io/docs/
3. Contact the performance engineering team
4. Create GitHub issues for bugs or enhancements