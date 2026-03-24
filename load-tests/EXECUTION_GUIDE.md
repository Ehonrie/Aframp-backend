# Load Testing Execution Guide

This guide provides detailed instructions for running load tests both locally and in CI/CD environments.

## Quick Start

### Local Execution

1. **Install k6**
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

2. **Configure Environment**
   ```bash
   # Copy environment template
   cp load-tests/environments/load.env.example load-tests/environments/load.env

   # Edit with your load testing environment details
   nano load-tests/environments/load.env
   ```

3. **Run Tests**
   ```bash
   # Load environment variables
   set -a
   source load-tests/environments/load.env
   set +a

   # Run individual scenarios
   ./load-tests/run.sh sustained
   ./load-tests/run.sh spike
   ./load-tests/run.sh stress
   ./load-tests/run.sh soak

   # Run all scenarios
   ./load-tests/run-all.sh
   ```

## Environment Configuration

### Load Testing Environment Setup

The load testing environment should be completely isolated from production:

#### Infrastructure Requirements

- **Database**: Dedicated PostgreSQL instance
- **Redis**: Separate Redis cluster
- **Application Servers**: Isolated from production
- **Network**: Separate VPC/subnet
- **DNS**: Dedicated domain (e.g., api-load-test.aframp.com)

#### Environment Variables

Create `load-tests/environments/load.env` with the following variables:

```bash
# Base URL for load testing environment
BASE_URL=https://api-load-test.aframp.com

# API Key for load testing
LOAD_TEST_API_KEY=your-load-test-api-key

# Test data
TEST_WALLET_ADDRESS=GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF
TEST_TX_ID=tx-load-test-placeholder

# k6 configuration
K6_INSECURE_SKIP_TLS_VERIFY=false
K6_NO_CONNECTION_REUSE=false
```

### Test Data Preparation

#### Stellar Test Wallets

Create test wallets for load testing:

```bash
# Generate test wallet (using Stellar SDK)
node -e "
const StellarSdk = require('stellar-sdk');
const keypair = StellarSdk.Keypair.random();
console.log('Public Key:', keypair.publicKey());
console.log('Secret Key:', keypair.secret());
"
```

#### Database Seeding

Seed the load testing database with synthetic data:

```bash
# Run database seeding script
./scripts/seed-load-test-data.sh
```

## Test Scenarios

### 1. Sustained Load Test

**Purpose**: Validate system performance under expected average daily traffic

**Command**:
```bash
./load-tests/run.sh sustained
```

**Duration**: 30 minutes
**Load**: 45 RPS constant
**Distribution**:
- 24% onramp quotes
- 15% onramp initiations
- 17% onramp status checks
- 17% offramp quotes
- 11% offramp initiations
- 7% bill payments
- 9% rate queries

**Success Criteria**:
- P95 < target for all endpoints
- Error rate < 2%
- Stable response times

### 2. Spike Load Test

**Purpose**: Test graceful degradation under sudden traffic surges

**Command**:
```bash
./load-tests/run.sh spike
```

**Duration**: 14 minutes
**Load Pattern**: Ramp from 25 to 250 RPS
**Focus**: Quote and initiation endpoints

**Success Criteria**:
- No system crashes
- Error rate < 5% during peak
- Quick recovery after spike

### 3. Stress Test

**Purpose**: Find system breaking point and failure modes

**Command**:
```bash
./load-tests/run.sh stress
```

**Duration**: 25 minutes
**Load Pattern**: Gradual ramp from 20 to 320 RPS

**Success Criteria**:
- Document throughput ceiling
- Identify primary failure mode
- Validate error handling

### 4. Soak Test

**Purpose**: Detect memory leaks and resource exhaustion

**Command**:
```bash
./load-tests/run.sh soak
```

**Duration**: 2 hours
**Load**: 25 RPS constant

**Success Criteria**:
- No memory leaks
- Stable response times
- No resource exhaustion

## CI/CD Integration

### GitHub Actions

The load testing workflow is configured in `.github/workflows/load-tests.yml`.

#### Manual Trigger

```bash
# Trigger via GitHub CLI
gh workflow run load-tests.yml -f scenario=sustained -f enforce_thresholds=true
```

#### Workflow Inputs

- `scenario`: sustained | spike | stress | soak | all
- `enforce_thresholds`: true | false
- `environment`: load-test | staging | production
- `baseline_comparison`: true | false

#### Environment Secrets

Configure these secrets in your GitHub repository:

```bash
# Load testing environment
LOAD_TEST_BASE_URL=https://api-load-test.aframp.com
LOAD_TEST_API_KEY=your-load-test-api-key

# Staging environment
STAGING_BASE_URL=https://api-staging.aframp.com
STAGING_API_KEY=your-staging-api-key

# Production environment
PRODUCTION_BASE_URL=https://api.aframp.com
PRODUCTION_API_KEY=your-production-api-key

# Test data
TEST_WALLET_ADDRESS=GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF
TEST_TX_ID=tx-load-test-placeholder

# Notifications
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
```

### Jenkins Integration

Create a Jenkins pipeline for load testing:

```groovy
pipeline {
    agent any
    
    environment {
        BASE_URL = credentials('LOAD_TEST_BASE_URL')
        LOAD_TEST_API_KEY = credentials('LOAD_TEST_API_KEY')
    }
    
    stages {
        stage('Install k6') {
            steps {
                sh '''
                    sudo gpg -k
                    sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
                    echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
                    sudo apt-get update
                    sudo apt-get install k6
                '''
            }
        }
        
        stage('Run Load Tests') {
            steps {
                sh './load-tests/run.sh sustained'
            }
        }
        
        stage('Publish Results') {
            steps {
                archiveArtifacts artifacts: 'load-tests/results/runs/**/*', fingerprint: true
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: false,
                    keepAll: true,
                    reportDir: 'load-tests/results/runs',
                    reportFiles: 'summary.md',
                    reportName: 'Load Test Results'
                ])
            }
        }
    }
}
```

### Docker Integration

#### Build Load Testing Container

```dockerfile
# Dockerfile.load-tests
FROM grafana/k6:latest

WORKDIR /app

COPY load-tests/ ./load-tests/
COPY .env.load-test .env

CMD ["k6", "run", "load-tests/scenarios/sustained.js"]
```

```bash
# Build container
docker build -f Dockerfile.load-tests -t aframp-load-tests .

# Run tests
docker run --env-file .env.load-test aframp-load-tests
```

#### Kubernetes Deployment

```yaml
# load-test-job.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: load-test-sustained
spec:
  template:
    spec:
      containers:
      - name: k6
        image: aframp-load-tests:latest
        env:
        - name: BASE_URL
          valueFrom:
            secretKeyRef:
              name: load-test-secrets
              key: base-url
        - name: LOAD_TEST_API_KEY
          valueFrom:
            secretKeyRef:
              name: load-test-secrets
              key: api-key
        command: ["k6", "run", "load-tests/scenarios/sustained.js"]
      restartPolicy: Never
  backoffLimit: 1
```

```bash
# Apply to cluster
kubectl apply -f load-test-job.yaml
```

## Results Analysis

### Output Files

Each test run generates:

- `summary.json`: Detailed metrics and thresholds
- `metrics.json`: Raw time-series data
- `summary.md`: Human-readable report
- `stdout.log`: Console output and errors

### Key Metrics

#### Response Time Percentiles

- **P50 (Median)**: 50% of requests complete faster than this
- **P95**: 95% of requests complete faster than this
- **P99**: 99% of requests complete faster than this
- **Max**: Slowest request time

#### Throughput

- **RPS**: Requests per second
- **Total Requests**: Total number of requests made
- **Successful vs Failed**: Success rate breakdown

#### Error Analysis

- **Error Rate**: Percentage of failed requests
- **Error Types**: Categorization of failure reasons
- **Error Timing**: When errors occurred during the test

### Performance Assessment

#### Excellent Performance

- Error rate < 1%
- P95 response time < 500ms
- P99 response time < 1000ms
- Stable throughput throughout test

#### Good Performance

- Error rate < 2%
- P95 response time < 1000ms
- P99 response time < 2000ms
- Minor throughput fluctuations

#### Warning Signs

- Error rate > 2%
- P95 response time > 1000ms
- P99 response time > 2000ms
- Significant throughput drops

#### Critical Issues

- Error rate > 5%
- System crashes or timeouts
- Memory leaks detected
- Resource exhaustion

### Baseline Comparison

Compare current results with established baselines:

```bash
# View latest baseline
cat load-tests/results/baseline/latest-summary.md

# Compare with previous baseline
./scripts/compare-baselines.sh v1.0 v1.1
```

#### Regression Detection

Alert if any of the following occur:

- P95 response time increases by > 20%
- Error rate increases by > 1%
- Throughput decreases by > 10%
- New error patterns emerge

## Troubleshooting

### Common Issues

#### Connection Timeouts

**Symptoms**: High error rate, timeout errors
**Causes**: Network issues, server overload, incorrect configuration
**Solutions**:
- Check network connectivity
- Verify API endpoints are accessible
- Increase k6 connection timeout settings
- Check server logs for errors

#### High Error Rates

**Symptoms**: Error rate > 2%
**Causes**: Server errors, invalid requests, resource exhaustion
**Solutions**:
- Check application logs
- Verify test data validity
- Review rate limiting configurations
- Monitor server resources

#### Inconsistent Results

**Symptoms**: Different results across runs
**Causes**: Variable test environment, caching issues, data state
**Solutions**:
- Ensure consistent test environment state
- Clear caches between test runs
- Use same test data across runs
- Run tests during low-traffic periods

#### Memory Leaks

**Symptoms**: Increasing memory usage over time
**Causes**: Application memory leaks, connection pool exhaustion
**Solutions**:
- Monitor memory usage during soak tests
- Check for connection pool exhaustion
- Review garbage collection patterns
- Analyze application memory usage

### Debug Mode

Enable debug logging for troubleshooting:

```bash
# Enable debug logging
export K6_LOG_LEVEL=debug
./load-tests/run.sh sustained

# Run with fewer VUs for debugging
K6_VUS=10 ./load-tests/run.sh sustained
```

### Performance Monitoring

Monitor system resources during tests:

```bash
# Monitor system resources
htop
iotop
netstat -i

# Monitor application metrics
curl http://localhost:9090/metrics

# Monitor database performance
pg_top
```

## Best Practices

### Test Design

1. **Realistic Traffic Patterns**
   - Use actual traffic distribution
   - Include think time between requests
   - Test both happy path and error scenarios

2. **Proper Test Data**
   - Use synthetic test data
   - Ensure data validity
   - Avoid data conflicts between runs

3. **Resource Management**
   - Monitor resource usage during tests
   - Clean up test data after runs
   - Use appropriate VU counts

### Execution

1. **Environment Isolation**
   - Use dedicated load testing environment
   - Isolate from production and staging
   - Use test-only credentials

2. **Consistent Conditions**
   - Run tests during low-traffic periods
   - Ensure consistent environment state
   - Use same test configuration

3. **Documentation**
   - Document test scenarios clearly
   - Maintain up-to-date configuration
   - Share results with stakeholders

### Continuous Improvement

1. **Regular Updates**
   - Update test scenarios regularly
   - Review and adjust thresholds
   - Incorporate lessons learned

2. **Performance Tracking**
   - Track performance trends over time
   - Set up automated alerts
   - Regular baseline updates

3. **Team Collaboration**
   - Share results with development team
   - Collaborate on performance improvements
   - Document performance best practices

## Support

For questions or issues:

1. **Check Documentation**
   - Review this execution guide
   - Check k6 documentation: https://k6.io/docs/
   - Review troubleshooting section

2. **Contact Team**
   - Performance engineering team
   - DevOps team for infrastructure issues
   - Development team for application issues

3. **GitHub Issues**
   - Create issues for bugs or enhancements
   - Include detailed error information
   - Provide reproduction steps

## Appendix

### Load Testing Checklist

- [ ] k6 installed and configured
- [ ] Environment variables set
- [ ] Test data prepared
- [ ] Load testing environment ready
- [ ] Monitoring tools configured
- [ ] Team notified of test schedule
- [ ] Backup plans in place
- [ ] Results analysis plan ready

### Useful Commands

```bash
# Check k6 version
k6 version

# List available scenarios
ls load-tests/scenarios/

# View test results
cat load-tests/results/runs/latest/summary.md

# Compare baselines
./scripts/compare-baselines.sh baseline-1 baseline-2

# Clean up old results
find load-tests/results/runs -type d -mtime +7 -exec rm -rf {} \;
```

### External Resources

- [k6 Documentation](https://k6.io/docs/)
- [Performance Testing Best Practices](https://k6.io/docs/best-practices/)
- [Load Testing Guide](https://k6.io/docs/testing-guides/)