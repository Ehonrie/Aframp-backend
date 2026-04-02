# Mint Anomaly Detection & Automated Circuit Breaker

## Overview

This implementation provides comprehensive security monitoring and automated response for the cNGN stablecoin system, protecting the 1:1 reserve ratio by detecting anomalies and automatically halting operations when necessary.

## Features

### 🔍 Anomaly Detection Rules

1. **Velocity Limit Detection**
   - Triggers if more than X NGN is minted within a 60-second window
   - Default: 500M NGN limit in 60 seconds
   - Per-wallet tracking with automatic cleanup

2. **Negative Delta Detection**
   - Triggers if `Bank_Reserves < OnChain_Supply` beyond tolerance
   - Default tolerance: 0.01% (0.0001 as decimal)
   - Protects against reserve ratio breaches

3. **Unknown Origin Detection**
   - Triggers if on-chain mint lacks corresponding APPROVED database record
   - Detects "ghost mints" and compromised private keys
   - Real-time blockchain monitoring integration

### ⚡ Circuit Breaker Mechanism

- **System Status Flags**: `OPERATIONAL`, `PARTIAL_HALT`, `EMERGENCY_STOP`
- **Database Persistence**: System state stored in `system_status` table
- **Automatic Escalation**: Progressive response based on anomaly severity
- **No Auto-Recovery**: Requires manual audit and reset

### 🛡️ Security Features

- **Multi-Sig Protection**: Emergency stop requires multiple authorization codes
- **Manual Audit Required**: Two different executives must approve recovery
- **Comprehensive Logging**: All actions logged with full audit trail
- **Rate Limiting**: Prevents abuse of emergency endpoints

### 📊 Monitoring & Alerting

- **Real-time Dashboard**: System status, metrics, and alert history
- **Multi-Channel Alerts**: SMS, PagerDuty, Slack integration
- **Health Checks**: Comprehensive system health monitoring
- **Historical Data**: Uptime percentages and alert statistics

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   API Layer    │    │  Circuit Breaker │    │  Alert System   │
│                 │───▶│    Service       │───▶│                 │
│ • Onramp       │    │                  │    │ • PagerDuty    │
│ • Offramp      │    │ • Anomaly        │    │ • Slack        │
│ • Dashboard    │    │   Detection       │    │ • SMS          │
└─────────────────┘    │ • State Mgmt     │    └─────────────────┘
                       │ • Auto-Halt      │
                       └──────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │   Database       │
                       │                  │
                       │ • system_status  │
                       │ • transactions  │
                       │ • audit_logs    │
                       └──────────────────┘
```

## API Endpoints

### Circuit Breaker Control

| Method | Endpoint | Description | Auth Required |
|---------|-----------|-------------|---------------|
| GET | `/api/admin/circuit-breaker/status` | Get current system status | Admin |
| POST | `/api/admin/circuit-breaker/emergency-stop` | Manual emergency stop | Multi-sig |
| POST | `/api/admin/circuit-breaker/audit-reset` | Reset after audit | Multi-sig |
| GET | `/api/admin/circuit-breaker/health` | Health check endpoint | Admin |

### Dashboard & Monitoring

| Method | Endpoint | Description | Auth Required |
|---------|-----------|-------------|---------------|
| GET | `/api/admin/dashboard/status` | Dashboard status display | Admin |
| GET | `/api/admin/dashboard/health` | System health checks | Admin |
| GET | `/api/admin/dashboard/alerts` | Alert history | Admin |
| GET | `/api/admin/dashboard/metrics` | System metrics | Admin |

## Configuration

### Environment Variables

```bash
# Anomaly Detection
MINT_VELOCITY_LIMIT_NGN=500000000
NEGATIVE_DELTA_TOLERANCE=0.0001

# Alert Integration
PAGERDUTY_INTEGRATION_KEY=your_key_here
SLACK_WEBHOOK_URL=https://hooks.slack.com/your/webhook
EMERGENCY_AUTH_CODES=code1,code2,code3
AUDIT_AUTH_CODES=audit1,audit2,audit3

# Alert Recipients
ALERT_RECIPIENTS=admin@company.com,security@company.com
```

### Database Schema

The system creates a `system_status` table with the following structure:

```sql
CREATE TABLE system_status (
    id SERIAL PRIMARY KEY DEFAULT 1,
    status TEXT NOT NULL CHECK (status IN ('OPERATIONAL', 'PARTIAL_HALT', 'EMERGENCY_STOP')),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    triggered_at TIMESTAMP WITH TIME ZONE,
    last_anomaly JSONB,
    audit_required BOOLEAN NOT NULL DEFAULT FALSE
);
```

## Integration Guide

### 1. Initialize the Service

```rust
use crate::security::{AnomalyDetectionService, AnomalyDetectionConfig};

let config = AnomalyDetectionConfig::from_env();
let anomaly_service = Arc::new(AnomalyDetectionService::new(pool, config));
```

### 2. Add Middleware to API Endpoints

```rust
use crate::security::CircuitBreakerMiddleware;

let circuit_breaker = Arc::new(CircuitBreakerMiddleware::new(anomaly_service.clone()));

// In your API handlers
async fn mint_handler(
    State(state): State<Arc<YourState>>,
    request: YourRequest,
) -> Result<YourResponse, AppError> {
    // Check if operations are allowed
    state.circuit_breaker.check_operation_allowed().await?;
    
    // Your minting logic here
    // ...
    
    // Record mint event for velocity tracking
    let amount_ngn = request.amount.parse::<u64>()?;
    state.anomaly_service.record_mint_event(amount_ngn, &request.wallet).await?;
    
    Ok(response)
}
```

### 3. Monitor Blockchain for Unknown Origins

```rust
use crate::security::OnChainMint;

let on_chain_mints = vec![
    OnChainMint {
        tx_hash: "0x123...".to_string(),
        amount: 10_000_000,
        wallet: "GABC...".to_string(),
        timestamp: chrono::Utc::now(),
    }
];

anomaly_service.detect_unknown_origin_mints(on_chain_mints).await?;
```

### 4. Check Reserve Ratios

```rust
let bank_reserves = get_bank_reserves().await?; // From your banking API
let on_chain_supply = get_on_chain_supply().await?; // From blockchain

anomaly_service.check_reserve_ratio(bank_reserves, on_chain_supply).await?;
```

## Response Times

| Operation | Target Response Time | SLA |
|-----------|-------------------|------|
| Velocity Check | < 10ms | 99.9% |
| Reserve Ratio Check | < 50ms | 99.5% |
| Unknown Origin Detection | < 100ms | 99.0% |
| Circuit Breaker Trigger | < 50ms | 99.9% |
| Alert Delivery | < 5s | 99.0% |

## Testing

### Unit Tests

```bash
# Run all security tests
cargo test security

# Run specific test categories
cargo test security::anomaly_detection
cargo test security::circuit_breaker
cargo test security::alerts
```

### Integration Tests

```bash
# Run full integration test suite
cargo test --test integration_tests

# Test API endpoints
cargo test api_tests
```

### Load Testing

The system is designed to handle high-velocity scenarios:

- **Velocity Processing**: 10,000+ events/second
- **Concurrent Checks**: 100+ simultaneous anomaly detections
- **Alert Throughput**: 1,000+ alerts/minute

## Monitoring & Observability

### Key Metrics

- `circuit_breaker_status`: Current system status (0=Operational, 1=Partial, 2=Emergency)
- `anomaly_detection_events_total`: Count of anomaly detections
- `velocity_checks_total`: Count of velocity limit checks
- `reserve_ratio_checks_total`: Count of reserve ratio checks
- `alerts_sent_total`: Count of alerts sent by channel

### Dashboard Alerts

- **🟢 Green**: System operational
- **🟡 Yellow**: Partial halt (some operations affected)
- **🔴 Red**: Emergency stop (all operations halted)
- **⚠️ Warning**: Audit required

## Security Considerations

### Authentication & Authorization

- Emergency endpoints require multi-signature authorization
- Admin endpoints require proper authentication middleware
- Audit logs track all privileged operations

### Data Protection

- Sensitive configuration encrypted at rest
- API keys and webhook URLs stored securely
- Audit trail tamper-evident

### Availability

- No single points of failure in alerting
- Graceful degradation if external services unavailable
- Local caching for critical status information

## Troubleshooting

### Common Issues

1. **Circuit Breaker Won't Reset**
   - Check if audit is required: `SELECT audit_required FROM system_status`
   - Verify two different auditors approved reset
   - Check authorization codes are valid

2. **False Positive Velocity Alerts**
   - Review velocity window configuration
   - Check for duplicate event recording
   - Verify wallet address normalization

3. **Alerts Not Sending**
   - Verify external service credentials
   - Check network connectivity to alert services
   - Review alert service logs for errors

### Debug Commands

```sql
-- Check current system status
SELECT * FROM system_status_monitor;

-- View recent anomaly detections
SELECT * FROM audit_logs 
WHERE event_type = 'anomaly_detection' 
ORDER BY created_at DESC LIMIT 10;

-- Check halted transactions
SELECT COUNT(*) as halted_count, status
FROM transactions 
WHERE status IN ('SYSTEM_HALTED', 'HALTED_PENDING', 'HALTED_IN_PROGRESS')
GROUP BY status;
```

## Migration Guide

### From Previous Version

1. Run the database migration:
   ```sql
   -- Migration file: 20261229000000_circuit_breaker_system_status.sql
   ```

2. Update API endpoint configurations to include circuit breaker middleware

3. Configure alert integration credentials

4. Update monitoring dashboards to include new metrics

### Rollback Plan

1. Disable anomaly detection via feature flag
2. Restore previous API endpoint configurations  
3. Remove circuit breaker middleware
4. Drop system_status table if needed

## Support

For issues or questions about the circuit breaker system:

- **Documentation**: See inline code documentation
- **Monitoring**: Check `/api/admin/dashboard/health`
- **Logs**: Review `circuit_breaker` log level messages
- **Alerts**: Check configured alert channels for system notifications

## License

This implementation is part of the cNGN stablecoin system and follows the same licensing terms.
