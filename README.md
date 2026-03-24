# Aframp Backend

Payment infrastructure for African crypto onramp/offramp. Built with Rust for speed, reliability, and safety.

## What It Does

Aframp connects African payment systems (M-Pesa, MTN Money, Airtel Money) with blockchain networks using African stablecoins. Users connect their wallet, buy/sell crypto with CNGN stablecoins, and pay bills—all without creating an account.

**Core features:**
- Non-custodial crypto transactions
- African stablecoin (CNGN) integration
- Multi-chain support (Stellar, Ethereum, Bitcoin)
- Real-time payment processing
- Bill payment services

## About CNGN Stablecoin

CNGN is a blockchain-based stable currency pegged to African currencies, designed specifically for the African market. Learn more at [afristablecoin.org](https://www.afristablecoin.org/).
    [cngnstablecoin.org](https://cngn.co/)

**Key benefits:**
- Price stability pegged to local currencies
- Fast, low-cost transactions
- Built for African financial infrastructure
- Reduced volatility for everyday transactions

## Tech Stack

- **Framework**: Axum
- **Database**: PostgreSQL + SQLx
- **Cache**: Redis
- **Async Runtime**: Tokio
- **Blockchain**: Stellar SDK (CNGN primary chain), web3, bitcoin crates
- **Jobs**: Tokio tasks + Redis queues

## Project Structure

```
src/
├── api/              # HTTP handlers and routes
│   ├── wallet.rs     # Wallet connection endpoints
│   ├── onramp.rs     # Buy CNGN/crypto endpoints
│   ├── offramp.rs    # Sell CNGN/crypto endpoints
│   └── bills.rs      # Bill payment endpoints
├── services/         # Business logic
│   ├── transaction.rs
│   ├── payment.rs
│   ├── blockchain.rs
│   └── bill.rs
├── models/           # Database models
├── chains/           # Blockchain integrations
│   ├── stellar/      # CNGN stablecoin & Stellar
│   ├── ethereum/
│   └── bitcoin/
├── payments/         # Payment provider adapters
│   ├── flutterwave.rs
│   ├── paystack.rs
│   └── mpesa.rs
├── workers/          # Background jobs
├── middleware/       # Auth, logging, rate limiting
├── config.rs         # Configuration
└── main.rs
```

## Requirements

- Rust 1.75+
- PostgreSQL 14+
- Redis 6+
- Stellar Horizon access (testnet or mainnet)

## Installation

Clone and build:

```bash
git clone https://github.com/yourusername/aframp-backend.git
cd aframp-backend
cargo build
```

## Environment Setup

Copy example config:

```bash
cp .env.example .env
```

Required variables:

```bash
# Server
HOST=0.0.0.0
PORT=8000
RUST_LOG=info

# Database
DATABASE_URL=postgresql://user:password@localhost/aframp
DATABASE_MAX_CONNECTIONS=20

# Redis
REDIS_URL=redis://localhost:6379

# Blockchain Networks
STELLAR_NETWORK=testnet
STELLAR_HORIZON_URL=https://horizon-testnet.stellar.org

# cNGN Stablecoin Configuration
CNGN_ASSET_CODE=cNGN
CNGN_ISSUER_ADDRESS=GXXX...  # cNGN issuer account on Stellar
CNGN_SUPPORTED_CURRENCIES=NGN,KES,ZAR,GHS  # African currencies

# Other Chains (optional)
ETHEREUM_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/your-key
BITCOIN_RPC_URL=https://blockstream.info/testnet/api

# Payment Providers
FLUTTERWAVE_SECRET_KEY=your_key_here
FLUTTERWAVE_PUBLIC_KEY=your_key_here
PAYSTACK_SECRET_KEY=your_key_here
MPESA_CONSUMER_KEY=your_key_here
MPESA_CONSUMER_SECRET=your_secret_here

# Security
JWT_SECRET=your_random_secret_min_32_chars
RATE_LIMIT_PER_MINUTE=100

# Optional: Notifications
SENDGRID_API_KEY=your_key
TWILIO_ACCOUNT_SID=your_sid
TWILIO_AUTH_TOKEN=your_token
```

## Database Setup

Run migrations:

```bash
sqlx migrate run
```

Check migration status:

```bash
sqlx migrate info
```

Rollback last migration:

```bash
sqlx migrate revert
```

## Running

Development mode with hot reload:

```bash
cargo watch -x run
```

Standard run:

```bash
cargo run
```

Production build:

```bash
cargo build --release
./target/release/aframp-backend
```

API starts on `http://localhost:8000`

## Testing

Run all tests:

```bash
cargo test
```

Run specific test:

```bash
cargo test test_onramp_flow
```

Run with output:

```bash
cargo test -- --nocapture
```

Integration tests (needs testnet):

```bash
cargo test --features integration
```

### Load Testing

`k6` is the primary load testing tool for this project. Scenarios, thresholds, and CI usage are documented in `load-tests/README.md`.

Quick run examples:

```bash
./load-tests/run.sh sustained
./load-tests/run.sh spike
./load-tests/run.sh stress
./load-tests/run.sh soak
```

## API Overview

### Wallet Operations

```bash
# Get wallet balance (includes CNGN balance)
GET /api/wallet/balance?address=GXXX...

# Get supported chains
GET /api/wallet/chains
```

### Onramp (Buy CNGN/Crypto)

```bash
# Get quote for buying CNGN
POST /api/onramp/quote
{
  "from_currency": "KES",
  "to_asset": "CNGN",
  "amount": "5000"
}

# Initiate CNGN purchase
POST /api/onramp/initiate
{
  "wallet_address": "GXXX...",
  "from_currency": "KES",
  "to_asset": "CNGN",
  "amount": "5000",
  "payment_method": "mpesa"
}

# Check transaction status
GET /api/onramp/status/:tx_id
```

### Offramp (Sell CNGN/Crypto)

```bash
# Get quote for selling CNGN
POST /api/offramp/quote
{
  "from_asset": "CNGN",
  "to_currency": "KES",
  "amount": "100"
}

# Initiate withdrawal
POST /api/offramp/initiate
{
  "wallet_address": "GXXX...",
  "from_asset": "CNGN",
  "to_currency": "KES",
  "amount": "100",
  "withdrawal_method": "mpesa",
  "phone_number": "+254712345678"
}
```

### Bill Payments

```bash
# Get bill providers
GET /api/bills/providers?country=KE

# Pay bill with CNGN
POST /api/bills/pay
{
  "wallet_address": "GXXX...",
  "provider": "kplc",
  "account_number": "123456789",
  "amount": "50",
  "asset": "CNGN"
}
```

### Rates & Fees

```bash
# Get CNGN exchange rates
GET /api/rates?from=KES&to=CNGN

# Get fee structure
GET /api/fees
```

Full API docs available at `/api/docs` when server is running.

## Background Workers

Workers run as Tokio tasks:

**Transaction Monitor** - Watches Stellar blockchain for CNGN confirmations  
**Payment Processor** - Polls payment provider APIs  
**Webhook Handler** - Processes incoming webhooks  
**Settlement Worker** - Handles fund settlements  

Workers start automatically with the main server.

## Payment Provider Integration

Each provider implements the `PaymentProvider` trait:

```rust
#[async_trait]
pub trait PaymentProvider {
    async fn initiate_payment(&self, request: PaymentRequest) -> Result<PaymentResponse>;
    async fn verify_payment(&self, reference: &str) -> Result<PaymentStatus>;
    async fn process_withdrawal(&self, request: WithdrawalRequest) -> Result<WithdrawalResponse>;
}
```

Supported providers:
- **Flutterwave**: Multi-country support
- **Paystack**: Nigeria, Ghana, South Africa, Kenya
- **M-Pesa**: Kenya direct integration

Add new providers in `src/payments/providers/`.

## Blockchain Integration

### Stellar (CNGN Stablecoin)

Primary chain for CNGN stablecoin transactions:

```rust
// Send CNGN payment
let payment = stellar_service.send_payment(
    &recipient_address,
    "CNGN",
    "100"
).await?;

// Establish trustline for CNGN (first-time users)
let trustline = stellar_service.create_trustline(
    &user_address,
    "CNGN",
    &cngn_issuer_address
).await?;
```

### Ethereum

For ERC-20 tokens and future CNGN ERC-20 bridge:

```rust
let tx = ethereum_service.transfer_token(
    &token_address,
    &recipient,
    amount
).await?;
```

### Bitcoin

Lightning Network support planned.

## CNGN Stablecoin Operations

### Trustline Management

Before users can receive CNGN, they need to establish a trustline:

```rust
// Check if trustline exists
let has_trustline = stellar_service
    .check_trustline(&wallet_address, "CNGN", &cngn_issuer)
    .await?;

// Create trustline if needed
if !has_trustline {
    stellar_service
        .create_trustline(&wallet_address, "CNGN", &cngn_issuer)
        .await?;
}
```

### Currency Conversion

CNGN maintains peg to local currencies:

```rust
// Convert NGN to CNGN
let cngn_amount = conversion_service
    .convert("NGN", "CNGN", "50000")
    .await?;

// Convert CNGN to KES
let kes_amount = conversion_service
    .convert("CNGN", "KES", "100")
    .await?;
```

## Rate Limiting

Redis-backed limits:
- Onramp: 10 requests/minute per wallet
- Offramp: 10 requests/minute per wallet
- Quotes: 30 requests/minute per IP
- General API: 100 requests/minute per IP

Configure in `src/middleware/rate_limit.rs`.

## Webhooks

Providers send webhooks to `/webhooks/:provider`:

```
POST /webhooks/flutterwave
POST /webhooks/paystack
POST /webhooks/mpesa
```

All webhooks verify signatures before processing.

## Security

**Wallet Management**
- Non-custodial design
- Users control private keys
- Server never stores private keys

**CNGN Security**
- Trustline verification before transactions
- Asset issuer validation
- Transaction signing verification

**API Security**
- Rate limiting on all endpoints
- Request validation with strong typing
- SQL injection protection via SQLx
- CORS configured for frontend only

**Data Safety**
- Monetary values stored as strings (no float precision issues)
- Database transactions for atomic operations
- Idempotency keys for payment operations

## Monitoring & Logging

Logs use `tracing`:

```bash
RUST_LOG=debug cargo run  # Debug level
RUST_LOG=info cargo run   # Info level (default)
RUST_LOG=warn cargo run   # Warnings only
```

Key metrics tracked:
- CNGN transaction success/failure rates
- Payment provider response times
- Stellar blockchain confirmation times
- API endpoint latency
- Trustline creation rates

Production: Logs ship to CloudWatch (or your monitoring stack).

## Common Issues

**Database connection fails**  
→ Check PostgreSQL is running and credentials are correct

**CNGN transaction fails**  
→ Verify trustline exists and account has XLM for fees

**Trustline creation fails**  
→ Ensure wallet has minimum XLM balance (1.5 XLM) for trustline

**Payment webhook not received**  
→ Check provider IP whitelist and webhook URL configuration

**Redis connection timeout**  
→ Ensure Redis is running: `redis-cli ping`

**SQLx compile errors**  
→ Run `cargo sqlx prepare` to generate query metadata

**CNGN issuer not found**  
→ Verify CNGN_ISSUER_ADDRESS is correctly set in .env

## Development Tools

Recommended:

```bash
# Watch for changes and rebuild
cargo install cargo-watch
cargo watch -x run

# Check for common mistakes
cargo clippy

# Format code
cargo fmt

# Security audit
cargo audit

# Generate docs
cargo doc --open
```

## Deployment

**Docker:**

```bash
docker build -t aframp-backend .
docker run -p 8000:8000 --env-file .env aframp-backend
```

**Production:**
- Use release builds: `cargo build --release`
- Set `RUST_LOG=info` or `warn`
- Configure connection pools appropriately
- Enable HTTPS (use reverse proxy like nginx)
- Set up health checks: `GET /health`

## Contributing

See our [contributing guide](./CONTRIBUTING.md) for detailed instructions on setting up your development environment, coding standards, testing guidelines, and pull request process.

## Code of Conduct

Please read our [Code of Conduct](./CODE_OF_CONDUCT.md) to understand the standards we expect from contributors.

## Resources

- [CNGN Stablecoin Documentation](https://www.afristablecoin.org/)
- [Stellar Developer Docs](https://developers.stellar.org/)
- [Payment Provider APIs](./docs/PAYMENT_PROVIDERS.md)

## License

MIT - see LICENSE file

---