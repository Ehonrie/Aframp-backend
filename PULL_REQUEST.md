# feat: Implement Transaction History with Pagination

Closes #121

## Overview

Implements a comprehensive transaction history endpoint giving users full visibility into all past platform activity — onramp, offramp, and bill payment transactions — in a single unified view. Built to handle large datasets efficiently through cursor-based pagination, flexible filtering and sorting, wallet ownership enforcement, Redis caching, and CSV export for personal records or tax purposes.

---

## Changes

### `GET /api/transactions`

Returns paginated transaction history for the authenticated wallet with full detail per record:
- Transaction type, status, amounts, currencies, payment provider, payment reference, Stellar tx hash, and timestamps
- `next_cursor` token in the response when more pages are available, absent on the final page
- `total` count for the current filter set returned inline — no separate count query needed
- Wallet ownership enforced: every query is scoped to `wallet_address` — missing wallet returns `400`, wrong wallet returns empty set

### `GET /api/transactions/export`

- Accepts the same filter parameters as the history endpoint
- Generates a correctly formatted CSV of all matching records
- Capped at 10,000 rows — truncation signalled via `X-Export-Truncated: true` and `X-Export-Max-Rows` response headers plus a `_truncated` filename suffix
- Returns `Content-Type: text/csv; charset=utf-8` with correct `Content-Disposition: attachment` header

### Cursor-based pagination

Opaque base64-encoded cursor encodes `(created_at, transaction_id, from_amount)`. Each sort mode uses its own correct keyset comparison so pagination is stable across concurrent writes — no skipped or duplicated records regardless of inserts happening between pages.

### Filtering

| Parameter | Accepted values |
|-----------|----------------|
| `tx_type` | `onramp` \| `offramp` \| `bill_payment` |
| `status` | `pending` \| `processing` \| `completed` \| `failed` \| `refunded` |
| `date_from` / `date_to` | ISO-8601, validated, max range 365 days |
| `from_currency` / `to_currency` | currency code |

### Sorting

| Value | Behaviour |
|-------|-----------|
| `created_desc` | Default — newest first |
| `created_asc` | Oldest first |
| `amount_desc` | Largest first |
| `amount_asc` | Smallest first |

### Redis caching

Paginated history responses cached in Redis with a 30-second TTL keyed by `(wallet, cursor, all filters, sort)` — reduces repeated identical queries without serving stale data.

### Database indexes (`migrations/20260326000000_transaction_history_indexes.sql`)

Six targeted indexes added to keep history queries performant as transaction volumes grow:

- `idx_transactions_history_cursor` — primary keyset pagination on `(wallet_address, created_at DESC, transaction_id DESC)`
- `idx_transactions_wallet_type` — type filter
- `idx_transactions_wallet_status` — status filter
- `idx_transactions_wallet_created` — date range filter
- `idx_transactions_wallet_currencies` — currency pair filter
- `idx_transactions_wallet_amount` — amount sort

### Unit tests (17 tests)

- Cursor encode/decode roundtrip, invalid base64, invalid JSON
- Default, min, and max page size clamping
- All valid and invalid `tx_type`, `status`, and `sort` values
- Inverted and oversized date range rejection, exact max boundary accepted
- Cache key stability and differentiation by `to_currency` and `sort`
- All `SortMode` variants

---

## How to test

```bash
# Apply migration
sqlx migrate run

# Paginated history
GET /api/transactions?wallet_address=<addr>

# With filters
GET /api/transactions?wallet_address=<addr>&tx_type=onramp&status=completed&sort=amount_desc

# Next page using cursor from previous response
GET /api/transactions?wallet_address=<addr>&cursor=<next_cursor>

# CSV export
GET /api/transactions/export?wallet_address=<addr>&date_from=2026-01-01T00:00:00Z
```

---

## Acceptance criteria

| Criteria | Status |
|----------|--------|
| Paginated history returned for authenticated wallet | ✅ |
| Cursor pagination stable across concurrent writes | ✅ keyset on `(created_at, id)` or `(from_amount, id)` |
| All filter options work correctly | ✅ |
| All sort options work with correct default | ✅ `created_desc` default |
| `next_cursor` present/absent correctly | ✅ |
| Total count returned inline | ✅ |
| CSV export correctly formatted and downloadable | ✅ |
| Export capped with truncation indication | ✅ headers + filename suffix |
| Wallet ownership enforced | ✅ all queries scoped by `wallet_address` |
| Queries backed by database indexes | ✅ 6 targeted indexes added |
| Unit tests for cursor and filter logic | ✅ 17 unit tests |
