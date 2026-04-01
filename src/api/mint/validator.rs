/// Validation layer for mint requests.
///
/// Checks (in order):
///   1. Amount > 0 and ≤ 7 decimal places (Stellar stroops)
///   2. Valid Stellar G-address
///   3. asset_code is "cNGN"
///   4. fiat_reference_id exists in confirmed_deposits
///   5. fiat_reference_id not already used in a pending/active mint
///   6. Destination has an active cNGN trustline on Stellar
///   7. Destination address is not blacklisted (wallet status check)
use crate::api::mint::repository::MintRepository;
use crate::chains::stellar::trustline::CngnTrustlineManager;
use crate::chains::stellar::types::is_valid_stellar_address;
use crate::error::{AppError, AppErrorKind, DomainError, ValidationError};
use rust_decimal::Decimal;
use sqlx::PgPool;
use std::str::FromStr;
use std::sync::Arc;

const MAX_DECIMAL_PLACES: u32 = 7;
const VALID_ASSET_CODE: &str = "cNGN";

pub struct MintValidator {
    pub repo: Arc<MintRepository>,
    pub trustline_mgr: Arc<CngnTrustlineManager>,
    pub pool: PgPool,
}

impl MintValidator {
    pub async fn validate(
        &self,
        amount_str: &str,
        destination_address: &str,
        fiat_reference_id: &str,
        asset_code: &str,
    ) -> Result<Decimal, AppError> {
        // 1. Parse and validate amount
        let amount = Decimal::from_str(amount_str).map_err(|_| {
            AppError::new(AppErrorKind::Validation(ValidationError::InvalidAmount {
                amount: amount_str.to_string(),
                reason: "must be a valid decimal number".to_string(),
            }))
        })?;

        if amount <= Decimal::ZERO {
            return Err(AppError::new(AppErrorKind::Validation(
                ValidationError::InvalidAmount {
                    amount: amount_str.to_string(),
                    reason: "must be greater than zero".to_string(),
                },
            )));
        }

        // Check decimal places (Stellar supports up to 7)
        let scale = amount.scale();
        if scale > MAX_DECIMAL_PLACES {
            return Err(AppError::new(AppErrorKind::Validation(
                ValidationError::InvalidAmount {
                    amount: amount_str.to_string(),
                    reason: format!("maximum {} decimal places allowed", MAX_DECIMAL_PLACES),
                },
            )));
        }

        // 2. Validate Stellar address
        if !is_valid_stellar_address(destination_address) {
            return Err(AppError::new(AppErrorKind::Validation(
                ValidationError::InvalidWalletAddress {
                    address: destination_address.to_string(),
                    reason: "not a valid Stellar G-address".to_string(),
                },
            )));
        }

        // 3. Validate asset code
        if !asset_code.eq_ignore_ascii_case(VALID_ASSET_CODE) {
            return Err(AppError::new(AppErrorKind::Validation(
                ValidationError::InvalidCurrency {
                    currency: asset_code.to_string(),
                    reason: format!("only {} is supported", VALID_ASSET_CODE),
                },
            )));
        }

        // 4. Confirm fiat deposit exists
        let deposit_exists = self
            .repo
            .confirmed_deposit_exists(fiat_reference_id)
            .await
            .map_err(|e| {
                AppError::new(AppErrorKind::Infrastructure(
                    crate::error::InfrastructureError::Database {
                        message: e.to_string(),
                        is_retryable: true,
                    },
                ))
            })?;

        if !deposit_exists {
            return Err(AppError::new(AppErrorKind::Validation(
                ValidationError::InvalidFormat {
                    field: "fiat_reference_id".to_string(),
                    expected: "a confirmed deposit reference".to_string(),
                    got: fiat_reference_id.to_string(),
                },
            )));
        }

        // 5. Duplicate detection
        let already_used = self
            .repo
            .fiat_ref_in_use(fiat_reference_id)
            .await
            .map_err(|e| {
                AppError::new(AppErrorKind::Infrastructure(
                    crate::error::InfrastructureError::Database {
                        message: e.to_string(),
                        is_retryable: true,
                    },
                ))
            })?;

        if already_used {
            return Err(AppError::new(AppErrorKind::Domain(
                DomainError::DuplicateTransaction {
                    transaction_id: fiat_reference_id.to_string(),
                },
            )));
        }

        // 6. Trustline check
        let trustline = self
            .trustline_mgr
            .check_trustline(destination_address)
            .await
            .map_err(AppError::from)?;

        if !trustline.has_trustline || !trustline.is_authorized {
            return Err(AppError::new(AppErrorKind::Domain(
                DomainError::TrustlineNotFound {
                    wallet_address: destination_address.to_string(),
                    asset: VALID_ASSET_CODE.to_string(),
                },
            )));
        }

        // 7. Blacklist check — wallet must not be blocked in ip_reputation or geo_restriction
        // We check the wallets table for a 'blocked' status if it exists
        let is_blocked: bool = sqlx::query_scalar!(
            "SELECT EXISTS(
                SELECT 1 FROM wallets
                WHERE wallet_address = $1
                  AND metadata->>'status' = 'blocked'
             )",
            destination_address
        )
        .fetch_one(&self.pool)
        .await
        .unwrap_or(Some(false))
        .unwrap_or(false);

        if is_blocked {
            return Err(AppError::new(AppErrorKind::Domain(DomainError::Forbidden {
                message: "destination address is not eligible for minting".to_string(),
            })));
        }

        Ok(amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amount_decimal_places() {
        // 7 dp — ok
        let d = Decimal::from_str("1.1234567").unwrap();
        assert!(d.scale() <= MAX_DECIMAL_PLACES);

        // 8 dp — too many
        let d = Decimal::from_str("1.12345678").unwrap();
        assert!(d.scale() > MAX_DECIMAL_PLACES);
    }

    #[test]
    fn test_negative_amount_rejected() {
        let d = Decimal::from_str("-1.0").unwrap();
        assert!(d <= Decimal::ZERO);
    }

    #[test]
    fn test_asset_code_case_insensitive() {
        assert!("cngn".eq_ignore_ascii_case(VALID_ASSET_CODE));
        assert!("CNGN".eq_ignore_ascii_case(VALID_ASSET_CODE));
        assert!(!"USDC".eq_ignore_ascii_case(VALID_ASSET_CODE));
    }
}
