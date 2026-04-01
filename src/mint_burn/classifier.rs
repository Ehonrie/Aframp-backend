use crate::mint_burn::models::HorizonOperation;

// ---------------------------------------------------------------------------
// Operation type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationType {
    Mint,
    Burn,
    Clawback,
    SelfTransfer,
    Other,
}

// ---------------------------------------------------------------------------
// Classifier
// ---------------------------------------------------------------------------

/// Classify a Horizon operation relative to the issuer account.
///
/// Rules (in priority order):
/// 1. `clawback`  → `Clawback` (regardless of accounts)
/// 2. `payment` where source == issuer AND to == issuer → `SelfTransfer`
/// 3. `payment` where source == issuer AND to != issuer → `Mint`
/// 4. `payment` where to == issuer AND source != issuer → `Burn`
/// 5. anything else → `Other`
///
/// For payment operations the effective source is `op.from` when present,
/// falling back to `op.source_account`.
pub fn classify(op: &HorizonOperation, issuer_id: &str) -> OperationType {
    match op.op_type.as_str() {
        "clawback" => OperationType::Clawback,
        "payment" => {
            let source = op.from.as_deref().unwrap_or(&op.source_account);
            let destination = op.to.as_deref().unwrap_or("");

            let source_is_issuer = source == issuer_id;
            let dest_is_issuer = destination == issuer_id;

            match (source_is_issuer, dest_is_issuer) {
                (true, true) => OperationType::SelfTransfer,
                (true, false) => OperationType::Mint,
                (false, true) => OperationType::Burn,
                (false, false) => OperationType::Other,
            }
        }
        _ => OperationType::Other,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    const ISSUER: &str = "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGZWM9CQJUQE3QLQNZJQE";
    const OTHER: &str = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";

    fn make_op(op_type: &str, from: Option<&str>, to: Option<&str>) -> HorizonOperation {
        HorizonOperation {
            id: "1".into(),
            paging_token: "1".into(),
            op_type: op_type.into(),
            transaction_hash: "abc".into(),
            ledger: 1,
            created_at: Utc::now(),
            source_account: from.unwrap_or("").into(),
            asset_code: None,
            asset_issuer: None,
            amount: None,
            from: from.map(str::to_owned),
            to: to.map(str::to_owned),
            account: None,
            transaction_memo: None,
            transaction_memo_type: None,
        }
    }

    #[test]
    fn payment_source_is_issuer_dest_is_other_is_mint() {
        let op = make_op("payment", Some(ISSUER), Some(OTHER));
        assert_eq!(classify(&op, ISSUER), OperationType::Mint);
    }

    #[test]
    fn payment_source_is_other_dest_is_issuer_is_burn() {
        let op = make_op("payment", Some(OTHER), Some(ISSUER));
        assert_eq!(classify(&op, ISSUER), OperationType::Burn);
    }

    #[test]
    fn clawback_is_clawback_regardless_of_accounts() {
        let op = make_op("clawback", Some(OTHER), Some(OTHER));
        assert_eq!(classify(&op, ISSUER), OperationType::Clawback);
    }

    #[test]
    fn payment_both_accounts_are_issuer_is_self_transfer() {
        let op = make_op("payment", Some(ISSUER), Some(ISSUER));
        assert_eq!(classify(&op, ISSUER), OperationType::SelfTransfer);
    }

    #[test]
    fn unknown_op_type_is_other() {
        let op = make_op("create_account", Some(ISSUER), Some(OTHER));
        assert_eq!(classify(&op, ISSUER), OperationType::Other);
    }

    #[test]
    fn payment_neither_account_is_issuer_is_other() {
        let op = make_op("payment", Some(OTHER), Some(OTHER));
        assert_eq!(classify(&op, ISSUER), OperationType::Other);
    }

    #[test]
    fn fallback_to_source_account_when_from_is_none() {
        // `from` is None — classifier should fall back to `source_account`
        let mut op = make_op("payment", None, Some(OTHER));
        op.source_account = ISSUER.into();
        op.from = None;
        assert_eq!(classify(&op, ISSUER), OperationType::Mint);
    }
}
