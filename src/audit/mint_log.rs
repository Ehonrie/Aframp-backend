use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::{sync::watch, task, time::{sleep, Duration}};

const DEFAULT_MINT_AUDIT_DIR: &str = "./mint_audit_logs";
const MINT_AUDIT_FILENAME: &str = "mint_authorizations.log";
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Error)]
pub enum MintAuditError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("invalid mint audit entry: {0}")]
    InvalidEntry(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintAuditEntry {
    pub actor_id: String,
    pub public_key: String,
    pub timestamp: DateTime<Utc>,
    pub action_type: String,
    pub request_payload: Value,
    pub previous_hash: String,
    pub current_hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct MintAuditEntryContent<'a> {
    actor_id: &'a str,
    public_key: &'a str,
    timestamp: &'a DateTime<Utc>,
    action_type: &'a str,
    request_payload: &'a Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct MintAuditVerificationResult {
    pub valid: bool,
    pub total_checked: usize,
    pub first_entry_hash: Option<String>,
    pub last_entry_hash: Option<String>,
    pub tampered_entries: Vec<TamperedMintAuditEntry>,
    pub gaps_detected: Vec<String>,
    pub verified_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TamperedMintAuditEntry {
    pub line_number: usize,
    pub expected_hash: String,
    pub actual_hash: String,
    pub entry: Option<MintAuditEntry>,
}

#[derive(Clone)]
pub struct MintAuditStore {
    log_path: PathBuf,
}

impl fmt::Debug for MintAuditStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MintAuditStore")
            .field("log_path", &self.log_path)
            .finish()
    }
}

impl MintAuditStore {
    pub fn from_env() -> Result<Self, MintAuditError> {
        let directory = std::env::var("MINT_AUDIT_LOG_DIR").unwrap_or_else(|_| DEFAULT_MINT_AUDIT_DIR.to_string());
        Self::new(PathBuf::from(directory))
    }

    pub fn new(log_dir: PathBuf) -> Result<Self, MintAuditError> {
        fs::create_dir_all(&log_dir)?;
        let log_path = log_dir.join(MINT_AUDIT_FILENAME);
        Ok(Self { log_path })
    }

    pub async fn append_event(
        self: Arc<Self>,
        actor_id: String,
        public_key: String,
        action_type: String,
        request_payload: Value,
    ) -> Result<MintAuditEntry, MintAuditError> {
        let path = self.log_path.clone();
        task::spawn_blocking(move || {
            let previous_hash = last_entry_hash_sync(&path)?.unwrap_or_else(|| GENESIS_HASH.to_string());
            let timestamp = Utc::now();
            let content = MintAuditEntryContent {
                actor_id: &actor_id,
                public_key: &public_key,
                timestamp: &timestamp,
                action_type: &action_type,
                request_payload: &request_payload,
            };
            let content_bytes = serde_json::to_vec(&content)?;
            let current_hash = sha256_hex(&[previous_hash.as_bytes(), &content_bytes].concat());

            let entry = MintAuditEntry {
                actor_id,
                public_key,
                timestamp,
                action_type,
                request_payload,
                previous_hash,
                current_hash,
            };

            let serialized = serde_json::to_string(&entry)?;
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .write(true)
                .open(&path)?;
            writeln!(file, "{}", serialized)?;
            file.sync_all()?;
            Ok(entry)
        })
        .await
        .map_err(|e| MintAuditError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?
    }

    pub async fn verify(self: Arc<Self>) -> Result<MintAuditVerificationResult, MintAuditError> {
        let path = self.log_path.clone();
        task::spawn_blocking(move || verify_sync(&path)).await
            .map_err(|e| MintAuditError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?
    }
}

pub async fn run_verifier(
    store: Arc<MintAuditStore>,
    verify_interval_secs: u64,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let interval_secs = verify_interval_secs.max(60);
    while !*shutdown_rx.borrow() {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                tracing::info!("Mint audit verifier shutdown requested");
                break;
            }
            _ = sleep(Duration::from_secs(interval_secs)) => {
                match store.clone().verify().await {
                    Ok(result) => {
                        if result.valid {
                            tracing::debug!(entries = result.total_checked, "Mint audit chain verified successfully");
                        } else {
                            tracing::error!(
                                alert = "CRITICAL_SECURITY_ALERT",
                                valid = result.valid,
                                total_checked = result.total_checked,
                                tampered_entries = result.tampered_entries.len(),
                                gaps_detected = result.gaps_detected.len(),
                                "Mint audit chain integrity failure detected"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Mint audit verifier encountered an error");
                    }
                }
            }
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

fn last_entry_hash_sync(path: &Path) -> Result<Option<String>, MintAuditError> {
    if !path.exists() {
        return Ok(None);
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut last_line = None;
    for line in reader.lines() {
        let line = line?;
        if !line.trim().is_empty() {
            last_line = Some(line);
        }
    }

    if let Some(line) = last_line {
        let entry: MintAuditEntry = serde_json::from_str(&line)?;
        Ok(Some(entry.current_hash))
    } else {
        Ok(None)
    }
}

fn verify_sync(path: &Path) -> Result<MintAuditVerificationResult, MintAuditError> {
    let mut tampered_entries = Vec::new();
    let mut gaps_detected = Vec::new();
    let mut total_checked = 0;
    let mut expected_previous = GENESIS_HASH.to_string();
    let mut first_entry_hash = None;
    let mut last_entry_hash = None;

    if !path.exists() {
        return Ok(MintAuditVerificationResult {
            valid: true,
            total_checked: 0,
            first_entry_hash: None,
            last_entry_hash: None,
            tampered_entries,
            gaps_detected,
            verified_at: Utc::now(),
        });
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);

    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        total_checked += 1;
        let entry: MintAuditEntry = match serde_json::from_str(&line) {
            Ok(entry) => entry,
            Err(err) => {
                tampered_entries.push(TamperedMintAuditEntry {
                    line_number,
                    expected_hash: expected_previous.clone(),
                    actual_hash: format!("parse_error: {}", err),
                    entry: None,
                });
                continue;
            }
        };

        if first_entry_hash.is_none() {
            first_entry_hash = Some(entry.current_hash.clone());
        }

        if entry.previous_hash != expected_previous {
            gaps_detected.push(format!(
                "expected previous_hash '{}' at line {}, got '{}'",
                expected_previous, line_number, entry.previous_hash
            ));
        }

        let content = MintAuditEntryContent {
            actor_id: &entry.actor_id,
            public_key: &entry.public_key,
            timestamp: &entry.timestamp,
            action_type: &entry.action_type,
            request_payload: &entry.request_payload,
        };
        let content_bytes = serde_json::to_vec(&content)?;
        let expected_current_hash = sha256_hex(&[entry.previous_hash.as_bytes(), &content_bytes].concat());
        if expected_current_hash != entry.current_hash {
            tampered_entries.push(TamperedMintAuditEntry {
                line_number,
                expected_hash: expected_current_hash,
                actual_hash: entry.current_hash.clone(),
                entry: Some(entry.clone()),
            });
        }

        expected_previous = entry.current_hash.clone();
        last_entry_hash = Some(entry.current_hash.clone());
    }

    let valid = tampered_entries.is_empty() && gaps_detected.is_empty();

    Ok(MintAuditVerificationResult {
        valid,
        total_checked,
        first_entry_hash,
        last_entry_hash,
        tampered_entries,
        gaps_detected,
        verified_at: Utc::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use uuid::Uuid;

    fn create_temp_dir() -> PathBuf {
        let tmp = std::env::temp_dir().join(format!("mint_audit_tests_{}", Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        tmp
    }

    #[tokio::test]
    async fn append_and_verify_mint_audit_entry() {
        let temp = create_temp_dir();
        let store = Arc::new(MintAuditStore::new(temp).unwrap());

        let payload = json!({"transaction_id": "tx-1", "amount_cngn": "1000"});
        let entry = store
            .clone()
            .append_event(
                "00000000-0000-0000-0000-000000000000".to_string(),
                "GABCDEF1234567890".to_string(),
                "MINT_REQUESTED".to_string(),
                payload,
            )
            .await
            .unwrap();

        assert_eq!(entry.action_type, "MINT_REQUESTED");
        assert_eq!(entry.previous_hash, GENESIS_HASH.to_string());
        assert_eq!(entry.current_hash.len(), 64);

        let verification = store.verify().await.unwrap();
        assert!(verification.valid);
        assert_eq!(verification.total_checked, 1);
        assert_eq!(verification.tampered_entries.len(), 0);
    }

    #[tokio::test]
    async fn detect_tampering_in_mint_audit_log() {
        let temp = create_temp_dir();
        let store = Arc::new(MintAuditStore::new(temp).unwrap());

        let payload = json!({"transaction_id": "tx-1", "amount_cngn": "1000"});
        let _ = store
            .clone()
            .append_event(
                "00000000-0000-0000-0000-000000000000".to_string(),
                "GABCDEF1234567890".to_string(),
                "MINT_REQUESTED".to_string(),
                payload,
            )
            .await
            .unwrap();

        let mut contents = fs::read_to_string(store.log_path.clone()).unwrap();
        contents = contents.replace("MINT_REQUESTED", "MINT_SUBMITTED");
        fs::write(&store.log_path, contents).unwrap();

        let result = store.verify().await.unwrap();
        assert!(!result.valid);
        assert!(!result.tampered_entries.is_empty());
    }
}
