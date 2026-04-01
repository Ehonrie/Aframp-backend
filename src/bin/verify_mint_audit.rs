use bitmesh_backend::audit::MintAuditStore;
use std::env;
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let arg_path = env::args().nth(1);
    let log_dir = match arg_path {
        Some(path) => {
            let path = PathBuf::from(path);
            if path.is_file() {
                path.parent().map(PathBuf::from).unwrap_or_else(|| path)
            } else {
                path
            }
        }
        None => env::var("MINT_AUDIT_LOG_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./mint_audit_logs")),
    };

    let store = match MintAuditStore::new(log_dir) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("Failed to initialize mint audit store: {}", e);
            std::process::exit(1);
        }
    };

    match store.verify().await {
        Ok(result) => {
            println!("Mint audit verification completed");
            println!("  valid: {}", result.valid);
            println!("  total_checked: {}", result.total_checked);
            if let Some(first) = result.first_entry_hash {
                println!("  first_entry_hash: {}", first);
            }
            if let Some(last) = result.last_entry_hash {
                println!("  last_entry_hash: {}", last);
            }
            if !result.gaps_detected.is_empty() {
                println!("  gaps_detected: {}", result.gaps_detected.len());
                for gap in result.gaps_detected {
                    println!("    - {}", gap);
                }
            }
            if !result.tampered_entries.is_empty() {
                println!("  tampered_entries: {}", result.tampered_entries.len());
                for entry in result.tampered_entries {
                    println!("    - line {} expected={} actual={}", entry.line_number, entry.expected_hash, entry.actual_hash);
                }
            }
            if result.valid {
                std::process::exit(0);
            } else {
                std::process::exit(2);
            }
        }
        Err(e) => {
            eprintln!("Mint audit verification failed: {}", e);
            std::process::exit(1);
        }
    }
}
