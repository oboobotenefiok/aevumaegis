use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
};

use alloy_primitives::{Address, B256, U256, U8, keccak256};
use alloy_sol_types::SolValue;
use clap::Parser;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(
    name = "aevumaegis-verify",
    about = "Recompute and verify an Aevumaegis on-chain forensic hash chain"
)]
struct Arguments {
    /// JSON Lines action log exported from the Aevumaegis event stream.
    #[arg(long)]
    log: PathBuf,

    /// Final ForensicCommitment hash read from the Aevum explorer.
    #[arg(long)]
    expected_hash: String,
}

#[derive(Debug, Deserialize)]
struct ActionRecord {
    index: u64,
    session_key: String,
    recipient: String,
    amount: String,
    timestamp: u64,
    kind: u8,
    action_hash: String,
}

#[derive(Debug, Error)]
enum VerificationError {
    #[error("action log I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid JSON on line {line}: {source}")]
    InvalidJson {
        line: usize,
        source: serde_json::Error,
    },
    #[error("invalid {field} on line {line}: {value}")]
    InvalidField {
        line: usize,
        field: &'static str,
        value: String,
    },
    #[error("unexpected action index on line {line}: expected {expected}, got {actual}")]
    InvalidIndex {
        line: usize,
        expected: u64,
        actual: u64,
    },
    #[error("action hash mismatch on line {line}: expected {expected}, computed {actual}")]
    ActionHashMismatch {
        line: usize,
        expected: B256,
        actual: B256,
    },
    #[error("final commitment mismatch: expected {expected}, computed {actual}")]
    CommitmentMismatch { expected: B256, actual: B256 },
    #[error("the action log is empty")]
    EmptyLog,
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    match verify_log(arguments.log.as_path(), &arguments.expected_hash) {
        Ok(report) => {
            println!("PASS: {} actions verified", report.action_count);
            println!("Final hash: {}", report.final_hash);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("FAIL: {error}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct VerificationReport {
    action_count: u64,
    final_hash: B256,
}

fn verify_log(path: &Path, expected_hash: &str) -> Result<VerificationReport, VerificationError> {
    let expected = B256::from_str(expected_hash).map_err(|_| VerificationError::InvalidField {
        line: 0,
        field: "expected_hash",
        value: expected_hash.to_owned(),
    })?;
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut previous_hash = B256::ZERO;
    let mut action_count = 0_u64;

    for (line_index, line_result) in reader.lines().enumerate() {
        let line_number = line_index + 1;
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }

        let record: ActionRecord = serde_json::from_str(&line).map_err(|source| {
            VerificationError::InvalidJson {
                line: line_number,
                source,
            }
        })?;
        let next_index = action_count + 1;
        if record.index != next_index {
            return Err(VerificationError::InvalidIndex {
                line: line_number,
                expected: next_index,
                actual: record.index,
            });
        }

        let session_key = parse_address(&record.session_key, "session_key", line_number)?;
        let recipient = parse_address(&record.recipient, "recipient", line_number)?;
        let amount = U256::from_str(&record.amount).map_err(|_| VerificationError::InvalidField {
            line: line_number,
            field: "amount",
            value: record.amount.clone(),
        })?;
        let encoded = (
            previous_hash,
            session_key,
            recipient,
            amount,
            U256::from(record.timestamp),
            U256::from(record.index),
            U8::from(record.kind),
        )
            .abi_encode();
        let computed_hash = keccak256(encoded);
        let recorded_hash = B256::from_str(&record.action_hash).map_err(|_| {
            VerificationError::InvalidField {
                line: line_number,
                field: "action_hash",
                value: record.action_hash.clone(),
            }
        })?;

        if computed_hash != recorded_hash {
            return Err(VerificationError::ActionHashMismatch {
                line: line_number,
                expected: recorded_hash,
                actual: computed_hash,
            });
        }

        previous_hash = computed_hash;
        action_count = next_index;
    }

    if action_count == 0 {
        return Err(VerificationError::EmptyLog);
    }
    if previous_hash != expected {
        return Err(VerificationError::CommitmentMismatch {
            expected,
            actual: previous_hash,
        });
    }

    Ok(VerificationReport {
        action_count,
        final_hash: previous_hash,
    })
}

fn parse_address(
    value: &str,
    field: &'static str,
    line: usize,
) -> Result<Address, VerificationError> {
    Address::from_str(value).map_err(|_| VerificationError::InvalidField {
        line,
        field,
        value: value.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn accepts_a_valid_single_action_chain() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("valid-actions.jsonl");
        let session_key = Address::from([1_u8; 20]);
        let recipient = Address::from([2_u8; 20]);
        let encoded = (
            B256::ZERO,
            session_key,
            recipient,
            U256::from(1_000_000_u64),
            U256::from(1_u64),
            U256::from(1_u64),
            U8::from(0_u8),
        )
            .abi_encode();
        let action_hash = keccak256(encoded);
        let mut file = File::create(&path)?;
        writeln!(
            file,
            r#"{{"index":1,"session_key":"{session_key}","recipient":"{recipient}","amount":"1000000","timestamp":1,"kind":0,"action_hash":"{action_hash}"}}"#
        )?;

        let report = verify_log(path.as_path(), &action_hash.to_string())?;
        assert_eq!(report.action_count, 1);
        assert_eq!(report.final_hash, action_hash);
        Ok(())
    }

    #[test]
    fn rejects_tampered_action_hash() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("actions.jsonl");
        let mut file = File::create(&path)?;
        writeln!(
            file,
            r#"{{"index":1,"session_key":"0x0000000000000000000000000000000000000001","recipient":"0x0000000000000000000000000000000000000002","amount":"1000000","timestamp":1,"kind":0,"action_hash":"0x{}"}}"#,
            "00".repeat(32)
        )?;

        let result = verify_log(path.as_path(), &format!("0x{}", "00".repeat(32)));
        assert!(matches!(result, Err(VerificationError::ActionHashMismatch { .. })));
        Ok(())
    }

    #[test]
    fn rejects_empty_log() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("empty.jsonl");
        File::create(&path)?;

        let result = verify_log(path.as_path(), &format!("0x{}", "00".repeat(32)));
        assert!(matches!(result, Err(VerificationError::EmptyLog)));
        Ok(())
    }
}
