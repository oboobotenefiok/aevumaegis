use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, B256, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    sol,
    sol_types::{SolEvent, SolValue},
};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

const AEVUM_CHAIN_ID: u64 = 44_005;
const MAX_TRACKED_AMOUNT: u64 = 1_000_000_000_000_000_000;

sol! {
    event ActionRecorded(
        uint256 indexed index,
        bytes32 indexed actionHash,
        uint8 kind,
        bytes32 intentHash
    );
    event PaymentDecision(
        address indexed sessionKey,
        address indexed recipient,
        uint256 amount,
        bool allowed
    );
    event PaymentIntentAuthenticated(
        address indexed sessionKey,
        address indexed recipient,
        uint256 amount,
        bytes32 purposeHash,
        uint256 nonce,
        uint256 expiry,
        bytes32 intentHash
    );

    struct SessionStats {
        uint8 state;
        uint64 throttleUntil;
        uint256 actionCount;
        uint64 cumulativeSpend;
        uint64 baselineMean;
        uint128 baselineVariance;
        uint32 totalObservedTransactions;
        uint8 lastThreatScore;
        bytes32 rollingHash;
        bytes32 finalForensicHash;
        bytes32 freezeReason;
        bool hasBaseline;
    }

    #[sol(rpc)]
    interface IGuardModule {
        function vault() external view returns (address);
        function getSessionStats(address sessionKey) external view returns (SessionStats memory);
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "aevumaegis-verify",
    about = "Export and verify Aevumaegis on-chain forensic action logs"
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Recompute and verify an existing JSON Lines forensic log.
    Verify(VerifyArguments),
    /// Export events from Aevum and verify the resulting forensic log.
    Export(ExportArguments),
}

#[derive(Debug, Args)]
struct VerifyArguments {
    /// JSON Lines action log.
    #[arg(long)]
    log: PathBuf,
    /// Final ForensicCommitment hash read from the Aevum explorer.
    #[arg(long)]
    expected_hash: String,
}

#[derive(Debug, Args)]
struct ExportArguments {
    /// Aevum JSON-RPC endpoint.
    #[arg(long, env = "RPC_URL", default_value = "https://rpc-test.qday.info")]
    rpc_url: String,
    /// Deployed GuardModule address.
    #[arg(long)]
    guard_address: String,
    /// Session key whose independent hash chain should be exported.
    #[arg(long)]
    session_key: String,
    /// Deployed AgentVault address used in the signed intent domain.
    #[arg(long)]
    vault_address: String,
    /// First block to inspect, inclusive.
    #[arg(long, default_value_t = 0)]
    from_block: u64,
    /// Last block to inspect, inclusive. Must be the current head so state and logs share a snapshot.
    #[arg(long)]
    to_block: Option<u64>,
    /// Maximum number of blocks requested in one eth_getLogs call.
    #[arg(long, default_value_t = 2_000)]
    chunk_size: u64,
    /// Destination JSON Lines file.
    #[arg(long, default_value = "actions.jsonl")]
    output: PathBuf,
    /// Final ForensicCommitment hash for this session key.
    #[arg(long)]
    expected_hash: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ActionRecord {
    index: u64,
    session_key: String,
    recipient: String,
    amount: String,
    timestamp: u64,
    kind: u8,
    allowed: bool,
    action_hash: String,
    intent_hash: String,
    vault_address: String,
    chain_id: u64,
    purpose_hash: String,
    nonce: String,
    expiry: String,
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
    #[error("action decision does not match action kind on line {line}")]
    DecisionMismatch { line: usize },
    #[error("payment intent hash mismatch on line {line}: expected {expected}, computed {actual}")]
    IntentHashMismatch {
        line: usize,
        expected: B256,
        actual: B256,
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
    #[error("unexpected chain ID in action log: expected {expected}, got {actual}")]
    WrongChain { expected: u64, actual: u64 },
    #[error("duplicate payment intent nonce on line {line}: {nonce}")]
    DuplicateNonce { line: usize, nonce: String },
    #[error("action log mixes session keys: expected {expected}, got {actual}")]
    MixedSessionKeys { expected: Address, actual: Address },
    #[error("action log mixes vaults: expected {expected}, got {actual}")]
    MixedVaults { expected: Address, actual: Address },
    #[error("invalid payment intent fields on line {line}")]
    InvalidIntentFields { line: usize },
    #[error("action timestamp regressed on line {line}: previous {previous}, current {current}")]
    TimestampRegression {
        line: usize,
        previous: u64,
        current: u64,
    },
}

#[derive(Debug, Error)]
enum ExportError {
    #[error("invalid {field}: {value}")]
    InvalidField { field: &'static str, value: String },
    #[error("RPC request failed: {0}")]
    Rpc(String),
    #[error("expected Aevum chain ID {expected}, received {actual}")]
    WrongChain { expected: u64, actual: u64 },
    #[error("requested block range is invalid: from {from_block}, to {to_block}")]
    InvalidBlockRange { from_block: u64, to_block: u64 },
    #[error(
        "vault address mismatch: GuardModule is bound to {configured}, caller supplied {supplied}"
    )]
    VaultMismatch {
        configured: Address,
        supplied: Address,
    },
    #[error("forensic export must end at the latest block to compare the current commitment")]
    HistoricalExportUnsupported,
    #[error("chain head changed during export: expected block {expected}, now at {actual}; retry")]
    ChainAdvancedDuringExport { expected: u64, actual: u64 },
    #[error("session key has no on-chain forensic commitment; freeze the session before exporting")]
    MissingOnchainCommitment,
    #[error("session key is not FROZEN on chain; forensic export is only valid after a freeze")]
    SessionNotFrozen,
    #[error("on-chain action count mismatch: expected {expected}, exported {actual}")]
    ActionCountMismatch { expected: U256, actual: U256 },
    #[error("on-chain rolling hash does not match the frozen forensic commitment")]
    RollingHashMismatch,
    #[error("supplied commitment {supplied} does not match on-chain commitment {onchain}")]
    OnchainCommitmentMismatch { onchain: B256, supplied: B256 },
    #[error("chunk size must be greater than zero")]
    InvalidChunkSize,
    #[error("RPC log is missing {field} metadata")]
    MissingLogMetadata { field: &'static str },
    #[error("event decoding failed: {0}")]
    EventDecode(String),
    #[error(
        "transaction {transaction_hash} has {actions} action events, {decisions} payment decisions, and {intents} payment intents"
    )]
    EventPairMismatch {
        transaction_hash: B256,
        actions: usize,
        decisions: usize,
        intents: usize,
    },
    #[error(
        "action event at log index {action_log_index} does not precede its payment decision at log index {decision_log_index}"
    )]
    EventOrderMismatch {
        action_log_index: u64,
        decision_log_index: u64,
    },
    #[error(
        "payment intent at log index {intent_log_index} does not precede action at log index {action_log_index}"
    )]
    IntentOrderMismatch {
        intent_log_index: u64,
        action_log_index: u64,
    },
    #[error("payment intent and action event data do not match in transaction {transaction_hash}")]
    IntentEventMismatch { transaction_hash: B256 },
    #[error("the RPC response does not include a block timestamp for block {block_number}")]
    MissingBlockTimestamp { block_number: u64 },
    #[error("more than one action has index {0} for this session key")]
    DuplicateActionIndex(u64),
    #[error("no matching actions were found for session key {0}")]
    NoActions(String),
    #[error("output serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("output file operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("verification failed after export: {0}")]
    Verification(#[from] VerificationError),
}

#[derive(Debug, PartialEq, Eq)]
struct VerificationReport {
    action_count: u64,
    final_hash: B256,
}

#[derive(Debug)]
struct ActionEvent {
    index: u64,
    action_hash: B256,
    kind: u8,
    intent_hash: B256,
    block_number: u64,
    block_timestamp: Option<u64>,
    log_index: u64,
}

#[derive(Debug)]
struct PaymentEvent {
    session_key: Address,
    recipient: Address,
    amount: U256,
    allowed: bool,
    log_index: u64,
}

#[derive(Debug)]
struct IntentEvent {
    session_key: Address,
    recipient: Address,
    amount: U256,
    purpose_hash: B256,
    nonce: U256,
    expiry: U256,
    intent_hash: B256,
    log_index: u64,
}

#[derive(Debug, Default)]
struct TransactionEvents {
    actions: Vec<ActionEvent>,
    decisions: Vec<PaymentEvent>,
    intents: Vec<IntentEvent>,
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    match arguments.command {
        Command::Verify(arguments) => {
            match verify_log(arguments.log.as_path(), &arguments.expected_hash) {
                Ok(report) => {
                    print_report(&report);
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("FAIL: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Export(arguments) => match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => match runtime.block_on(export_and_verify(arguments)) {
                Ok(report) => {
                    print_report(&report);
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("FAIL: {error}");
                    ExitCode::FAILURE
                }
            },
            Err(error) => {
                eprintln!("FAIL: could not initialize async runtime: {error}");
                ExitCode::FAILURE
            }
        },
    }
}

fn print_report(report: &VerificationReport) {
    println!("PASS: {} actions verified", report.action_count);
    println!("Final hash: {}", report.final_hash);
}

fn verify_log(path: &Path, expected_hash: &str) -> Result<VerificationReport, VerificationError> {
    let expected = parse_hash(expected_hash, 0, "expected_hash")?;
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();

    for (line_index, line_result) in reader.lines().enumerate() {
        let line_number = line_index + 1;
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }
        let record =
            serde_json::from_str(&line).map_err(|source| VerificationError::InvalidJson {
                line: line_number,
                source,
            })?;
        records.push((line_number, record));
    }

    verify_records(&records, expected)
}

fn verify_records(
    records: &[(usize, ActionRecord)],
    expected: B256,
) -> Result<VerificationReport, VerificationError> {
    let mut previous_hash = B256::ZERO;
    let mut action_count = 0_u64;
    let mut seen_nonces = HashSet::new();
    let mut log_session_key = None;
    let mut log_vault = None;
    let mut previous_timestamp = None;

    for (line_number, record) in records {
        let next_index = action_count + 1;
        if record.index != next_index {
            return Err(VerificationError::InvalidIndex {
                line: *line_number,
                expected: next_index,
                actual: record.index,
            });
        }
        if record.kind > 1 || record.allowed != (record.kind == 0) {
            return Err(VerificationError::DecisionMismatch { line: *line_number });
        }
        if record.chain_id != AEVUM_CHAIN_ID {
            return Err(VerificationError::WrongChain {
                expected: AEVUM_CHAIN_ID,
                actual: record.chain_id,
            });
        }

        let session_key = parse_address(&record.session_key, "session_key", *line_number)?;
        let recipient = parse_address(&record.recipient, "recipient", *line_number)?;
        let amount =
            U256::from_str(&record.amount).map_err(|_| VerificationError::InvalidField {
                line: *line_number,
                field: "amount",
                value: record.amount.clone(),
            })?;
        let vault_address = parse_address(&record.vault_address, "vault_address", *line_number)?;
        let purpose_hash = parse_hash(&record.purpose_hash, *line_number, "purpose_hash")?;
        let recorded_intent_hash = parse_hash(&record.intent_hash, *line_number, "intent_hash")?;
        if session_key == Address::ZERO
            || recipient == Address::ZERO
            || vault_address == Address::ZERO
            || amount.is_zero()
            || amount > U256::from(MAX_TRACKED_AMOUNT)
            || purpose_hash == B256::ZERO
            || recorded_intent_hash == B256::ZERO
        {
            return Err(VerificationError::InvalidIntentFields { line: *line_number });
        }
        if let Some(expected) = log_session_key {
            if expected != session_key {
                return Err(VerificationError::MixedSessionKeys {
                    expected,
                    actual: session_key,
                });
            }
        } else {
            log_session_key = Some(session_key);
        }
        if let Some(expected) = log_vault {
            if expected != vault_address {
                return Err(VerificationError::MixedVaults {
                    expected,
                    actual: vault_address,
                });
            }
        } else {
            log_vault = Some(vault_address);
        }
        let intent_type_hash = alloy::primitives::keccak256(
            b"PaymentIntent(address vault,uint256 chainId,address sessionKey,address recipient,uint256 amount,bytes32 purposeHash,uint256 nonce,uint256 expiry)",
        );
        let nonce = U256::from_str(&record.nonce).map_err(|_| VerificationError::InvalidField {
            line: *line_number,
            field: "nonce",
            value: record.nonce.clone(),
        })?;
        let expiry =
            U256::from_str(&record.expiry).map_err(|_| VerificationError::InvalidField {
                line: *line_number,
                field: "expiry",
                value: record.expiry.clone(),
            })?;
        if expiry < U256::from(record.timestamp) {
            return Err(VerificationError::InvalidIntentFields { line: *line_number });
        }
        if let Some(previous) = previous_timestamp {
            if record.timestamp < previous {
                return Err(VerificationError::TimestampRegression {
                    line: *line_number,
                    previous,
                    current: record.timestamp,
                });
            }
        }
        previous_timestamp = Some(record.timestamp);
        if !seen_nonces.insert(nonce) {
            return Err(VerificationError::DuplicateNonce {
                line: *line_number,
                nonce: record.nonce.clone(),
            });
        }
        let intent_encoded = (
            intent_type_hash,
            vault_address,
            U256::from(record.chain_id),
            session_key,
            recipient,
            amount,
            purpose_hash,
            nonce,
            expiry,
        )
            .abi_encode();
        let computed_intent_hash = alloy::primitives::keccak256(intent_encoded);
        if computed_intent_hash != recorded_intent_hash {
            return Err(VerificationError::IntentHashMismatch {
                line: *line_number,
                expected: recorded_intent_hash,
                actual: computed_intent_hash,
            });
        }

        let encoded = (
            previous_hash,
            session_key,
            recipient,
            amount,
            U256::from(record.timestamp),
            U256::from(record.index),
            alloy::primitives::Uint::<8, 1>::from(record.kind),
            recorded_intent_hash,
        )
            .abi_encode();
        let computed_hash = alloy::primitives::keccak256(encoded);
        let recorded_hash = parse_hash(&record.action_hash, *line_number, "action_hash")?;

        if computed_hash != recorded_hash {
            return Err(VerificationError::ActionHashMismatch {
                line: *line_number,
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

fn parse_hash(value: &str, line: usize, field: &'static str) -> Result<B256, VerificationError> {
    B256::from_str(value).map_err(|_| VerificationError::InvalidField {
        line,
        field,
        value: value.to_owned(),
    })
}

async fn export_and_verify(arguments: ExportArguments) -> Result<VerificationReport, ExportError> {
    let guard_address =
        Address::from_str(&arguments.guard_address).map_err(|_| ExportError::InvalidField {
            field: "guard_address",
            value: arguments.guard_address.clone(),
        })?;
    let session_key =
        Address::from_str(&arguments.session_key).map_err(|_| ExportError::InvalidField {
            field: "session_key",
            value: arguments.session_key.clone(),
        })?;
    let vault_address =
        Address::from_str(&arguments.vault_address).map_err(|_| ExportError::InvalidField {
            field: "vault_address",
            value: arguments.vault_address.clone(),
        })?;
    if guard_address == Address::ZERO
        || session_key == Address::ZERO
        || vault_address == Address::ZERO
    {
        return Err(ExportError::InvalidField {
            field: "address",
            value: "zero address is not valid for export".to_owned(),
        });
    }
    let expected_hash =
        B256::from_str(&arguments.expected_hash).map_err(|_| ExportError::InvalidField {
            field: "expected_hash",
            value: arguments.expected_hash.clone(),
        })?;
    let rpc_url = Url::parse(&arguments.rpc_url).map_err(|_| ExportError::InvalidField {
        field: "rpc_url",
        value: arguments.rpc_url.clone(),
    })?;
    let provider = ProviderBuilder::new().connect_http(rpc_url);
    let chain_id = provider
        .get_chain_id()
        .await
        .map_err(|error| ExportError::Rpc(error.to_string()))?;
    if chain_id != AEVUM_CHAIN_ID {
        return Err(ExportError::WrongChain {
            expected: AEVUM_CHAIN_ID,
            actual: chain_id,
        });
    }

    let guard_contract = IGuardModule::new(guard_address, provider.clone());
    let configured_vault = guard_contract
        .vault()
        .call()
        .await
        .map_err(|error| ExportError::Rpc(error.to_string()))?;
    if configured_vault != vault_address {
        return Err(ExportError::VaultMismatch {
            configured: configured_vault,
            supplied: vault_address,
        });
    }

    let latest_block = provider
        .get_block_number()
        .await
        .map_err(|error| ExportError::Rpc(error.to_string()))?;
    let to_block = arguments.to_block.unwrap_or(latest_block);
    if to_block != latest_block {
        return Err(ExportError::HistoricalExportUnsupported);
    }
    if arguments.from_block > to_block || to_block > latest_block {
        return Err(ExportError::InvalidBlockRange {
            from_block: arguments.from_block,
            to_block,
        });
    }

    if arguments.chunk_size == 0 {
        return Err(ExportError::InvalidChunkSize);
    }

    let mut logs = Vec::new();
    let mut chunk_start = arguments.from_block;
    loop {
        let chunk_end = chunk_start
            .saturating_add(arguments.chunk_size - 1)
            .min(to_block);
        let filter = Filter::new()
            .address(guard_address)
            .from_block(BlockNumberOrTag::Number(chunk_start))
            .to_block(BlockNumberOrTag::Number(chunk_end));
        let mut chunk_logs = provider
            .get_logs(&filter)
            .await
            .map_err(|error| ExportError::Rpc(error.to_string()))?;
        logs.append(&mut chunk_logs);
        if chunk_end == to_block {
            break;
        }
        chunk_start = chunk_end + 1;
    }

    let mut by_transaction: HashMap<B256, TransactionEvents> = HashMap::new();
    for log in logs {
        if log.removed {
            continue;
        }
        let Some(transaction_hash) = log.transaction_hash else {
            return Err(ExportError::MissingLogMetadata {
                field: "transaction_hash",
            });
        };
        let log_index = log
            .log_index
            .ok_or(ExportError::MissingLogMetadata { field: "log_index" })?;
        let transaction = by_transaction.entry(transaction_hash).or_default();

        if log.topic0() == Some(&ActionRecorded::SIGNATURE_HASH) {
            let decoded = log
                .log_decode::<ActionRecorded>()
                .map_err(|error| ExportError::EventDecode(error.to_string()))?;
            let block_number = log.block_number.ok_or(ExportError::MissingLogMetadata {
                field: "block_number",
            })?;
            let index: u64 = decoded.inner.data.index.try_into().map_err(|_| {
                ExportError::EventDecode("action index does not fit in u64".to_owned())
            })?;
            transaction.actions.push(ActionEvent {
                index,
                action_hash: decoded.inner.data.actionHash,
                kind: decoded.inner.data.kind,
                intent_hash: decoded.inner.data.intentHash,
                block_number,
                block_timestamp: log.block_timestamp,
                log_index,
            });
        } else if log.topic0() == Some(&PaymentDecision::SIGNATURE_HASH) {
            let decoded = log
                .log_decode::<PaymentDecision>()
                .map_err(|error| ExportError::EventDecode(error.to_string()))?;
            transaction.decisions.push(PaymentEvent {
                session_key: decoded.inner.data.sessionKey,
                recipient: decoded.inner.data.recipient,
                amount: decoded.inner.data.amount,
                allowed: decoded.inner.data.allowed,
                log_index,
            });
        } else if log.topic0() == Some(&PaymentIntentAuthenticated::SIGNATURE_HASH) {
            let decoded = log
                .log_decode::<PaymentIntentAuthenticated>()
                .map_err(|error| ExportError::EventDecode(error.to_string()))?;
            transaction.intents.push(IntentEvent {
                session_key: decoded.inner.data.sessionKey,
                recipient: decoded.inner.data.recipient,
                amount: decoded.inner.data.amount,
                purpose_hash: decoded.inner.data.purposeHash,
                nonce: decoded.inner.data.nonce,
                expiry: decoded.inner.data.expiry,
                intent_hash: decoded.inner.data.intentHash,
                log_index,
            });
        }
    }

    let mut records_by_index = BTreeMap::new();
    let mut timestamp_cache = HashMap::new();

    for (transaction_hash, mut events) in by_transaction {
        events.actions.sort_by_key(|event| event.log_index);
        events.decisions.sort_by_key(|event| event.log_index);
        events.intents.sort_by_key(|event| event.log_index);
        if events.actions.len() != events.decisions.len()
            || events.actions.len() != events.intents.len()
        {
            return Err(ExportError::EventPairMismatch {
                transaction_hash,
                actions: events.actions.len(),
                decisions: events.decisions.len(),
                intents: events.intents.len(),
            });
        }

        for ((action, decision), intent) in events
            .actions
            .into_iter()
            .zip(events.decisions)
            .zip(events.intents)
        {
            if intent.log_index >= action.log_index {
                return Err(ExportError::IntentOrderMismatch {
                    intent_log_index: intent.log_index,
                    action_log_index: action.log_index,
                });
            }
            if action.log_index >= decision.log_index {
                return Err(ExportError::EventOrderMismatch {
                    action_log_index: action.log_index,
                    decision_log_index: decision.log_index,
                });
            }
            if intent.intent_hash != action.intent_hash
                || intent.session_key != decision.session_key
                || intent.recipient != decision.recipient
                || intent.amount != decision.amount
            {
                return Err(ExportError::IntentEventMismatch { transaction_hash });
            }
            if decision.session_key != session_key {
                continue;
            }

            let timestamp = match action.block_timestamp {
                Some(timestamp) => timestamp,
                None => match timestamp_cache.get(&action.block_number) {
                    Some(timestamp) => *timestamp,
                    None => {
                        let block = provider
                            .get_block_by_number(BlockNumberOrTag::Number(action.block_number))
                            .await
                            .map_err(|error| ExportError::Rpc(error.to_string()))?
                            .ok_or(ExportError::MissingBlockTimestamp {
                                block_number: action.block_number,
                            })?;
                        let timestamp = block.header.inner.timestamp;
                        timestamp_cache.insert(action.block_number, timestamp);
                        timestamp
                    }
                },
            };

            let record = ActionRecord {
                index: action.index,
                session_key: decision.session_key.to_string(),
                recipient: decision.recipient.to_string(),
                amount: decision.amount.to_string(),
                timestamp,
                kind: action.kind,
                allowed: decision.allowed,
                action_hash: action.action_hash.to_string(),
                intent_hash: action.intent_hash.to_string(),
                vault_address: vault_address.to_string(),
                chain_id: AEVUM_CHAIN_ID,
                purpose_hash: intent.purpose_hash.to_string(),
                nonce: intent.nonce.to_string(),
                expiry: intent.expiry.to_string(),
            };
            if records_by_index.insert(action.index, record).is_some() {
                return Err(ExportError::DuplicateActionIndex(action.index));
            }
        }
    }

    if records_by_index.is_empty() {
        return Err(ExportError::NoActions(session_key.to_string()));
    }

    let head_before_state_read = provider
        .get_block_number()
        .await
        .map_err(|error| ExportError::Rpc(error.to_string()))?;
    if head_before_state_read != to_block {
        return Err(ExportError::ChainAdvancedDuringExport {
            expected: to_block,
            actual: head_before_state_read,
        });
    }
    let onchain_stats = guard_contract
        .getSessionStats(session_key)
        .call()
        .await
        .map_err(|error| ExportError::Rpc(error.to_string()))?;
    let head_after_state_read = provider
        .get_block_number()
        .await
        .map_err(|error| ExportError::Rpc(error.to_string()))?;
    if head_after_state_read != to_block {
        return Err(ExportError::ChainAdvancedDuringExport {
            expected: to_block,
            actual: head_after_state_read,
        });
    }
    if onchain_stats.state != 2 {
        return Err(ExportError::SessionNotFrozen);
    }
    if onchain_stats.finalForensicHash == B256::ZERO {
        return Err(ExportError::MissingOnchainCommitment);
    }
    if onchain_stats.rollingHash != onchain_stats.finalForensicHash {
        return Err(ExportError::RollingHashMismatch);
    }
    if onchain_stats.finalForensicHash != expected_hash {
        return Err(ExportError::OnchainCommitmentMismatch {
            onchain: onchain_stats.finalForensicHash,
            supplied: expected_hash,
        });
    }
    let exported_action_count = U256::from(records_by_index.len() as u64);
    if onchain_stats.actionCount != exported_action_count {
        return Err(ExportError::ActionCountMismatch {
            expected: onchain_stats.actionCount,
            actual: exported_action_count,
        });
    }

    let records: Vec<_> = records_by_index
        .into_values()
        .enumerate()
        .map(|(index, record)| (index + 1, record))
        .collect();
    let report = verify_records(&records, expected_hash)?;
    write_jsonl(&arguments.output, &records)?;

    println!(
        "Exported {} actions to {}",
        report.action_count,
        arguments.output.display()
    );
    Ok(report)
}

fn write_jsonl(path: &Path, records: &[(usize, ActionRecord)]) -> Result<(), ExportError> {
    let mut output = String::new();
    for (_, record) in records {
        output.push_str(&serde_json::to_string(record)?);
        output.push('\n');
    }

    let temporary_path = path.with_extension("jsonl.tmp");
    {
        let mut file = File::create(&temporary_path)?;
        file.write_all(output.as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(temporary_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::keccak256;

    fn sample_record() -> Result<ActionRecord, Box<dyn std::error::Error>> {
        let session_key = Address::from([1_u8; 20]);
        let recipient = Address::from([2_u8; 20]);
        let vault_address = Address::from([4_u8; 20]);
        let purpose_hash = B256::from([5_u8; 32]);
        let type_hash = keccak256(
            b"PaymentIntent(address vault,uint256 chainId,address sessionKey,address recipient,uint256 amount,bytes32 purposeHash,uint256 nonce,uint256 expiry)",
        );
        let intent_hash = keccak256(
            (
                type_hash,
                vault_address,
                U256::from(AEVUM_CHAIN_ID),
                session_key,
                recipient,
                U256::from(1_000_000_u64),
                purpose_hash,
                U256::from(9_u64),
                U256::from(1_000_u64),
            )
                .abi_encode(),
        );
        let action_hash = keccak256(
            (
                B256::ZERO,
                session_key,
                recipient,
                U256::from(1_000_000_u64),
                U256::from(1_u64),
                U256::from(1_u64),
                alloy::primitives::Uint::<8, 1>::from(0_u8),
                intent_hash,
            )
                .abi_encode(),
        );

        Ok(ActionRecord {
            index: 1,
            session_key: session_key.to_string(),
            recipient: recipient.to_string(),
            amount: "1000000".to_owned(),
            timestamp: 1,
            kind: 0,
            allowed: true,
            action_hash: action_hash.to_string(),
            intent_hash: intent_hash.to_string(),
            vault_address: vault_address.to_string(),
            chain_id: AEVUM_CHAIN_ID,
            purpose_hash: purpose_hash.to_string(),
            nonce: "9".to_owned(),
            expiry: "1000".to_owned(),
        })
    }

    #[test]
    fn accepts_a_valid_single_action_chain() -> Result<(), Box<dyn std::error::Error>> {
        let record = sample_record()?;
        let expected = B256::from_str(&record.action_hash)?;
        let report = verify_records(&[(1, record)], expected)?;
        assert_eq!(report.action_count, 1);
        assert_eq!(report.final_hash, expected);
        Ok(())
    }

    #[test]
    fn rejects_tampered_action_hash() -> Result<(), Box<dyn std::error::Error>> {
        let mut record = sample_record()?;
        record.action_hash = format!("0x{}", "00".repeat(32));
        let expected = B256::from_str(&record.action_hash)?;
        let result = verify_records(&[(1, record)], expected);
        assert!(matches!(
            result,
            Err(VerificationError::ActionHashMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_decision_kind_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let mut record = sample_record()?;
        record.allowed = false;
        let result = verify_records(&[(1, record)], B256::ZERO);
        assert!(matches!(
            result,
            Err(VerificationError::DecisionMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_reused_intent_nonce() -> Result<(), Box<dyn std::error::Error>> {
        let first = sample_record()?;
        let mut second = sample_record()?;
        second.index = 2;
        let second_hash = keccak256(
            (
                B256::from_str(&first.action_hash)?,
                Address::from_str(&second.session_key)?,
                Address::from_str(&second.recipient)?,
                U256::from_str(&second.amount)?,
                U256::from(2_u64),
                U256::from(2_u64),
                alloy::primitives::Uint::<8, 1>::from(second.kind),
                B256::from_str(&second.intent_hash)?,
            )
                .abi_encode(),
        );
        second.action_hash = second_hash.to_string();
        let expected = second_hash;
        let result = verify_records(&[(1, first), (2, second)], expected);
        assert!(matches!(
            result,
            Err(VerificationError::DuplicateNonce { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_tampered_intent_fields() -> Result<(), Box<dyn std::error::Error>> {
        let mut record = sample_record()?;
        record.purpose_hash = B256::from([6_u8; 32]).to_string();
        let result = verify_records(&[(1, record)], B256::ZERO);
        assert!(matches!(
            result,
            Err(VerificationError::IntentHashMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_empty_log() -> Result<(), Box<dyn std::error::Error>> {
        let result = verify_records(&[], B256::ZERO);
        assert!(matches!(result, Err(VerificationError::EmptyLog)));
        Ok(())
    }

    #[test]
    fn rejects_mixed_session_keys() -> Result<(), Box<dyn std::error::Error>> {
        let first = sample_record()?;
        let mut second = sample_record()?;
        second.index = 2;
        second.session_key = Address::from([9_u8; 20]).to_string();
        let result = verify_records(&[(1, first), (2, second)], B256::ZERO);
        assert!(matches!(
            result,
            Err(VerificationError::MixedSessionKeys { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_mixed_vaults() -> Result<(), Box<dyn std::error::Error>> {
        let first = sample_record()?;
        let mut second = sample_record()?;
        second.index = 2;
        second.vault_address = Address::from([9_u8; 20]).to_string();
        let result = verify_records(&[(1, first), (2, second)], B256::ZERO);
        assert!(matches!(result, Err(VerificationError::MixedVaults { .. })));
        Ok(())
    }

    #[test]
    fn rejects_expiry_before_recorded_block_timestamp() -> Result<(), Box<dyn std::error::Error>> {
        let mut record = sample_record()?;
        record.expiry = "0".to_owned();
        let result = verify_records(&[(1, record)], B256::ZERO);
        assert!(matches!(
            result,
            Err(VerificationError::InvalidIntentFields { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_zero_amount() -> Result<(), Box<dyn std::error::Error>> {
        let mut record = sample_record()?;
        record.amount = "0".to_owned();
        let result = verify_records(&[(1, record)], B256::ZERO);
        assert!(matches!(
            result,
            Err(VerificationError::InvalidIntentFields { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_regressing_timestamps() -> Result<(), Box<dyn std::error::Error>> {
        let first = sample_record()?;
        let mut second = sample_record()?;
        second.index = 2;
        second.timestamp = 0;
        let result = verify_records(&[(1, first), (2, second)], B256::ZERO);
        assert!(matches!(
            result,
            Err(VerificationError::TimestampRegression { .. })
        ));
        Ok(())
    }

    #[test]
    fn reads_jsonl_and_checks_chain() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("valid-actions.jsonl");
        let record = sample_record()?;
        let expected = record.action_hash.clone();
        let mut file = File::create(&path)?;
        writeln!(file, "{}", serde_json::to_string(&record)?)?;

        let report = verify_log(path.as_path(), &expected)?;
        assert_eq!(report.action_count, 1);
        assert_eq!(report.final_hash, B256::from_str(&expected)?);
        Ok(())
    }
}
