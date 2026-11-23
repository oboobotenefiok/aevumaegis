use std::{str::FromStr, time::Duration};

use {
    alloy::{
        eips::BlockNumberOrTag,
        network::{EthereumWallet, ReceiptResponse},
        primitives::{keccak256, Address, B256, U256},
        providers::{Provider, ProviderBuilder},
        signers::{local::PrivateKeySigner, Signer},
        sol,
        sol_types::SolValue,
    },
    clap::{Parser, ValueEnum},
    thiserror::Error,
    url::Url,
    IAgentVault::IAgentVaultInstance,
    IGuardModule::IGuardModuleInstance,
    IERC20::IERC20Instance,
};

const AEVUM_CHAIN_ID: u64 = 44_005;
const PAYMENT_INTENT_TYPE: &str = "PaymentIntent(address vault,uint256 chainId,address sessionKey,address recipient,uint256 amount,bytes32 purposeHash,uint256 nonce,uint256 expiry)";
const PAYMENT_PURPOSE: &str = "aevumaegis:demo-invoice";

sol! {
    struct PaymentIntent {
        address recipient;
        uint256 amount;
        bytes32 purposeHash;
        uint256 nonce;
        uint256 expiry;
    }

    #[sol(rpc)]
    interface IAgentVault {
        function pay(PaymentIntent calldata intent, bytes calldata signature) external returns (bool allowed);
        function sessionKey() external view returns (address);
        function guard() external view returns (address);
        function token() external view returns (address);
    }

    #[sol(rpc)]
    interface IGuardModule {
        function vault() external view returns (address);
        function getSessionState(address sessionKey) external view returns (uint8);
        function getActionCount(address sessionKey) external view returns (uint256);
        function getFinalForensicHash(address sessionKey) external view returns (bytes32);
        function authorizedPurposeAmount(address recipient, bytes32 purposeHash) external view returns (uint256);
    }

    #[sol(rpc)]
    interface IERC20 {
        function balanceOf(address account) external view returns (uint256);
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "aevumaegis-agent",
    about = "Drive legitimate and adversarial Aevumaegis payment scenarios"
)]
struct Arguments {
    #[arg(long, default_value = "https://rpc-test.qday.info")]
    rpc_url: Url,

    #[arg(long)]
    vault: Address,

    #[arg(long)]
    session_private_key: String,

    #[arg(long)]
    supplier: Address,

    #[arg(long)]
    attacker: Address,

    #[arg(long, value_enum, default_value_t = DemoMode::Demo)]
    mode: DemoMode,

    #[arg(long, default_value_t = 1_000_000)]
    payment_amount: u64,

    #[arg(long, default_value_t = 20_000_000)]
    drain_amount: u64,

    #[arg(long, default_value_t = 0)]
    starting_nonce: u64,

    #[arg(long)]
    purpose_hash: Option<B256>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum DemoMode {
    Demo,
    Legit,
    Velocity,
    Drain,
}

#[derive(Debug, Error)]
enum SimulatorError {
    #[error("invalid session private key: {0}")]
    InvalidPrivateKey(String),
    #[error("transaction submission failed: {0}")]
    Transaction(String),
    #[error("transaction confirmation failed: {0}")]
    Confirmation(String),
    #[error("intent signing failed: {0}")]
    Signing(String),
    #[error("latest Aevum block is unavailable")]
    LatestBlockUnavailable,
    #[error("Aevum block lookup failed: {0}")]
    BlockLookup(String),
    #[error("transaction receipt lookup failed: {0}")]
    ReceiptLookup(String),
    #[error("timed out waiting for transaction {0}")]
    ConfirmationTimeout(B256),
    #[error("transaction reverted: {0}")]
    TransactionReverted(B256),
    #[error("unexpected guard state: expected {expected}, got {actual}")]
    UnexpectedGuardState { expected: u8, actual: u8 },
    #[error("drain attempt transferred tokens to the attacker")]
    DrainTransferredTokens,
    #[error("velocity burst transferred an unexpected amount to the supplier")]
    UnexpectedVelocityTransfers,
    #[error("frozen session has no forensic commitment")]
    MissingForensicCommitment,
    #[error("demo mode requires a fresh session with zero recorded actions")]
    SessionNotFresh,
    #[error("recipient purpose authorization cap is below the requested demo amount")]
    PurposeAmountCap,
    #[error("supplier and attacker addresses must be distinct in demo mode")]
    CounterpartiesMustDiffer,
    #[error("refusing to use chain ID {0}; expected Aevum testnet 44005")]
    UnexpectedChainId(u64),
    #[error("session key mismatch: vault expects {configured}, supplied signer is {supplied}")]
    UnexpectedSessionKey {
        configured: Address,
        supplied: Address,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse();
    let signer = PrivateKeySigner::from_str(&arguments.session_private_key)
        .map_err(|error| SimulatorError::InvalidPrivateKey(error.to_string()))?
        .with_chain_id(Some(AEVUM_CHAIN_ID));
    let session_key = signer.address();
    let wallet = EthereumWallet::from(signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(arguments.rpc_url);
    let chain_id = provider.get_chain_id().await?;
    if chain_id != AEVUM_CHAIN_ID {
        return Err(SimulatorError::UnexpectedChainId(chain_id).into());
    }
    let vault = IAgentVault::new(arguments.vault, provider.clone());
    let guard_address = vault.guard().call().await?;
    let token_address = vault.token().call().await?;
    let guard = IGuardModule::new(guard_address, provider.clone());
    let token = IERC20::new(token_address, provider.clone());
    let configured_vault = guard.vault().call().await?;
    if configured_vault != arguments.vault {
        return Err(SimulatorError::GuardVaultMismatch);
    }
    let configured_session_key = vault.sessionKey().call().await?;
    if configured_session_key != session_key {
        return Err(SimulatorError::UnexpectedSessionKey {
            configured: configured_session_key,
            supplied: session_key,
        }
        .into());
    }
    let purpose_hash = match arguments.purpose_hash {
        Some(hash) => hash,
        None => keccak256(PAYMENT_PURPOSE.as_bytes()),
    };
    if arguments.mode == DemoMode::Demo {
        if arguments.supplier == arguments.attacker {
            return Err(SimulatorError::CounterpartiesMustDiffer);
        }
        let action_count = guard
            .getActionCount(session_key)
            .call()
            .await
            .map_err(|error| SimulatorError::Transaction(error.to_string()))?;
        let supplier_cap = guard
            .authorizedPurposeAmount(arguments.supplier, purpose_hash)
            .call()
            .await
            .map_err(|error| SimulatorError::Transaction(error.to_string()))?;
        let attacker_cap = guard
            .authorizedPurposeAmount(arguments.attacker, purpose_hash)
            .call()
            .await
            .map_err(|error| SimulatorError::Transaction(error.to_string()))?;
        if !action_count.is_zero() {
            return Err(SimulatorError::SessionNotFresh);
        }
        if supplier_cap < U256::from(arguments.payment_amount)
            || attacker_cap < U256::from(arguments.drain_amount)
        {
            return Err(SimulatorError::PurposeAmountCap);
        }
    }
    let mut payments = PaymentClient {
        vault: &vault,
        guard: &guard,
        token: &token,
        provider: &provider,
        signer: &signer,
        vault_address: arguments.vault,
        session_key,
        next_nonce: arguments.starting_nonce,
        purpose_hash,
        pending_transactions: Vec::new(),
    };

    println!("Session key: {session_key}");
    println!("Intent purpose: {purpose_hash}");

    match arguments.mode {
        DemoMode::Legit => {
            payments
                .run_payments(
                    arguments.supplier,
                    arguments.payment_amount,
                    5,
                    Duration::from_secs(4),
                )
                .await?;
        }
        DemoMode::Velocity => {
            tokio::time::sleep(Duration::from_secs(11)).await;
            payments
                .run_payments(
                    arguments.supplier,
                    arguments.payment_amount,
                    4,
                    Duration::ZERO,
                )
                .await?;
            payments.wait_for_pending_transactions().await?;
            payments.require_guard_state(1).await?;
        }
        DemoMode::Drain => {
            payments
                .submit_payment(arguments.attacker, arguments.drain_amount, true)
                .await?;
        }
        DemoMode::Demo => {
            println!("ACT 1: legitimate agent");
            payments
                .run_payments(
                    arguments.supplier,
                    arguments.payment_amount,
                    5,
                    Duration::from_secs(4),
                )
                .await?;
            println!("Waiting for the velocity window to expire");
            tokio::time::sleep(Duration::from_secs(11)).await;
            println!("ACT 2: six attempts planned; submit up to four and stop at the first throttle");
            let supplier_balance_before = payments.token_balance(arguments.supplier).await?;
            payments
                .run_payments(
                    arguments.supplier,
                    arguments.payment_amount,
                    4,
                    Duration::ZERO,
                )
                .await?;
            payments.wait_for_pending_transactions().await?;
            payments.require_guard_state(1).await?;
            let supplier_balance_after = payments.token_balance(arguments.supplier).await?;
            let expected_supplier_balance =
                supplier_balance_before + U256::from(arguments.payment_amount) * U256::from(3_u64);
            if supplier_balance_after != expected_supplier_balance {
                return Err(SimulatorError::UnexpectedVelocityTransfers);
            }
            println!("ACT 3: drain attempt to a novel, authorized counterparty");
            let attacker_balance_before = payments.token_balance(arguments.attacker).await?;
            payments
                .submit_payment(arguments.attacker, arguments.drain_amount, true)
                .await?;
            let attacker_balance_after = payments.token_balance(arguments.attacker).await?;
            if attacker_balance_after != attacker_balance_before {
                return Err(SimulatorError::DrainTransferredTokens);
            }
            payments.require_guard_state(2).await?;
            let forensic_hash = payments
                .guard
                .getFinalForensicHash(payments.session_key)
                .call()
                .await
                .map_err(|error| SimulatorError::Transaction(error.to_string()))?;
            if forensic_hash == B256::ZERO {
                return Err(SimulatorError::MissingForensicCommitment);
            }
            println!("Verified FROZEN state and forensic commitment {forensic_hash}");
            println!("ACT 4: run scripts/rearm.sh with the owner and sentinel keys after confirming the freeze.");
        }
    }

    Ok(())
}

struct PaymentClient<'a, P> {
    vault: &'a IAgentVaultInstance<P>,
    guard: &'a IGuardModuleInstance<P>,
    token: &'a IERC20Instance<P>,
    provider: &'a P,
    signer: &'a PrivateKeySigner,
    vault_address: Address,
    session_key: Address,
    next_nonce: u64,
    purpose_hash: B256,
    pending_transactions: Vec<B256>,
}

impl<'a, P> PaymentClient<'a, P>
where
    P: alloy::providers::Provider + Clone,
{
    async fn run_payments(
        &mut self,
        recipient: Address,
        amount: u64,
        count: usize,
        delay: Duration,
    ) -> Result<(), SimulatorError> {
        for attempt in 1..=count {
            println!("Payment attempt {attempt}/{count}");
            self.submit_payment(recipient, amount, !delay.is_zero()).await?;
            if !delay.is_zero() && attempt < count {
                tokio::time::sleep(delay).await;
            }
        }
        Ok(())
    }

    async fn wait_for_pending_transactions(&mut self) -> Result<(), SimulatorError> {
        let pending_transactions = std::mem::take(&mut self.pending_transactions);
        for transaction_hash in pending_transactions {
            let mut confirmed = false;
            for _ in 0..600 {
                let receipt = self
                    .provider
                    .get_transaction_receipt(transaction_hash)
                    .await
                    .map_err(|error| SimulatorError::ReceiptLookup(error.to_string()))?;
                if let Some(receipt) = receipt {
                    if !receipt.status() {
                        return Err(SimulatorError::TransactionReverted(transaction_hash));
                    }
                    confirmed = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            if !confirmed {
                return Err(SimulatorError::ConfirmationTimeout(transaction_hash));
            }
        }
        Ok(())
    }

    async fn require_guard_state(&self, expected: u8) -> Result<(), SimulatorError> {
        let actual = self
            .guard
            .getSessionState(self.session_key)
            .call()
            .await
            .map_err(|error| SimulatorError::Transaction(error.to_string()))?;
        if actual != expected {
            return Err(SimulatorError::UnexpectedGuardState { expected, actual });
        }
        Ok(())
    }

    async fn token_balance(&self, account: Address) -> Result<U256, SimulatorError> {
        self.token
            .balanceOf(account)
            .call()
            .await
            .map_err(|error| SimulatorError::Transaction(error.to_string()))
    }

    async fn submit_payment(
        &mut self,
        recipient: Address,
        amount: u64,
        wait_for_receipt: bool,
    ) -> Result<(), SimulatorError> {
        let latest_block = self
            .provider
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await
            .map_err(|error| SimulatorError::BlockLookup(error.to_string()))?
            .ok_or(SimulatorError::LatestBlockUnavailable)?;
        let timestamp = latest_block.header.inner.timestamp;
        let intent = PaymentIntent {
            recipient,
            amount: U256::from(amount),
            purposeHash: self.purpose_hash,
            nonce: U256::from(self.next_nonce),
            expiry: U256::from(timestamp.saturating_add(86_400)),
        };
        let intent_digest = keccak256(
            (
                keccak256(PAYMENT_INTENT_TYPE.as_bytes()),
                self.vault_address,
                U256::from(AEVUM_CHAIN_ID),
                self.signer.address(),
                intent.recipient,
                intent.amount,
                intent.purposeHash,
                intent.nonce,
                intent.expiry,
            )
                .abi_encode(),
        );
        let signature = self
            .signer
            .sign_hash(&intent_digest)
            .await
            .map_err(|error| SimulatorError::Signing(error.to_string()))?;
        let pending = self
            .vault
            .pay(intent, signature.as_bytes().to_vec().into())
            .send()
            .await
            .map_err(|error| SimulatorError::Transaction(error.to_string()))?;
        let transaction_hash_value = *pending.tx_hash();
        let transaction_hash = transaction_hash_value.to_string();
        if wait_for_receipt {
            let receipt = pending
                .get_receipt()
                .await
                .map_err(|error| SimulatorError::Confirmation(error.to_string()))?;
            if !receipt.status() {
                return Err(SimulatorError::TransactionReverted(transaction_hash_value));
            }
            println!("Confirmed transaction {transaction_hash} for intent nonce {}.", self.next_nonce);
        } else {
            self.pending_transactions.push(transaction_hash_value);
            println!("Submitted transaction {transaction_hash} for intent nonce {}.", self.next_nonce);
        }
        self.next_nonce = self.next_nonce.saturating_add(1);
        Ok(())
    }
}
