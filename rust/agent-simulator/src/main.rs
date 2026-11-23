use std::{str::FromStr, time::Duration};

use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use clap::{Parser, ValueEnum};
use thiserror::Error;
use url::Url;
use IAgentVault::IAgentVaultInstance;

sol! {
    #[sol(rpc)]
    interface IAgentVault {
        function pay(address recipient, uint256 amount) external returns (bool allowed);
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
}

#[derive(Clone, Copy, Debug, ValueEnum)]
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
    #[error("refusing to use chain ID {0}; expected Aevum testnet 44005")]
    UnexpectedChainId(u64),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse();
    let signer = PrivateKeySigner::from_str(&arguments.session_private_key)
        .map_err(|error| SimulatorError::InvalidPrivateKey(error.to_string()))?
        .with_chain_id(Some(44_005));
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(arguments.rpc_url);
    let chain_id = provider.get_chain_id().await?;
    if chain_id != 44_005 {
        return Err(SimulatorError::UnexpectedChainId(chain_id).into());
    }
    let vault = IAgentVault::new(arguments.vault, provider);

    match arguments.mode {
        DemoMode::Legit => {
            run_payments(&vault, arguments.supplier, arguments.payment_amount, 5, Duration::from_secs(1)).await?;
        }
        DemoMode::Velocity => {
            tokio::time::sleep(Duration::from_secs(11)).await;
            run_payments(&vault, arguments.supplier, arguments.payment_amount, 6, Duration::ZERO).await?;
        }
        DemoMode::Drain => {
            submit_payment(&vault, arguments.attacker, arguments.drain_amount).await?;
        }
        DemoMode::Demo => {
            println!("ACT 1: legitimate agent");
            run_payments(&vault, arguments.supplier, arguments.payment_amount, 5, Duration::from_secs(1)).await?;
            println!("Waiting for the velocity window to expire");
            tokio::time::sleep(Duration::from_secs(11)).await;
            println!("ACT 2: velocity attack");
            run_payments(&vault, arguments.supplier, arguments.payment_amount, 6, Duration::ZERO).await?;
            println!("ACT 3: drain attempt to a novel recipient");
            submit_payment(&vault, arguments.attacker, arguments.drain_amount).await?;
            println!("ACT 4: perform quorum re-arm and sentinel veto using the owner workflow.");
        }
    }

    Ok(())
}

async fn run_payments<P>(
    vault: &IAgentVaultInstance<P>,
    recipient: Address,
    amount: u64,
    count: usize,
    delay: Duration,
) -> Result<(), SimulatorError>
where
    P: alloy::providers::Provider + Clone,
{
    for attempt in 1..=count {
        println!("Payment attempt {attempt}/{count}");
        submit_payment(vault, recipient, amount).await?;
        if !delay.is_zero() && attempt < count {
            tokio::time::sleep(delay).await;
        }
    }
    Ok(())
}

async fn submit_payment<P>(
    vault: &IAgentVaultInstance<P>,
    recipient: Address,
    amount: u64,
) -> Result<(), SimulatorError>
where
    P: alloy::providers::Provider + Clone,
{
    let pending = vault
        .pay(recipient, U256::from(amount))
        .send()
        .await
        .map_err(|error| SimulatorError::Transaction(error.to_string()))?;
    let transaction_hash = pending.tx_hash().to_string();
    println!("Submitted {transaction_hash}; inspect the explorer for its event outcome.");
    Ok(())
}
