//! pegin-request: pegin helper (request + prepare + cancel).
//!
//! Purpose:
//! - request: compose and post a pegin request to GoatChain
//! - prepare: build, sign, and broadcast the pegin deposit tx on Bitcoin
//! - request-prepare: request then wait ~12 minutes before prepare
//! - cancel: build, sign, and broadcast the pegin refund tx on Bitcoin
//!
//! Env:
//! - BITVM_SECRET: node BTC private key (hex or seed:...)
//! - GOAT_PRIVATE_KEY: node GoatNetwork private key
//! - BITCOIN_NETWORK: bitcoin | testnet | testnet4 | signet | regtest
//! - GOAT_CHAIN_URL: GoatNetwork RPC URL
//! - GOAT_GATEWAY_CONTRACT_ADDRESS: Gateway contract address
//!
//! Args:
//! - Most args are optional; use --help for the full list.
//!
//! Example:
//! - cargo run -p bitvm-noded --bin pegin-request -- request-prepare

use alloy::primitives::Address as EvmAddress;
use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{Result, anyhow, bail};
use bitcoin::hashes::Hash;
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::{Address, Amount, key::Keypair};
use bitcoin::{Network, TapSighashType};
use bitvm_lib::types::BitvmGcInstanceParameters;
use clap::{Parser, Subcommand};
use client::btc_chain::BTCClient;
use client::goat_chain::utils::get_gateway_relay_contracts;
use client::goat_chain::{GOATClient, GoatInitConfig, GoatNetwork, Utxo as ClientUtxo};
use dotenv::dotenv;
use goat::connectors::base::TaprootConnector;
use goat::transactions::pre_signed::{PreSignedTransaction, pre_sign_taproot_input_default};
use reqwest::Url;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::time::Duration;
use tokio::time::sleep;
use tracing_subscriber::EnvFilter;

use bitvm_noded::env::{
    ENV_BITCOIN_NETWORK, ENV_BITVM_SECRET, ENV_GOAT_ADDRESS, get_goat_network,
    get_node_goat_address, goat_config_from_env, parse_bitcoin_network,
};
use bitvm_noded::utils::{
    broadcast_tx, get_fee_rate, get_proper_utxo_set, node_p2wsh_address, node_sign,
};

const PEGIN_PREPARE_BASE_VBYTES: u64 = 200;
const PEGIN_REFUND_EST_VBYTES: u64 = 300;
const PEGIN_CONFIRM_EST_VBYTES: u64 = 300;
const REQUEST_PREPARE_WAIT_MINUTES: u64 = 12;

#[derive(Parser)]
#[command(name = "send-pegin", version, about = "Pegin helper (request + prepare)")]
struct Args {
    #[command(subcommand)]
    command: Commands,

    /// Bitcoin network
    #[arg(long, env = ENV_BITCOIN_NETWORK, default_value = "testnet4")]
    network: String,

    /// Esplora base URL (for Bitcoin RPC via Esplora)
    #[arg(long, default_value = "https://mempool.space/testnet4/api")]
    esplora_url: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Post a pegin request to GoatChain
    Request {
        /// The instance id (UUID) for this pegin, optional (generated if not provided)
        #[arg(long)]
        instance_id: Option<String>,
        /// Pegin amount in satoshis, default 1000000 sats (0.01 BTC)
        #[arg(long, default_value = "1000000")]
        pegin_amount_sats: u64,
        /// Optional user's BTC key to derive addresses and select UTXOs, otherwise read from ENV_BITVM_SECRET
        #[arg(long, env = ENV_BITVM_SECRET)]
        user_btc_secret: String,
        /// Optional fees rate in sat/vbyte to compute deposit/confirm/refund fees, otherwise get from api
        #[arg(long)]
        fee_rate: Option<f64>,
        /// Optional explicit change address; default derived from user key (p2wsh)
        #[arg(long)]
        user_change_address: Option<String>,
        /// Optional explicit refund address; default derived from user key (p2wsh)
        #[arg(long)]
        user_refund_address: Option<String>,
        /// Optional explicit EVM receiver (0x...), otherwise read from env
        #[arg(long)]
        receiver_evm_address: Option<String>,
    },
    /// Build, sign and broadcast the pegin deposit transaction on Bitcoin
    Prepare {
        /// The instance id (UUID) used in the request
        #[arg(long)]
        instance_id: String,
        /// Optional user's BTC key to derive addresses and select UTXOs, otherwise read from ENV_BITVM_SECRET
        #[arg(long, env = ENV_BITVM_SECRET)]
        user_btc_secret: String,
    },
    /// Post a pegin request and automatically prepare after waiting ~12 minutes
    RequestPrepare {
        /// The instance id (UUID) for this pegin, optional (generated if not provided)
        #[arg(long)]
        instance_id: Option<String>,
        /// Pegin amount in satoshis, default 1000000 sats (0.01 BTC)
        #[arg(long, default_value = "1000000")]
        pegin_amount_sats: u64,
        /// Optional user's BTC key to derive addresses and select UTXOs, otherwise read from ENV_BITVM_SECRET
        #[arg(long, env = ENV_BITVM_SECRET)]
        user_btc_secret: String,
        /// Optional fees rate in sat/vbyte to compute deposit/confirm/refund fees, otherwise get from api
        #[arg(long)]
        fee_rate: Option<f64>,
        /// Optional explicit change address; default derived from user key (p2wsh)
        #[arg(long)]
        user_change_address: Option<String>,
        /// Optional explicit refund address; default derived from user key (p2wsh)
        #[arg(long)]
        user_refund_address: Option<String>,
        /// Optional explicit EVM receiver (0x...), otherwise read from env
        #[arg(long)]
        receiver_evm_address: Option<String>,
        /// Minutes to wait between request completion and prepare submission
        #[arg(long, default_value_t = REQUEST_PREPARE_WAIT_MINUTES)]
        wait_minutes: u64,
    },
    /// Build, sign and broadcast the pegin cancel (refund) transaction on Bitcoin
    Cancel {
        /// The instance id (UUID) used in the request
        #[arg(long)]
        instance_id: String,
        /// Optional user's BTC key to derive addresses and select UTXOs, otherwise read from ENV_BITVM_SECRET
        #[arg(long, env = ENV_BITVM_SECRET)]
        user_btc_secret: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let args = Args::parse();
    let network = parse_bitcoin_network(&args.network)?;
    // Addresses are also checked by node code that reads BITCOIN_NETWORK; both must agree.
    if let Ok(configured) = std::env::var(ENV_BITCOIN_NETWORK)
        && parse_bitcoin_network(&configured)? != network
    {
        bail!("--network {} disagrees with {ENV_BITCOIN_NETWORK}={configured}", args.network);
    }
    let btc_client = BTCClient::new(network, Some(&args.esplora_url));

    let goat_client = {
        let cfg = goat_config_from_env().await;
        let goat_net = get_goat_network();
        GOATClient::new(cfg, goat_net)
    };

    match args.command {
        Commands::Request {
            instance_id,
            pegin_amount_sats,
            user_btc_secret,
            fee_rate,
            user_change_address,
            user_refund_address,
            receiver_evm_address,
        } => action_request(
            network,
            &btc_client,
            &goat_client,
            instance_id.as_deref(),
            pegin_amount_sats,
            &user_btc_secret,
            fee_rate,
            user_change_address.as_deref(),
            user_refund_address.as_deref(),
            receiver_evm_address.as_deref(),
        )
        .await
        .map(|_| ()),
        Commands::Prepare { instance_id, user_btc_secret } => {
            action_prepare(network, &btc_client, &goat_client, &instance_id, &user_btc_secret).await
        }
        Commands::RequestPrepare {
            instance_id,
            pegin_amount_sats,
            user_btc_secret,
            fee_rate,
            user_change_address,
            user_refund_address,
            receiver_evm_address,
            wait_minutes,
        } => {
            let uuid = action_request(
                network,
                &btc_client,
                &goat_client,
                instance_id.as_deref(),
                pegin_amount_sats,
                &user_btc_secret,
                fee_rate,
                user_change_address.as_deref(),
                user_refund_address.as_deref(),
                receiver_evm_address.as_deref(),
            )
            .await?;
            let wait_secs = wait_minutes.saturating_mul(60);
            tracing::info!(
                "Request complete. Waiting {} minutes before broadcasting prepare transaction...",
                wait_minutes
            );
            sleep(Duration::from_secs(wait_secs)).await;

            let uuid_str = uuid.to_string();
            action_prepare(network, &btc_client, &goat_client, &uuid_str, &user_btc_secret).await
        }
        Commands::Cancel { instance_id, user_btc_secret } => {
            action_cancel(&btc_client, &goat_client, &instance_id, &user_btc_secret).await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn action_request(
    network: Network,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    instance_id_str: Option<&str>,
    pegin_amount_sats: u64,
    user_btc_secret: &str,
    fee_rate: Option<f64>,
    user_change_address: Option<&str>,
    user_refund_address: Option<&str>,
    receiver_evm_address: Option<&str>,
) -> Result<uuid::Uuid> {
    let instance_id = match instance_id_str {
        Some(s) => uuid::Uuid::from_str(s).map_err(|e| anyhow!("invalid instance_id {s}: {e}"))?,
        None => uuid::Uuid::new_v4(),
    };

    let user_btc_secret = if !user_btc_secret.starts_with("seed:") {
        user_btc_secret
    } else {
        let hashed = Sha256::digest(user_btc_secret.as_bytes());
        let sk = secp256k1::SecretKey::from_slice(&hashed).expect("valid secret key");
        &hex::encode(sk.secret_bytes()).to_string()
    };
    let user_keypair = Keypair::from_seckey_str_global(user_btc_secret)?;
    let user_xonly = user_keypair.public_key().x_only_public_key().0;
    let user_address = node_p2wsh_address(network, &user_keypair.public_key().into());

    let change_addr = match user_change_address {
        Some(s) => Address::from_str(s)?.require_network(network)?,
        None => user_address.clone(),
    };
    let refund_addr = match user_refund_address {
        Some(s) => Address::from_str(s)?.require_network(network)?,
        None => user_address.clone(),
    };

    // Compute default fees or parse overrides
    let fee_rate = match fee_rate {
        Some(r) => r,
        None => get_fee_rate(btc_client).await?,
    };

    // Select UTXOs from user's address sufficient to cover pegin_amount + deposit fee
    let pegin_confirm_fee = (PEGIN_CONFIRM_EST_VBYTES as f64 * fee_rate).ceil() as u64;
    let pegin_refund_fee = (PEGIN_REFUND_EST_VBYTES as f64 * fee_rate).ceil() as u64;
    let target = Amount::from_sat(pegin_amount_sats + pegin_confirm_fee);
    let (utxos, pegin_prepare_fee, _) = get_proper_utxo_set(
        btc_client,
        PEGIN_PREPARE_BASE_VBYTES,
        user_address.clone(),
        target,
        fee_rate,
    )
    .await?
    .ok_or_else(|| anyhow!("insufficient funds in address {user_address}"))?;
    let fees = [pegin_prepare_fee.to_sat(), pegin_confirm_fee, pegin_refund_fee];

    // Convert to client Utxo
    let user_inputs: Vec<ClientUtxo> = utxos
        .iter()
        .map(|i| ClientUtxo {
            txid: i.outpoint.txid.to_byte_array(),
            vout: i.outpoint.vout,
            amount_sats: i.amount.to_sat(),
        })
        .collect();

    // Derive EVM receiver address
    let receiver_evm_address = match receiver_evm_address {
        Some(s) => {
            let parsed = alloy::primitives::Address::from_str(s)
                .map_err(|_| anyhow!("invalid EVM receiver address: {s}"))?;
            parsed.into_array()
        }
        None => get_node_goat_address()
            .ok_or_else(|| {
                anyhow!("EVM receiver address not provided and {ENV_GOAT_ADDRESS} not set")
            })?
            .into_array(),
    };

    let tx_hash = goat_client
        .gateway_post_pegin_request(
            &instance_id,
            pegin_amount_sats,
            &fees,
            &receiver_evm_address,
            &user_inputs,
            &user_xonly.serialize(),
            &change_addr.to_string(),
            &refund_addr.to_string(),
        )
        .await?;

    tracing::info!("Pegin request posted. instance_id: {instance_id}, goat tx: {tx_hash}");
    Ok(instance_id)
}

async fn action_prepare(
    _network: Network,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    instance_id_str: &str,
    user_btc_secret: &str,
) -> Result<()> {
    let instance_id = uuid::Uuid::from_str(instance_id_str)
        .map_err(|e| anyhow!("invalid instance_id {instance_id_str}: {e}"))?;

    let user_btc_secret = if !user_btc_secret.starts_with("seed:") {
        user_btc_secret
    } else {
        let hashed = Sha256::digest(user_btc_secret.as_bytes());
        let sk = secp256k1::SecretKey::from_slice(&hashed).expect("valid secret key");
        &hex::encode(sk.secret_bytes()).to_string()
    };
    let user_keypair = Keypair::from_seckey_str_global(user_btc_secret)?;

    let instance_params: BitvmGcInstanceParameters =
        bitvm_noded::utils::read_instance_info_from_goat(goat_client, instance_id).await?;

    // Build pegin deposit/confirm/refund transactions
    let (mut pegin_deposit, _confirm, _refund) = instance_params.build_pegin_tx()?;

    for i in 0..pegin_deposit.tx().input.len() {
        let input_value = pegin_deposit.input_amounts[i];
        node_sign(pegin_deposit.tx_mut(), i, input_value, EcdsaSighashType::All, &user_keypair)?;
    }

    // Broadcast deposit
    broadcast_tx(btc_client, pegin_deposit.tx()).await?;
    tracing::info!("Broadcasted pegin prepare tx: {}", pegin_deposit.tx().compute_txid());
    Ok(())
}

async fn action_cancel(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    instance_id_str: &str,
    user_btc_secret: &str,
) -> Result<()> {
    let instance_id = uuid::Uuid::from_str(instance_id_str)
        .map_err(|e| anyhow!("invalid instance_id {instance_id_str}: {e}"))?;

    let user_btc_secret = if !user_btc_secret.starts_with("seed:") {
        user_btc_secret
    } else {
        let hashed = Sha256::digest(user_btc_secret.as_bytes());
        let sk = secp256k1::SecretKey::from_slice(&hashed).expect("valid secret key");
        &hex::encode(sk.secret_bytes()).to_string()
    };
    let user_keypair = Keypair::from_seckey_str_global(user_btc_secret)?;

    let instance_params: BitvmGcInstanceParameters =
        bitvm_noded::utils::read_instance_info_from_goat(goat_client, instance_id).await?;

    // Build pegin deposit/confirm/refund transactions and pick the refund (cancel)
    let (_deposit, _confirm, mut pegin_refund) = instance_params.build_pegin_tx()?;

    let connector_z = instance_params.connector_z();
    pre_sign_taproot_input_default(
        &mut pegin_refund,
        0,
        TapSighashType::All,
        connector_z.generate_taproot_spend_info(),
        &vec![&user_keypair],
    );

    // Broadcast refund (cancel)
    broadcast_tx(btc_client, pegin_refund.tx()).await?;
    tracing::info!("Broadcasted pegin cancel/refund tx: {}", pegin_refund.tx().compute_txid());
    Ok(())
}

#[allow(dead_code)]
async fn build_goat_client(
    rpc_url: Url,
    goat_network: GoatNetwork,
    gateway_address: EvmAddress,
    private_key: &str,
) -> GOATClient {
    let provider = ProviderBuilder::new().connect_http(rpc_url.clone());
    let chain_id = provider
        .get_chain_id()
        .await
        .unwrap_or_else(|_| panic!("cannot get chain_id from {rpc_url}")) as u32;

    let (committee_management_address, stake_management_address, btc_spv_address, peg_btc_address) =
        get_gateway_relay_contracts(&provider, gateway_address)
            .await
            .expect("fail to get committee and stake management contract online addresses");

    let cfg = GoatInitConfig {
        rpc_url,
        chain_id,
        private_key: Some(private_key.to_string()),
        gateway_address: Some(gateway_address),
        sequencer_set_publisher_address: None,
        committee_management_address: Some(committee_management_address),
        stake_management_address: Some(stake_management_address),
        multi_sig_verifier_address: None,
        btc_spv_address: Some(btc_spv_address),
        peg_btc_address: Some(peg_btc_address),
    };

    GOATClient::new(cfg, goat_network)
}
