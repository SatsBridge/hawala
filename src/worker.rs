use anyhow::Error;
use hex;
use log::{debug, error, info};

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{ops::Div, str::FromStr};
use std::ptr::addr_of;
use tokio::sync::broadcast::Sender;
use tokio::time::timeout;
use tokio::time::{self};

use cln_aleph::model::{Notification, PluginState};
use cln_aleph::rpc::{make_rpc_path, pay_invoice};
use cln_plugin::Plugin;

use cln_rpc::{
    model::{requests::PayRequest, responses::PayResponse},
    ClnRpc, Request, Response,
};
use serde::Serialize;
use std::sync::Arc;

use sp_keyring::AccountKeyring;
use sp_runtime::MultiAddress;
use sp_weights::Weight;
use sp_core::{
    crypto::{AccountId32, Pair, Ss58Codec},
    sr25519,
};
use substrate_api_client::{
    ac_node_api::StaticEvent,
    ac_compose_macros::{compose_call, compose_extrinsic},
    ac_primitives::{AssetRuntimeConfig, Config, ExtrinsicSigner as GenericExtrinsicSigner},
    api_client::UpdateRuntime,
    extrinsic::{BalancesExtrinsics, ContractsExtrinsics},
    rpc::{TungsteniteRpcClient, HandleSubscription},
    rpc_api::RuntimeUpdateDetector,
    Api, GetAccountInformation, GetChainInfo, SubscribeChain, SubmitAndWatch, SubscribeEvents, XtStatus,
};
use substrate_api_client::ac_primitives::ExtrinsicSigner;


pub async fn events_worker(plugin: Plugin<PluginState>) -> Result<(), Error> {
    time::sleep(Duration::from_secs(3)).await;
    let sleep_time = plugin.state().sleep_time;
    debug!("Creating Aleph Zero Tungstenite API instance");
    let mut api = Api::<AssetRuntimeConfig, _>::new(plugin.state().aleph_node.clone()).unwrap();
    info!("Subscribing to finalized heads");
    let mut subscription = api.subscribe_finalized_heads().unwrap();
    loop {
        match subscription.next().unwrap() {
            Ok(head) => {
                //debug!("New Aleph block {} - {}", head.number, head.parent_hash);
                time::sleep(Duration::from_secs(1 as u64)).await;
            }
            _ => {
                //debug!("No chain events. Listener sleeps");
                time::sleep(Duration::from_secs(sleep_time)).await;
            }
        };
    }
    //Ok(())
}

pub async fn control_worker(
    plugin: Plugin<PluginState>,
    notification_sender: Sender<Notification>,
) -> Result<(), Error> {
    let mut notification_receiver = notification_sender.subscribe();
    //debug!("Subscribed to notifications, sleep for 7 sec...");
    time::sleep(Duration::from_secs(7)).await;
    let sleep_time = plugin.state().sleep_time;

    debug!("Creating Aleph Zero Tungstenite API instance");
    let mut api = Api::<AssetRuntimeConfig, _>::new(plugin.state().aleph_node.clone()).unwrap();

    debug!("Obtaining Aleph Zero network status");
    let genesis_block = api.get_genesis_block().unwrap();
    info!("Genesis block: {:?}", genesis_block);

    info!("Setting a signer for Aleph API instance");
    // TODO: read from config
    let node_keypair: sr25519::Pair = Pair::from_string(
        "0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a",
        None,
    )
        .unwrap();
    let node_pk = node_keypair.public();
    let node_balance = api.get_account_data(&node_pk.into()).unwrap().unwrap_or_default().free;
    info!("Node Aleph Zero account {}, balance {}", node_pk.to_ss58check(), node_balance);
    api.set_signer(ExtrinsicSigner::<AssetRuntimeConfig>::new(node_keypair.clone()));
    // This all below is just a blocking code. No way without help
    /*
    info!("Deploying contract...");
    const CONTRACT: &str = r#"
    (module
        (func (export "call"))
        (func (export "deploy"))
    )
    "#;
    let wasm = wabt::wat2wasm(CONTRACT).expect("invalid wabt");
    let xt = api.contract_instantiate_with_code(
        1_000_000_000_000_000,
        500_000,
        wasm,
        vec![1u8],
        vec![1u8],
    );
    info!("[+] Creating a contract instance with extrinsic:\n\n{:?}\n", xt);
    let report = api.submit_and_watch_extrinsic_until(xt, XtStatus::InBlock).unwrap();
    info!("[+] Extrinsic is in Block. Hash: {:?}\n", report.block_hash.unwrap());
    */
    info!("Loading contract...");
    //let new_wasm: &[u8] = include_bytes!("contracts/htlc/target/ink/htlc.wasm");
    /*
    let new_wasm: &[u8] = include_bytes!("/home/ilya/Code/Rust/satsbridge/hackatons/cln-aleph/contracts/htlc/target/ink/kitchensink_runtime.compact.compressed.wasm");
    // this call can only be called by sudo
    let call = compose_call!(api.metadata(), "System", "set_code", new_wasm.to_vec());
    let weight: Weight = 0.into();
    let xt = compose_extrinsic!(&api, "Sudo", "sudo_unchecked_weight", call, weight);

    info!("Sending extrinsic to trigger runtime update");
    let block_hash = api
        .submit_and_watch_extrinsic_until(xt, XtStatus::InBlock)
        .unwrap()
        .block_hash
        .unwrap();
    info!("[+] Extrinsic got included. Block Hash: {:?}", block_hash);
    */
    /*
    let contract =
        AccountId32::from_ss58check("5HHNyfTWUwHxZwxakXdmdrrtAuuUV1hRS7niLzsUMTrrbE6b").unwrap();
    info!("Contract loaded. Address {}", contract);
    let xt = api.contract_call(contract.into(), 500_000, 500_000, vec![0u8]);
    info!("[+] Calling the contract with extrinsic Extrinsic:\n{:?}\n\n", xt);
    let report = api.submit_and_watch_extrinsic_until(xt, XtStatus::Finalized).unwrap();
    info!("[+] Extrinsic got finalized. Extrinsic Hash: {:?}", report.extrinsic_hash);
    */
    info!("Starting Main Aleph Worker Loop");
    loop {
        let header_hash = api.get_finalized_head().unwrap().unwrap();
        let signed_block = api.get_finalized_block().unwrap().unwrap();
        info!("Latest Finalized Header Hash: {:?}", header_hash);
        info!("Latest Signed Block: {:?}", signed_block);

        match timeout(Duration::from_secs(60 as u64), notification_receiver.recv()).await {
            Ok(Ok(Notification::GasPrice(v))) => {},
            Ok(Ok(Notification::SendZero(n ))) => {
                info!(
                    "Sending {} ZEROs from {} to {}",
                    n.amount,
                    node_pk,
                    n.recipient
                );
                let xt = api.balance_transfer_allow_death(MultiAddress::Id(n.recipient.into()), n.amount);
                debug!("Prepared extrinsic: {:?}", xt);

                // Send and watch extrinsic until in block.
                let block_hash = api
                    .submit_and_watch_extrinsic_until(xt, XtStatus::InBlock)
                    .unwrap()
                    .block_hash
                    .unwrap();
                info!("ZEROs have been sent. Block Hash: {:?}", block_hash);
            },
            _ => {
                let block_number = 1; //provider.get_block_number().await?;
                info!("No messages for worker. Aleph height {block_number}")
            }
        }
        debug!("Main Aleph Worker sleeps for {}", sleep_time);
        time::sleep(Duration::from_secs(sleep_time)).await;
    }
}
