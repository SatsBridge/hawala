use std::{collections::BTreeMap, sync::Arc};

use anyhow::{anyhow, Result};
use cln_plugin::{options, Builder};
use log::{debug, warn};
use parking_lot::Mutex;
use tokio::sync::broadcast;

mod hooks;
mod worker;

use cln_aleph::model::PluginState;
use cln_aleph::rpc::{get_gas, send_zero};

use substrate_api_client::{
    ac_primitives::AssetRuntimeConfig,
    rpc::TungsteniteRpcClient,
    rpc::{HandleSubscription, JsonrpseeClient},
    Api, GetChainInfo, SubscribeChain,
};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    debug!("Starting Ethereum Virtual Machine plugin");
    std::env::set_var("CLN_PLUGIN_LOG", "debug");

    let (notification_sender, _) = broadcast::channel(1024);

    let plugin = if let Some(p) = Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(options::ConfigOption::new(
            "aleph-worker-sleep",
            options::Value::OptInteger,
            "ETH worker sleep option",
        ))
        .option(options::ConfigOption::new(
            "aleph-host",
            options::Value::OptString,
            "Alchemy API token string for requesting smart-contract data",
        ))
        .rpcmethod("aleph_gas", "get gas price estimation", get_gas)
        .rpcmethod(
            "sendzero",
            "Sends ZERO tokens to an account",
            send_zero,
        )
        .hook("custommsg", hooks::message_handler)
        .hook("htlc_accepted", hooks::dummy_handler)
        .subscribe("block_added", hooks::block_added)
        .configure()
        .await?
    {
        p
    } else {
        return Ok(());
    };

    debug!("Reading Aleph host");
    let url = match plugin.option("aleph-host") {
        Some(v) => v.as_str().unwrap().to_owned(),
        _ => return Err(std::fmt::Error.into()),
    };
    debug!("Reading other options");
    let sleep_time = match plugin.option("aleph-worker-sleep") {
        Some(v) => v.as_i64().unwrap().to_owned() as u64,
        _ => return Err(std::fmt::Error.into()),
    };
    debug!("Creating Aleph Zero Tungstenite client on {}", url);
    let aleph_node = TungsteniteRpcClient::new(url.as_str(), 100).unwrap();
    let mut api = Api::<AssetRuntimeConfig, _>::new(aleph_node.clone()).unwrap();

    debug!("Obtaining Aleph Zero network status");
    let genesis_block = api.get_genesis_block().unwrap();
    debug!("Genesis block: {:?}", genesis_block);

    let state = PluginState {
        blockheight: Arc::new(Mutex::new(u32::default())),
        channel: notification_sender.clone(),
        aleph_node,
        sleep_time,
    };

    if let Ok(plugin) = plugin.start(state).await {
        let pcloned = plugin.clone();
        tokio::spawn(async move {
            match worker::control_worker(pcloned, notification_sender.clone()).await {
                Ok(()) => (),
                Err(e) => warn!(
                    "Error in Ethereum Virtual Machine worker: {}",
                    e.to_string()
                ),
            };
        });
        let pcloned = plugin.clone();
        tokio::spawn(async move {
            match worker::events_worker(pcloned).await {
                Ok(()) => (),
                Err(e) => warn!("Error in Generic worker: {}", e.to_string()),
            };
        });
        plugin.join().await
    } else {
        Err(anyhow!("Error starting the plugin!"))
    }
}
