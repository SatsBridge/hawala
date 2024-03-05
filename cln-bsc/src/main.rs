use std::{collections::BTreeMap, sync::Arc};

use anyhow::{anyhow, Result};
use cln_plugin::{options, Builder};
use log::{debug, warn};
use parking_lot::Mutex;
use tokio::sync::broadcast;

mod hooks;
mod worker;

use cln_bsc::model::PluginState;
use cln_bsc::rpc::{
    bep20_withdraw, get_gas, redeem_bep20_htlc, refund_bep20_htlc, set_bep20_htlc,
    pay_redeem_bep20_htlc,
};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    debug!("Starting Binance Chain Virtual Machine plugin");
    std::env::set_var("CLN_PLUGIN_LOG", "debug");

    let (notification_sender, _) = broadcast::channel(1024);

    let state = PluginState {
        blockheight: Arc::new(Mutex::new(u32::default())),
        evminvoices: Arc::new(tokio::sync::Mutex::new(BTreeMap::new())),
        channel: notification_sender.clone(),
    };

    let plugin = if let Some(p) = Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(options::ConfigOption::new(
            "bsc-worker-sleep",
            options::Value::OptInteger,
            "ETH worker sleep option",
        ))
        .option(options::ConfigOption::new(
            "bsc-rpc",
            options::Value::OptString,
            "RPC API with or without token string for requesting smart-contract data",
        ))
        .option(options::ConfigOption::new(
            "bsc-seed",
            options::Value::OptString,
            "Wallet seed",
        ))
        .option(options::ConfigOption::new(
            "bsc-token",
            options::Value::OptString,
            "Token contract address",
        ))
        .option(options::ConfigOption::new(
            "bsc-htlc",
            options::Value::OptString,
            "Hashed Timelock token contract address",
        ))
        .option(options::ConfigOption::new(
            "bsc-htlc-timelock",
            options::Value::OptInteger,
            "bep20 HTLC contract timelock",
        ))
        .option(options::ConfigOption::new(
            "bsc-native-limit",
            options::Value::OptInteger,
            "ETH token withdtawal limit",
        ))
        .option(options::ConfigOption::new(
            "bsc-token-limit",
            options::Value::OptInteger,
            "bep20 token withdtawal limit",
        ))
        .option(options::ConfigOption::new(
            "bsc-event-callback",
            options::Value::OptString,
            "URL for callbacks from worker",
        ))
        .rpcmethod(
            "bsctokenwithdraw",
            "Creates, signs and submits onchain bep20 transaction",
            bep20_withdraw,
        )
        .rpcmethod(
            "bscsettokenhtlc",
            "Creates, signs and submits onchain bep20 transaction",
            set_bep20_htlc,
        )
        .rpcmethod(
            "bscredeemtokenhtlc",
            "Redeems bep20 tokens from HTLC contract",
            redeem_bep20_htlc,
        )
        .rpcmethod(
            "bscrefundtokenhtlc",
            "Redeems bep20 tokens from HTLC contract",
            refund_bep20_htlc,
        )
        .rpcmethod(
            "bscpayredeemtokenhtlc",
            "Pays an invoice and redeems bep20 tokens from HTLC contract",
            pay_redeem_bep20_htlc,
        )
        .rpcmethod("bscgas", "Get gas price estimation", get_gas)
        .hook("htlc_accepted", hooks::dummy_handler)
        .subscribe("block_added", hooks::block_added)
        .configure()
        .await?
    {
        p
    } else {
        return Ok(());
    };

    if let Ok(plugin) = plugin.start(state).await {
        let pcloned = plugin.clone();
        tokio::spawn(async move {
            match worker::bsc(pcloned, notification_sender.clone()).await {
                Ok(()) => (),
                Err(e) => warn!(
                    "Error in BSC Virtual Machine worker: {}",
                    e.to_string()
                ),
            };
        });
        plugin.join().await
    } else {
        Err(anyhow!("Error starting the plugin!"))
    }
}
