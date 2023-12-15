use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use tokio::sync::broadcast::Sender;

use cln_rpc::model::responses::ListinvoicesInvoices;
use parking_lot::Mutex;
use substrate_api_client::ac_primitives::AssetRuntimeConfig;
use substrate_api_client::Api;
use substrate_api_client::rpc::TungsteniteRpcClient;
use tokio::net::unix::uid_t;

use sp_core::{
    sr25519,
};

/*
#[derive(Clone, Debug)]
pub struct Contract {
    pub sender: String,
    pub receiver: String,
    pub tokenContract: String,
    pub hashlock: String,
    pub timelock: String,
    pub amount: u64,
    pub expiry: u32,
    pub loop_mutex: Arc<tokio::sync::Mutex<bool>>,
}
*/

#[derive(Clone)]
pub struct PluginState {
    pub blockheight: Arc<Mutex<u32>>,
    pub channel: Sender<Notification>,
    pub aleph_node: TungsteniteRpcClient,
    pub sleep_time: u64,
}

pub type GasPrice = u64;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SendZero {
    pub recipient: sr25519::Public,
    pub amount: u128,
}

/// Used to send messages via broadcast channel to outside workers
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Notification {
    GasPrice(GasPrice),
    SendZero(SendZero),
}
