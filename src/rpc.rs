use anyhow::{anyhow, Error};
use cln_plugin::Plugin;
use std::path::{Path, PathBuf};

use hex;

use log::{debug, error, info};
use serde_json::json;
use std::{str::FromStr, time::Duration};

use tokio::time;

use crate::model::{PluginState, SendZero};

use crate::model::Notification;

use cln_rpc::primitives::Amount;
use cln_rpc::{
    model::{
        requests::{DecodepayRequest, PayRequest},
        responses::{DecodepayResponse, PayResponse},
    },
    ClnRpc, Request, Response,
};

use sp_core::{
    crypto::{Pair, Ss58Codec},
    sr25519,
};

pub async fn get_gas(
    plugin: Plugin<PluginState>,
    _args: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    info!("Sending Gas request to Worker");
    match plugin.state().channel.send(Notification::GasPrice(0_u64)) {
        Ok(_) => {
            debug!("Sent notification GasPrice");
        }
        Err(e) => {
            error!("Couldnt send notification: {e:?}");
            return Ok(json!({
                "code": 1,
                "message": "Command failed"
            }));
        }
    };
    let mut notification_receiver = plugin.state().channel.subscribe();

    match time::timeout(Duration::from_secs(60 as u64), notification_receiver.recv()).await {
        Ok(Ok(Notification::GasPrice(gas))) => Ok(json!({
            "code": 0,
            "message": gas,
        })),
        _ => Ok(json!({
            "code": 1,
            "message": "Impossible to request gas"
        })),
    }
}

pub async fn send_zero(
    plugin: Plugin<PluginState>,
    args: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let valid_arg_keys = vec!["address", "amount"];

    let new_args = assign_arguments(&args, &valid_arg_keys);
    match new_args {
        Ok(a) => {
            if !a["address"].is_string() {
                return Ok(invalid_input_error("address is not a string"));
            }
            if !a["amount"].is_u64() {
                return Ok(invalid_input_error("amount is not an unsigned integer"));
            }
            // TODO: Get rid from unwrap, do address check
            let recipient =
                sr25519::Public::from_ss58check(a["address"].as_str().unwrap()).unwrap();
            // TODO: upgrade serializer or use string, or something else
            let amount = a["amount"].as_u64().unwrap() as u128;
            info!(
                "Sending notification {:?} / {:?} to Worker",
                recipient, amount
            );
            match plugin
                .state()
                .channel
                .send(Notification::SendZero(SendZero { recipient, amount }))
            {
                Ok(_) => {
                    debug!("Sent notification SendZero");
                    Ok(json!({
                        "code": 0,
                        "message": "This is fine"
                    }))
                }
                Err(e) => {
                    error!("Couldnt send notification: {e:?}");
                    Ok(json!({
                        "code": 1,
                        "message": format!("Failed to broadcast SendZero {}/{}", recipient, amount)
                    }))
                }
            }
        }
        Err(e) => Ok(e),
    }
}

pub fn make_rpc_path(plugin: Plugin<PluginState>) -> PathBuf {
    Path::new(&plugin.configuration().lightning_dir).join(plugin.configuration().rpc_file)
}

pub async fn decode_invoice(rpc_path: &PathBuf, bolt1: String) -> Result<DecodepayResponse, Error> {
    let mut rpc = ClnRpc::new(&rpc_path).await?;
    let decoded = rpc
        .call(Request::DecodePay(DecodepayRequest {
            bolt11: bolt1,
            description: None,
        }))
        .await
        .map_err(|e| anyhow!("Error calling decodepay: {:?}", e))?;
    match decoded {
        Response::DecodePay(info) => Ok(info),
        e => Err(anyhow!("Unexpected result in decodepay: {:?}", e)),
    }
}

pub async fn pay_invoice(rpc_path: &PathBuf, bolt1: String) -> Result<PayResponse, Error> {
    let mut rpc = ClnRpc::new(&rpc_path).await?;
    let decoded = rpc
        .call(Request::Pay(PayRequest {
            bolt11: bolt1,
            retry_for: Some(120),
            maxfeepercent: Some(1.),
            maxdelay: None,
            // Less critical parameters
            maxfee: None,
            amount_msat: None,
            label: None,
            riskfactor: None,
            exemptfee: None,
            localinvreqid: None,
            exclude: None,
            description: None,
        }))
        .await
        .map_err(|e| anyhow!("Error calling decodepay: {:?}", e))?;
    match decoded {
        Response::Pay(info) => Ok(info),
        e => Err(anyhow!("Unexpected result in decodepay: {:?}", e)),
    }
}

fn assign_arguments(
    args: &serde_json::Value,
    keys: &Vec<&str>,
) -> Result<serde_json::Value, serde_json::Value> {
    let mut new_args = serde_json::Value::Object(Default::default());
    match args {
        serde_json::Value::Array(a) => {
            if a.len() != keys.len() {
                return Err(invalid_argument_amount(&a.len(), &keys.len()));
            }
            for (idx, arg) in a.iter().enumerate() {
                if idx < keys.len() {
                    new_args[keys[idx]] = arg.clone();
                }
            }
        }
        serde_json::Value::Object(o) => {
            for (k, v) in o.iter() {
                if !keys.contains(&k.as_str()) {
                    return Err(invalid_argument_error(k));
                }
                new_args[k] = v.clone();
            }
        }
        _ => return Err(invalid_input_error(&args.to_string())),
    };
    Ok(new_args.clone())
}

fn invalid_argument_error(arg: &str) -> serde_json::Value {
    json!({
        "code": 1,
        "message": format!("Invalid argument: '{}'", arg)
    })
}

fn invalid_input_error(input: &str) -> serde_json::Value {
    json!({
        "code": 1,
        "message": format!("Invalid input: '{}'", input)
    })
}

fn invalid_argument_amount(size: &usize, needed: &usize) -> serde_json::Value {
    json!({
        "code": 1,
        "message": format!("Provided '{}', needed '{}'", size, needed)
    })
}
