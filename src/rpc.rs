//! A bitcoind-compatible JSON-RPC server: the subset LND, Core Lightning's
//! `bcli` and the platforms' sync screens call.
//! No wallet calls exist at all.

use std::str::FromStr;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hex::DisplayHex;
use bitcoin::{Block, BlockHash, Network, Transaction, Txid};
use serde_json::{Value, json};

use crate::fees;
use crate::node::{
    Node, RPC_IN_WARMUP, RPC_INVALID_PARAMETER, RPC_MISC_ERROR, RPC_NOT_FOUND, RpcError, header_hex,
};

pub const RPC_METHOD_NOT_FOUND: i32 = -32601;
pub const RPC_INVALID_REQUEST: i32 = -32600;
pub const RPC_PARSE_ERROR: i32 = -32700;

/// We report bitcoind 28 compatibility (LND and CLN check the number) but
/// the subversion says plainly what we are, the way Knots does.
pub const VERSION: u32 = 280000;
pub const SUBVERSION: &str = concat!(
    "/Satoshi:28.0.0/trust-issues:",
    env!("CARGO_PKG_VERSION"),
    "/"
);

/// Accepted credentials: the cookie (always) and an optional user/password.
pub struct Auth {
    pub cookie_password: String,
    pub user: Option<String>,
    pub password: Option<String>,
}

impl Auth {
    fn allows(&self, headers: &HeaderMap) -> bool {
        let Some(value) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        else {
            return false;
        };
        let Some(b64) = value.strip_prefix("Basic ") else {
            return false;
        };
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
            return false;
        };
        let Ok(text) = String::from_utf8(decoded) else {
            return false;
        };
        let Some((u, p)) = text.split_once(':') else {
            return false;
        };
        let cookie_ok = u == "__cookie__" && constant_eq(p, &self.cookie_password);
        let user_ok = match (&self.user, &self.password) {
            (Some(eu), Some(ep)) => constant_eq(u, eu) && constant_eq(p, ep),
            _ => false,
        };
        cookie_ok || user_ok
    }
}

fn constant_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Clone)]
struct AppState {
    node: Arc<Node>,
    auth: Arc<Auth>,
}

pub fn router(node: Arc<Node>, auth: Auth) -> Router {
    Router::new()
        .route("/", post(handle_rpc))
        .route("/status", get(handle_status))
        .with_state(AppState {
            node,
            auth: Arc::new(auth),
        })
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"jsonrpc\"")],
        "",
    )
        .into_response()
}

async fn handle_status(State(s): State<AppState>, headers: HeaderMap) -> Response {
    if !s.auth.allows(&headers) {
        return unauthorized();
    }
    axum::Json(s.node.status()).into_response()
}

async fn handle_rpc(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if !s.auth.allows(&headers) {
        return unauthorized();
    }
    let (status, value) = process_body(&s.node, &body).await;
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        value.to_string(),
    )
        .into_response()
}

/// Handle one HTTP body: a single request or a batch. Public so tests can
/// drive it without a socket.
pub async fn process_body(node: &Node, body: &[u8]) -> (StatusCode, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                reply(
                    Value::Null,
                    Err(RpcError::new(RPC_PARSE_ERROR, "Parse error")),
                ),
            );
        }
    };
    match parsed {
        Value::Array(reqs) => {
            let mut out = Vec::with_capacity(reqs.len());
            for r in reqs {
                out.push(process_one(node, r).await.1);
            }
            (StatusCode::OK, Value::Array(out))
        }
        single => process_one(node, single).await,
    }
}

async fn process_one(node: &Node, req: Value) -> (StatusCode, Value) {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = req.get("method").and_then(Value::as_str) else {
        return (
            StatusCode::BAD_REQUEST,
            reply(
                id,
                Err(RpcError::new(
                    RPC_INVALID_REQUEST,
                    "Method must be a string",
                )),
            ),
        );
    };
    let params = req.get("params").cloned().unwrap_or(Value::Array(vec![]));
    let result = dispatch(node, method, &params).await;
    let status = match &result {
        Ok(_) => StatusCode::OK,
        Err(e) if e.code == RPC_METHOD_NOT_FOUND => StatusCode::NOT_FOUND,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, reply(id, result))
}

fn reply(id: Value, result: Result<Value, RpcError>) -> Value {
    match result {
        Ok(v) => json!({"result": v, "error": null, "id": id}),
        Err(e) => {
            json!({"result": null, "error": {"code": e.code, "message": e.message}, "id": id})
        }
    }
}

// ---------- parameters ----------

fn param<'a>(params: &'a Value, idx: usize, name: &str) -> Option<&'a Value> {
    let v = match params {
        Value::Array(a) => a.get(idx),
        Value::Object(o) => o.get(name),
        _ => None,
    };
    v.filter(|v| !v.is_null())
}

fn bad_param(name: &str) -> RpcError {
    RpcError::new(
        RPC_INVALID_PARAMETER,
        format!("Invalid or missing parameter: {name}"),
    )
}

fn req_str<'a>(params: &'a Value, idx: usize, name: &str) -> Result<&'a str, RpcError> {
    param(params, idx, name)
        .and_then(Value::as_str)
        .ok_or_else(|| bad_param(name))
}

fn req_parse<T: FromStr>(params: &Value, idx: usize, name: &str) -> Result<T, RpcError> {
    req_str(params, idx, name)?
        .parse::<T>()
        .map_err(|_| bad_param(name))
}

fn req_u64(params: &Value, idx: usize, name: &str) -> Result<u64, RpcError> {
    param(params, idx, name)
        .and_then(Value::as_u64)
        .ok_or_else(|| bad_param(name))
}

/// Booleans or 0/1/2 levels, as bitcoind accepts both for `verbose`.
fn verbosity(params: &Value, idx: usize, name: &str, default: u64) -> u64 {
    match param(params, idx, name) {
        Some(Value::Bool(b)) => u64::from(*b),
        Some(v) => v.as_u64().unwrap_or(default),
        None => default,
    }
}

fn chain_name(n: Network) -> &'static str {
    match n {
        Network::Signet => "signet",
        Network::Regtest => "regtest",
        Network::Testnet => "test",
        Network::Testnet4 => "testnet4",
        _ => "main",
    }
}

/// Calls that work before the node has a checkpoint.
const WARMUP_OK: &[&str] = &[
    "help",
    "uptime",
    "getnetworkinfo",
    "getconnectioncount",
    "getpeerinfo",
];

pub async fn dispatch(node: &Node, method: &str, params: &Value) -> Result<Value, RpcError> {
    if !node.is_ready() && !WARMUP_OK.contains(&method) {
        return Err(RpcError::new(
            RPC_IN_WARMUP,
            "Starting: waiting for sources to agree on a checkpoint",
        ));
    }
    match method {
        "help" => Ok(json!(format!(
            "trust-issues: a bitcoind stand-in. Supported: {}",
            SUPPORTED.join(", ")
        ))),
        "uptime" => Ok(json!(node.uptime())),
        "getnetworkinfo" => Ok(json!({
            "version": VERSION,
            "subversion": SUBVERSION,
            "protocolversion": 70016,
            "localservices": "0000000000000000",
            "localservicesnames": [],
            "localrelay": true,
            "timeoffset": 0,
            "networkactive": true,
            "connections": node.healthy_count(),
            "connections_in": 0,
            "connections_out": node.healthy_count(),
            "networks": [],
            "relayfee": fees::sat_vb_to_btc_kvb(fees::FLOOR_SAT_VB),
            "incrementalfee": fees::sat_vb_to_btc_kvb(fees::FLOOR_SAT_VB),
            "localaddresses": [],
            "warnings": warnings(node),
        })),
        "getconnectioncount" => Ok(json!(node.healthy_count())),
        "getpeerinfo" => Ok(peer_info(node)),
        "getblockchaininfo" => Ok(blockchain_info(node)),
        "getblockcount" => Ok(json!(node.with_chain(|c| c.tip_height()))),
        "getbestblockhash" => Ok(json!(node.with_chain(|c| c.tip_hash().to_string()))),
        "getdifficulty" => Ok(json!(
            node.with_chain(|c| c.tip_header().difficulty_float())
        )),
        "getblockhash" => {
            let height = req_u64(params, 0, "height")?;
            let height = u32::try_from(height).map_err(|_| bad_param("height"))?;
            node.with_chain(|c| c.hash_at(height))
                .map(|h| json!(h.to_string()))
                .ok_or_else(|| RpcError::new(RPC_INVALID_PARAMETER, "Block height out of range"))
        }
        "getblockheader" => {
            let hash: BlockHash = req_parse(params, 0, "blockhash")?;
            let verbose = verbosity(params, 1, "verbose", 1) != 0;
            let Some(h) = node.with_chain(|c| c.header(&hash)) else {
                return Err(RpcError::new(RPC_NOT_FOUND, "Block not found"));
            };
            if verbose {
                Ok(header_json(node, &hash, None))
            } else {
                Ok(json!(header_hex(&h)))
            }
        }
        "getblock" => {
            let hash: BlockHash = req_parse(params, 0, "blockhash")?;
            let level = verbosity(params, 1, "verbosity", 1);
            let raw = node.get_block(hash).await?;
            if level == 0 {
                return Ok(json!(raw.to_lower_hex_string()));
            }
            let block: Block = deserialize(&raw)
                .map_err(|_| RpcError::new(RPC_MISC_ERROR, "Block decode failed"))?;
            Ok(block_json(node, &hash, &block, raw.len(), level))
        }
        "getrawtransaction" => {
            let txid: Txid = req_parse(params, 0, "txid")?;
            let verbose = verbosity(params, 1, "verbose", 0) != 0;
            let in_block = param(params, 2, "blockhash").and_then(Value::as_str);
            let (tx, conf) = match in_block {
                Some(b) => {
                    let bh: BlockHash = b.parse().map_err(|_| bad_param("blockhash"))?;
                    let raw = node.get_block(bh).await?;
                    let block: Block = deserialize(&raw)
                        .map_err(|_| RpcError::new(RPC_MISC_ERROR, "Block decode failed"))?;
                    let tx = block
                        .txdata
                        .into_iter()
                        .find(|t| t.compute_txid() == txid)
                        .ok_or_else(|| {
                            RpcError::new(
                                RPC_NOT_FOUND,
                                "No such transaction found in the provided block",
                            )
                        })?;
                    let height = node.with_chain(|c| c.height_of(&bh)).unwrap_or(0);
                    (tx, Some((bh, height)))
                }
                None => node.get_tx(txid).await?,
            };
            let hex = serialize(&tx).to_lower_hex_string();
            if !verbose {
                return Ok(json!(hex));
            }
            let mut v = tx_json(&tx, node.network());
            v["hex"] = json!(hex);
            if let Some((bh, _)) = conf {
                v["blockhash"] = json!(bh.to_string());
                let (confs, time) =
                    node.with_chain(|c| (c.confirmations(&bh), c.header(&bh).map(|h| h.time)));
                v["confirmations"] = json!(confs.unwrap_or(0));
                if let Some(t) = time {
                    v["time"] = json!(t);
                    v["blocktime"] = json!(t);
                }
            }
            Ok(v)
        }
        "gettxout" => {
            let txid: Txid = req_parse(params, 0, "txid")?;
            let n = u32::try_from(req_u64(params, 1, "n")?).map_err(|_| bad_param("n"))?;
            Ok(node.get_txout(txid, n).await?.unwrap_or(Value::Null))
        }
        "estimatesmartfee" => {
            let target = req_u64(params, 0, "conf_target")?.clamp(1, 1008) as u16;
            Ok(match node.estimate_fee(target) {
                Some(f) => json!({"feerate": fees::sat_vb_to_btc_kvb(f), "blocks": target}),
                None => {
                    json!({"errors": ["Insufficient data or no feerate found"], "blocks": target})
                }
            })
        }
        "getmempoolinfo" => {
            let ours = node.our_mempool();
            let bytes: usize = ours.iter().map(|(_, b)| b).sum();
            let floor = fees::sat_vb_to_btc_kvb(fees::FLOOR_SAT_VB);
            Ok(json!({
                "loaded": true, "size": ours.len(), "bytes": bytes, "usage": bytes, "total_fee": 0.0,
                "maxmempool": 300_000_000u64, "mempoolminfee": floor, "minrelaytxfee": floor,
                "incrementalrelayfee": floor, "unbroadcastcount": 0, "fullrbf": true,
            }))
        }
        "getrawmempool" => {
            let ours = node.our_mempool();
            if verbosity(params, 0, "verbose", 0) != 0 {
                let mut m = serde_json::Map::new();
                for (t, b) in ours {
                    m.insert(t.to_string(), json!({"vsize": b, "depends": []}));
                }
                Ok(Value::Object(m))
            } else {
                Ok(json!(
                    ours.iter().map(|(t, _)| t.to_string()).collect::<Vec<_>>()
                ))
            }
        }
        "sendrawtransaction" => {
            let hex = req_str(params, 0, "hexstring")?;
            Ok(json!(node.broadcast(hex).await?.to_string()))
        }
        "testmempoolaccept" => {
            let Some(Value::Array(txs)) = param(params, 0, "rawtxs") else {
                return Err(bad_param("rawtxs"));
            };
            if txs.len() != 1 {
                return Err(RpcError::new(
                    RPC_INVALID_PARAMETER,
                    "Only one transaction at a time is supported",
                ));
            }
            let hex = txs[0].as_str().ok_or_else(|| bad_param("rawtxs"))?;
            Ok(json!([node.test_accept(hex).await?]))
        }
        "gettxspendingprevout" => {
            // bitcoind answers this from its mempool; ours is only our own broadcasts.
            let Some(Value::Array(outs)) = param(params, 0, "outputs") else {
                return Err(bad_param("outputs"));
            };
            let mut res = Vec::new();
            for o in outs {
                let txid = o
                    .get("txid")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad_param("outputs"))?;
                let vout = o
                    .get("vout")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| bad_param("outputs"))?;
                let mut entry = json!({"txid": txid, "vout": vout});
                if let Ok(prev) = txid.parse::<Txid>()
                    && let Some(spender) = node.our_spender_of(prev, vout as u32)
                {
                    entry["spendingtxid"] = json!(spender.to_string());
                }
                res.push(entry);
            }
            Ok(Value::Array(res))
        }
        "getindexinfo" => Ok(json!({})),
        "getzmqnotifications" => Ok(json!([])),
        "getnodeaddresses" => Ok(json!([])),
        "getmininginfo" => Ok(json!({
            "blocks": node.with_chain(|c| c.tip_height()),
            "difficulty": node.with_chain(|c| c.tip_header().difficulty_float()),
            "networkhashps": 0, "pooledtx": node.our_mempool().len(),
            "chain": chain_name(node.network()), "warnings": warnings(node),
        })),
        "getdeploymentinfo" => Ok(
            json!({"hash": node.with_chain(|c| c.tip_hash().to_string()), "height": node.with_chain(|c| c.tip_height()), "deployments": {}}),
        ),
        _ => Err(RpcError::new(RPC_METHOD_NOT_FOUND, "Method not found")),
    }
}

pub const SUPPORTED: &[&str] = &[
    "help",
    "uptime",
    "getnetworkinfo",
    "getconnectioncount",
    "getpeerinfo",
    "getblockchaininfo",
    "getblockcount",
    "getbestblockhash",
    "getdifficulty",
    "getblockhash",
    "getblockheader",
    "getblock",
    "getrawtransaction",
    "gettxout",
    "estimatesmartfee",
    "getmempoolinfo",
    "getrawmempool",
    "sendrawtransaction",
    "testmempoolaccept",
    "gettxspendingprevout",
    "getindexinfo",
    "getzmqnotifications",
    "getnodeaddresses",
    "getmininginfo",
    "getdeploymentinfo",
];

fn warnings(node: &Node) -> String {
    node.alarms()
        .values()
        .map(|a| a.message.clone())
        .collect::<Vec<_>>()
        .join("; ")
}

fn peer_info(node: &Node) -> Value {
    let status = node.status();
    let empty = vec![];
    let peers: Vec<Value> = status["sources"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .enumerate()
        .filter(|(_, s)| s["healthy"].as_bool() == Some(true))
        .map(|(i, s)| {
            json!({
                "id": i, "addr": s["name"], "subver": "esplora", "inbound": false,
                "synced_headers": s["tip_height"], "synced_blocks": s["tip_height"],
                "connection_type": "outbound-full-relay",
            })
        })
        .collect();
    Value::Array(peers)
}

fn blockchain_info(node: &Node) -> Value {
    let synced = node.is_synced();
    let progress = if !node.is_ready() {
        0.0
    } else if synced {
        1.0
    } else {
        0.99
    };
    node.with_chain(|c| {
        let tip = c.tip_hash();
        let h = c.tip_header();
        json!({
            "chain": chain_name(node.network()),
            "blocks": c.tip_height(),
            "headers": c.tip_height(),
            "bestblockhash": tip.to_string(),
            "difficulty": h.difficulty_float(),
            "time": h.time,
            "mediantime": c.median_time_past(&tip),
            "verificationprogress": progress,
            "initialblockdownload": !synced,
            "chainwork": c.tip_work().to_be_bytes().to_lower_hex_string(),
            "size_on_disk": 0,
            "pruned": false,
            "warnings": warnings(node),
        })
    })
}

fn header_json(node: &Node, hash: &BlockHash, n_tx: Option<usize>) -> Value {
    node.with_chain(|c| {
        let Some(h) = c.header(hash) else {
            return Value::Null;
        };
        let mut v = json!({
            "hash": hash.to_string(),
            "confirmations": c.confirmations(hash).map_or(-1, i64::from),
            "height": c.height_of(hash),
            "version": h.version.to_consensus(),
            "versionHex": format!("{:08x}", h.version.to_consensus()),
            "merkleroot": h.merkle_root.to_string(),
            "time": h.time,
            "mediantime": c.median_time_past(hash),
            "nonce": h.nonce,
            "bits": format!("{:08x}", h.bits.to_consensus()),
            "difficulty": h.difficulty_float(),
            "chainwork": c.work_of(hash).map(|w| w.to_be_bytes().to_lower_hex_string()),
            "previousblockhash": h.prev_blockhash.to_string(),
        });
        if let Some(n) = n_tx {
            v["nTx"] = json!(n);
        }
        if let Some(next) = c.next_on_best(hash) {
            v["nextblockhash"] = json!(next.to_string());
        }
        v
    })
}

fn block_json(node: &Node, hash: &BlockHash, block: &Block, size: usize, level: u64) -> Value {
    let mut v = header_json(node, hash, Some(block.txdata.len()));
    v["size"] = json!(size);
    v["weight"] = json!(block.weight().to_wu());
    v["tx"] = if level >= 2 {
        let net = node.network();
        json!(
            block
                .txdata
                .iter()
                .map(|t| {
                    let mut j = tx_json(t, net);
                    j["hex"] = json!(serialize(t).to_lower_hex_string());
                    j
                })
                .collect::<Vec<_>>()
        )
    } else {
        json!(
            block
                .txdata
                .iter()
                .map(|t| t.compute_txid().to_string())
                .collect::<Vec<_>>()
        )
    };
    v
}

fn tx_json(tx: &Transaction, network: Network) -> Value {
    let vin: Vec<Value> = tx
        .input
        .iter()
        .map(|i| {
            let witness: Vec<String> = i.witness.iter().map(|w| w.to_lower_hex_string()).collect();
            if tx.is_coinbase() {
                json!({"coinbase": i.script_sig.as_bytes().to_lower_hex_string(), "txinwitness": witness, "sequence": i.sequence.0})
            } else {
                json!({
                    "txid": i.previous_output.txid.to_string(), "vout": i.previous_output.vout,
                    "scriptSig": {"asm": i.script_sig.to_asm_string(), "hex": i.script_sig.as_bytes().to_lower_hex_string()},
                    "txinwitness": witness, "sequence": i.sequence.0,
                })
            }
        })
        .collect();
    let vout: Vec<Value> = tx
        .output
        .iter()
        .enumerate()
        .map(|(n, o)| {
            let mut spk = json!({"asm": o.script_pubkey.to_asm_string(), "hex": o.script_pubkey.as_bytes().to_lower_hex_string()});
            if let Ok(a) = bitcoin::Address::from_script(&o.script_pubkey, network) {
                spk["address"] = json!(a.to_string());
            }
            json!({"value": o.value.to_btc(), "n": n, "scriptPubKey": spk})
        })
        .collect();
    json!({
        "txid": tx.compute_txid().to_string(),
        "hash": tx.compute_wtxid().to_string(),
        "version": tx.version.0,
        "size": tx.total_size(),
        "vsize": tx.vsize(),
        "weight": tx.weight().to_wu(),
        "locktime": tx.lock_time.to_consensus_u32(),
        "vin": vin,
        "vout": vout,
    })
}
