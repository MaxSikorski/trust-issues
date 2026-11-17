//! Broadcasting to every source, following up, and the bitcoind-compatible
//! JSON-RPC surface LND and Core Lightning talk to.

mod common;

use std::sync::Arc;

use bitcoin::hex::DisplayHex;
use common::*;
use serde_json::{Value, json};
use trust_issues::node::{BROADCAST_ALARM_SECS, BROADCAST_FIRST_CHECK_SECS, ManualClock, Node};
use trust_issues::rpc::{Auth, process_body, router};
use trust_issues::source::{Source, SourceError};

fn has_alarm(node: &Node, prefix: &str) -> bool {
    alarm_codes(node).iter().any(|c| c.starts_with(prefix))
}

async fn rpc(node: &Node, method: &str, params: Value) -> (u16, Value) {
    let body = json!({"jsonrpc": "1.0", "id": 7, "method": method, "params": params}).to_string();
    let (status, v) = process_body(node, body.as_bytes()).await;
    (status.as_u16(), v)
}

#[tokio::test]
async fn broadcast_goes_to_every_source_and_succeeds_if_any_accepts() {
    let blocks = build_chain(3, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    b.with(|s| {
        s.reject_body = Some(
            "sendrawtransaction RPC error: {\"code\":-26,\"message\":\"min relay fee not met\"}"
                .into(),
        )
    });
    let (node, _) = started_node(&[a.clone(), b.clone()], &blocks).await;
    let tx = spend(&blocks[1].txdata[0], 0, 4000, 8);
    let txid = node.broadcast(&tx_hex(&tx)).await.unwrap();
    assert_eq!(txid, tx.compute_txid());
    assert_eq!(a.with(|s| s.received.len()), 1);
    assert_eq!(b.with(|s| s.received.len()), 1, "every source was sent it");
    assert_eq!(node.our_mempool().len(), 1);
}

#[tokio::test]
async fn when_every_source_rejects_the_error_is_bitcoinds_own() {
    let blocks = build_chain(3, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    for s in [&a, &b] {
        s.with(|st| st.reject_body = Some("sendrawtransaction RPC error: {\"code\":-25,\"message\":\"bad-txns-inputs-missingorspent\"}".into()));
    }
    let (node, _) = started_node(&[a, b], &blocks).await;
    let tx = spend(&blocks[1].txdata[0], 0, 4000, 8);
    let err = node.broadcast(&tx_hex(&tx)).await.unwrap_err();
    assert_eq!(err.code, -25);
    assert_eq!(err.message, "bad-txns-inputs-missingorspent");
    assert!(node.our_mempool().is_empty());
    assert_eq!(node.broadcast("zz").await.unwrap_err().code, -22, "bad hex");
}

#[tokio::test]
async fn a_source_that_forgets_a_broadcast_gets_it_again() {
    let blocks = build_chain(3, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    b.with(|s| s.forget_broadcasts = true);
    let (node, clock) = started_node(&[a, b.clone()], &blocks).await;
    let tx = spend(&blocks[1].txdata[0], 0, 4000, 8);
    node.broadcast(&tx_hex(&tx)).await.unwrap();
    b.with(|s| s.forget_broadcasts = false);
    clock.advance(BROADCAST_FIRST_CHECK_SECS);
    node.recheck_broadcasts().await;
    assert_eq!(b.with(|s| s.received.len()), 2, "re-sent once");
    assert!(b.with(|s| s.mempool.contains_key(&tx.compute_txid())));
}

#[tokio::test]
async fn too_few_sources_seeing_a_broadcast_raises_a_critical_alarm() {
    let blocks = build_chain(3, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let (node, clock) = started_node(&[a, b.clone()], &blocks).await;
    b.with(|s| s.reject_body = Some("dropped".into()));
    b.with(|s| s.forget_broadcasts = true);
    let tx = spend(&blocks[1].txdata[0], 0, 4000, 8);
    node.broadcast(&tx_hex(&tx)).await.unwrap();
    clock.advance(BROADCAST_ALARM_SECS);
    node.recheck_broadcasts().await;
    assert!(has_alarm(&node, "broadcast-not-seen"));
}

#[tokio::test]
async fn a_confirmed_broadcast_is_forgotten_once_proven() {
    let mut blocks = build_chain(3, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let (node, clock) = started_node(&[a.clone(), b.clone()], &blocks).await;
    let tx = spend(&blocks[1].txdata[0], 0, 4000, 8);
    node.broadcast(&tx_hex(&tx)).await.unwrap();
    let tip = blocks[3].header;
    blocks.push(mine(&tip, 4, vec![tx.clone()], 1, REGTEST_BITS));
    a.set_chain(&blocks);
    b.set_chain(&blocks);
    clock.advance(BROADCAST_FIRST_CHECK_SECS);
    node.tick().await;
    assert!(node.our_mempool().is_empty());
}

#[tokio::test]
async fn test_accept_refuses_a_spent_input_and_allows_a_fresh_one() {
    let mut blocks = build_chain(3, 1);
    let first = spend(&blocks[1].txdata[0], 0, 4000, 8);
    let tip = blocks[3].header;
    blocks.push(mine(&tip, 4, vec![first], 1, REGTEST_BITS));
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let (node, _) = started_node(&[a, b], &blocks).await;
    let double = spend(&blocks[1].txdata[0], 0, 3000, 9);
    let v = node.test_accept(&tx_hex(&double)).await.unwrap();
    assert_eq!(v["allowed"], false);
    assert_eq!(v["reject-reason"], "bad-txns-inputs-missingorspent");
    let fresh = spend(&blocks[2].txdata[0], 0, 3000, 9);
    assert_eq!(
        node.test_accept(&tx_hex(&fresh)).await.unwrap()["allowed"],
        true
    );
}

// ---------- JSON-RPC ----------

#[tokio::test]
async fn before_a_checkpoint_chain_calls_answer_warming_up() {
    let blocks = build_chain(2, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let node = Node::new(
        settings(None),
        vec![a as Arc<dyn Source>, b],
        Arc::new(ManualClock::new(1)),
    );
    let (status, v) = rpc(&node, "getblockcount", json!([])).await;
    assert_eq!(status, 500);
    assert_eq!(v["error"]["code"], -28);
    let (status, v) = rpc(&node, "getnetworkinfo", json!([])).await;
    assert_eq!(status, 200);
    assert!(
        v["result"]["subversion"]
            .as_str()
            .unwrap()
            .contains("trust-issues")
    );
    assert!(
        v["result"]["version"].as_u64().unwrap() >= 250000,
        "LND and CLN version checks"
    );
}

#[tokio::test]
async fn getblockchaininfo_looks_like_a_synced_unpruned_bitcoind() {
    let blocks = build_chain(8, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let (node, _) = started_node(&[a, b], &blocks).await;
    let (_, v) = rpc(&node, "getblockchaininfo", json!([])).await;
    let r = &v["result"];
    assert_eq!(r["chain"], "regtest");
    assert_eq!(r["blocks"], 8);
    assert_eq!(r["headers"], 8);
    assert_eq!(r["bestblockhash"], blocks[8].block_hash().to_string());
    assert_eq!(r["pruned"], false, "keeps LND's pruned-block fetcher off");
    assert_eq!(r["initialblockdownload"], false);
    assert_eq!(r["verificationprogress"], 1.0);
    assert_eq!(r["chainwork"].as_str().unwrap().len(), 64);
}

#[tokio::test]
async fn blocks_headers_and_hashes_over_rpc() {
    let blocks = build_chain(5, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let (node, _) = started_node(&[a, b], &blocks).await;
    let h3 = blocks[3].block_hash().to_string();
    assert_eq!(rpc(&node, "getblockhash", json!([3])).await.1["result"], h3);
    assert_eq!(
        rpc(&node, "getblockhash", json!([99])).await.1["error"]["code"],
        -8
    );
    let hex = rpc(&node, "getblockheader", json!([h3, false])).await.1["result"].clone();
    assert_eq!(hex.as_str().unwrap().len(), 160);
    let hdr = rpc(&node, "getblockheader", json!({"blockhash": h3}))
        .await
        .1["result"]
        .clone();
    assert_eq!(hdr["height"], 3);
    assert_eq!(hdr["confirmations"], 3);
    assert_eq!(hdr["nextblockhash"], blocks[4].block_hash().to_string());
    let raw = rpc(&node, "getblock", json!([h3, 0])).await.1["result"].clone();
    assert_eq!(
        raw,
        bitcoin::consensus::encode::serialize(&blocks[3]).to_lower_hex_string()
    );
    let verbose = rpc(&node, "getblock", json!([h3])).await.1["result"].clone();
    assert_eq!(
        verbose["tx"][0],
        blocks[3].txdata[0].compute_txid().to_string()
    );
    assert_eq!(verbose["nTx"], 1);
    let unknown = "00".repeat(32);
    assert_eq!(
        rpc(&node, "getblock", json!([unknown])).await.1["error"]["code"],
        -5
    );
}

#[tokio::test]
async fn batches_unknown_methods_and_fees_over_rpc() {
    let blocks = build_chain(2, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let (node, _) = started_node(&[a, b], &blocks).await;
    let (status, v) = rpc(&node, "importprivkey", json!(["x"])).await;
    assert_eq!(status, 404);
    assert_eq!(v["error"]["code"], -32601, "no wallet calls at all");
    let batch = json!([
        {"id": 1, "method": "getblockcount"},
        {"id": 2, "method": "estimatesmartfee", "params": [6]},
        {"id": 3, "method": "nope"}
    ]);
    let (status, v) = process_body(&node, batch.to_string().as_bytes()).await;
    assert_eq!(status.as_u16(), 200);
    assert_eq!(v[0]["result"], 2);
    assert_eq!(
        v[1]["result"]["feerate"], 0.0001,
        "10 sat/vB at the 6-block target"
    );
    assert_eq!(v[2]["error"]["code"], -32601);
    let (status, v) = process_body(&node, b"{not json").await;
    assert_eq!(status.as_u16(), 500);
    assert_eq!(v["error"]["code"], -32700);
}

#[tokio::test]
async fn send_then_see_it_in_our_mempool_and_spending_lookup() {
    let blocks = build_chain(3, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let (node, _) = started_node(&[a, b], &blocks).await;
    let tx = spend(&blocks[1].txdata[0], 0, 4000, 8);
    let txid = tx.compute_txid().to_string();
    assert_eq!(
        rpc(&node, "sendrawtransaction", json!([tx_hex(&tx)]))
            .await
            .1["result"],
        txid
    );
    assert_eq!(
        rpc(&node, "getrawmempool", json!([])).await.1["result"],
        json!([txid])
    );
    let prev = blocks[1].txdata[0].compute_txid().to_string();
    let v = rpc(
        &node,
        "gettxspendingprevout",
        json!([[{"txid": prev, "vout": 0}]]),
    )
    .await
    .1;
    assert_eq!(v["result"][0]["spendingtxid"], txid);
    let v = rpc(&node, "getrawtransaction", json!([txid, true])).await.1;
    assert_eq!(v["result"]["txid"], txid);
    let v = rpc(&node, "testmempoolaccept", json!([[tx_hex(&tx)]]))
        .await
        .1;
    assert_eq!(v["result"][0]["reject-reason"], "txn-already-in-mempool");
}

#[tokio::test]
async fn the_http_server_requires_the_cookie_or_rpc_password() {
    let blocks = build_chain(2, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let (node, _) = started_node(&[a, b], &blocks).await;
    let app = router(
        node,
        Auth {
            cookie_password: "c00k1e".into(),
            user: Some("lnd".into()),
            password: Some("pw".into()),
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = format!("http://{addr}/");
    let body = json!({"id": 1, "method": "getblockcount"}).to_string();

    let r = client.post(&url).body(body.clone()).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 401);
    let r = client
        .post(&url)
        .basic_auth("lnd", Some("wrong"))
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
    for (u, p) in [("__cookie__", "c00k1e"), ("lnd", "pw")] {
        let r = client
            .post(&url)
            .basic_auth(u, Some(p))
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        let v: Value = serde_json::from_str(&r.text().await.unwrap()).unwrap();
        assert_eq!(v["result"], 2);
    }
    let r = client
        .get(format!("http://{addr}/status"))
        .basic_auth("lnd", Some("pw"))
        .send()
        .await
        .unwrap();
    let v: Value = serde_json::from_str(&r.text().await.unwrap()).unwrap();
    assert_eq!(v["synced"], true);
    assert_eq!(v["healthy_sources"], 2);
    let _ = SourceError::NotFound;
}
