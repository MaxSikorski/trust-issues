//! A real source: an Esplora-compatible HTTP API (mempool.space, blockstream.info
//! or your own), reached over Tor for onions.
//!
//! Each source gets its own Tor circuit (a distinct SOCKS username, which Tor
//! isolates by default), and every broadcast gets a fresh one.

use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::block::Header;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hex::FromHex;
use bitcoin::{BlockHash, TxMerkleNode, Txid};
use serde::Deserialize;

use crate::config::{Route, SourceSpec};
use crate::source::{FeeMap, MerkleProof, Outspend, Source, SourceError, TxStatus};

const TIMEOUT: Duration = Duration::from_secs(90);
/// Signet and mainnet blocks are at most 4 MB; refuse anything far bigger.
const MAX_BODY: usize = 8 * 1024 * 1024;
const USER_AGENT: &str = "trust-issues/0.1";

pub struct EsploraSource {
    name: String,
    base: String,
    route: Route,
    client: reqwest::Client,
    /// Session tag that keeps this source on its own circuit.
    session: String,
    broadcasts: AtomicU64,
}

fn build_client(route: &Route, isolation: &str) -> Result<reqwest::Client, String> {
    let builder = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::none());
    let builder = match route {
        Route::Tor(socks) => {
            // socks5h: the onion name is resolved inside Tor, never locally.
            let proxy = reqwest::Proxy::all(format!("socks5h://{isolation}:x@{socks}"))
                .map_err(|e| e.to_string())?;
            builder.proxy(proxy)
        }
        Route::Direct => builder.no_proxy(),
    };
    builder.build().map_err(|e| e.to_string())
}

fn random_tag() -> String {
    let mut b = [0u8; 8];
    let _ = getrandom::fill(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The error and its causes, cleaned, e.g. "error sending request: socks connect error: …".
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut cur = e.source();
    while let Some(s) = cur {
        out.push_str(": ");
        out.push_str(&s.to_string());
        cur = s.source();
    }
    clean_text(&out)
}

/// Keep only printable characters and at most 200 of them: answers from
/// sources are untrusted text.
pub fn clean_text(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect::<String>()
        .trim()
        .to_string()
}

impl EsploraSource {
    pub fn new(spec: &SourceSpec) -> Result<Self, String> {
        let session = format!("eb-{}", random_tag());
        Ok(Self {
            name: spec.name.clone(),
            base: spec.url.trim_end_matches('/').to_string(),
            route: spec.route.clone(),
            client: build_client(&spec.route, &session)?,
            session,
            broadcasts: AtomicU64::new(0),
        })
    }

    async fn get_bytes(&self, path: &str) -> Result<Vec<u8>, SourceError> {
        let resp = self
            .client
            .get(format!("{}{}", self.base, path))
            .send()
            .await
            .map_err(|e| SourceError::Transport(error_chain(&e.without_url())))?;
        read_body(resp).await
    }

    async fn get_text(&self, path: &str) -> Result<String, SourceError> {
        let bytes = self.get_bytes(path).await?;
        String::from_utf8(bytes)
            .map(|s| s.trim().to_string())
            .map_err(|_| SourceError::Invalid("not text".into()))
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, SourceError> {
        let bytes = self.get_bytes(path).await?;
        serde_json::from_slice(&bytes).map_err(|e| SourceError::Invalid(clean_text(&e.to_string())))
    }
}

async fn read_body(resp: reqwest::Response) -> Result<Vec<u8>, SourceError> {
    let status = resp.status().as_u16();
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    if resp.content_length().is_some_and(|l| l as usize > MAX_BODY) {
        return Err(SourceError::Invalid("answer too large".into()));
    }
    let body = resp
        .bytes()
        .await
        .map_err(|e| SourceError::Transport(error_chain(&e.without_url())))?;
    if body.len() > MAX_BODY {
        return Err(SourceError::Invalid("answer too large".into()));
    }
    match status {
        // Any 2xx counts: mempool.space answers /fee-estimates with 203.
        200..=299 => Ok(body.to_vec()),
        429 => Err(SourceError::RateLimited { retry_after }),
        404 => Err(SourceError::NotFound),
        s => Err(SourceError::Http {
            status: s,
            body: clean_text(&String::from_utf8_lossy(&body)),
        }),
    }
}

fn parse<T: FromStr>(s: &str, what: &str) -> Result<T, SourceError> {
    s.trim()
        .parse::<T>()
        .map_err(|_| SourceError::Invalid(format!("bad {what}")))
}

#[derive(Deserialize)]
struct StatusJson {
    confirmed: bool,
    block_height: Option<u32>,
    block_hash: Option<String>,
}

#[derive(Deserialize)]
struct MerkleJson {
    block_height: u32,
    merkle: Vec<String>,
    pos: u32,
}

#[derive(Deserialize)]
struct OutspendJson {
    spent: bool,
    txid: Option<String>,
    vin: Option<u32>,
}

#[async_trait]
impl Source for EsploraSource {
    fn name(&self) -> &str {
        &self.name
    }

    async fn tip_hash(&self) -> Result<BlockHash, SourceError> {
        parse(&self.get_text("/blocks/tip/hash").await?, "block hash")
    }

    async fn tip_height(&self) -> Result<u32, SourceError> {
        parse(&self.get_text("/blocks/tip/height").await?, "height")
    }

    async fn block_hash_at(&self, height: u32) -> Result<BlockHash, SourceError> {
        parse(
            &self.get_text(&format!("/block-height/{height}")).await?,
            "block hash",
        )
    }

    async fn header(&self, hash: BlockHash) -> Result<Header, SourceError> {
        let hex = self.get_text(&format!("/block/{hash}/header")).await?;
        let bytes =
            Vec::<u8>::from_hex(&hex).map_err(|_| SourceError::Invalid("header hex".into()))?;
        if bytes.len() != 80 {
            return Err(SourceError::Invalid("header is not 80 bytes".into()));
        }
        deserialize(&bytes).map_err(|_| SourceError::Invalid("header".into()))
    }

    async fn raw_block(&self, hash: BlockHash) -> Result<Vec<u8>, SourceError> {
        self.get_bytes(&format!("/block/{hash}/raw")).await
    }

    async fn raw_tx(&self, txid: Txid) -> Result<Vec<u8>, SourceError> {
        let hex = self.get_text(&format!("/tx/{txid}/hex")).await?;
        Vec::<u8>::from_hex(&hex).map_err(|_| SourceError::Invalid("tx hex".into()))
    }

    async fn tx_status(&self, txid: Txid) -> Result<TxStatus, SourceError> {
        let s: StatusJson = self.get_json(&format!("/tx/{txid}/status")).await?;
        let block_hash = match s.block_hash {
            Some(h) => Some(parse(&h, "block hash")?),
            None => None,
        };
        Ok(TxStatus {
            confirmed: s.confirmed,
            block_height: s.block_height,
            block_hash,
        })
    }

    async fn merkle_proof(&self, txid: Txid) -> Result<MerkleProof, SourceError> {
        let m: MerkleJson = self.get_json(&format!("/tx/{txid}/merkle-proof")).await?;
        let merkle = m
            .merkle
            .iter()
            .map(|s| parse::<TxMerkleNode>(s, "merkle node"))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(MerkleProof {
            block_height: m.block_height,
            merkle,
            pos: m.pos,
        })
    }

    async fn outspend(&self, txid: Txid, vout: u32) -> Result<Outspend, SourceError> {
        let o: OutspendJson = self
            .get_json(&format!("/tx/{txid}/outspend/{vout}"))
            .await?;
        let txid = match o.txid {
            Some(t) => Some(parse(&t, "txid")?),
            None => None,
        };
        Ok(Outspend {
            spent: o.spent,
            txid,
            vin: o.vin,
        })
    }

    async fn fee_estimates(&self) -> Result<FeeMap, SourceError> {
        let raw: std::collections::BTreeMap<String, f64> = self.get_json("/fee-estimates").await?;
        let mut out = FeeMap::new();
        for (k, v) in raw {
            if let Ok(target) = k.parse::<u16>()
                && v.is_finite()
                && v > 0.0
            {
                out.insert(target, v);
            }
        }
        Ok(out)
    }

    async fn broadcast(&self, tx_hex: &str) -> Result<Txid, SourceError> {
        // A fresh circuit for every broadcast, so sends can't be linked to
        // each other or to this source's polling.
        let n = self.broadcasts.fetch_add(1, Ordering::Relaxed);
        let client = build_client(
            &self.route,
            &format!("{}-tx{n}-{}", self.session, random_tag()),
        )
        .map_err(SourceError::Transport)?;
        let resp = client
            .post(format!("{}/tx", self.base))
            .header(reqwest::header::CONTENT_TYPE, "text/plain")
            .body(tx_hex.to_string())
            .send()
            .await
            .map_err(|e| SourceError::Transport(error_chain(&e.without_url())))?;
        let bytes = read_body(resp).await?;
        let text = String::from_utf8_lossy(&bytes);
        parse(&text, "txid")
    }
}
