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
use crate::source::{FeeMap, MerkleProof, Outspend, Source, SourceError, TxStatus, clean_text};

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

async fn read_body(mut resp: reqwest::Response) -> Result<Vec<u8>, SourceError> {
    let status = resp.status().as_u16();
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    // A slow-down needs no body. Returning before reading one means the
    // instruction is recorded even if the caller stops waiting meanwhile.
    if let Err(e @ SourceError::RateLimited { .. }) = classify(status, retry_after, &[]) {
        return Err(e);
    }
    if resp.content_length().is_some_and(|l| l as usize > MAX_BODY) {
        return Err(SourceError::Invalid("answer too large".into()));
    }
    // Read piece by piece and stop as soon as it's too big: a chunked
    // answer has no length up front, and must not be held whole first.
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| SourceError::Transport(error_chain(&e.without_url())))?
    {
        if body.len() + chunk.len() > MAX_BODY {
            return Err(SourceError::Invalid("answer too large".into()));
        }
        body.extend_from_slice(&chunk);
    }
    classify(status, retry_after, &body)
}

fn classify(status: u16, retry_after: Option<u64>, body: &[u8]) -> Result<Vec<u8>, SourceError> {
    match status {
        // Any 2xx counts: mempool.space answers /fee-estimates with 203.
        200..=299 => Ok(body.to_vec()),
        429 => Err(SourceError::RateLimited { retry_after }),
        // A 503 that says when to come back is asking us to slow down too
        // (RFC 9110 section 10.2.3).
        503 if retry_after.is_some() => Err(SourceError::RateLimited { retry_after }),
        404 => Err(SourceError::NotFound),
        s => Err(SourceError::Http {
            status: s,
            body: clean_text(&String::from_utf8_lossy(body)),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_on_a_503_is_a_rate_limit() {
        assert!(matches!(
            classify(503, Some(600), b""),
            Err(SourceError::RateLimited {
                retry_after: Some(600)
            })
        ));
        assert!(matches!(
            classify(503, None, b"busy"),
            Err(SourceError::Http { status: 503, .. })
        ));
        assert!(matches!(
            classify(429, None, b""),
            Err(SourceError::RateLimited { retry_after: None })
        ));
    }

    /// A chunked answer has no length up front. A tiny HTTP server on
    /// loopback (no network) streams 64 MiB in 64 KiB chunks; we must stop
    /// reading soon after 8 MiB instead of holding the whole answer first.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_chunked_answer_is_cut_off_at_the_limit_while_streaming() {
        use bitcoin::hashes::Hash;
        use std::io::{Read, Write};

        const TOTAL: usize = 64 * 1024 * 1024;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            // Never hang the test: a reader that stalls ends the stream.
            s.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
            let mut req: Vec<u8> = Vec::new();
            let mut buf = [0u8; 4096];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => return 0,
                    Ok(n) => req.extend(&buf[..n]),
                }
            }
            let head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
            if s.write_all(head.as_bytes()).is_err() {
                return 0;
            }
            let chunk = vec![0u8; 64 * 1024];
            let size = format!("{:x}\r\n", chunk.len());
            let mut sent = 0;
            while sent < TOTAL {
                let ok = s.write_all(size.as_bytes()).is_ok()
                    && s.write_all(&chunk).is_ok()
                    && s.write_all(b"\r\n").is_ok();
                if !ok {
                    return sent;
                }
                sent += chunk.len();
            }
            let _ = s.write_all(b"0\r\n\r\n");
            sent
        });
        let source = EsploraSource::new(&SourceSpec {
            name: "loopback".into(),
            url: format!("http://{addr}"),
            route: Route::Direct,
        })
        .unwrap();
        let res = source.raw_block(BlockHash::all_zeros()).await;
        assert!(
            matches!(&res, Err(SourceError::Invalid(m)) if m.contains("too large")),
            "{res:?}"
        );
        drop(source);
        // Joined off the runtime, so the client can finish hanging up.
        let sent = tokio::task::spawn_blocking(move || server.join().unwrap())
            .await
            .unwrap();
        // What the server got rid of: what we read plus what the kernel's
        // socket buffers took before we hung up. Far less than all of it.
        assert!(sent < 24 * 1024 * 1024, "server sent {sent} bytes");
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
