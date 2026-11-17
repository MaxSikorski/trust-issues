//! What we ask of a chain-data source. The real one is [`crate::esplora`];
//! tests use scripted fakes that lie in specific ways.

use std::collections::BTreeMap;

use async_trait::async_trait;
use bitcoin::block::Header;
use bitcoin::{BlockHash, TxMerkleNode, Txid};

#[derive(Debug, Clone, PartialEq)]
pub enum SourceError {
    /// HTTP 429: slow down. `retry_after` in seconds, when the source told us.
    RateLimited {
        retry_after: Option<u64>,
    },
    /// We are backing off this source after earlier failures; nothing was sent.
    Cooling,
    NotFound,
    /// Any other HTTP status, with a short, cleaned-up body.
    Http {
        status: u16,
        body: String,
    },
    /// Couldn't reach it (Tor, DNS, timeout, connection).
    Transport(String),
    /// It answered, but the answer isn't well formed.
    Invalid(String),
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceError::RateLimited { retry_after } => {
                write!(f, "rate limited (retry after {retry_after:?} s)")
            }
            SourceError::Cooling => f.write_str("backing off after earlier failures"),
            SourceError::NotFound => f.write_str("not found"),
            SourceError::Http { status, body } => write!(f, "HTTP {status}: {body}"),
            SourceError::Transport(e) => write!(f, "unreachable: {e}"),
            SourceError::Invalid(e) => write!(f, "malformed answer: {e}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxStatus {
    pub confirmed: bool,
    pub block_height: Option<u32>,
    pub block_hash: Option<BlockHash>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    pub block_height: u32,
    pub merkle: Vec<TxMerkleNode>,
    pub pos: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outspend {
    pub spent: bool,
    pub txid: Option<Txid>,
    pub vin: Option<u32>,
}

/// Fee estimates in sat/vB, keyed by confirmation target in blocks.
pub type FeeMap = BTreeMap<u16, f64>;

#[async_trait]
pub trait Source: Send + Sync {
    /// A short label for logs and the status page (never a secret).
    fn name(&self) -> &str;
    async fn tip_hash(&self) -> Result<BlockHash, SourceError>;
    async fn tip_height(&self) -> Result<u32, SourceError>;
    async fn block_hash_at(&self, height: u32) -> Result<BlockHash, SourceError>;
    async fn header(&self, hash: BlockHash) -> Result<Header, SourceError>;
    async fn raw_block(&self, hash: BlockHash) -> Result<Vec<u8>, SourceError>;
    async fn raw_tx(&self, txid: Txid) -> Result<Vec<u8>, SourceError>;
    async fn tx_status(&self, txid: Txid) -> Result<TxStatus, SourceError>;
    async fn merkle_proof(&self, txid: Txid) -> Result<MerkleProof, SourceError>;
    async fn outspend(&self, txid: Txid, vout: u32) -> Result<Outspend, SourceError>;
    async fn fee_estimates(&self) -> Result<FeeMap, SourceError>;
    /// Send a raw transaction (hex). Real sources use a fresh Tor circuit for each call.
    async fn broadcast(&self, tx_hex: &str) -> Result<Txid, SourceError>;
}

/// Characters that are not "control" to Rust but still fake line breaks,
/// reorder text or hide it: zero-width and direction marks (U+200B-200F,
/// U+061C), line/paragraph separators and bidi overrides (U+2028-202E),
/// invisible operators and bidi isolates (U+2060-206F), U+180E, U+FEFF.
fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{61c}' | '\u{180e}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}'
        | '\u{2060}'..='\u{206f}' | '\u{feff}')
}

/// Keep only printable characters and at most 200 of them: answers from
/// sources are untrusted text. Control characters (including U+0085) and the
/// invisible ones above are dropped.
pub fn clean_text(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && !is_invisible(*c))
        .take(200)
        .collect::<String>()
        .trim()
        .to_string()
}
