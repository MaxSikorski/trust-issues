//! Deterministic regtest chains and fake explorers that can be told to lie,
//! withhold, rate-limit or drop broadcasts. Used by the demo and the tests.
//! No network, no keys, no real coins.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use crate::node::{ManualClock, Node, Settings};
use crate::source::{FeeMap, MerkleProof, Outspend, Source, SourceError, TxStatus};
use async_trait::async_trait;
use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version as BlockVersion};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::hex::DisplayHex;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxMerkleNode, TxOut, Txid, Witness,
};

pub const REGTEST_BITS: u32 = 0x207f_ffff;

pub fn genesis() -> Block {
    bitcoin::constants::genesis_block(Network::Regtest)
}

pub fn coinbase(height: u32, tag: u8) -> Transaction {
    let mut sig = height.to_le_bytes().to_vec();
    sig.push(tag);
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(sig),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50 * 100_000_000),
            script_pubkey: p2wpkh_like(tag),
        }],
    }
}

/// A 22-byte witness-v0 script (keeps test transactions well clear of 64 bytes).
pub fn p2wpkh_like(tag: u8) -> ScriptBuf {
    let mut s = vec![0x00, 0x14];
    s.extend([tag; 20]);
    ScriptBuf::from_bytes(s)
}

/// Spend output `vout` of `prev`, paying `value` sat.
pub fn spend(prev: &Transaction, vout: u32, value: u64, tag: u8) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev.compute_txid(),
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: p2wpkh_like(tag),
        }],
    }
}

pub fn mine(prev: &Header, height: u32, mut txs: Vec<Transaction>, tag: u8, bits: u32) -> Block {
    txs.insert(0, coinbase(height, tag));
    let mut block = Block {
        header: Header {
            version: BlockVersion::from_consensus(0x2000_0000),
            prev_blockhash: prev.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: prev.time + 600,
            bits: CompactTarget::from_consensus(bits),
            nonce: 0,
        },
        txdata: txs,
    };
    block.header.merkle_root = block.compute_merkle_root().expect("has txs");
    while block.header.validate_pow(block.header.target()).is_err() {
        block.header.nonce += 1;
    }
    block
}

/// A chain from regtest genesis: `blocks[h]` is the block at height `h`.
pub fn build_chain(len: u32, tag: u8) -> Vec<Block> {
    let mut blocks = vec![genesis()];
    extend(&mut blocks, len, tag);
    blocks
}

pub fn extend(blocks: &mut Vec<Block>, n: u32, tag: u8) {
    for _ in 0..n {
        let prev = blocks.last().expect("non-empty").header;
        let h = blocks.len() as u32;
        blocks.push(mine(&prev, h, vec![], tag, REGTEST_BITS));
    }
}

/// A copy of `blocks[..=fork_at]` extended by `n` different blocks.
pub fn fork(blocks: &[Block], fork_at: u32, n: u32, tag: u8) -> Vec<Block> {
    let mut f = blocks[..=fork_at as usize].to_vec();
    extend(&mut f, n, tag);
    f
}

/// Electrum-style merkle branch for the transaction at `pos`.
pub fn merkle_branch(block: &Block, pos: usize) -> Vec<TxMerkleNode> {
    let mut level: Vec<[u8; 32]> = block
        .txdata
        .iter()
        .map(|t| t.compute_txid().to_byte_array())
        .collect();
    let mut idx = pos;
    let mut branch = Vec::new();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("non-empty"));
        }
        branch.push(TxMerkleNode::from_byte_array(level[idx ^ 1]));
        level = level
            .chunks(2)
            .map(|p| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&p[0]);
                buf[32..].copy_from_slice(&p[1]);
                sha256d::Hash::hash(&buf).to_byte_array()
            })
            .collect();
        idx /= 2;
    }
    branch
}

#[derive(Default)]
pub struct FakeState {
    pub blocks: Vec<Block>,
    /// Withholding: show nothing above this height.
    pub visible: u32,
    pub genesis_override: Option<BlockHash>,
    /// Every call fails with this.
    pub fail: Option<SourceError>,
    /// The next calls fail with these, one each, front first; then the
    /// source answers normally again (a flaky explorer or Tor circuit).
    pub fail_next: VecDeque<SourceError>,
    pub tamper_blocks: bool,
    /// header(hash) answers this instead of the truth.
    pub header_lie: Option<Header>,
    /// tip_hash answers this instead of the truth.
    pub tip_lie: Option<BlockHash>,
    /// Lies for specific outspend lookups.
    pub outspend_lie: HashMap<(Txid, u32), Outspend>,
    pub fees: FeeMap,
    /// Reject broadcasts with this HTTP 400 body.
    pub reject_body: Option<String>,
    /// Accept broadcasts but then forget them (status says not found).
    pub forget_broadcasts: bool,
    pub received: Vec<String>,
    pub mempool: HashMap<Txid, Transaction>,
    pub calls: usize,
}

pub struct FakeSource {
    pub name: String,
    pub state: Mutex<FakeState>,
}

impl FakeSource {
    pub fn honest(name: &str, blocks: &[Block]) -> Arc<Self> {
        let mut fees = FeeMap::new();
        fees.insert(1, 20.0);
        fees.insert(6, 10.0);
        fees.insert(144, 2.0);
        Arc::new(Self {
            name: name.into(),
            state: Mutex::new(FakeState {
                visible: blocks.len() as u32 - 1,
                blocks: blocks.to_vec(),
                fees,
                ..Default::default()
            }),
        })
    }

    pub fn with<T>(&self, f: impl FnOnce(&mut FakeState) -> T) -> T {
        f(&mut self.state.lock().unwrap())
    }

    /// Replace this source's chain and show all of it.
    pub fn set_chain(&self, blocks: &[Block]) {
        self.with(|s| {
            s.blocks = blocks.to_vec();
            s.visible = blocks.len() as u32 - 1;
        });
    }

    fn visible_blocks(s: &FakeState) -> &[Block] {
        &s.blocks[..=(s.visible as usize).min(s.blocks.len() - 1)]
    }

    fn guard(&self) -> Result<std::sync::MutexGuard<'_, FakeState>, SourceError> {
        let mut s = self.state.lock().unwrap();
        s.calls += 1;
        if let Some(e) = &s.fail {
            return Err(e.clone());
        }
        if let Some(e) = s.fail_next.pop_front() {
            return Err(e);
        }
        Ok(s)
    }

    fn find_tx(s: &FakeState, txid: Txid) -> Option<(Transaction, Option<(u32, usize)>)> {
        for (h, b) in Self::visible_blocks(s).iter().enumerate() {
            if let Some(pos) = b.txdata.iter().position(|t| t.compute_txid() == txid) {
                return Some((b.txdata[pos].clone(), Some((h as u32, pos))));
            }
        }
        s.mempool.get(&txid).map(|t| (t.clone(), None))
    }
}

#[async_trait]
impl Source for FakeSource {
    fn name(&self) -> &str {
        &self.name
    }

    async fn tip_hash(&self) -> Result<BlockHash, SourceError> {
        let s = self.guard()?;
        if let Some(h) = s.tip_lie {
            return Ok(h);
        }
        Ok(Self::visible_blocks(&s).last().unwrap().block_hash())
    }

    async fn tip_height(&self) -> Result<u32, SourceError> {
        let s = self.guard()?;
        Ok(Self::visible_blocks(&s).len() as u32 - 1)
    }

    async fn block_hash_at(&self, height: u32) -> Result<BlockHash, SourceError> {
        let s = self.guard()?;
        if height == 0
            && let Some(g) = s.genesis_override
        {
            return Ok(g);
        }
        Self::visible_blocks(&s)
            .get(height as usize)
            .map(|b| b.block_hash())
            .ok_or(SourceError::NotFound)
    }

    async fn header(&self, hash: BlockHash) -> Result<Header, SourceError> {
        let s = self.guard()?;
        if let Some(h) = s.header_lie {
            return Ok(h);
        }
        s.blocks
            .iter()
            .find(|b| b.block_hash() == hash)
            .map(|b| b.header)
            .ok_or(SourceError::NotFound)
    }

    async fn raw_block(&self, hash: BlockHash) -> Result<Vec<u8>, SourceError> {
        let s = self.guard()?;
        let mut b = s
            .blocks
            .iter()
            .find(|b| b.block_hash() == hash)
            .cloned()
            .ok_or(SourceError::NotFound)?;
        if s.tamper_blocks {
            b.txdata[0].output[0].value = Amount::from_sat(21_000_000 * 100_000_000);
        }
        Ok(serialize(&b))
    }

    async fn raw_tx(&self, txid: Txid) -> Result<Vec<u8>, SourceError> {
        let s = self.guard()?;
        Self::find_tx(&s, txid)
            .map(|(t, _)| serialize(&t))
            .ok_or(SourceError::NotFound)
    }

    async fn tx_status(&self, txid: Txid) -> Result<TxStatus, SourceError> {
        let s = self.guard()?;
        match Self::find_tx(&s, txid) {
            Some((_, Some((h, _)))) => Ok(TxStatus {
                confirmed: true,
                block_height: Some(h),
                block_hash: Some(s.blocks[h as usize].block_hash()),
            }),
            Some((_, None)) => Ok(TxStatus {
                confirmed: false,
                block_height: None,
                block_hash: None,
            }),
            None => Err(SourceError::NotFound),
        }
    }

    async fn merkle_proof(&self, txid: Txid) -> Result<MerkleProof, SourceError> {
        let s = self.guard()?;
        match Self::find_tx(&s, txid) {
            Some((_, Some((h, pos)))) => Ok(MerkleProof {
                block_height: h,
                merkle: merkle_branch(&s.blocks[h as usize], pos),
                pos: pos as u32,
            }),
            _ => Err(SourceError::NotFound),
        }
    }

    async fn outspend(&self, txid: Txid, vout: u32) -> Result<Outspend, SourceError> {
        let s = self.guard()?;
        if let Some(o) = s.outspend_lie.get(&(txid, vout)) {
            return Ok(o.clone());
        }
        let target = OutPoint { txid, vout };
        let in_blocks = Self::visible_blocks(&s)
            .iter()
            .flat_map(|b| b.txdata.iter());
        for t in in_blocks.chain(s.mempool.values()) {
            if let Some(vin) = t.input.iter().position(|i| i.previous_output == target) {
                return Ok(Outspend {
                    spent: true,
                    txid: Some(t.compute_txid()),
                    vin: Some(vin as u32),
                });
            }
        }
        Ok(Outspend {
            spent: false,
            txid: None,
            vin: None,
        })
    }

    async fn fee_estimates(&self) -> Result<FeeMap, SourceError> {
        let s = self.guard()?;
        Ok(s.fees.clone())
    }

    async fn broadcast(&self, tx_hex: &str) -> Result<Txid, SourceError> {
        let mut s = self.guard()?;
        s.received.push(tx_hex.to_string());
        if let Some(body) = &s.reject_body {
            return Err(SourceError::Http {
                status: 400,
                body: body.clone(),
            });
        }
        let bytes = <Vec<u8> as bitcoin::hex::FromHex>::from_hex(tx_hex).map_err(|_| {
            SourceError::Http {
                status: 400,
                body: "bad hex".into(),
            }
        })?;
        let tx: Transaction =
            bitcoin::consensus::encode::deserialize(&bytes).map_err(|_| SourceError::Http {
                status: 400,
                body: "TX decode failed".into(),
            })?;
        let txid = tx.compute_txid();
        if !s.forget_broadcasts {
            s.mempool.insert(txid, tx);
        }
        Ok(txid)
    }
}

pub fn tx_hex(tx: &Transaction) -> String {
    serialize(tx).to_lower_hex_string()
}

pub fn fixed_jitter() -> f64 {
    0.0
}

pub fn settings(checkpoint: Option<(u32, BlockHash)>) -> Settings {
    Settings {
        network: Network::Regtest,
        checkpoint,
        fee_ceiling_sat_vb: 1000.0,
        requests_per_sec: 2.0,
        burst: 1_000_000.0,
        jitter: fixed_jitter,
    }
}

/// A node over these fakes, its clock set just after `blocks`' tip, started
/// from genesis and ticked once.
pub async fn started_node(
    sources: &[Arc<FakeSource>],
    blocks: &[Block],
) -> (Arc<Node>, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(
        u64::from(blocks.last().unwrap().header.time) + 60,
    ));
    let dyns: Vec<Arc<dyn Source>> = sources
        .iter()
        .map(|s| s.clone() as Arc<dyn Source>)
        .collect();
    let node = Arc::new(Node::new(
        settings(Some((0, genesis().block_hash()))),
        dyns,
        clock.clone(),
    ));
    node.start().await.expect("start");
    node.tick().await;
    (node, clock)
}

pub fn alarm_codes(node: &Node) -> Vec<String> {
    node.alarms().keys().cloned().collect()
}

pub fn sorted<T: Ord>(v: impl IntoIterator<Item = T>) -> Vec<T> {
    let mut v: Vec<T> = v.into_iter().collect();
    v.sort();
    v
}
