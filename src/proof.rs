//! Checks for things a source can prove: block contents, transactions and
//! "this transaction is in that block" (merkle proofs).

use bitcoin::block::Header;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::{Block, BlockHash, Network, Transaction, TxMerkleNode, Txid};

use crate::signet::{
    STANDARD_SIGNET_CHALLENGE, SignetError, check_block_solution, witness_commitment_index,
};

/// Why a block or transaction from a source was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    Undecodable,
    WrongHash,
    BadMerkleRoot,
    /// The transaction list repeats a transaction where the merkle tree
    /// pads with a copy, so it matches the header's merkle root without
    /// being the block (CVE-2012-2459; Core's "mutated" merkle tree).
    DuplicateTransactions,
    /// The witness data doesn't match the coinbase's witness commitment,
    /// or is there without one, or the commitment's reserved value is
    /// missing (Core's `CheckWitnessMalleation`). Stripping a block's
    /// witnesses keeps its header; this is what catches it.
    BadWitnessCommitment,
    /// 64-byte transactions can be confused with merkle tree nodes (CVE-2012-2459 family).
    SuspiciousSize,
    BadMerkleProof,
    /// On signet: the block isn't signed for our signet (BIP325), or we
    /// can't tell (see [`ProofError::proves_a_lie`]).
    BadSignetSignature(SignetError),
}

impl ProofError {
    /// True if the data is provably not what was asked for, so the source
    /// that served it lied (or passed on a lie). False only for a signet
    /// solution this checker can't judge: Bitcoin Core might accept that
    /// block, so we refuse it without blaming whoever served it.
    pub fn proves_a_lie(&self) -> bool {
        match self {
            ProofError::BadSignetSignature(e) => e.proves_a_lie(),
            _ => true,
        }
    }
}

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ProofError::Undecodable => "data doesn't decode",
            ProofError::WrongHash => "data doesn't hash to what was asked for",
            ProofError::BadMerkleRoot => "block's transactions don't match its merkle root",
            ProofError::DuplicateTransactions => {
                "block's transaction list is padded with a duplicate (a mutated merkle tree)"
            }
            ProofError::BadWitnessCommitment => "block's witness data doesn't match its commitment",
            ProofError::SuspiciousSize => "64-byte transaction refused",
            ProofError::BadMerkleProof => "merkle proof doesn't lead to the block's merkle root",
            ProofError::BadSignetSignature(e) => {
                return write!(f, "block's signet signature fails: {e}");
            }
        };
        f.write_str(s)
    }
}

/// Decode a raw block and check it is exactly the block `expected` names,
/// as Bitcoin Core's `CheckBlock` would before trusting a body: same hash,
/// transactions matching the merkle root with no duplicate padding, and
/// witness data matching the coinbase's witness commitment. Anything that
/// passes is byte-for-byte the block (no other body has this header).
pub fn verify_block(raw: &[u8], expected: BlockHash) -> Result<Block, ProofError> {
    let block: Block = deserialize(raw).map_err(|_| ProofError::Undecodable)?;
    if block.block_hash() != expected {
        return Err(ProofError::WrongHash);
    }
    let txids: Vec<[u8; 32]> = block
        .txdata
        .iter()
        .map(|t| t.compute_txid().to_byte_array())
        .collect();
    let Some((root, mutated)) = merkle_root_and_mutation(txids) else {
        return Err(ProofError::BadMerkleRoot);
    };
    if root != block.header.merkle_root.to_byte_array() {
        return Err(ProofError::BadMerkleRoot);
    }
    if mutated {
        return Err(ProofError::DuplicateTransactions);
    }
    check_witness_malleation(&block)?;
    Ok(block)
}

/// Core's `ComputeMerkleRoot` with its `mutated` flag: the root, and
/// whether any level has two identical neighbours (which is how a
/// duplicated transaction can keep the root). `None` for no transactions.
fn merkle_root_and_mutation(mut level: Vec<[u8; 32]>) -> Option<([u8; 32], bool)> {
    if level.is_empty() {
        return None;
    }
    let mut mutated = false;
    while level.len() > 1 {
        if level.as_chunks::<2>().0.iter().any(|[a, b]| a == b) {
            mutated = true;
        }
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("non-empty"));
        }
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|[a, b]| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(a);
                buf[32..].copy_from_slice(b);
                sha256d::Hash::hash(&buf).to_byte_array()
            })
            .collect();
    }
    Some((level[0], mutated))
}

/// Core's `CheckWitnessMalleation` (segwit is active from the start on
/// signet and regtest): if the coinbase has a witness commitment, its
/// input's witness must be exactly one 32-byte reserved value and the
/// commitment must match the block's witness merkle root; if it has none,
/// no transaction may carry witness data.
fn check_witness_malleation(block: &Block) -> Result<(), ProofError> {
    let coinbase = block.txdata.first().ok_or(ProofError::BadMerkleRoot)?;
    let Some(idx) = witness_commitment_index(coinbase) else {
        let any_witness = block
            .txdata
            .iter()
            .any(|t| t.input.iter().any(|i| !i.witness.is_empty()));
        return if any_witness {
            Err(ProofError::BadWitnessCommitment)
        } else {
            Ok(())
        };
    };
    let witness = &coinbase
        .input
        .first()
        .ok_or(ProofError::BadWitnessCommitment)?
        .witness;
    let reserved = match witness.nth(0) {
        Some(r) if witness.len() == 1 && r.len() == 32 => r,
        _ => return Err(ProofError::BadWitnessCommitment),
    };
    let root = block
        .witness_root()
        .ok_or(ProofError::BadWitnessCommitment)?;
    let expected = Block::compute_witness_commitment(&root, reserved);
    let script = coinbase.output[idx].script_pubkey.as_bytes();
    if script[6..38] != expected.to_byte_array() {
        return Err(ProofError::BadWitnessCommitment);
    }
    Ok(())
}

/// [`verify_block`], plus, on signet, the block's signature (BIP325): a
/// block from another signet, or one with grinded-out proof of work but no
/// signer's signature, is refused. Regtest has no block signatures.
///
/// In a build without the `signet-check` feature (the browser demo) every
/// signet block is refused: there is no checker to pass it.
pub fn verify_block_for(
    network: Network,
    raw: &[u8],
    expected: BlockHash,
) -> Result<Block, ProofError> {
    let block = verify_block(raw, expected)?;
    if network == Network::Signet {
        let challenge = <Vec<u8> as bitcoin::hex::FromHex>::from_hex(STANDARD_SIGNET_CHALLENGE)
            .expect("constant is hex");
        check_block_solution(&block, &challenge).map_err(ProofError::BadSignetSignature)?;
    }
    Ok(block)
}

/// Decode a raw transaction and check it is the one `expected` names.
pub fn verify_tx(raw: &[u8], expected: Txid) -> Result<Transaction, ProofError> {
    if raw.len() == 64 {
        return Err(ProofError::SuspiciousSize);
    }
    let tx: Transaction = deserialize(raw).map_err(|_| ProofError::Undecodable)?;
    if tx.compute_txid() != expected {
        return Err(ProofError::WrongHash);
    }
    Ok(tx)
}

/// Check an Electrum-style merkle branch: `txid` at position `pos` in a block
/// whose header is `header`.
pub fn verify_merkle_branch(
    txid: Txid,
    branch: &[TxMerkleNode],
    pos: u32,
    header: &Header,
) -> Result<(), ProofError> {
    // A position that doesn't fit the branch length is malformed. (A
    // single-transaction block has an empty branch and position 0.)
    if branch.len() >= 32 || u64::from(pos) >= (1u64 << branch.len()) {
        return Err(ProofError::BadMerkleProof);
    }
    let mut acc = txid.to_byte_array();
    let mut index = pos;
    for node in branch {
        let sibling = node.to_byte_array();
        let mut buf = [0u8; 64];
        if index & 1 == 0 {
            buf[..32].copy_from_slice(&acc);
            buf[32..].copy_from_slice(&sibling);
        } else {
            buf[..32].copy_from_slice(&sibling);
            buf[32..].copy_from_slice(&acc);
        }
        acc = sha256d::Hash::hash(&buf).to_byte_array();
        index >>= 1;
    }
    if acc == header.merkle_root.to_byte_array() {
        Ok(())
    } else {
        Err(ProofError::BadMerkleProof)
    }
}
