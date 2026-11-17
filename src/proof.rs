//! Checks for things a source can prove: block contents, transactions and
//! "this transaction is in that block" (merkle proofs).

use bitcoin::block::Header;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::{Block, BlockHash, Network, Transaction, TxMerkleNode, Txid};

use crate::signet::{STANDARD_SIGNET_CHALLENGE, SignetError, check_block_solution};

/// Why a block or transaction from a source was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    Undecodable,
    WrongHash,
    BadMerkleRoot,
    BadWitnessCommitment,
    /// 64-byte transactions can be confused with merkle tree nodes (CVE-2012-2459 family).
    SuspiciousSize,
    BadMerkleProof,
    /// On signet: the block isn't signed for our signet (BIP325).
    BadSignetSignature(SignetError),
}

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ProofError::Undecodable => "data doesn't decode",
            ProofError::WrongHash => "data doesn't hash to what was asked for",
            ProofError::BadMerkleRoot => "block's transactions don't match its merkle root",
            ProofError::BadWitnessCommitment => "block's witness commitment doesn't match",
            ProofError::SuspiciousSize => "64-byte transaction refused",
            ProofError::BadMerkleProof => "merkle proof doesn't lead to the block's merkle root",
            ProofError::BadSignetSignature(e) => {
                return write!(f, "block's signet signature fails: {e}");
            }
        };
        f.write_str(s)
    }
}

/// Decode a raw block and check it is exactly the block `expected` names:
/// same hash, transactions matching the merkle root and witness commitment.
pub fn verify_block(raw: &[u8], expected: BlockHash) -> Result<Block, ProofError> {
    let block: Block = deserialize(raw).map_err(|_| ProofError::Undecodable)?;
    if block.block_hash() != expected {
        return Err(ProofError::WrongHash);
    }
    if !block.check_merkle_root() {
        return Err(ProofError::BadMerkleRoot);
    }
    if !block.check_witness_commitment() {
        return Err(ProofError::BadWitnessCommitment);
    }
    Ok(block)
}

/// [`verify_block`], plus, on signet, the block's signature (BIP325): a
/// block from another signet, or one with grinded-out proof of work but no
/// signer's signature, is refused. Regtest has no block signatures.
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
