//! Pure checks: block, transaction and merkle proofs; fee combining; the
//! request budget and backoff schedule.

mod common;

use std::time::Duration;

use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, TxMerkleNode};
use common::*;
use trust_issues::fees;
use trust_issues::limits::{TokenBucket, backoff};
use trust_issues::proof::{ProofError, verify_block, verify_merkle_branch, verify_tx};
use trust_issues::source::FeeMap;

fn block_with_txs(n: usize) -> bitcoin::Block {
    let g = genesis();
    let funding = coinbase(1, 1);
    let txs = (0..n)
        .map(|i| spend(&funding, 0, 1000 + i as u64, i as u8))
        .collect();
    mine(&g.header, 1, txs, 7, REGTEST_BITS)
}

#[test]
fn verified_block_must_match_hash_and_merkle_root() {
    let b = block_with_txs(3);
    let raw = serialize(&b);
    assert!(verify_block(&raw, b.block_hash()).is_ok());
    assert_eq!(
        verify_block(&raw, genesis().block_hash()).unwrap_err(),
        ProofError::WrongHash
    );
    let mut tampered = b.clone();
    tampered.txdata[1].output[0].value = Amount::from_sat(999_999);
    assert_eq!(
        verify_block(&serialize(&tampered), b.block_hash()).unwrap_err(),
        ProofError::BadMerkleRoot
    );
    assert_eq!(
        verify_block(&[1, 2, 3], b.block_hash()).unwrap_err(),
        ProofError::Undecodable
    );
}

#[test]
fn verified_tx_must_match_txid_and_not_be_64_bytes() {
    let tx = spend(&coinbase(1, 1), 0, 5000, 3);
    let raw = serialize(&tx);
    assert_eq!(verify_tx(&raw, tx.compute_txid()).unwrap(), tx);
    let other = spend(&coinbase(2, 1), 0, 5000, 3);
    assert_eq!(
        verify_tx(&raw, other.compute_txid()).unwrap_err(),
        ProofError::WrongHash
    );
    assert_eq!(
        verify_tx(&[0u8; 64], tx.compute_txid()).unwrap_err(),
        ProofError::SuspiciousSize
    );
}

#[test]
fn merkle_branch_checks_every_position_and_rejects_tampering() {
    let b = block_with_txs(4); // 5 transactions: an odd level gets duplicated
    for pos in 0..b.txdata.len() {
        let branch = merkle_branch(&b, pos);
        let txid = b.txdata[pos].compute_txid();
        assert!(
            verify_merkle_branch(txid, &branch, pos as u32, &b.header).is_ok(),
            "pos {pos}"
        );
        // The last transaction of an odd level is paired with a copy of
        // itself, so its left/right bit can't be told apart (Bitcoin's own
        // merkle quirk; harmless here, it's the same txid). Every other
        // position must fail when flipped.
        if pos != b.txdata.len() - 1 {
            let wrong_pos = (pos as u32) ^ 1;
            assert!(
                verify_merkle_branch(txid, &branch, wrong_pos, &b.header).is_err(),
                "pos {pos}"
            );
        }
        let mut bad = branch.clone();
        bad[0] = TxMerkleNode::all_zeros();
        assert!(verify_merkle_branch(txid, &bad, pos as u32, &b.header).is_err());
    }
    // A position too big for the branch is malformed.
    let txid = b.txdata[0].compute_txid();
    assert!(verify_merkle_branch(txid, &merkle_branch(&b, 0), 99, &b.header).is_err());
    // A one-transaction block: empty branch, position 0, txid is the root.
    let single = mine(&genesis().header, 1, vec![], 1, REGTEST_BITS);
    assert!(verify_merkle_branch(single.txdata[0].compute_txid(), &[], 0, &single.header).is_ok());
}

#[test]
fn fee_pick_uses_the_nearest_target_that_is_not_slower() {
    let mut m = FeeMap::new();
    m.insert(1, 30.0);
    m.insert(6, 12.0);
    m.insert(144, 2.0);
    assert_eq!(fees::pick(&m, 1), Some(30.0));
    assert_eq!(fees::pick(&m, 5), Some(30.0));
    assert_eq!(fees::pick(&m, 6), Some(12.0));
    assert_eq!(fees::pick(&m, 100), Some(12.0));
    assert_eq!(fees::pick(&m, 1008), Some(2.0));
    assert_eq!(fees::pick(&FeeMap::new(), 6), None);
}

#[test]
fn fees_use_median_normally_and_highest_when_urgent_and_are_clamped() {
    let v = [5.0, 9.0, 40.0];
    assert_eq!(fees::aggregate(&v, 12, 1000.0), Some(9.0));
    assert_eq!(fees::aggregate(&v, 6, 1000.0), Some(40.0));
    assert_eq!(fees::aggregate(&v, 2, 30.0), Some(30.0), "ceiling");
    assert_eq!(fees::aggregate(&[0.2], 12, 1000.0), Some(1.0), "floor");
    assert_eq!(
        fees::aggregate(&[4.0, 8.0], 12, 1000.0),
        Some(8.0),
        "upper middle"
    );
    assert_eq!(fees::aggregate(&[], 12, 1000.0), None);
    assert_eq!(fees::sat_vb_to_btc_kvb(1.0), 0.00001);
}

#[test]
fn fee_disagreement_is_more_than_double() {
    assert!(!fees::disagree(&[10.0, 20.0]));
    assert!(fees::disagree(&[10.0, 20.1]));
    assert!(!fees::disagree(&[7.0]));
}

#[tokio::test(start_paused = true)]
async fn token_bucket_allows_a_burst_then_the_rate() {
    let start = tokio::time::Instant::now();
    let mut b = TokenBucket::new(1.0, 3.0, start);
    for _ in 0..3 {
        assert_eq!(b.take(start), Duration::ZERO);
    }
    assert_eq!(b.take(start), Duration::from_secs(1));
    // Asking for more than the hard ceiling is clamped to 2 per second.
    let mut fast = TokenBucket::new(50.0, 1.0, start);
    assert_eq!(fast.take(start), Duration::ZERO);
    assert_eq!(fast.take(start), Duration::from_millis(500));
}

#[test]
fn backoff_doubles_from_five_seconds_to_a_ten_minute_cap() {
    let secs: Vec<u64> = (1..=9).map(|n| backoff(n, 0.0).as_secs()).collect();
    assert_eq!(secs, vec![5, 10, 20, 40, 80, 160, 320, 600, 600]);
    assert_eq!(
        backoff(1, 0.5),
        Duration::from_millis(5500),
        "jitter adds up to 20%"
    );
}
