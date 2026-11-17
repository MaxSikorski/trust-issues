//! The header chain accepts only headers that link, meet their proof of
//! work, follow the difficulty rules, aren't from the far future and are
//! later than the median time of the 11 blocks before them, and it
//! follows the branch with the most work.

mod common;

use bitcoin::{CompactTarget, Network};
use common::*;
use trust_issues::chain::{ChainError, HeaderChain, MAX_FUTURE_SECS};

fn headers(blocks: &[bitcoin::Block], from: usize) -> Vec<bitcoin::block::Header> {
    blocks[from..].iter().map(|b| b.header).collect()
}

fn now_after(blocks: &[bitcoin::Block]) -> u64 {
    u64::from(blocks.last().unwrap().header.time) + 60
}

#[test]
fn valid_chain_extends_from_checkpoint() {
    let blocks = build_chain(20, 1);
    let mut chain = HeaderChain::new(Network::Regtest, 0, genesis().header);
    let c = chain
        .connect(&headers(&blocks, 1), now_after(&blocks))
        .unwrap();
    assert!(c.new_best);
    assert_eq!(c.reorg_depth, 0);
    assert_eq!(chain.tip_height(), 20);
    assert_eq!(chain.tip_hash(), blocks[20].block_hash());
    assert_eq!(chain.hash_at(7), Some(blocks[7].block_hash()));
    assert_eq!(chain.confirmations(&blocks[20].block_hash()), Some(1));
    assert_eq!(
        chain.next_on_best(&blocks[3].block_hash()),
        Some(blocks[4].block_hash())
    );
}

#[test]
fn checkpoint_above_genesis_hides_older_heights_except_genesis() {
    let blocks = build_chain(10, 1);
    let mut chain = HeaderChain::new(Network::Regtest, 5, blocks[5].header);
    chain
        .connect(&headers(&blocks, 6), now_after(&blocks))
        .unwrap();
    assert_eq!(chain.tip_height(), 10);
    assert_eq!(chain.hash_at(3), None);
    assert_eq!(chain.hash_at(0), Some(genesis().block_hash()));
    assert_eq!(chain.hash_at(5), Some(blocks[5].block_hash()));
}

#[test]
fn rejects_header_failing_proof_of_work() {
    let blocks = build_chain(3, 1);
    let mut bad = blocks[3].header;
    // Find a nonce whose hash misses the target.
    while bad.validate_pow(bad.target()).is_ok() {
        bad.nonce = bad.nonce.wrapping_add(1);
    }
    let mut chain = HeaderChain::new(Network::Regtest, 0, genesis().header);
    let mut hs = headers(&blocks, 1);
    hs[2] = bad;
    let err = chain.connect(&hs, now_after(&blocks)).unwrap_err();
    assert!(matches!(err, ChainError::BadPow { .. }), "{err:?}");
    // Nothing from the bad batch was added.
    assert_eq!(chain.tip_height(), 0);
}

#[test]
fn rejects_target_easier_than_the_network_allows() {
    let blocks = build_chain(1, 1);
    let easy = mine(&blocks[1].header, 2, vec![], 9, 0x2100_ffff);
    let mut chain = HeaderChain::new(Network::Regtest, 0, genesis().header);
    chain
        .connect(&headers(&blocks, 1), now_after(&blocks))
        .unwrap();
    let err = chain
        .connect(&[easy.header], now_after(&blocks) + 600)
        .unwrap_err();
    assert!(
        matches!(err, ChainError::TargetAboveLimit { .. }),
        "{err:?}"
    );
}

#[test]
fn rejects_difficulty_change_where_none_is_allowed() {
    let blocks = build_chain(1, 1);
    let harder = mine(&blocks[1].header, 2, vec![], 9, 0x207f_fffe);
    assert_ne!(
        harder.header.bits,
        CompactTarget::from_consensus(REGTEST_BITS)
    );
    let mut chain = HeaderChain::new(Network::Regtest, 0, genesis().header);
    chain
        .connect(&headers(&blocks, 1), now_after(&blocks))
        .unwrap();
    let err = chain
        .connect(&[harder.header], now_after(&blocks) + 600)
        .unwrap_err();
    assert!(
        matches!(err, ChainError::BadDifficulty { height: 2, .. }),
        "{err:?}"
    );
}

#[test]
fn rejects_header_more_than_two_hours_in_the_future() {
    let blocks = build_chain(2, 1);
    let mut chain = HeaderChain::new(Network::Regtest, 0, genesis().header);
    let now = u64::from(blocks[2].header.time) - MAX_FUTURE_SECS - 1;
    let err = chain.connect(&headers(&blocks, 1), now).unwrap_err();
    assert!(matches!(err, ChainError::TimeTooNew { .. }), "{err:?}");
}

#[test]
fn rejects_unknown_parent_and_broken_links() {
    let blocks = build_chain(4, 1);
    let mut chain = HeaderChain::new(Network::Regtest, 0, genesis().header);
    let err = chain
        .connect(&headers(&blocks, 2), now_after(&blocks))
        .unwrap_err();
    assert!(matches!(err, ChainError::UnknownParent(_)), "{err:?}");
    let hs = vec![blocks[1].header, blocks[3].header];
    let err = chain.connect(&hs, now_after(&blocks)).unwrap_err();
    assert!(matches!(err, ChainError::BadLink { height: 2 }), "{err:?}");
}

#[test]
fn switches_to_a_fork_with_more_work_and_reports_reorg_depth() {
    let main = build_chain(10, 1);
    let longer = fork(&main, 7, 5, 2); // 8 blocks at heights 8..12
    let mut chain = HeaderChain::new(Network::Regtest, 0, genesis().header);
    chain
        .connect(&headers(&main, 1), now_after(&longer))
        .unwrap();
    let c = chain
        .connect(&headers(&longer, 8), now_after(&longer))
        .unwrap();
    assert!(c.new_best);
    assert_eq!(c.reorg_depth, 3, "heights 8, 9 and 10 were replaced");
    assert_eq!(chain.tip_hash(), longer[12].block_hash());
    assert!(!chain.is_best(&main[10].block_hash()));
    assert_eq!(chain.confirmations(&main[9].block_hash()), None);
}

#[test]
fn ignores_a_fork_with_less_work() {
    let main = build_chain(10, 1);
    let shorter = fork(&main, 5, 3, 2);
    let mut chain = HeaderChain::new(Network::Regtest, 0, genesis().header);
    chain.connect(&headers(&main, 1), now_after(&main)).unwrap();
    let c = chain
        .connect(&headers(&shorter, 6), now_after(&main))
        .unwrap();
    assert!(!c.new_best);
    assert_eq!(chain.tip_hash(), main[10].block_hash());
    assert!(
        chain.contains(&shorter[8].block_hash()),
        "kept as a side branch"
    );
    assert!(!chain.is_best(&shorter[8].block_hash()));
}

/// A regtest block on `prev` at `time` (regtest work is trivial to redo).
fn mine_at(prev: &bitcoin::block::Header, height: u32, time: u32) -> bitcoin::Block {
    let mut b = mine(prev, height, vec![], 7, REGTEST_BITS);
    b.header.time = time;
    b.header.nonce = 0;
    while b.header.validate_pow(b.header.target()).is_err() {
        b.header.nonce += 1;
    }
    b
}

#[test]
fn rejects_header_not_later_than_the_median_of_the_last_eleven() {
    let blocks = build_chain(20, 1);
    let mut chain = HeaderChain::new(Network::Regtest, 0, genesis().header);
    chain
        .connect(&headers(&blocks, 1), now_after(&blocks))
        .unwrap();
    // Times rise by 600 s, so the median of blocks 10..=20 is block 15's.
    let mtp = blocks[15].header.time;
    assert_eq!(chain.median_time_past(&blocks[20].block_hash()), mtp);
    let equal = mine_at(&blocks[20].header, 21, mtp);
    let err = chain
        .connect(&[equal.header], now_after(&blocks))
        .unwrap_err();
    assert!(matches!(err, ChainError::TimeTooOld { .. }), "{err:?}");
    assert!(err.to_string().contains("median time"), "{err}");
    // One second later is fine, even though it's before block 20's time.
    let later = mine_at(&blocks[20].header, 21, mtp + 1);
    chain.connect(&[later.header], now_after(&blocks)).unwrap();
    assert_eq!(chain.tip_height(), 21);

    // Inside one batch too: the times of headers earlier in the batch count,
    // and nothing from a failing batch is kept.
    let mut fresh = HeaderChain::new(Network::Regtest, 0, genesis().header);
    let mut hs = headers(&blocks, 1);
    hs.push(equal.header);
    let err = fresh.connect(&hs, now_after(&blocks)).unwrap_err();
    assert!(matches!(err, ChainError::TimeTooOld { .. }), "{err:?}");
    assert_eq!(fresh.tip_height(), 0);
}

#[test]
fn the_median_time_rule_waits_for_eleven_known_headers_above_a_checkpoint() {
    // Just above a checkpoint we don't know the 11 earlier times, and the
    // median of fewer, more recent ones could wrongly refuse an honest
    // header, so the rule is skipped there.
    let blocks = build_chain(10, 1);
    let mut chain = HeaderChain::new(Network::Regtest, 10, blocks[10].header);
    let early = mine_at(&blocks[10].header, 11, blocks[10].header.time - 1000);
    chain.connect(&[early.header], now_after(&blocks)).unwrap();
    assert_eq!(chain.tip_height(), 11);

    // Once 11 headers are known (heights 10 to 20), it applies.
    let mut chain = HeaderChain::new(Network::Regtest, 10, blocks[10].header);
    let mut more = blocks[..=10].to_vec();
    extend(&mut more, 10, 2);
    chain
        .connect(&headers(&more, 11), now_after(&more))
        .unwrap();
    let mtp = more[15].header.time;
    let old = mine_at(&more[20].header, 21, mtp);
    let err = chain.connect(&[old.header], now_after(&more)).unwrap_err();
    assert!(matches!(err, ChainError::TimeTooOld { .. }), "{err:?}");
}
