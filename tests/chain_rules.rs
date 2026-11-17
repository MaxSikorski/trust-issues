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

// ---------- retargeting exactly like Bitcoin Core (review, 2026-11-17) ----------

/// Signet's rules with a 4-block retarget interval and regtest's easy
/// limit, so a test can mine its way to a retarget boundary.
fn short_signet_params() -> bitcoin::params::Params {
    let mut p = bitcoin::params::Params::new(Network::Signet);
    p.pow_target_timespan = 4 * 600;
    p.max_attainable_target =
        bitcoin::Target::from_compact(CompactTarget::from_consensus(REGTEST_BITS));
    p
}

/// A header on `prev` at `time` with `bits`, mined to meet them.
fn mine_bits(prev: &bitcoin::block::Header, time: u32, bits: u32) -> bitcoin::block::Header {
    let mut h = mine(prev, 0, vec![], 7, bits).header;
    h.time = time;
    h.nonce = 0;
    while h.validate_pow(h.target()).is_err() {
        h.nonce += 1;
    }
    h
}

/// A base header (height 0) and three more with `bits`, `step` seconds
/// apart: the first retarget period. Returns the base and the three.
fn first_period(bits: u32, step: u32) -> (bitcoin::block::Header, Vec<bitcoin::block::Header>) {
    let mut base = genesis().header;
    base.bits = CompactTarget::from_consensus(bits);
    // Mined too: it may be given as a period's first header.
    while base.validate_pow(base.target()).is_err() {
        base.nonce += 1;
    }
    let mut hs: Vec<bitcoin::block::Header> = Vec::new();
    let mut prev = base;
    for _ in 0..3 {
        let h = mine_bits(&prev, prev.time + step, bits);
        hs.push(h);
        prev = h;
    }
    (base, hs)
}

#[test]
fn at_a_retarget_the_bits_must_be_exactly_what_core_computes() {
    let p = short_signet_params();
    // The period took 300 s for three blocks spaced 100 s: well under the
    // 2400 s target, so the target shrinks (to a quarter at most).
    let (base, hs) = first_period(0x1f7f_ffff, 400);
    let last = *hs.last().unwrap();
    let now = u64::from(last.time) + 10_000;
    // timespan = 3 * 400 = 1200 of 2400: half the target.
    let expected = 0x1f3f_ffff;
    let mut chain = HeaderChain::with_params(p.clone(), 0, base);
    chain.connect(&hs, now).unwrap();
    for bits in [expected - 1, expected + 1, 0x1f2f_ffff, 0x1f7f_ffff] {
        let h = mine_bits(&last, last.time + 400, bits);
        let err = chain.check(&[h], now).unwrap_err();
        assert!(
            matches!(err, ChainError::BadDifficulty { height: 4, .. }),
            "{bits:x}: {err:?}"
        );
    }
    let h = mine_bits(&last, last.time + 400, expected);
    chain.connect(&[h], now).unwrap();
    assert_eq!(chain.tip_height(), 4);
    // Between boundaries nothing may change.
    let next = mine_bits(&h, h.time + 400, expected + 1);
    assert!(matches!(
        chain.check(&[next], now).unwrap_err(),
        ChainError::BadDifficulty { height: 5, .. }
    ));
}

#[test]
fn an_honest_four_times_harder_retarget_survives_compact_rounding() {
    // A quarter of 0x2014fcee's target is 0x53f3b.8 in the compact form's
    // units, which rounds down to 0x20053f3b: just under a strict quarter.
    // Bitcoin Core computes exactly that, so it must be accepted.
    let p = short_signet_params();
    let (base, hs) = first_period(0x2014_fcee, 1);
    let last = *hs.last().unwrap();
    let now = u64::from(last.time) + 10_000;
    let h = mine_bits(&last, last.time + 1, 0x2005_3f3b);

    // With the whole period known (exact rule).
    let mut chain = HeaderChain::with_params(p.clone(), 0, base);
    chain.connect(&hs, now).unwrap();
    chain.connect(&[h], now).unwrap();
    assert_eq!(chain.tip_height(), 4);

    // Starting from a checkpoint inside the period, with the headers below
    // it walked back by hash (as the node does): the same header is
    // accepted, one unit harder is not.
    let mut chain = HeaderChain::with_params(p, 3, last);
    walk(&mut chain, &[hs[1], hs[0], base]);
    let too_hard = mine_bits(&last, last.time + 1, 0x2005_3f3a);
    assert!(matches!(
        chain.check(&[too_hard], now).unwrap_err(),
        ChainError::BadDifficulty { height: 4, .. }
    ));
    chain.connect(&[h], now).unwrap();
    assert_eq!(chain.tip_height(), 4);
}

#[test]
fn the_retarget_matches_real_signet_and_cores_rounding() {
    use trust_issues::chain::next_work_required;
    let p = bitcoin::params::Params::new(Network::Signet);
    let bits = CompactTarget::from_consensus;
    // Real signet, read from a local node: the period 328608..330623 took
    // 1793327751 to 1794548120 at 0x1d14cd85, and block 330624 carries
    // 0x1d14fcee.
    assert_eq!(
        next_work_required(bits(0x1d14_cd85), 1_793_327_751, 1_794_548_120, &p),
        bits(0x1d14_fcee)
    );
    // Four times harder from the current signet bits rounds to 0x1d053f3b,
    // a hair under a strict quarter (what the old check demanded).
    assert_eq!(
        next_work_required(bits(0x1d14_fcee), 1000, 1000 + 60, &p),
        bits(0x1d05_3f3b)
    );
    assert!(
        bitcoin::Target::from_compact(bits(0x1d05_3f3b))
            < bitcoin::Target::from_compact(bits(0x1d14_fcee)).min_transition_threshold()
    );
    // Time running backwards counts as the fastest period, as in Core.
    assert_eq!(
        next_work_required(bits(0x1d14_fcee), 2000, 1000, &p),
        bits(0x1d05_3f3b)
    );
    // Four times easier is capped at signet's limit.
    assert_eq!(
        next_work_required(bits(0x1e03_77ae), 0, 10 * 1_209_600, &p),
        bits(0x1e03_77ae)
    );
}

// ---------- second review (2026-11-17) ----------

#[test]
fn a_retarget_just_above_a_checkpoint_needs_the_periods_first_header() {
    // A checkpoint at height 3 (inside the first 4-block period): the
    // period's first header (height 0) is below it, so the exact retarget
    // can't be computed from the chain alone.
    let p = short_signet_params();
    let (base, hs) = first_period(0x1f7f_ffff, 400);
    let last = *hs.last().unwrap();
    let now = u64::from(last.time) + 10_000;
    let expected = 0x1f3f_ffff;
    let mut chain = HeaderChain::with_params(p, 3, last);

    // One unit harder than Core computes: inside Core's permitted range,
    // which is all 5f78d99 checked here, so it was accepted.
    let harder = mine_bits(&last, last.time + 400, expected - 1);
    let err = chain.check(&[harder], now).unwrap_err();
    assert_eq!(err, ChainError::NeedPeriodStart { height: 0, at: 4 });
    // So is the exact header: without the first header nothing passes.
    let exact = mine_bits(&last, last.time + 400, expected);
    assert_eq!(
        chain.check(&[exact], now).unwrap_err(),
        ChainError::NeedPeriodStart { height: 0, at: 4 }
    );

    // The walk back takes only the header with the hash it asked for: not
    // one from another height, nor the right one with other bits.
    assert_eq!(chain.walk_back_next(), Some((2, hs[1].block_hash())));
    assert!(chain.add_walked(hs[0]).is_err());
    let mut other_bits = hs[1];
    other_bits.bits = CompactTarget::from_consensus(REGTEST_BITS);
    assert!(chain.add_walked(other_bits).is_err());
    assert_eq!(chain.walked_len(), 0);
    // Part of the way is not enough.
    walk(&mut chain, &[hs[1], hs[0]]);
    assert_eq!(
        chain.check(&[exact], now).unwrap_err(),
        ChainError::NeedPeriodStart { height: 0, at: 4 }
    );

    // With the walk at the first header the retarget is exact, and a
    // wrong one is provably wrong.
    walk(&mut chain, &[base]);
    assert!(chain.walk_back_done());
    assert!(chain.add_walked(base).is_err());
    assert!(matches!(
        chain.check(&[harder], now).unwrap_err(),
        ChainError::BadDifficulty { height: 4, .. }
    ));
    chain.connect(&[exact], now).unwrap();
    assert_eq!(chain.tip_height(), 4);
}

#[test]
fn bits_that_overflow_or_go_negative_are_refused_like_core() {
    use trust_issues::chain::decode_compact;
    let bits = CompactTarget::from_consensus;
    // rust-bitcoin wraps the shift: 0x3f3fffff decodes to 0x1f3fffff's
    // target. Bitcoin Core's SetCompact reports an overflow.
    assert_eq!(
        bitcoin::Target::from_compact(bits(0x3f3f_ffff)),
        bitcoin::Target::from_compact(bits(0x1f3f_ffff))
    );
    for (b, ok) in [
        (0x1d14_fcee, true),
        (0x3d14_fcee, false),
        (0x2200_00ff, true),
        (0x2200_0100, false),
        (0x2100_ffff, true),
        (0x2101_0000, false),
        (0x2300_0001, false),
        (0x0480_0001, false),
        (0x0400_0000, false),
        (0x0000_0000, false),
        (0x0100_3456, false),
        (0x0112_3456, true),
        (0x0180_0000, false),
    ] {
        assert_eq!(decode_compact(bits(b)).is_some(), ok, "{b:08x}");
    }
    assert_eq!(
        decode_compact(bits(0x0112_3456)),
        Some(bitcoin::Target::from_be_bytes({
            let mut t = [0u8; 32];
            t[31] = 0x12;
            t
        }))
    );

    // In the chain: at the retarget above a checkpoint, the overflowing
    // form of the expected bits met its (wrapped) target and fell inside
    // Core's permitted range, so 5f78d99 accepted it.
    let (_, hs) = first_period(0x1f7f_ffff, 400);
    let last = *hs.last().unwrap();
    let now = u64::from(last.time) + 10_000;
    let chain = HeaderChain::with_params(short_signet_params(), 3, last);
    let overflow = mine_bits(&last, last.time + 400, 0x3f3f_ffff);
    assert!(overflow.validate_pow(overflow.target()).is_ok());
    assert!(matches!(
        chain.check(&[overflow], now).unwrap_err(),
        ChainError::BadBits { .. }
    ));
}

fn real_header(hex: &str) -> bitcoin::block::Header {
    use bitcoin::hex::FromHex;
    bitcoin::consensus::encode::deserialize(&Vec::<u8>::from_hex(hex.trim()).unwrap()).unwrap()
}

#[test]
fn the_real_retarget_at_330624_is_exact_from_a_checkpoint_inside_its_period() {
    use bitcoin::hex::FromHex;
    let h623 = real_header(include_str!("fixtures/signet-330623-header.hex"));
    let h608 = real_header(include_str!("fixtures/signet-328608-header.hex"));
    let b624: bitcoin::Block = bitcoin::consensus::encode::deserialize(
        &Vec::<u8>::from_hex(include_str!("fixtures/signet-330624-block.hex").trim()).unwrap(),
    )
    .unwrap();
    let h624 = b624.header;
    assert_eq!(h624.bits, CompactTarget::from_consensus(0x1d14_fcee));
    let now = u64::from(h624.time) + 60;
    let mut chain = HeaderChain::new(Network::Signet, 330_623, h623);
    assert_eq!(
        chain.check(&[h624], now).unwrap_err(),
        ChainError::NeedPeriodStart {
            height: 328_608,
            at: 330_624
        }
    );
    // Walk back from the checkpoint through the real headers, 330622 down
    // to 328608: each proven by its hash, and no more than that kept.
    let period: Vec<bitcoin::block::Header> =
        include_bytes!("fixtures/signet-328608-to-330623-headers.bin")
            .chunks(80)
            .map(|c| bitcoin::consensus::encode::deserialize(c).unwrap())
            .collect();
    assert_eq!(period[0], h608);
    assert_eq!(period[2015], h623);
    let below: Vec<_> = period[..2015].iter().rev().copied().collect();
    walk(&mut chain, &below);
    assert!(chain.walk_back_done());
    assert_eq!(chain.walked_len(), 2015);
    assert_eq!(chain.hash_at(328_608), Some(h608.block_hash()));
    assert_eq!(
        chain.walked_header(&h608.block_hash()),
        Some((328_608, h608))
    );
    assert_eq!(chain.hash_at(328_607), None);
    // One unit harder: Core's permitted range allows it (5f78d99 did), the
    // exact rule doesn't. The bits are checked before the proof of work,
    // so an unmined header shows which rule refuses it.
    let mut harder = h624;
    harder.bits = CompactTarget::from_consensus(0x1d14_fced);
    assert!(matches!(
        chain.check(&[harder], now).unwrap_err(),
        ChainError::BadDifficulty {
            height: 330_624,
            ..
        }
    ));
    let mut overflow = h624;
    overflow.bits = CompactTarget::from_consensus(0x3d14_fcee);
    assert!(matches!(
        chain.check(&[overflow], now).unwrap_err(),
        ChainError::BadBits { .. }
    ));
    chain.connect(&[h624], now).unwrap();
    assert_eq!(chain.tip_hash(), h624.block_hash());
}

// ---------- third review (2026-11-17): walking back from the checkpoint ----------

/// Regtest's rules, but retargeting every 16 blocks, so a node test can
/// reach a retarget on blocks it mines itself.
fn retargeting_regtest() -> bitcoin::params::Params {
    let mut p = bitcoin::params::Params::new(Network::Regtest);
    p.no_pow_retargeting = false;
    p.pow_target_timespan = 16 * 600;
    p
}

/// A regtest chain of `n` blocks 800 s apart: slower than the target, so
/// every retarget stays at regtest's limit and the bits never change.
fn slow_chain(n: u32) -> Vec<bitcoin::Block> {
    let mut blocks = vec![genesis()];
    for h in 1..=n {
        let prev = blocks.last().unwrap().header;
        let mut b = mine(&prev, h, vec![], 1, REGTEST_BITS);
        b.header.time = prev.time + 800;
        b.header.nonce = 0;
        while b.header.validate_pow(b.header.target()).is_err() {
            b.header.nonce += 1;
        }
        blocks.push(b);
    }
    blocks
}

/// A fake explorer showing `blocks`, serving every header by hash quickly.
fn indexed_source(name: &str, blocks: &[bitcoin::Block]) -> std::sync::Arc<FakeSource> {
    let s = FakeSource::honest(name, blocks);
    s.with(|st| {
        st.extra_headers = blocks.iter().map(|b| (b.block_hash(), b.header)).collect();
    });
    s
}

fn retargeting_node(
    sources: &[std::sync::Arc<FakeSource>],
    blocks: &[bitcoin::Block],
    checkpoint: u32,
) -> trust_issues::node::Node {
    use std::sync::Arc;
    let dyns: Vec<Arc<dyn trust_issues::source::Source>> = sources
        .iter()
        .map(|s| s.clone() as Arc<dyn trust_issues::source::Source>)
        .collect();
    let clock = Arc::new(trust_issues::node::ManualClock::new(now_after(blocks)));
    trust_issues::node::Node::new(
        settings(Some((checkpoint, blocks[checkpoint as usize].block_hash()))),
        dyns,
        clock,
    )
    .with_chain_params(retargeting_regtest())
}

#[tokio::test]
async fn a_checkpoint_just_below_the_first_retarget_needs_no_vote_on_genesis() {
    let blocks = slow_chain(20);
    let up = indexed_source("up", &blocks);
    let down = indexed_source("down", &blocks);
    down.with(|st| st.fail = Some(trust_issues::source::SourceError::Transport("down".into())));
    // The checkpoint is the last block of the first period, so the
    // retarget at 16 needs the period's first block: genesis, which we
    // know ourselves. d2097ae asked two explorers to vote on it, and one
    // was down: the chain stopped at 15.
    let node = retargeting_node(&[up, down], &blocks, 15);
    node.start().await.expect("start");
    for _ in 0..3 {
        node.tick().await;
    }
    assert_eq!(
        node.with_chain(|c| c.tip_height()),
        20,
        "{:?}",
        node.alarms()
    );
    assert!(!node.alarms().contains_key("retarget-held"));
}

#[tokio::test(start_paused = true)]
async fn catching_up_more_than_2016_blocks_after_explorers_come_back() {
    let blocks = slow_chain(2100);
    let a = indexed_source("a", &blocks);
    let b = indexed_source("b", &blocks);
    let node = retargeting_node(&[a.clone(), b.clone()], &blocks, 15);
    node.start().await.expect("start");
    // Both explorers go down: nothing can be walked or followed.
    let down = trust_issues::source::SourceError::Transport("down".into());
    for s in [&a, &b] {
        s.with(|st| st.fail = Some(down.clone()));
    }
    node.tick().await;
    assert_eq!(node.with_chain(|c| c.tip_height()), 15);
    // They come back 2085 blocks ahead of us: more than one walk from
    // their tip (2016 headers) can cover. d2097ae gave up there for good.
    for s in [&a, &b] {
        s.with(|st| st.fail = None);
    }
    // (Past the backoff their failures earned.)
    tokio::time::advance(trust_issues::limits::BACKOFF_CAP * 2).await;
    for _ in 0..5 {
        node.tick().await;
    }
    assert_eq!(
        node.with_chain(|c| c.tip_height()),
        2100,
        "{:?}",
        node.alarms()
    );
    assert!(!node.alarms().keys().any(|k| k.starts_with("source-bad:")));
    assert!(!node.alarms().contains_key("retarget-held"));
}

/// Give the chain these headers below its checkpoint, newest first, as the
/// node's walk back does.
fn walk(chain: &mut HeaderChain, newest_first: &[bitcoin::block::Header]) {
    for h in newest_first {
        chain.add_walked(*h).unwrap();
    }
}

#[test]
fn the_walk_back_is_bounded_by_what_the_rules_need() {
    let period: Vec<bitcoin::block::Header> =
        include_bytes!("fixtures/signet-328608-to-330623-headers.bin")
            .chunks(80)
            .map(|c| bitcoin::consensus::encode::deserialize(c).unwrap())
            .collect();
    let newest_first = |n: usize| period[..n].iter().rev().copied().collect::<Vec<_>>();
    // The last block of a period: 2015 headers back to its first, the
    // most the walk ever keeps (80 bytes each).
    let mut last = HeaderChain::new(Network::Signet, 330_623, period[2015]);
    walk(&mut last, &newest_first(2015));
    assert!(last.walk_back_done());
    assert_eq!(last.walked_len(), 2015);
    // Inside a period: back to its first (330613 is 2005 in).
    let mut inside = HeaderChain::new(Network::Signet, 330_613, period[2005]);
    assert_eq!(inside.walk_back_next().map(|(h, _)| h), Some(330_612));
    walk(&mut inside, &newest_first(2005));
    assert!(inside.walk_back_done());
    assert_eq!(inside.walked_len(), 2005);
    // A period's first block needs only the 10 before it, for the
    // median-time-past rule: 330614..330623.
    let b624: bitcoin::Block = bitcoin::consensus::encode::deserialize(
        &<Vec<u8> as bitcoin::hex::FromHex>::from_hex(
            include_str!("fixtures/signet-330624-block.hex").trim(),
        )
        .unwrap(),
    )
    .unwrap();
    let mut first = HeaderChain::new(Network::Signet, 330_624, b624.header);
    walk(
        &mut first,
        &period[2006..].iter().rev().copied().collect::<Vec<_>>(),
    );
    assert!(first.walk_back_done());
    assert_eq!(first.walked_len(), 10);
    // Regtest never retargets: nothing to walk.
    let blocks = build_chain(20, 1);
    let regtest = HeaderChain::new(Network::Regtest, 20, blocks[20].header);
    assert!(regtest.walk_back_done());
}

// ---------- fourth review (2026-11-17) ----------

/// Our tip at 30, on a branch that forked `depth` blocks below it (0: no
/// fork); then both explorers come back 2017 blocks past our tip on the
/// other branch. Where the node's tip ends up after a few rounds.
async fn catch_up_across_a_fork(depth: u32) -> (u32, Vec<bitcoin::Block>) {
    use std::sync::Arc;
    let tip = 30;
    let honest = build_chain(tip + 2017, 1);
    let ours = if depth == 0 {
        honest[..=tip as usize].to_vec()
    } else {
        fork(&honest, tip - depth, depth, 2)
    };
    let (a, b) = (indexed_source("a", &ours), indexed_source("b", &ours));
    let dyns: Vec<Arc<dyn trust_issues::source::Source>> = [&a, &b]
        .iter()
        .map(|s| (*s).clone() as Arc<dyn trust_issues::source::Source>)
        .collect();
    let node = trust_issues::node::Node::new(
        settings(Some((0, genesis().block_hash()))),
        dyns,
        Arc::new(trust_issues::node::ManualClock::new(now_after(&honest))),
    );
    node.start().await.expect("start");
    node.tick().await;
    assert_eq!(
        node.with_chain(|c| c.tip_hash()),
        ours[tip as usize].block_hash()
    );
    for s in [&a, &b] {
        s.set_chain(&honest);
        s.with(|st| {
            st.extra_headers
                .extend(honest.iter().map(|b| (b.block_hash(), b.header)));
        });
    }
    for _ in 0..3 {
        node.tick().await;
    }
    assert!(
        !node.alarms().keys().any(|k| k.starts_with("source-bad:")),
        "{:?}",
        node.alarms()
    );
    (node.with_chain(|c| c.tip_height()), honest)
}

#[tokio::test]
async fn catching_up_more_than_one_walk_works_across_a_fork_below_our_tip() {
    // c8b7481 stepped from exactly one walk (2016) above our tip, so the
    // walk back from there ended one header short of a fork one block
    // below our tip, and did that again every round, for good.
    for depth in [0, 1, 10] {
        let (tip, honest) = catch_up_across_a_fork(depth).await;
        assert_eq!(tip, honest.len() as u32 - 1, "fork {depth} deep");
    }
}

#[tokio::test(start_paused = true)]
async fn a_slow_explorer_doesnt_hold_up_the_round_and_the_walk_prefers_the_fast_one() {
    let blocks = slow_chain(20);
    let slow = indexed_source("slow", &blocks);
    let fast = indexed_source("fast", &blocks);
    // Checkpoint at the tip, so only the walk back (19 down to 10) asks
    // for headers.
    let node = retargeting_node(&[slow.clone(), fast.clone()], &blocks, 20);
    node.start().await.expect("start");
    slow.with(|st| st.header_delay = Some(std::time::Duration::from_secs(89)));
    // c8b7481 asked the slow one first for about every other header, so a
    // round took minutes and the fee and broadcast rechecks after the
    // walk waited for it.
    for _ in 0..3 {
        let started = tokio::time::Instant::now();
        node.tick().await;
        let took = started.elapsed();
        assert!(
            took <= trust_issues::node::WALK_BACK_ROUND_LIMIT + std::time::Duration::from_secs(1),
            "a round took {took:?}"
        );
    }
    assert!(node.with_chain(|c| c.walk_back_done()));
    // Asked at most once, then the fast one was preferred.
    assert!(
        slow.with(|st| st.header_calls) <= 2,
        "{}",
        slow.with(|st| st.header_calls)
    );
    assert!(!node.alarms().keys().any(|k| k.starts_with("source-bad:")));
}

#[tokio::test(start_paused = true)]
async fn an_explorer_without_the_old_headers_is_asked_for_them_less_and_less() {
    let blocks = slow_chain(20);
    // Both explorers show only block 20 and up: every walk-back header is
    // "not found". That's not a lie, but it shouldn't cost a request
    // per explorer every round forever.
    let make = |name: &str| {
        let s = FakeSource::honest(name, &blocks[20..]);
        s.with(|st| {
            st.height_offset = 20;
            st.genesis_override = Some(genesis().block_hash());
        });
        s
    };
    let (a, b) = (make("a"), make("b"));
    let node = retargeting_node(&[a.clone(), b.clone()], &blocks, 20);
    node.start().await.expect("start");
    for s in [&a, &b] {
        s.with(|st| st.header_calls = 0);
    }
    // 30 rounds a minute apart: c8b7481 asked each one 30 times.
    for _ in 0..30 {
        node.tick().await;
        tokio::time::advance(std::time::Duration::from_secs(60)).await;
    }
    for s in [&a, &b] {
        let asked = s.with(|st| st.header_calls);
        assert!((1..=10).contains(&asked), "{} asked {asked} times", s.name);
    }
    assert_eq!(node.with_chain(|c| c.walked_len()), 0);
    assert!(!node.alarms().keys().any(|k| k.starts_with("source-bad:")));
}

#[tokio::test(start_paused = true)]
async fn an_old_block_vote_is_checked_against_headers_walked_while_it_waited() {
    let blocks = slow_chain(20);
    // Another block at 15, with valid proof of work.
    let other = mine(&blocks[14].header, 15, vec![], 9, REGTEST_BITS);
    let (a, b) = (indexed_source("a", &blocks), indexed_source("b", &blocks));
    let node = retargeting_node(&[a.clone(), b.clone()], &blocks, 20);
    node.start().await.expect("start");
    // Both explorers name the other block at 15, slowly.
    for s in [&a, &b] {
        s.with(|st| {
            st.at_height.insert(15, other.block_hash());
            st.extra_headers.insert(other.block_hash(), other.header);
            st.hash_at_delay = Some(std::time::Duration::from_secs(30));
        });
    }
    // While the lookup waits for their votes, a round walks back past 15:
    // block 15 is proven by hash. c8b7481 took the vote anyway.
    let (answer, ()) = tokio::join!(node.deep_hash_at(15), node.tick());
    assert_eq!(
        node.with_chain(|c| c.hash_at(15)),
        Some(blocks[15].block_hash())
    );
    assert_eq!(answer, Ok(blocks[15].block_hash()));
    // Naming another block there is a provable lie.
    let bad: Vec<String> = node
        .alarms()
        .keys()
        .filter(|k| k.starts_with("source-bad:"))
        .cloned()
        .collect();
    assert_eq!(bad, vec!["source-bad:a", "source-bad:b"]);
    assert_eq!(node.deep_header(&other.block_hash()), None);
}

#[test]
fn the_median_time_rule_uses_the_headers_walked_below_the_checkpoint() {
    let blocks = slow_chain(30);
    let now = now_after(&blocks);
    // Block 21 at exactly the median time of 10..=20 (block 15's time).
    let early = mine_at(&blocks[20].header, 21, blocks[15].header.time);
    let mut chain = HeaderChain::with_params(retargeting_regtest(), 20, blocks[20].header);
    // Only the checkpoint is known: the rule waits.
    chain.check(&[early.header], now).unwrap();
    assert_eq!(
        chain.median_time_past(&blocks[20].block_hash()),
        blocks[20].header.time
    );
    let below: Vec<_> = blocks[10..20].iter().rev().map(|b| b.header).collect();
    walk(&mut chain, &below);
    assert!(chain.walk_back_done());
    // With the ten walked below it, it applies, and the median time we
    // report counts them too.
    assert!(matches!(
        chain.check(&[early.header], now).unwrap_err(),
        ChainError::TimeTooOld { .. }
    ));
    assert_eq!(
        chain.median_time_past(&blocks[20].block_hash()),
        blocks[15].header.time
    );
}

#[test]
fn the_median_time_at_a_real_checkpoint_counts_the_walked_headers() {
    let period: Vec<bitcoin::block::Header> =
        include_bytes!("fixtures/signet-328608-to-330623-headers.bin")
            .chunks(80)
            .map(|c| bitcoin::consensus::encode::deserialize(c).unwrap())
            .collect();
    let h623 = period[2015];
    let mut chain = HeaderChain::new(Network::Signet, 330_623, h623);
    walk(
        &mut chain,
        &period[..2015].iter().rev().copied().collect::<Vec<_>>(),
    );
    // Median of 330613..=330623: getblockheader and getblockchaininfo
    // give this for 330623 (c8b7481 gave 330623's own time).
    assert_eq!(chain.median_time_past(&h623.block_hash()), 1_794_546_305);
}
