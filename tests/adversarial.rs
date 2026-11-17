//! Scripted lying, withholding and failing sources, each with a fixed
//! expected outcome: follow the most-work valid chain, mark liars bad,
//! raise alarms, and fail closed when unsure.

mod common;

use std::sync::Arc;

use bitcoin::{Block, OutPoint};
use common::*;
use trust_issues::node::{LAG_SECS, ManualClock, Node, TIP_CRITICAL_SECS, TIP_WARN_SECS};
use trust_issues::source::{Outspend, Source, SourceError};

fn has_alarm(node: &Node, prefix: &str) -> bool {
    alarm_codes(node).iter().any(|c| c.starts_with(prefix))
}

#[tokio::test]
async fn two_honest_sources_mean_synced_at_their_tip() {
    let blocks = build_chain(12, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let (node, _) = started_node(&[a, b], &blocks).await;
    assert!(node.is_synced());
    assert_eq!(node.with_chain(|c| c.tip_hash()), blocks[12].block_hash());
    assert!(alarm_codes(&node).is_empty(), "{:?}", alarm_codes(&node));
}

#[tokio::test]
async fn one_reachable_source_is_never_enough_to_be_synced() {
    let blocks = build_chain(5, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    b.with(|s| s.fail = Some(SourceError::Transport("down".into())));
    let (node, _) = started_node(&[a, b], &blocks).await;
    assert_eq!(
        node.with_chain(|c| c.tip_height()),
        5,
        "still follows the chain"
    );
    assert!(!node.is_synced());
    assert!(has_alarm(&node, "too-few-sources"));
}

#[tokio::test]
async fn one_honest_source_beats_a_withholding_one_and_the_withholder_is_flagged() {
    let blocks = build_chain(10, 1);
    let honest = FakeSource::honest("honest", &blocks);
    let hider = FakeSource::honest("hider", &blocks);
    hider.with(|s| s.visible = 5);
    let (node, clock) = started_node(&[honest, hider.clone()], &blocks).await;
    assert_eq!(
        node.with_chain(|c| c.tip_height()),
        10,
        "most work wins, not a vote"
    );
    assert!(!has_alarm(&node, "source-lagging"));
    clock.advance(LAG_SECS);
    node.tick().await;
    assert!(has_alarm(&node, "source-lagging:hider"));
    assert!(
        !node.is_synced(),
        "a lagging source doesn't count towards the two"
    );
    hider.with(|s| s.visible = 10);
    node.tick().await;
    assert!(!has_alarm(&node, "source-lagging"));
}

#[tokio::test]
async fn when_every_source_hides_blocks_the_tip_alarm_fires_and_sync_is_dropped() {
    let blocks = build_chain(4, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let (node, clock) = started_node(&[a, b], &blocks).await;
    let tip_time = u64::from(blocks[4].header.time);
    clock.set(tip_time + TIP_WARN_SECS);
    node.tick().await;
    assert_eq!(
        node.alarms()["tip-stale"].level,
        trust_issues::node::AlarmLevel::Warning
    );
    assert!(node.is_synced(), "a warning alone doesn't drop sync");
    clock.set(tip_time + TIP_CRITICAL_SECS);
    node.tick().await;
    assert_eq!(
        node.alarms()["tip-stale"].level,
        trust_issues::node::AlarmLevel::Critical
    );
    assert!(!node.is_synced());
}

#[tokio::test]
async fn a_source_serving_a_header_without_proof_of_work_is_marked_bad() {
    let blocks = build_chain(6, 1);
    let honest = FakeSource::honest("honest", &blocks[..=5]);
    let liar = FakeSource::honest("liar", &blocks[..=5]);
    let (node, _) = started_node(&[honest.clone(), liar.clone()], &blocks).await;
    // The liar now claims a new tip whose header fails proof of work.
    let mut bad = mine(&blocks[5].header, 6, vec![], 9, REGTEST_BITS).header;
    while bad.validate_pow(bad.target()).is_ok() {
        bad.nonce = bad.nonce.wrapping_add(1);
    }
    liar.with(|s| {
        s.tip_lie = Some(bad.block_hash());
        s.header_lie = Some(bad);
    });
    node.tick().await;
    assert!(has_alarm(&node, "source-bad:liar"));
    assert_eq!(node.with_chain(|c| c.tip_height()), 5, "chain untouched");
    assert!(!node.is_synced(), "only one usable source left");
    // Honest progress still gets through.
    honest.set_chain(&blocks);
    node.tick().await;
    assert_eq!(node.with_chain(|c| c.tip_height()), 6);
}

#[tokio::test]
async fn a_header_that_does_not_hash_to_what_was_asked_is_a_lie() {
    let blocks = build_chain(3, 1);
    let honest = FakeSource::honest("honest", &blocks[..=2]);
    let liar = FakeSource::honest("liar", &blocks[..=2]);
    let (node, _) = started_node(&[honest, liar.clone()], &blocks).await;
    liar.set_chain(&blocks);
    liar.with(|s| s.header_lie = Some(blocks[1].header));
    node.tick().await;
    assert!(has_alarm(&node, "source-bad:liar"));
}

#[tokio::test]
async fn a_lower_work_fork_is_ignored_without_blaming_the_source() {
    let main = build_chain(10, 1);
    let short = fork(&main, 6, 2, 2);
    let a = FakeSource::honest("a", &main);
    let b = FakeSource::honest("b", &short);
    let (node, _) = started_node(&[a, b], &main).await;
    assert_eq!(node.with_chain(|c| c.tip_hash()), main[10].block_hash());
    assert!(!has_alarm(&node, "source-bad"));
}

#[tokio::test]
async fn a_tampered_block_is_refused_and_fetched_from_another_source() {
    let blocks = build_chain(3, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    a.with(|s| s.tamper_blocks = true);
    b.with(|s| s.tamper_blocks = true);
    let (node, _) = started_node(&[a.clone(), b.clone()], &blocks).await;
    let h = blocks[2].block_hash();
    assert!(
        node.get_block(h).await.is_err(),
        "no verified copy anywhere"
    );
    assert!(has_alarm(&node, "source-bad:a") && has_alarm(&node, "source-bad:b"));

    let c = FakeSource::honest("c", &blocks);
    let d = FakeSource::honest("d", &blocks);
    d.with(|s| s.tamper_blocks = true);
    let (node, _) = started_node(&[d, c], &blocks).await;
    for _ in 0..2 {
        // Whichever source is asked first, the answer is the true block.
        let raw = node.get_block(h).await.unwrap();
        assert_eq!(*raw, bitcoin::consensus::encode::serialize(&blocks[2]));
    }
    assert!(has_alarm(&node, "source-bad:d"));
}

#[tokio::test]
async fn a_source_on_another_network_is_never_used() {
    let blocks = build_chain(3, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let wrong = FakeSource::honest("wrong", &blocks);
    wrong.with(|s| {
        s.genesis_override =
            Some(bitcoin::constants::genesis_block(bitcoin::Network::Signet).block_hash())
    });
    let (node, _) = started_node(&[a, b, wrong.clone()], &blocks).await;
    assert!(has_alarm(&node, "wrong-network:wrong"));
    let calls = wrong.with(|s| s.calls);
    node.tick().await;
    assert_eq!(wrong.with(|s| s.calls), calls, "never asked again");
    assert_eq!(node.healthy_count(), 2);
}

#[tokio::test]
async fn bootstrap_needs_two_sources_agreeing_six_blocks_down() {
    let blocks = build_chain(20, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let clock = Arc::new(ManualClock::new(u64::from(blocks[20].header.time) + 60));
    let node = Node::new(
        settings(None),
        vec![a.clone() as Arc<dyn Source>, b.clone()],
        clock.clone(),
    );
    node.start().await.unwrap();
    assert_eq!(node.with_chain(|c| c.base_height()), 14);
    node.tick().await;
    assert_eq!(node.with_chain(|c| c.tip_height()), 20);

    // Two sources that disagree about the starting block: refuse to start.
    let other = fork(&blocks, 10, 10, 2);
    let c = FakeSource::honest("c", &blocks);
    let d = FakeSource::honest("d", &other);
    let node = Node::new(settings(None), vec![c as Arc<dyn Source>, d], clock.clone());
    assert!(node.start().await.is_err());
    assert!(!node.is_ready());
    assert!(has_alarm(&node, "starting"));
}

// ---------- gettxout: "spent" is provable, "unspent" is not ----------

/// A chain where block 2 holds a funding tx paying to output 0.
fn chain_with_funding() -> (Vec<Block>, bitcoin::Transaction) {
    let mut blocks = build_chain(1, 1);
    let funding = spend(&blocks[1].txdata[0], 0, 1_000_000, 4);
    let b2 = mine(&blocks[1].header, 2, vec![funding.clone()], 1, REGTEST_BITS);
    blocks.push(b2);
    extend(&mut blocks, 3, 1);
    (blocks, funding)
}

#[tokio::test]
async fn unspent_needs_two_agreeing_sources_and_a_proven_confirmation() {
    let (blocks, funding) = chain_with_funding();
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let (node, _) = started_node(&[a, b.clone()], &blocks).await;
    let out = node
        .get_txout(funding.compute_txid(), 0)
        .await
        .unwrap()
        .expect("unspent");
    assert_eq!(out["confirmations"], 4);
    assert_eq!(out["value"], 0.01);
    assert!(
        node.get_txout(funding.compute_txid(), 7)
            .await
            .unwrap()
            .is_none(),
        "no such output"
    );

    b.with(|s| s.fail = Some(SourceError::Transport("down".into())));
    assert!(
        node.get_txout(funding.compute_txid(), 0)
            .await
            .unwrap()
            .is_none(),
        "one voice isn't enough"
    );
}

#[tokio::test]
async fn a_proven_spend_beats_any_number_of_unspent_claims() {
    let (mut blocks, funding) = chain_with_funding();
    let spender = spend(&funding, 0, 900_000, 5);
    let tip = blocks.last().unwrap().header;
    blocks.push(mine(&tip, 6, vec![spender], 1, REGTEST_BITS));
    let honest = FakeSource::honest("honest", &blocks);
    let liar1 = FakeSource::honest("liar1", &blocks);
    let liar2 = FakeSource::honest("liar2", &blocks);
    let unspent = Outspend {
        spent: false,
        txid: None,
        vin: None,
    };
    for l in [&liar1, &liar2] {
        l.with(|s| {
            s.outspend_lie
                .insert((funding.compute_txid(), 0), unspent.clone())
        });
    }
    let (node, _) = started_node(&[liar1, liar2, honest], &blocks).await;
    assert!(
        node.get_txout(funding.compute_txid(), 0)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_false_spent_claim_marks_the_liar_bad() {
    let (blocks, funding) = chain_with_funding();
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let liar = FakeSource::honest("liar", &blocks);
    // Claims the output was spent by the funding tx itself (which doesn't spend it).
    liar.with(|s| {
        s.outspend_lie.insert(
            (funding.compute_txid(), 0),
            Outspend {
                spent: true,
                txid: Some(funding.compute_txid()),
                vin: Some(0),
            },
        )
    });
    let (node, _) = started_node(&[liar, a, b], &blocks).await;
    assert!(
        node.get_txout(funding.compute_txid(), 0)
            .await
            .unwrap()
            .is_some()
    );
    assert!(has_alarm(&node, "source-bad:liar"));
}

#[tokio::test]
async fn an_unconfirmed_output_is_answered_as_null() {
    let blocks = build_chain(3, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let pending = spend(&blocks[1].txdata[0], 0, 5000, 6);
    for s in [&a, &b] {
        s.with(|st| st.mempool.insert(pending.compute_txid(), pending.clone()));
    }
    let (node, _) = started_node(&[a, b], &blocks).await;
    assert!(
        node.get_txout(pending.compute_txid(), 0)
            .await
            .unwrap()
            .is_none()
    );
}

// ---------- fees and rate limits ----------

#[tokio::test]
async fn fees_combine_across_sources_and_disagreement_raises_an_alarm() {
    let blocks = build_chain(2, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let c = FakeSource::honest("c", &blocks);
    c.with(|s| {
        s.fees.insert(1, 200.0);
        s.fees.insert(6, 90.0);
    });
    let (node, _) = started_node(&[a, b, c], &blocks).await;
    assert_eq!(node.estimate_fee(12), Some(10.0), "median for normal sends");
    assert_eq!(node.estimate_fee(2), Some(200.0), "highest for urgent ones");
    assert!(has_alarm(&node, "fee-disagreement"));
}

#[tokio::test(start_paused = true)]
async fn a_rate_limited_source_cools_off_while_the_others_carry_on() {
    let blocks = build_chain(3, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let c = FakeSource::honest("c", &blocks);
    let (node, _) = started_node(&[a.clone(), b, c], &blocks).await;
    a.with(|s| {
        s.fail = Some(SourceError::RateLimited {
            retry_after: Some(30),
        })
    });
    node.tick().await;
    let calls = a.with(|s| s.calls);
    node.tick().await;
    assert_eq!(a.with(|s| s.calls), calls, "no requests while cooling");
    assert_eq!(node.status()["sources"][0]["cooling"], true);
    a.with(|s| s.fail = None);
    tokio::time::advance(std::time::Duration::from_secs(31)).await;
    node.tick().await;
    assert!(a.with(|s| s.calls) > calls, "back after Retry-After");
    let _ = OutPoint::null();
}
