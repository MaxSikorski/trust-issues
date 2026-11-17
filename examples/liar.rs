//! `cargo run --example liar`: watch Trust Issues catch a lying explorer.
//!
//! Three fake block explorers on a made-up regtest chain: alice and bob are
//! honest, mallory lies. Five scenes, each a real attack on a Lightning
//! node's chain backend, each caught by the real code in `src/`.
//!
//! No Tor, no network, no keys, no real coins. It's deterministic: the same
//! fake explorers and hand-set clock as the tests (`tests/common/mod.rs`),
//! and every scene here is also an automated test in `tests/`.
//!
//! Add `--fast` to skip the pauses (they're only there so you can read along).

#[path = "../tests/common/mod.rs"]
mod common;

use std::io::{IsTerminal, Write};
use std::sync::Arc;
use std::time::Duration;

use bitcoin::Block;
use bitcoin::consensus::encode::serialize;
use common::*;
use trust_issues::node::{
    AlarmLevel, BROADCAST_FIRST_CHECK_SECS, LAG_SECS, Node, TIP_CRITICAL_SECS, TIP_WARN_SECS,
};
use trust_issues::source::Outspend;

struct Show {
    color: bool,
    pause: Duration,
    missed: std::cell::Cell<u32>,
}

impl Show {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    fn wait(&self, times: u32) {
        std::io::stdout().flush().ok();
        std::thread::sleep(self.pause * times);
    }

    fn scene(&self, n: u32, title: &str, story: &str) {
        println!();
        println!("{}", self.paint("1", &format!("Scene {n}: {title}")));
        println!("{}", self.paint("2", story));
        self.wait(2);
    }

    fn step(&self, s: &str) {
        println!("  {s}");
        self.wait(1);
    }

    fn good(&self, s: &str) {
        println!("  {} {s}", self.paint("32", "✔"));
        self.wait(1);
    }

    /// Say "caught" only if the code really caught it; otherwise say so loudly.
    fn caught(&self, really: bool, s: &str) {
        if really {
            println!("  {} {s}", self.paint("31;1", "✘ CAUGHT:"));
        } else {
            self.missed.set(self.missed.get() + 1);
            println!(
                "  {} expected: {s} This is a bug; please report it.",
                self.paint("41;1", "NOT CAUGHT")
            );
        }
        self.wait(1);
    }

    /// Print the node's alarms whose code starts with `prefix`.
    fn alarms(&self, node: &Node, prefix: &str) {
        for (code, alarm) in node.alarms() {
            if code.starts_with(prefix) {
                let level = match alarm.level {
                    AlarmLevel::Warning => self.paint("33;1", "⚠ WARNING"),
                    AlarmLevel::Critical => self.paint("31;1", "🚨 CRITICAL"),
                };
                println!("  {level} [{code}] {}", alarm.message);
                self.wait(1);
            }
        }
    }

    fn synced(&self, node: &Node) {
        let tip = node.with_chain(|c| c.tip_height());
        let synced = if node.is_synced() {
            self.paint("32", "yes")
        } else {
            self.paint("31", "NO")
        };
        self.step(&format!("Tip: block {tip}. Synced: {synced}."));
    }
}

/// A chain where block 2 holds a channel's funding transaction.
fn chain_with_funding() -> (Vec<Block>, bitcoin::Transaction) {
    let mut blocks = build_chain(1, 1);
    let funding = spend(&blocks[1].txdata[0], 0, 1_000_000, 4);
    blocks.push(mine(
        &blocks[1].header,
        2,
        vec![funding.clone()],
        1,
        REGTEST_BITS,
    ));
    extend(&mut blocks, 3, 1);
    (blocks, funding)
}

fn has_alarm(node: &Node, prefix: &str) -> bool {
    node.alarms().keys().any(|c| c.starts_with(prefix))
}

fn trio(blocks: &[Block]) -> [Arc<FakeSource>; 3] {
    [
        FakeSource::honest("alice", blocks),
        FakeSource::honest("bob", blocks),
        FakeSource::honest("mallory", blocks),
    ]
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let fast = std::env::args().any(|a| a == "--fast");
    let tty = std::io::stdout().is_terminal();
    let show = Show {
        color: tty,
        pause: if fast || !tty {
            Duration::ZERO
        } else {
            Duration::from_millis(900)
        },
        missed: std::cell::Cell::new(0),
    };

    println!(
        "{}",
        show.paint(
            "1",
            "Trust Issues: not a node. Just a chorus of block explorers it doesn't believe."
        )
    );
    println!("Three explorers: alice and bob are honest. mallory lies.");
    println!(
        "Everything below is fake (a made-up regtest chain, no network), but the checks are the real code."
    );
    show.wait(2);

    // ---------- 1. Hiding a block ----------
    show.scene(
        1,
        "mallory hides the newest block",
        "Hiding blocks is how a cheating channel close slips past you. A simple majority vote can be fooled by enough liars.",
    );
    let mut blocks = build_chain(10, 1);
    let [alice, bob, mallory] = trio(&blocks);
    let (node, clock) = started_node(&[alice.clone(), bob.clone(), mallory.clone()], &blocks).await;
    show.synced(&node);
    extend(&mut blocks, 3, 1);
    alice.set_chain(&blocks);
    bob.set_chain(&blocks);
    mallory.with(|s| s.visible = 10);
    show.step("Blocks 11, 12 and 13 are mined. alice and bob show them; mallory keeps quiet.");
    node.tick().await;
    show.good(&format!(
        "Followed block {} anyway: the chain with the most proof of work wins, not a vote.",
        node.with_chain(|c| c.tip_height())
    ));
    clock.advance(LAG_SECS);
    node.tick().await;
    show.step("30 minutes later, mallory still hasn't shown them...");
    show.caught(
        has_alarm(&node, "source-lagging:mallory"),
        "mallory is hiding blocks.",
    );
    show.alarms(&node, "source-lagging:mallory");

    // ---------- 2. A fake block ----------
    show.scene(
        2,
        "mallory serves a forged block",
        "She edits a block to pay herself 21 million coins and hopes nobody checks.",
    );
    let blocks = build_chain(5, 1);
    let [alice, bob, mallory] = trio(&blocks);
    mallory.with(|s| s.tamper_blocks = true);
    let (node, _) = started_node(&[mallory, alice, bob], &blocks).await;
    let mut all_true = true;
    for b in &blocks[1..] {
        let raw = node
            .get_block(b.block_hash())
            .await
            .expect("an honest copy");
        all_true &= *raw == serialize(b);
    }
    show.caught(
        has_alarm(&node, "source-bad:mallory"),
        "mallory's block doesn't match the merkle root its header commits to, so it's thrown away.",
    );
    show.alarms(&node, "source-bad:mallory");
    if all_true {
        show.good("Every block was fetched again from an honest explorer and verified.");
        show.good("mallory is ignored for the next 24 hours.");
    } else {
        show.caught(false, "every block we kept matches the real one.");
    }

    // ---------- 3. Lying about a channel ----------
    show.scene(
        3,
        "two explorers say a closed channel is still open",
        "mallory and her friend marvin say the channel's funding output is unspent. Only bob tells the truth.",
    );
    let (mut blocks, funding) = chain_with_funding();
    let close = spend(&funding, 0, 900_000, 5);
    let tip = blocks.last().expect("non-empty").header;
    blocks.push(mine(&tip, 6, vec![close], 1, REGTEST_BITS));
    let bob = FakeSource::honest("bob", &blocks);
    let mallory = FakeSource::honest("mallory", &blocks);
    let marvin = FakeSource::honest("marvin", &blocks);
    let unspent = Outspend {
        spent: false,
        txid: None,
        vin: None,
    };
    for liar in [&mallory, &marvin] {
        liar.with(|s| {
            s.outspend_lie
                .insert((funding.compute_txid(), 0), unspent.clone())
        });
    }
    let (node, _) = started_node(&[mallory, marvin, bob], &blocks).await;
    let answer = node
        .get_txout(funding.compute_txid(), 0)
        .await
        .expect("answers");
    show.step(
        "2 votes say \"unspent\". 1 explorer shows the spending transaction, with a merkle proof.",
    );
    show.caught(
        answer.is_none(),
        "a proven spend beats any number of \"unspent\" claims.",
    );
    if answer.is_none() {
        show.good(
            "gettxout answers null, so Lightning sees the channel as closed and can react in time.",
        );
    }

    // ---------- 4. Dropping a broadcast ----------
    show.scene(
        4,
        "mallory drops your penalty transaction",
        "If your node only asked one explorer to broadcast, a cheater's explorer could quietly lose it.",
    );
    let blocks = build_chain(3, 1);
    let [alice, bob, mallory] = trio(&blocks);
    mallory.with(|s| s.forget_broadcasts = true);
    let (node, clock) = started_node(&[alice.clone(), bob.clone(), mallory.clone()], &blocks).await;
    let justice = spend(&blocks[1].txdata[0], 0, 4000, 8);
    node.broadcast(&tx_hex(&justice)).await.expect("accepted");
    let seen = |s: &Arc<FakeSource>| s.with(|st| st.mempool.contains_key(&justice.compute_txid()));
    show.good(&format!(
        "Sent to every explorer at once (in real use, each over its own Tor circuit). alice has it: {}. bob has it: {}.",
        seen(&alice),
        seen(&bob)
    ));
    show.step(&format!(
        "mallory said \"got it\", but has it: {}.",
        seen(&mallory)
    ));
    mallory.with(|s| s.forget_broadcasts = false);
    clock.advance(BROADCAST_FIRST_CHECK_SECS);
    node.recheck_broadcasts().await;
    show.caught(
        mallory.with(|s| s.received.len()) >= 2,
        "mallory forgot it. Trust Issues checks back and sends it again.",
    );
    show.good(&format!(
        "Now mallory has it too: {} (sent to her {} times).",
        seen(&mallory),
        mallory.with(|s| s.received.len())
    ));

    // ---------- 5. Everyone goes quiet ----------
    show.scene(
        5,
        "every explorer goes quiet",
        "The worst case: all of them hide new blocks (or someone between you and them does). No proof can catch that, but a clock can.",
    );
    let blocks = build_chain(4, 1);
    let [alice, bob, mallory] = trio(&blocks);
    let (node, clock) = started_node(&[alice, bob, mallory], &blocks).await;
    let tip_time = u64::from(blocks[4].header.time);
    show.synced(&node);
    clock.set(tip_time + TIP_WARN_SECS);
    node.tick().await;
    show.step("90 minutes without a new block (one is due about every 10)...");
    show.alarms(&node, "tip-stale");
    clock.set(tip_time + TIP_CRITICAL_SECS);
    node.tick().await;
    show.step("3 hours...");
    show.alarms(&node, "tip-stale");
    show.synced(&node);
    show.caught(
        !node.is_synced(),
        "the chain has gone quiet for too long, so it stops saying \"synced\".",
    );
    show.good("Lightning now sees \"not synced\" and you're told loudly, while there's still time to act.");

    println!();
    let missed = show.missed.get();
    if missed > 0 {
        println!(
            "{}",
            show.paint(
                "41;1",
                &format!("{missed} check(s) did NOT catch the lie. Please report this.")
            )
        );
        std::process::exit(1);
    }
    println!(
        "{}",
        show.paint("1", "5 attacks, 5 caught. Don't trust, verify.")
    );
    println!(
        "Each scene is also an automated test: tests/adversarial.rs and tests/broadcast_and_rpc.rs."
    );
    println!("Signet only for now. Never use it with real money.");
}
