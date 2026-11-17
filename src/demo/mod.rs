//! The liar demo: five attacks by lying explorers, each run against the real
//! node code and recorded as a list of [`Event`]s.
//!
//! The terminal demo (`cargo run --example liar`) prints these events, and
//! the browser demo (`web/`) animates the very same events from a
//! WebAssembly build. Everything is fake (a made-up regtest chain, scripted
//! explorers, a hand-set clock), but every check is the real code.
//!
//! A scene only records "caught" if the node really caught the lie. If it
//! didn't, the scene records [`Event::Missed`] instead, so the demo can never
//! claim more than the code does.

pub mod fakes;

use std::sync::Arc;

use bitcoin::consensus::encode::serialize;
use bitcoin::{Block, Transaction};
use serde::Serialize;

use crate::node::{
    AlarmLevel, BROADCAST_FIRST_CHECK_SECS, LAG_SECS, Node, TIP_CRITICAL_SECS, TIP_WARN_SECS,
};
use crate::source::Outspend;
use fakes::{FakeSource, REGTEST_BITS, build_chain, extend, mine, spend, started_node, tx_hex};

/// One explorer in a scene.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Actor {
    pub name: String,
    pub honest: bool,
}

/// One line of the demo.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Event {
    /// A new scene starts.
    Scene {
        n: u32,
        title: String,
        story: String,
        cast: Vec<Actor>,
    },
    /// What happens next in the story.
    Step { text: String },
    /// Something went right.
    Good { text: String },
    /// The node caught a lie. `who` is the liar, if there's one to point at.
    Caught { who: Option<String>, text: String },
    /// The node did NOT catch a lie it should have. This is a bug.
    Missed { text: String },
    /// An alarm the node raised, exactly as it raised it.
    Alarm {
        critical: bool,
        code: String,
        message: String,
    },
    /// The node's view: its tip and whether it says "synced".
    Status { tip: u32, synced: bool },
}

/// How many lies the node failed to catch (0 means all five were caught).
pub fn missed(events: &[Event]) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, Event::Missed { .. }))
        .count()
}

/// Run all five scenes and return what happened, in order.
pub async fn run() -> Vec<Event> {
    let mut r = Recorder::default();
    hiding_blocks(&mut r).await;
    forged_block(&mut r).await;
    closed_channel_called_open(&mut r).await;
    dropped_broadcast(&mut r).await;
    everyone_goes_quiet(&mut r).await;
    r.events
}

/// [`run`] without an async runtime (the fakes answer at once).
pub fn run_blocking() -> Vec<Event> {
    futures::executor::block_on(run())
}

#[derive(Default)]
struct Recorder {
    events: Vec<Event>,
}

impl Recorder {
    fn scene(&mut self, n: u32, title: &str, story: &str, cast: &[(&str, bool)]) {
        self.events.push(Event::Scene {
            n,
            title: title.into(),
            story: story.into(),
            cast: cast
                .iter()
                .map(|(name, honest)| Actor {
                    name: (*name).into(),
                    honest: *honest,
                })
                .collect(),
        });
    }

    fn step(&mut self, text: impl Into<String>) {
        self.events.push(Event::Step { text: text.into() });
    }

    fn good(&mut self, text: impl Into<String>) {
        self.events.push(Event::Good { text: text.into() });
    }

    /// Record "caught" only if `really` is true; otherwise record a miss.
    fn caught(&mut self, really: bool, who: Option<&str>, text: &str) {
        self.events.push(if really {
            Event::Caught {
                who: who.map(Into::into),
                text: text.into(),
            }
        } else {
            Event::Missed { text: text.into() }
        });
    }

    /// Record the node's alarms whose code starts with `prefix`.
    fn alarms(&mut self, node: &Node, prefix: &str) {
        for (code, alarm) in node.alarms() {
            if code.starts_with(prefix) {
                self.events.push(Event::Alarm {
                    critical: alarm.level == AlarmLevel::Critical,
                    code,
                    message: alarm.message,
                });
            }
        }
    }

    fn status(&mut self, node: &Node) {
        self.events.push(Event::Status {
            tip: node.with_chain(|c| c.tip_height()),
            synced: node.is_synced(),
        });
    }
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

const TRIO: &[(&str, bool)] = &[("alice", true), ("bob", true), ("mallory", false)];

/// A chain where block 2 holds a channel's funding transaction.
fn chain_with_funding() -> (Vec<Block>, Transaction) {
    let mut blocks = build_chain(1, 1);
    let funding = spend(&blocks[1].txdata[0], 0, 1_000_000, 4);
    let b2 = mine(&blocks[1].header, 2, vec![funding.clone()], 1, REGTEST_BITS);
    blocks.push(b2);
    extend(&mut blocks, 3, 1);
    (blocks, funding)
}

async fn hiding_blocks(r: &mut Recorder) {
    r.scene(
        1,
        "mallory hides the newest block",
        "Hide a block, and a cheating channel close slips past you.",
        TRIO,
    );
    let mut blocks = build_chain(10, 1);
    let [alice, bob, mallory] = trio(&blocks);
    let (node, clock) = started_node(&[alice.clone(), bob.clone(), mallory.clone()], &blocks).await;
    r.status(&node);
    extend(&mut blocks, 3, 1);
    alice.set_chain(&blocks);
    bob.set_chain(&blocks);
    mallory.with(|s| s.visible = 10);
    r.step("Blocks 11 to 13 are mined. mallory keeps quiet.");
    node.tick().await;
    r.good(format!(
        "Followed block {} anyway: most proof of work wins, not a vote.",
        node.with_chain(|c| c.tip_height())
    ));
    r.status(&node);
    clock.advance(LAG_SECS);
    node.tick().await;
    r.step("30 minutes later...");
    r.caught(
        has_alarm(&node, "source-lagging:mallory"),
        Some("mallory"),
        "mallory is hiding blocks.",
    );
    r.alarms(&node, "source-lagging:mallory");
}

async fn forged_block(r: &mut Recorder) {
    r.scene(
        2,
        "mallory serves a forged block",
        "She edits a block to pay herself 21 million coins.",
        TRIO,
    );
    let blocks = build_chain(5, 1);
    let [alice, bob, mallory] = trio(&blocks);
    mallory.with(|s| s.tamper_blocks = true);
    let (node, _) = started_node(&[mallory, alice, bob], &blocks).await;
    let mut all_true = true;
    for b in &blocks[1..] {
        all_true &= match node.get_block(b.block_hash()).await {
            Ok(raw) => *raw == serialize(b),
            Err(_) => false,
        };
    }
    r.caught(
        has_alarm(&node, "source-bad:mallory"),
        Some("mallory"),
        "the block doesn't match its merkle root. Thrown away.",
    );
    r.alarms(&node, "source-bad:mallory");
    if all_true {
        r.good("Fetched again from an honest explorer and verified.");
        r.good("mallory is ignored for 24 hours.");
    } else {
        r.caught(false, None, "every block we kept matches the real one.");
    }
}

async fn closed_channel_called_open(r: &mut Recorder) {
    r.scene(
        3,
        "two explorers say a closed channel is still open",
        "mallory and marvin say it's unspent. Only bob tells the truth.",
        &[("mallory", false), ("marvin", false), ("bob", true)],
    );
    let (mut blocks, funding) = chain_with_funding();
    let close = spend(&funding, 0, 900_000, 5);
    let tip = blocks[blocks.len() - 1].header;
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
    // Ok(None) is gettxout's null: "spent, or not sure".
    let said_closed = matches!(node.get_txout(funding.compute_txid(), 0).await, Ok(None));
    r.step("2 votes say \"unspent\". bob shows the spending transaction, with proof.");
    r.caught(said_closed, None, "proof beats votes.");
    if said_closed {
        r.good("Lightning sees the channel closed, in time to react.");
    }
}

async fn dropped_broadcast(r: &mut Recorder) {
    r.scene(
        4,
        "mallory drops your penalty transaction",
        "Ask only one explorer to broadcast, and it can quietly lose it.",
        TRIO,
    );
    let blocks = build_chain(3, 1);
    let [alice, bob, mallory] = trio(&blocks);
    mallory.with(|s| s.forget_broadcasts = true);
    let (node, clock) = started_node(&[alice.clone(), bob.clone(), mallory.clone()], &blocks).await;
    let justice = spend(&blocks[1].txdata[0], 0, 4000, 8);
    let sent = node.broadcast(&tx_hex(&justice)).await.is_ok();
    let seen = |s: &Arc<FakeSource>| s.with(|st| st.mempool.contains_key(&justice.compute_txid()));
    if !sent {
        r.caught(
            false,
            None,
            "the penalty transaction was accepted for broadcast.",
        );
        return;
    }
    let has = |s: &Arc<FakeSource>| if seen(s) { "has it" } else { "doesn't have it" };
    r.good(format!(
        "Sent to every explorer at once. alice {}, bob {}.",
        has(&alice),
        has(&bob)
    ));
    r.step(format!("mallory said \"got it\", but {}.", has(&mallory)));
    mallory.with(|s| s.forget_broadcasts = false);
    clock.advance(BROADCAST_FIRST_CHECK_SECS);
    node.recheck_broadcasts().await;
    r.caught(
        mallory.with(|s| s.received.len()) >= 2 && seen(&mallory),
        Some("mallory"),
        "mallory forgot it, so it's sent again.",
    );
    r.good(format!(
        "Now mallory {} (sent {} times).",
        has(&mallory),
        mallory.with(|s| s.received.len())
    ));
}

async fn everyone_goes_quiet(r: &mut Recorder) {
    r.scene(
        5,
        "every explorer goes quiet",
        "All of them hide new blocks. No proof catches that. A clock does.",
        &[("alice", false), ("bob", false), ("mallory", false)],
    );
    let blocks = build_chain(4, 1);
    let [alice, bob, mallory] = trio(&blocks);
    let (node, clock) = started_node(&[alice, bob, mallory], &blocks).await;
    let tip_time = u64::from(blocks[4].header.time);
    r.status(&node);
    clock.set(tip_time + TIP_WARN_SECS);
    node.tick().await;
    r.step("90 minutes, no new block...");
    r.alarms(&node, "tip-stale");
    clock.set(tip_time + TIP_CRITICAL_SECS);
    node.tick().await;
    r.step("3 hours...");
    r.alarms(&node, "tip-stale");
    r.status(&node);
    r.caught(
        !node.is_synced(),
        None,
        "too quiet for too long. No more \"synced\".",
    );
    r.good("You're told loudly, while there's still time to act.");
}
