//! The coordinator: polls every source, keeps the verified header chain,
//! decides when we're "synced", fetches and checks blocks and transactions,
//! combines fee estimates, broadcasts to every source and watches what
//! happens to our broadcasts. Everything that can go wrong raises an alarm.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::time::Instant;
use bitcoin::block::Header;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::{BlockHash, Network, OutPoint, Transaction, Txid};
use futures::future::join_all;
use futures::stream::{FuturesUnordered, StreamExt};
use serde_json::{Value, json};
use tracing::{info, warn};

use crate::chain::HeaderChain;
use crate::fees;
use crate::limits::{BACKOFF_CAP, TokenBucket, backoff};
use crate::proof::{verify_block, verify_merkle_branch, verify_tx};
use crate::source::{FeeMap, Source, SourceError};

/// How deep below the agreed tip a bootstrap checkpoint is taken.
pub const BOOTSTRAP_DEPTH: u32 = 6;
/// How far back we follow a source's tip looking for our chain.
pub const MAX_WALK: usize = 2016;
/// A source must have answered within this long to count as healthy.
pub const HEALTHY_WITHIN_SECS: u64 = 5 * 60;
/// A source more than 2 blocks behind for this long is "lagging".
pub const LAG_BLOCKS: u32 = 2;
pub const LAG_SECS: u64 = 30 * 60;
/// No new block for this long: warning, then critical (and "not synced").
pub const TIP_WARN_SECS: u64 = 90 * 60;
pub const TIP_CRITICAL_SECS: u64 = 3 * 60 * 60;
/// A source caught lying is ignored for a day.
pub const BAD_FOR_SECS: u64 = 24 * 60 * 60;
pub const FEE_REFRESH_SECS: u64 = 5 * 60;
/// Broadcast follow-up: first check, later checks, alarm, give up.
pub const BROADCAST_FIRST_CHECK_SECS: u64 = 60;
pub const BROADCAST_RECHECK_SECS: u64 = 10 * 60;
pub const BROADCAST_ALARM_SECS: u64 = 5 * 60;
pub const BROADCAST_GIVE_UP_SECS: u64 = 14 * 24 * 60 * 60;
pub const BLOCK_CACHE_BYTES: usize = 256 * 1024 * 1024;
/// Sources needed for "synced", for "unspent", and to count a broadcast as seen.
pub const MIN_AGREEING: usize = 2;
/// The longest an old-block lookup waits for a missed source's backoff
/// before asking it once more. Longer than that (a long `Retry-After`), we
/// fail closed instead of holding the wallet's RPC call open.
pub const OLD_BLOCK_RETRY_MAX_WAIT: Duration = Duration::from_secs(15);

/// Unix seconds. Injected so tests can move time deterministically.
pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// A clock tests can set by hand.
pub struct ManualClock(std::sync::atomic::AtomicU64);

impl ManualClock {
    pub fn new(t: u64) -> Self {
        Self(std::sync::atomic::AtomicU64::new(t))
    }
    pub fn set(&self, t: u64) {
        self.0.store(t, Ordering::SeqCst);
    }
    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// An error in bitcoind's own codes, so LND and CLN understand it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl RpcError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub const RPC_MISC_ERROR: i32 = -1;
pub const RPC_INVALID_PARAMETER: i32 = -8;
pub const RPC_NOT_FOUND: i32 = -5;
pub const RPC_DESERIALIZATION_ERROR: i32 = -22;
pub const RPC_VERIFY_ERROR: i32 = -25;
pub const RPC_VERIFY_REJECTED: i32 = -26;
pub const RPC_VERIFY_ALREADY_IN_CHAIN: i32 = -27;
pub const RPC_IN_WARMUP: i32 = -28;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlarmLevel {
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alarm {
    pub level: AlarmLevel,
    pub message: String,
    pub since: u64,
}

pub struct Settings {
    pub network: Network,
    pub checkpoint: Option<(u32, BlockHash)>,
    pub fee_ceiling_sat_vb: f64,
    pub requests_per_sec: f64,
    pub burst: f64,
    /// Jitter source for backoff, in [0, 1). Fixed in tests.
    pub jitter: fn() -> f64,
}

struct SourceState {
    bucket: TokenBucket,
    cooling_until: Option<Instant>,
    failures: u32,
    genesis_ok: Option<bool>,
    bad_until: u64,
    bad_reason: Option<String>,
    last_ok: Option<u64>,
    last_error: Option<String>,
    tip_height: Option<u32>,
    behind_since: Option<u64>,
    lagging: bool,
    fees: Option<FeeMap>,
}

struct Handle {
    source: Arc<dyn Source>,
    state: Mutex<SourceState>,
}

struct Pending {
    hex: String,
    first_sent: u64,
    last_check: u64,
    checks: u32,
}

#[derive(Default)]
struct BlockCache {
    map: HashMap<BlockHash, Arc<Vec<u8>>>,
    order: VecDeque<BlockHash>,
    bytes: usize,
}

impl BlockCache {
    fn get(&self, h: &BlockHash) -> Option<Arc<Vec<u8>>> {
        self.map.get(h).cloned()
    }
    fn insert(&mut self, h: BlockHash, raw: Arc<Vec<u8>>) {
        if self.map.contains_key(&h) {
            return;
        }
        self.bytes += raw.len();
        self.map.insert(h, raw);
        self.order.push_back(h);
        while self.bytes > BLOCK_CACHE_BYTES {
            let Some(old) = self.order.pop_front() else {
                break;
            };
            if let Some(r) = self.map.remove(&old) {
                self.bytes -= r.len();
            }
        }
    }
}

enum SpendCheck {
    Proven,
    Disproven,
    Unknown,
}

pub struct Node {
    settings: Settings,
    clock: Arc<dyn Clock>,
    sources: Vec<Handle>,
    chain: RwLock<HeaderChain>,
    ready: AtomicBool,
    blocks: Mutex<BlockCache>,
    pending: Mutex<BTreeMap<Txid, Pending>>,
    alarms: Mutex<BTreeMap<String, Alarm>>,
    last_fee_refresh: Mutex<Option<u64>>,
    rotation: AtomicUsize,
    started_at: u64,
    /// When (node clock) a source request or a poll round last finished,
    /// successful or not. The systemd watchdog pings only while this is
    /// recent, so a hung node gets restarted instead of serving a stale tip.
    last_progress: AtomicU64,
    /// Headers below the checkpoint that two sources agreed on (see
    /// [`Node::deep_hash_at`]). Cross-checked, not proven to link to our
    /// chain, so they're kept apart from it.
    deep: Mutex<DeepHeaders>,
    /// One old-block lookup at a time (see [`Node::deep_hash_at`]).
    deep_lookup: futures::lock::Mutex<()>,
    /// Cleaned names of RPC methods clients asked for that we don't support
    /// (at most [`UNSUPPORTED_RPC_MAX`]); shown on `/status`.
    unsupported_rpc: Mutex<BTreeSet<String>>,
}

/// How many distinct unsupported RPC method names to remember.
pub const UNSUPPORTED_RPC_MAX: usize = 64;

/// How many below-checkpoint headers to remember.
const DEEP_CACHE_MAX: usize = 4096;

#[derive(Default)]
struct DeepHeaders {
    by_height: HashMap<u32, BlockHash>,
    by_hash: HashMap<BlockHash, (u32, Header)>,
    /// Oldest first, for eviction.
    order: VecDeque<BlockHash>,
}

impl DeepHeaders {
    fn hash_at(&self, height: u32) -> Option<BlockHash> {
        self.by_height.get(&height).copied()
    }

    fn insert(&mut self, height: u32, hash: BlockHash, header: Header) {
        if self.by_hash.contains_key(&hash) {
            return;
        }
        while self.order.len() >= DEEP_CACHE_MAX {
            if let Some(old) = self.order.pop_front()
                && let Some((h, _)) = self.by_hash.remove(&old)
            {
                self.by_height.remove(&h);
            }
        }
        self.by_height.insert(height, hash);
        self.by_hash.insert(hash, (height, header));
        self.order.push_back(hash);
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Node {
    pub fn new(settings: Settings, sources: Vec<Arc<dyn Source>>, clock: Arc<dyn Clock>) -> Self {
        let genesis = bitcoin::constants::genesis_block(settings.network).header;
        let now_i = Instant::now();
        let handles = sources
            .into_iter()
            .map(|source| Handle {
                source,
                state: Mutex::new(SourceState {
                    bucket: TokenBucket::new(settings.requests_per_sec, settings.burst, now_i),
                    cooling_until: None,
                    failures: 0,
                    genesis_ok: None,
                    bad_until: 0,
                    bad_reason: None,
                    last_ok: None,
                    last_error: None,
                    tip_height: None,
                    behind_since: None,
                    lagging: false,
                    fees: None,
                }),
            })
            .collect();
        let started_at = clock.now();
        Self {
            chain: RwLock::new(HeaderChain::new(settings.network, 0, genesis)),
            settings,
            clock,
            sources: handles,
            ready: AtomicBool::new(false),
            blocks: Mutex::new(BlockCache::default()),
            pending: Mutex::new(BTreeMap::new()),
            alarms: Mutex::new(BTreeMap::new()),
            last_fee_refresh: Mutex::new(None),
            rotation: AtomicUsize::new(0),
            started_at,
            last_progress: AtomicU64::new(started_at),
            deep: Mutex::new(DeepHeaders::default()),
            deep_lookup: futures::lock::Mutex::new(()),
            unsupported_rpc: Mutex::new(BTreeSet::new()),
        }
    }

    /// The block hash at a height below our checkpoint, for wallets that
    /// look up old blocks (LND's wallet searches from block 0 for its
    /// "birthday", then rescans from there). We can't prove these link to
    /// our chain, so we cross-check and fail closed:
    /// - two usable sources are asked (rotating). If they agree, that's the
    ///   answer. If not, the rest are asked too, and a hash wins only with
    ///   at least two votes and a strict majority; otherwise we refuse.
    ///   Either way a disagreement raises an alarm (we can't prove who's
    ///   wrong, so nobody is marked bad for it);
    /// - the header must hash to that block and meet its own proof-of-work
    ///   target within the network's limit. A source serving a header that
    ///   doesn't is marked bad. (On signet that target is very easy, so the
    ///   real protection here is the two-source agreement.)
    ///
    /// Lookups run one at a time, so a wallet rescan can't book the sources'
    /// request budget far ahead of tip polling. The tip, which Lightning's
    /// safety depends on, never comes from here.
    pub async fn deep_hash_at(&self, height: u32) -> Result<BlockHash, RpcError> {
        if height >= self.read_chain().base_height() {
            return Err(RpcError::new(
                RPC_INVALID_PARAMETER,
                "Block height out of range",
            ));
        }
        if let Some(h) = lock(&self.deep).hash_at(height) {
            return Ok(h);
        }
        let _one_at_a_time = self.deep_lookup.lock().await;
        // Someone may have looked it up while we waited.
        if let Some(h) = lock(&self.deep).hash_at(height) {
            return Ok(h);
        }
        let order = self.rotated();
        if order.len() < MIN_AGREEING {
            return Err(RpcError::new(
                RPC_MISC_ERROR,
                "fewer than two sources are usable for old blocks right now",
            ));
        }
        let mut answers: Vec<(usize, BlockHash)> = Vec::new();
        // Sources that missed for a reason that may pass (Tor, 5xx, 429,
        // backoff). "Not found" and malformed answers are answers.
        let mut missed: Vec<usize> = Vec::new();
        let ask = |ids: Vec<usize>| {
            join_all(ids.into_iter().map(|i| async move {
                let r = self
                    .call(i, move |s| async move { s.block_hash_at(height).await })
                    .await;
                (i, r)
            }))
        };
        let sort = |results: Vec<(usize, Result<BlockHash, SourceError>)>,
                    answers: &mut Vec<(usize, BlockHash)>,
                    missed: &mut Vec<usize>| {
            for (i, r) in results {
                match r {
                    Ok(h) => answers.push((i, h)),
                    Err(
                        SourceError::Transport(_)
                        | SourceError::RateLimited { .. }
                        | SourceError::Cooling
                        | SourceError::Http { status: 500.., .. },
                    ) => missed.push(i),
                    Err(_) => {}
                }
            }
        };
        let (first, rest) = order.split_at(MIN_AGREEING);
        sort(ask(first.to_vec()).await, &mut answers, &mut missed);
        // A source caught lying (here or by the poller) doesn't vote, and its
        // answer never decides who else is asked.
        answers.retain(|&(i, _)| self.usable(i, self.clock.now()));
        let agreed =
            answers.len() == MIN_AGREEING && answers.iter().all(|(_, h)| *h == answers[0].1);
        if !agreed && !rest.is_empty() {
            sort(ask(rest.to_vec()).await, &mut answers, &mut missed);
        }
        // One missed lookup used to fail the whole call, and LND's rescan
        // doesn't ask again (2026-11-17). So when there's no winner yet, ask
        // each missed source once more, after its own backoff has run out,
        // never sooner. Still two agreeing answers or nothing.
        answers.retain(|&(i, _)| self.usable(i, self.clock.now()));
        if Self::old_block_winner(&answers).is_none() && !missed.is_empty() {
            let now = Instant::now();
            let waits: Vec<(usize, Duration)> = missed
                .iter()
                .map(|&i| {
                    let until = lock(&self.sources[i].state).cooling_until;
                    (
                        i,
                        until.map_or(Duration::ZERO, |u| u.saturating_duration_since(now)),
                    )
                })
                .filter(|(_, d)| *d <= OLD_BLOCK_RETRY_MAX_WAIT)
                .collect();
            if let Some(wait) = waits.iter().map(|(_, d)| *d).max() {
                crate::time::sleep(wait).await;
                // Caught lying while we waited: not asked.
                let now = self.clock.now();
                let mut out: Vec<usize> = waits
                    .into_iter()
                    .map(|(i, _)| i)
                    .filter(|&i| self.usable(i, now))
                    .collect();
                let mut pending: FuturesUnordered<_> = out
                    .clone()
                    .into_iter()
                    .map(|i| async move {
                        let r = self
                            .call(i, move |s| async move { s.block_hash_at(height).await })
                            .await;
                        (i, r)
                    })
                    .collect();
                // Stop as soon as the answers still out can't change the
                // outcome, so one hung source can't hold the wallet's call
                // past its timeout (LND's and CLN's are 60 s).
                while let Some((i, r)) = pending.next().await {
                    if let Ok(h) = r {
                        answers.push((i, h));
                    }
                    out.retain(|&j| j != i);
                    let now = self.clock.now();
                    answers.retain(|&(j, _)| self.usable(j, now));
                    // Votes still out from sources since caught lying would
                    // be dropped anyway, so they don't hold us up.
                    let still_out = out.iter().filter(|&&j| self.usable(j, now)).count();
                    let lead = Self::old_block_votes(&answers).first().map_or(0, |v| v.1);
                    if Self::old_block_winner(&answers).is_some()
                        && 2 * lead > answers.len() + still_out
                    {
                        break;
                    }
                }
            }
        }
        answers.retain(|&(i, _)| self.usable(i, self.clock.now()));
        let votes = Self::old_block_votes(&answers);
        if votes.len() > 1 {
            let names: Vec<String> = answers.iter().map(|(i, _)| self.name(*i)).collect();
            warn!(height, sources = ?names, "sources disagree about an old block");
            self.set_alarm(
                "old-block-disagreement",
                AlarmLevel::Warning,
                format!(
                    "{} disagree about the block at height {height} (below our checkpoint)",
                    names.join(", ")
                ),
            );
        } else if Self::old_block_winner(&answers).is_some() {
            // Cleared by agreement, never by sources that didn't answer.
            self.clear_alarm("old-block-disagreement");
        }
        let Some(winner) = Self::old_block_winner(&answers) else {
            let why = if matches!(votes.as_slice(), [] | [(_, 1)]) {
                "fewer than two sources answered for this height"
            } else {
                "sources disagree about the block at this height"
            };
            return Err(RpcError::new(RPC_MISC_ERROR, why));
        };
        // The block just below the checkpoint is provable: the checkpoint
        // header names its parent.
        let parent_of_base = {
            let c = self.read_chain();
            c.hash_at(c.base_height())
                .and_then(|b| c.header(&b))
                .map(|h| h.prev_blockhash)
        };
        if height + 1 == self.read_chain().base_height()
            && parent_of_base.is_some_and(|p| p != winner)
        {
            self.set_alarm(
                "old-block-disagreement",
                AlarmLevel::Warning,
                format!("sources' block at height {height} isn't our checkpoint's parent"),
            );
            return Err(RpcError::new(
                RPC_MISC_ERROR,
                "sources' answer contradicts our checkpoint",
            ));
        }
        if self.read_chain().contains(&winner) {
            // A block on our proven chain can't also be an old one below it.
            return Err(RpcError::new(
                RPC_MISC_ERROR,
                "sources gave a block from our own chain for an older height",
            ));
        }
        let hash = winner;
        let answers: Vec<(usize, BlockHash)> =
            answers.into_iter().filter(|(_, h)| *h == hash).collect();
        let max_target = bitcoin::params::Params::new(self.settings.network).max_attainable_target;
        for &(i, _) in &answers {
            let Ok(header) = self
                .call(i, move |s| async move { s.header(hash).await })
                .await
            else {
                continue;
            };
            let target = header.target();
            if header.block_hash() != hash
                || target > max_target
                || header.validate_pow(target).is_err()
            {
                self.mark_bad(i, format!("served a bad header for old block {hash}"));
                continue;
            }
            lock(&self.deep).insert(height, hash, header);
            return Ok(hash);
        }
        Err(RpcError::new(
            RPC_MISC_ERROR,
            "no source served a valid header for this height",
        ))
    }

    /// Distinct hashes among old-block answers, most votes first.
    fn old_block_votes(answers: &[(usize, BlockHash)]) -> Vec<(BlockHash, usize)> {
        let mut votes: Vec<(BlockHash, usize)> = Vec::new();
        for (_, h) in answers {
            match votes.iter_mut().find(|(v, _)| v == h) {
                Some((_, n)) => *n += 1,
                None => votes.push((*h, 1)),
            }
        }
        votes.sort_by_key(|v| std::cmp::Reverse(v.1));
        votes
    }

    /// The old-block hash with at least two votes and a strict majority of
    /// all answers (2–1–1 is not a majority).
    fn old_block_winner(answers: &[(usize, BlockHash)]) -> Option<BlockHash> {
        match Self::old_block_votes(answers).as_slice() {
            [(h, n), ..] if *n >= MIN_AGREEING && 2 * *n > answers.len() => Some(*h),
            _ => None,
        }
    }

    /// A below-checkpoint header found by [`Node::deep_hash_at`], with its height.
    pub fn deep_header(&self, hash: &BlockHash) -> Option<(u32, Header)> {
        lock(&self.deep).by_hash.get(hash).copied()
    }

    fn mark_progress(&self) {
        self.last_progress
            .store(self.clock.now(), Ordering::Relaxed);
    }

    /// Seconds since a source request or a poll round last finished. Failed
    /// requests count: they show the node is still working. Only a hang
    /// (nothing finishing at all) makes this grow past one poll interval.
    pub fn seconds_since_progress(&self) -> u64 {
        self.clock
            .now()
            .saturating_sub(self.last_progress.load(Ordering::Relaxed))
    }

    pub fn network(&self) -> Network {
        self.settings.network
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    pub fn now(&self) -> u64 {
        self.clock.now()
    }

    pub fn uptime(&self) -> u64 {
        self.clock.now().saturating_sub(self.started_at)
    }

    fn name(&self, i: usize) -> String {
        self.sources[i].source.name().to_string()
    }

    // ---------- talking to sources, politely ----------

    async fn call<T, F, Fut>(&self, i: usize, f: F) -> Result<T, SourceError>
    where
        F: FnOnce(Arc<dyn Source>) -> Fut,
        Fut: Future<Output = Result<T, SourceError>>,
    {
        let h = &self.sources[i];
        let wait = {
            let mut st = lock(&h.state);
            if let Some(until) = st.cooling_until {
                if Instant::now() < until {
                    return Err(SourceError::Cooling);
                }
                st.cooling_until = None;
            }
            st.bucket.take(Instant::now())
        };
        if !wait.is_zero() {
            crate::time::sleep(wait).await;
            // Another request may have been told to back off meanwhile.
            if lock(&h.state)
                .cooling_until
                .is_some_and(|u| Instant::now() < u)
            {
                return Err(SourceError::Cooling);
            }
        }
        let res = f(h.source.clone()).await;
        self.mark_progress();
        let now = self.clock.now();
        let mut st = lock(&h.state);
        match &res {
            Ok(_) | Err(SourceError::NotFound) => {
                st.failures = 0;
                st.last_ok = Some(now);
            }
            Err(e @ SourceError::RateLimited { retry_after }) => {
                st.failures += 1;
                let d = retry_after
                    .map(Duration::from_secs)
                    .unwrap_or_else(|| backoff(st.failures, (self.settings.jitter)()))
                    .min(BACKOFF_CAP);
                st.cooling_until = st.cooling_until.max(Some(Instant::now() + d));
                st.last_error = Some(e.to_string());
                warn!(source = %h.source.name(), wait_secs = d.as_secs(), "rate limited; backing off");
            }
            Err(e @ (SourceError::Transport(_) | SourceError::Http { status: 500.., .. })) => {
                st.failures += 1;
                let d = backoff(st.failures, (self.settings.jitter)());
                // Never shorten a longer wait another answer asked for.
                st.cooling_until = st.cooling_until.max(Some(Instant::now() + d));
                st.last_error = Some(e.to_string());
            }
            Err(e @ SourceError::Http { .. }) => {
                // It answered (for example a broadcast rejection): reachable.
                st.failures = 0;
                st.last_ok = Some(now);
                st.last_error = Some(e.to_string());
            }
            Err(e @ SourceError::Invalid(_)) => st.last_error = Some(e.to_string()),
            Err(SourceError::Cooling) => {}
        }
        res
    }

    fn usable(&self, i: usize, now: u64) -> bool {
        let st = lock(&self.sources[i].state);
        st.genesis_ok == Some(true) && st.bad_until <= now
    }

    fn usable_list(&self) -> Vec<usize> {
        let now = self.clock.now();
        (0..self.sources.len())
            .filter(|&i| self.usable(i, now))
            .collect()
    }

    /// Usable sources, starting at a rotating position so load spreads out.
    fn rotated(&self) -> Vec<usize> {
        let list = self.usable_list();
        if list.is_empty() {
            return list;
        }
        let start = self.rotation.fetch_add(1, Ordering::Relaxed) % list.len();
        list[start..]
            .iter()
            .chain(&list[..start])
            .copied()
            .collect()
    }

    fn healthy(&self, i: usize, now: u64) -> bool {
        if !self.usable(i, now) {
            return false;
        }
        let st = lock(&self.sources[i].state);
        !st.lagging
            && st
                .last_ok
                .is_some_and(|t| now.saturating_sub(t) <= HEALTHY_WITHIN_SECS)
    }

    pub fn healthy_count(&self) -> usize {
        let now = self.clock.now();
        (0..self.sources.len())
            .filter(|&i| self.healthy(i, now))
            .count()
    }

    /// Record that source `i` lied in a provable way.
    fn mark_bad(&self, i: usize, reason: String) {
        let now = self.clock.now();
        let name = self.name(i);
        {
            let mut st = lock(&self.sources[i].state);
            st.bad_until = now + BAD_FOR_SECS;
            st.bad_reason = Some(reason.clone());
        }
        warn!(source = %name, %reason, "source caught serving bad data; ignoring it for 24 hours");
        self.set_alarm(
            &format!("source-bad:{name}"),
            AlarmLevel::Critical,
            format!("{name} served data that failed our checks: {reason}"),
        );
    }

    fn set_alarm(&self, code: &str, level: AlarmLevel, message: String) {
        let now = self.clock.now();
        let mut alarms = lock(&self.alarms);
        match alarms.get_mut(code) {
            Some(a) if a.level == level => a.message = message,
            _ => {
                alarms.insert(
                    code.to_string(),
                    Alarm {
                        level,
                        message,
                        since: now,
                    },
                );
            }
        }
    }

    fn clear_alarm(&self, code: &str) {
        lock(&self.alarms).remove(code);
    }

    pub fn alarms(&self) -> BTreeMap<String, Alarm> {
        lock(&self.alarms).clone()
    }

    // ---------- starting up ----------

    async fn check_genesis(&self, i: usize) {
        let expected = bitcoin::constants::genesis_block(self.settings.network).block_hash();
        match self
            .call(i, |s| async move { s.block_hash_at(0).await })
            .await
        {
            Ok(h) if h == expected => lock(&self.sources[i].state).genesis_ok = Some(true),
            Ok(_) => {
                lock(&self.sources[i].state).genesis_ok = Some(false);
                let name = self.name(i);
                warn!(source = %name, "source is on a different network; it will never be used");
                self.set_alarm(
                    &format!("wrong-network:{name}"),
                    AlarmLevel::Critical,
                    format!("{name} is not on {}; check its URL", self.settings.network),
                );
            }
            Err(_) => {}
        }
    }

    /// Check every source's network, then settle on a checkpoint. Safe to
    /// call again until it succeeds.
    pub async fn start(&self) -> Result<(), String> {
        let unchecked: Vec<usize> = (0..self.sources.len())
            .filter(|&i| lock(&self.sources[i].state).genesis_ok.is_none())
            .collect();
        join_all(unchecked.into_iter().map(|i| self.check_genesis(i))).await;

        let (height, header) = match self.settings.checkpoint {
            Some((h, hash)) => (h, self.fetch_checkpoint_header(h, hash).await?),
            None => self.bootstrap_checkpoint().await?,
        };
        *self.chain.write().unwrap_or_else(|e| e.into_inner()) =
            HeaderChain::new(self.settings.network, height, header);
        self.ready.store(true, Ordering::SeqCst);
        self.clear_alarm("starting");
        info!(height, hash = %header.block_hash(), "checkpoint set; following the chain from here");
        Ok(())
    }

    async fn fetch_checkpoint_header(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Header, String> {
        let genesis = bitcoin::constants::genesis_block(self.settings.network);
        if height == 0 {
            if hash != genesis.block_hash() {
                return Err("checkpoint at height 0 must be this network's genesis block".into());
            }
            return Ok(genesis.header);
        }
        for i in self.rotated() {
            match self
                .call(i, move |s| async move { s.header(hash).await })
                .await
            {
                Ok(h) if h.block_hash() == hash => return Ok(h),
                Ok(_) => self.mark_bad(i, format!("served a header that doesn't hash to {hash}")),
                Err(_) => {}
            }
        }
        Err(format!(
            "no source could supply the checkpoint header {hash}"
        ))
    }

    async fn bootstrap_checkpoint(&self) -> Result<(u32, Header), String> {
        let list = self.usable_list();
        let heights: Vec<u32> = join_all(
            list.iter()
                .map(|&i| self.call(i, |s| async move { s.tip_height().await })),
        )
        .await
        .into_iter()
        .filter_map(Result::ok)
        .collect();
        if heights.len() < MIN_AGREEING {
            self.set_alarm(
                "starting",
                AlarmLevel::Warning,
                format!(
                    "waiting for two sources to agree on a starting point ({} answered)",
                    heights.len()
                ),
            );
            return Err("fewer than two sources answered; can't pick a starting point".into());
        }
        let height = heights
            .iter()
            .copied()
            .min()
            .unwrap_or(0)
            .saturating_sub(BOOTSTRAP_DEPTH);
        let hashes: Vec<BlockHash> = join_all(
            list.iter()
                .map(|&i| self.call(i, move |s| async move { s.block_hash_at(height).await })),
        )
        .await
        .into_iter()
        .filter_map(Result::ok)
        .collect();
        let first = hashes.first().copied();
        if hashes.len() < MIN_AGREEING || hashes.iter().any(|h| Some(*h) != first) {
            self.set_alarm(
                "starting",
                AlarmLevel::Critical,
                format!("sources don't agree on block {height}; not starting"),
            );
            return Err(format!("sources disagree about block {height}"));
        }
        let hash = first.expect("checked non-empty");
        let header = self.fetch_checkpoint_header(height, hash).await?;
        warn!(
            height,
            %hash,
            "no checkpoint configured: starting from the block {} sources agree on (set `checkpoint` to pin one)",
            hashes.len()
        );
        Ok((height, header))
    }

    // ---------- the polling loop ----------

    /// One round: check networks, poll tips, update lag, fees, broadcasts and alarms.
    pub async fn tick(&self) {
        if !self.is_ready() {
            if let Err(e) = self.start().await {
                warn!(error = %e, "not started yet");
            }
            self.mark_progress();
            return;
        }
        let unchecked: Vec<usize> = (0..self.sources.len())
            .filter(|&i| lock(&self.sources[i].state).genesis_ok.is_none())
            .collect();
        join_all(unchecked.into_iter().map(|i| self.check_genesis(i))).await;

        let list = self.usable_list();
        join_all(list.into_iter().map(|i| self.poll_tip(i))).await;
        let now = self.clock.now();
        self.update_lag(now);
        self.refresh_fees_if_due(now).await;
        self.recheck_broadcasts().await;
        self.update_alarms(self.clock.now());
        self.mark_progress();
    }

    async fn poll_tip(&self, i: usize) {
        let Ok(tip) = self.call(i, |s| async move { s.tip_hash().await }).await else {
            return;
        };
        if let Some(h) = self.read_chain().height_of(&tip) {
            lock(&self.sources[i].state).tip_height = Some(h);
            return;
        }
        let mut headers = Vec::new();
        let mut cur = tip;
        let mut connected = false;
        for _ in 0..MAX_WALK {
            let Ok(hdr) = self
                .call(i, move |s| async move { s.header(cur).await })
                .await
            else {
                return;
            };
            if hdr.block_hash() != cur {
                self.mark_bad(i, format!("served a header that doesn't hash to {cur}"));
                return;
            }
            let parent = hdr.prev_blockhash;
            headers.push(hdr);
            if self.read_chain().contains(&parent) {
                connected = true;
                break;
            }
            cur = parent;
        }
        if !connected {
            lock(&self.sources[i].state).last_error = Some(format!(
                "its tip doesn't connect to our chain within {MAX_WALK} headers"
            ));
            return;
        }
        headers.reverse();
        let now = self.clock.now();
        let result = self
            .chain
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .connect(&headers, now);
        match result {
            Ok(c) => {
                if c.new_best {
                    let chain = self.read_chain();
                    info!(height = chain.tip_height(), hash = %chain.tip_hash(), source = %self.name(i), "new tip");
                    if c.reorg_depth > 0 {
                        warn!(
                            depth = c.reorg_depth,
                            "reorg: switched to a branch with more work"
                        );
                    }
                }
                let h = self.read_chain().height_of(&tip);
                lock(&self.sources[i].state).tip_height = h;
            }
            Err(e) => self.mark_bad(i, e.to_string()),
        }
    }

    fn read_chain(&self) -> std::sync::RwLockReadGuard<'_, HeaderChain> {
        self.chain.read().unwrap_or_else(|e| e.into_inner())
    }

    fn update_lag(&self, now: u64) {
        let best = self.read_chain().tip_height();
        for h in &self.sources {
            let mut st = lock(&h.state);
            match st.tip_height {
                Some(t) if best > t + LAG_BLOCKS => {
                    let since = *st.behind_since.get_or_insert(now);
                    st.lagging = now.saturating_sub(since) >= LAG_SECS;
                }
                _ => {
                    st.behind_since = None;
                    st.lagging = false;
                }
            }
        }
    }

    /// Seconds since the tip block's own timestamp.
    pub fn tip_age(&self) -> u64 {
        let t = u64::from(self.read_chain().tip_header().time);
        self.clock.now().saturating_sub(t)
    }

    /// Synced = started, at least two healthy sources, and the tip isn't stale.
    pub fn is_synced(&self) -> bool {
        self.is_ready()
            && self.healthy_count() >= MIN_AGREEING
            && self.tip_age() < TIP_CRITICAL_SECS
    }

    fn update_alarms(&self, now: u64) {
        let age = self.tip_age();
        if age >= TIP_CRITICAL_SECS {
            self.set_alarm(
                "tip-stale",
                AlarmLevel::Critical,
                format!("no new block for {} minutes: sources may be hiding blocks; reporting NOT synced", age / 60),
            );
        } else if age >= TIP_WARN_SECS {
            self.set_alarm(
                "tip-stale",
                AlarmLevel::Warning,
                format!("no new block for {} minutes", age / 60),
            );
        } else {
            self.clear_alarm("tip-stale");
        }

        let healthy = (0..self.sources.len())
            .filter(|&i| self.healthy(i, now))
            .count();
        if healthy < MIN_AGREEING {
            self.set_alarm(
                "too-few-sources",
                AlarmLevel::Warning,
                format!("only {healthy} healthy source(s); need {MIN_AGREEING} to report synced"),
            );
        } else {
            self.clear_alarm("too-few-sources");
        }

        for i in 0..self.sources.len() {
            let name = self.name(i);
            let (lagging, bad_expired) = {
                let mut st = lock(&self.sources[i].state);
                let expired = st.bad_reason.is_some() && st.bad_until <= now;
                if expired {
                    st.bad_reason = None;
                }
                (st.lagging, expired)
            };
            if lagging {
                self.set_alarm(
                    &format!("source-lagging:{name}"),
                    AlarmLevel::Warning,
                    format!(
                        "{name} has been more than {LAG_BLOCKS} blocks behind for over 30 minutes"
                    ),
                );
            } else {
                self.clear_alarm(&format!("source-lagging:{name}"));
            }
            if bad_expired {
                self.clear_alarm(&format!("source-bad:{name}"));
            }
        }
    }

    // ---------- fees ----------

    async fn refresh_fees_if_due(&self, now: u64) {
        {
            let last = lock(&self.last_fee_refresh);
            if last.is_some_and(|t| now.saturating_sub(t) < FEE_REFRESH_SECS) {
                return;
            }
        }
        // Only wait the full interval after a refresh that got some fees.
        if self.refresh_fees().await > 0 {
            *lock(&self.last_fee_refresh) = Some(now);
        }
    }

    /// Ask every usable source for fee estimates; returns how many answered.
    pub async fn refresh_fees(&self) -> usize {
        let list = self.usable_list();
        let results = join_all(
            list.iter()
                .map(|&i| self.call(i, |s| async move { s.fee_estimates().await })),
        )
        .await;
        let mut answered = 0;
        for (i, r) in list.into_iter().zip(results) {
            if let Ok(map) = r
                && !map.is_empty()
            {
                lock(&self.sources[i].state).fees = Some(map);
                answered += 1;
            }
        }
        let urgent = self.fee_values(fees::URGENT_TARGET);
        if fees::disagree(&urgent) {
            self.set_alarm(
                "fee-disagreement",
                AlarmLevel::Warning,
                format!("sources' fee estimates differ by more than 2x: {urgent:?} sat/vB; using the highest for urgent sends"),
            );
        } else {
            self.clear_alarm("fee-disagreement");
        }
        answered
    }

    fn fee_values(&self, target: u16) -> Vec<f64> {
        let now = self.clock.now();
        (0..self.sources.len())
            .filter(|&i| self.usable(i, now))
            .filter_map(|i| {
                lock(&self.sources[i].state)
                    .fees
                    .as_ref()
                    .and_then(|m| fees::pick(m, target))
            })
            .collect()
    }

    /// Our fee estimate in sat/vB for `target` blocks, if any source gave one.
    pub fn estimate_fee(&self, target: u16) -> Option<f64> {
        fees::aggregate(
            &self.fee_values(target),
            target,
            self.settings.fee_ceiling_sat_vb,
        )
    }

    // ---------- chain questions ----------

    pub fn with_chain<T>(&self, f: impl FnOnce(&HeaderChain) -> T) -> T {
        f(&self.read_chain())
    }

    /// A verified copy of a block we know the header of.
    /// A block on our chain, or an old one below the checkpoint whose header
    /// [`Node::deep_hash_at`] cross-checked. Either way the block's contents
    /// are proven against that header (hash, merkle root, witness commitment).
    pub async fn get_block(&self, hash: BlockHash) -> Result<Arc<Vec<u8>>, RpcError> {
        if !self.read_chain().contains(&hash) && self.deep_header(&hash).is_none() {
            return Err(RpcError::new(RPC_NOT_FOUND, "Block not found"));
        }
        if let Some(raw) = lock(&self.blocks).get(&hash) {
            return Ok(raw);
        }
        for i in self.rotated() {
            match self
                .call(i, move |s| async move { s.raw_block(hash).await })
                .await
            {
                Ok(raw) => match verify_block(&raw, hash) {
                    Ok(_) => {
                        let raw = Arc::new(raw);
                        lock(&self.blocks).insert(hash, raw.clone());
                        return Ok(raw);
                    }
                    Err(e) => {
                        self.mark_bad(i, format!("served block {hash} that fails checks: {e}"))
                    }
                },
                Err(_) => continue,
            }
        }
        Err(RpcError::new(
            RPC_MISC_ERROR,
            "Block not available: no source could supply a verified copy right now",
        ))
    }

    /// Ask source `i` where `txid` confirmed, and check its merkle proof against our headers.
    async fn verified_confirmation(
        &self,
        i: usize,
        txid: Txid,
    ) -> Result<Option<(BlockHash, u32)>, ()> {
        let status = self
            .call(i, move |s| async move { s.tx_status(txid).await })
            .await
            .map_err(|_| ())?;
        if !status.confirmed {
            return Ok(None);
        }
        let proof = self
            .call(i, move |s| async move { s.merkle_proof(txid).await })
            .await
            .map_err(|_| ())?;
        let (hash, header) = {
            let chain = self.read_chain();
            let Some(hash) = chain.hash_at(proof.block_height) else {
                // Beyond our tip, or below our checkpoint: can't check it yet.
                return Err(());
            };
            (hash, chain.header(&hash))
        };
        let Some(header) = header else { return Err(()) };
        if status.block_hash.is_some_and(|h| h != hash) {
            // The source is on another branch than our best chain (or a reorg is under way).
            return Err(());
        }
        match verify_merkle_branch(txid, &proof.merkle, proof.pos, &header) {
            Ok(()) => Ok(Some((hash, proof.block_height))),
            Err(e) => {
                self.mark_bad(i, format!("merkle proof for {txid} doesn't check out: {e}"));
                Err(())
            }
        }
    }

    /// A verified transaction and, when proven, the best-chain block it's in.
    pub async fn get_tx(
        &self,
        txid: Txid,
    ) -> Result<(Transaction, Option<(BlockHash, u32)>), RpcError> {
        let ours = lock(&self.pending).get(&txid).map(|p| p.hex.clone());
        let mut tx_found = None;
        if let Some(hex) = ours
            && let Ok(bytes) = Vec::<u8>::from_hex(&hex)
            && let Ok(tx) = verify_tx(&bytes, txid)
        {
            tx_found = Some(tx);
        }
        for i in self.rotated() {
            let tx = match &tx_found {
                Some(tx) => tx.clone(),
                None => match self
                    .call(i, move |s| async move { s.raw_tx(txid).await })
                    .await
                {
                    Ok(raw) => match verify_tx(&raw, txid) {
                        Ok(tx) => tx,
                        Err(e) => {
                            self.mark_bad(
                                i,
                                format!("served transaction {txid} that fails checks: {e}"),
                            );
                            continue;
                        }
                    },
                    Err(_) => continue,
                },
            };
            tx_found = Some(tx.clone());
            if let Ok(conf) = self.verified_confirmation(i, txid).await {
                return Ok((tx, conf));
            }
        }
        match tx_found {
            Some(tx) => Ok((tx, None)),
            None => Err(RpcError::new(
                RPC_NOT_FOUND,
                "No such mempool or blockchain transaction",
            )),
        }
    }

    async fn check_spend(&self, i: usize, spender: Txid, outpoint: OutPoint) -> SpendCheck {
        match self
            .call(i, move |s| async move { s.raw_tx(spender).await })
            .await
        {
            Ok(raw) => match verify_tx(&raw, spender) {
                Ok(tx) if tx.input.iter().any(|inp| inp.previous_output == outpoint) => {
                    SpendCheck::Proven
                }
                _ => SpendCheck::Disproven,
            },
            Err(SourceError::NotFound) => SpendCheck::Disproven,
            Err(_) => SpendCheck::Unknown,
        }
    }

    /// bitcoind's `gettxout`. "Spent" can be proven; "unspent" can't, so it
    /// needs two sources agreeing and a proven confirmation, or we answer null.
    pub async fn get_txout(&self, txid: Txid, vout: u32) -> Result<Option<Value>, RpcError> {
        let list = self.usable_list();
        let answers = join_all(
            list.iter()
                .map(|&i| self.call(i, move |s| async move { s.outspend(txid, vout).await })),
        )
        .await;
        let outpoint = OutPoint { txid, vout };
        let mut unspent_votes = 0;
        let mut unsure = false;
        for (&i, answer) in list.iter().zip(answers) {
            match answer {
                Ok(o) if o.spent => match o.txid {
                    Some(spender) => match self.check_spend(i, spender, outpoint).await {
                        SpendCheck::Proven => return Ok(None),
                        SpendCheck::Disproven => self.mark_bad(
                            i,
                            format!(
                                "said {txid}:{vout} is spent by {spender}, which doesn't spend it"
                            ),
                        ),
                        SpendCheck::Unknown => unsure = true,
                    },
                    None => unsure = true,
                },
                Ok(_) => unspent_votes += 1,
                Err(_) => {}
            }
        }
        if unsure || unspent_votes < MIN_AGREEING {
            return Ok(None);
        }
        let Ok((tx, Some((_, height)))) = self.get_tx(txid).await else {
            return Ok(None);
        };
        let Some(out) = tx.output.get(vout as usize) else {
            return Ok(None);
        };
        let (tip_hash, tip_height) = {
            let c = self.read_chain();
            (c.tip_hash(), c.tip_height())
        };
        let script = &out.script_pubkey;
        let mut spk = json!({
            "hex": script.as_bytes().to_lower_hex_string(),
            "asm": script.to_asm_string(),
        });
        if let Ok(addr) = bitcoin::Address::from_script(script, self.settings.network) {
            spk["address"] = json!(addr.to_string());
        }
        Ok(Some(json!({
            "bestblock": tip_hash.to_string(),
            "confirmations": tip_height.saturating_sub(height) + 1,
            "value": out.value.to_btc(),
            "scriptPubKey": spk,
            "coinbase": tx.is_coinbase(),
        })))
    }

    /// bitcoind's `testmempoolaccept`, for one transaction, from local checks:
    /// it decodes, isn't a coinbase, and none of its inputs is proven spent by
    /// another transaction. LND needs this to answer before it will publish.
    pub async fn test_accept(&self, hex: &str) -> Result<Value, RpcError> {
        let bytes = Vec::<u8>::from_hex(hex.trim())
            .map_err(|_| RpcError::new(RPC_DESERIALIZATION_ERROR, "TX decode failed"))?;
        let tx: Transaction = deserialize(&bytes)
            .map_err(|_| RpcError::new(RPC_DESERIALIZATION_ERROR, "TX decode failed"))?;
        let txid = tx.compute_txid();
        let base = json!({ "txid": txid.to_string(), "wtxid": tx.compute_wtxid().to_string() });
        let reject = |reason: &str| {
            let mut v = base.clone();
            v["allowed"] = json!(false);
            v["reject-reason"] = json!(reason);
            Ok(v)
        };
        if bytes.len() == 64 {
            return reject("tx-size-small");
        }
        if tx.is_coinbase() {
            return reject("coinbase");
        }
        if lock(&self.pending).contains_key(&txid) {
            return reject("txn-already-in-mempool");
        }
        for inp in &tx.input {
            let prev = inp.previous_output;
            for i in self.usable_list() {
                let Ok(o) = self
                    .call(
                        i,
                        move |s| async move { s.outspend(prev.txid, prev.vout).await },
                    )
                    .await
                else {
                    continue;
                };
                if let (true, Some(spender)) = (o.spent, o.txid) {
                    if spender == txid {
                        return reject("txn-already-in-mempool");
                    }
                    if let SpendCheck::Proven = self.check_spend(i, spender, prev).await {
                        return reject("bad-txns-inputs-missingorspent");
                    }
                }
            }
        }
        let mut v = base;
        v["allowed"] = json!(true);
        v["vsize"] = json!(tx.vsize());
        Ok(v)
    }

    // ---------- broadcasting ----------

    /// Send to every usable source at once. Success if any accepts.
    pub async fn broadcast(&self, hex: &str) -> Result<Txid, RpcError> {
        let hex = hex.trim().to_ascii_lowercase();
        let bytes = Vec::<u8>::from_hex(&hex)
            .map_err(|_| RpcError::new(RPC_DESERIALIZATION_ERROR, "TX decode failed"))?;
        let tx: Transaction = deserialize(&bytes)
            .map_err(|_| RpcError::new(RPC_DESERIALIZATION_ERROR, "TX decode failed"))?;
        let txid = tx.compute_txid();
        let list = self.usable_list();
        if list.is_empty() {
            return Err(RpcError::new(
                RPC_MISC_ERROR,
                "no usable source to broadcast to",
            ));
        }
        let results = join_all(list.iter().map(|&i| {
            let hex = hex.clone();
            self.call(i, move |s| async move { s.broadcast(&hex).await })
        }))
        .await;
        let mut accepted = 0;
        let mut errors: Vec<RpcError> = Vec::new();
        for (&i, r) in list.iter().zip(results) {
            match r {
                Ok(t) if t == txid => accepted += 1,
                Ok(t) => self.mark_bad(
                    i,
                    format!("answered broadcast of {txid} with a different txid {t}"),
                ),
                Err(SourceError::Http { body, .. }) => {
                    let e = parse_reject(&body);
                    if e.message.contains("already-in-mempool")
                        || e.message.contains("txn-already-known")
                    {
                        accepted += 1;
                    } else {
                        errors.push(e);
                    }
                }
                Err(e) => errors.push(RpcError::new(RPC_MISC_ERROR, e.to_string())),
            }
        }
        info!(%txid, accepted, of = list.len(), "broadcast sent to every usable source");
        if accepted > 0 {
            let now = self.clock.now();
            lock(&self.pending).insert(
                txid,
                Pending {
                    hex,
                    first_sent: now,
                    last_check: now,
                    checks: 0,
                },
            );
            return Ok(txid);
        }
        Err(most_common(errors).unwrap_or_else(|| {
            RpcError::new(RPC_VERIFY_REJECTED, "no source accepted the transaction")
        }))
    }

    /// Follow up on our broadcasts: re-send to any source that doesn't know
    /// them, forget them once proven confirmed, alarm if too few sources see them.
    pub async fn recheck_broadcasts(&self) {
        let now = self.clock.now();
        let due: Vec<(Txid, String, u64)> = {
            let mut pending = lock(&self.pending);
            pending.retain(|_, p| now.saturating_sub(p.first_sent) < BROADCAST_GIVE_UP_SECS);
            pending
                .iter()
                .filter(|(_, p)| {
                    let wait = if p.checks == 0 {
                        BROADCAST_FIRST_CHECK_SECS
                    } else {
                        BROADCAST_RECHECK_SECS
                    };
                    now.saturating_sub(p.last_check) >= wait
                })
                .map(|(t, p)| (*t, p.hex.clone(), p.first_sent))
                .collect()
        };
        for (txid, hex, first_sent) in due {
            let mut seen = BTreeSet::new();
            let mut confirmed = false;
            for i in self.usable_list() {
                match self
                    .call(i, move |s| async move { s.tx_status(txid).await })
                    .await
                {
                    Ok(st) if st.confirmed => {
                        if let Ok(Some(_)) = self.verified_confirmation(i, txid).await {
                            confirmed = true;
                            break;
                        }
                        seen.insert(i);
                    }
                    Ok(_) => {
                        seen.insert(i);
                    }
                    Err(SourceError::NotFound) => {
                        let h = hex.clone();
                        if let Ok(t) = self
                            .call(i, move |s| async move { s.broadcast(&h).await })
                            .await
                            && t == txid
                        {
                            info!(%txid, source = %self.name(i), "re-sent broadcast to a source that didn't have it");
                            seen.insert(i);
                        }
                    }
                    Err(_) => {}
                }
            }
            let code = format!("broadcast-not-seen:{txid}");
            if confirmed {
                lock(&self.pending).remove(&txid);
                self.clear_alarm(&code);
                info!(%txid, "our broadcast is confirmed");
                continue;
            }
            if let Some(p) = lock(&self.pending).get_mut(&txid) {
                p.checks += 1;
                p.last_check = now;
            }
            if seen.len() < MIN_AGREEING && now.saturating_sub(first_sent) >= BROADCAST_ALARM_SECS {
                self.set_alarm(
                    &code,
                    AlarmLevel::Critical,
                    format!(
                        "transaction {txid} is known to only {} source(s) after {} minutes",
                        seen.len(),
                        now.saturating_sub(first_sent) / 60
                    ),
                );
            } else if seen.len() >= MIN_AGREEING {
                self.clear_alarm(&code);
            }
        }
    }

    /// Which of our own unconfirmed broadcasts spends this output, if any.
    pub fn our_spender_of(&self, txid: Txid, vout: u32) -> Option<Txid> {
        let outpoint = OutPoint { txid, vout };
        lock(&self.pending).iter().find_map(|(t, p)| {
            let bytes = Vec::<u8>::from_hex(&p.hex).ok()?;
            let tx: Transaction = deserialize(&bytes).ok()?;
            tx.input
                .iter()
                .any(|i| i.previous_output == outpoint)
                .then_some(*t)
        })
    }

    /// Our own unconfirmed broadcasts: the only "mempool" we show.
    pub fn our_mempool(&self) -> Vec<(Txid, usize)> {
        lock(&self.pending)
            .iter()
            .map(|(t, p)| (*t, p.hex.len() / 2))
            .collect()
    }

    // ---------- status ----------

    /// Remember that a client asked for an RPC method we don't support.
    /// Returns true the first time a (cleaned) name is seen and there is
    /// room for it; the set can't grow past [`UNSUPPORTED_RPC_MAX`].
    pub fn note_unsupported_rpc(&self, cleaned: &str) -> bool {
        let mut set = lock(&self.unsupported_rpc);
        if set.len() >= UNSUPPORTED_RPC_MAX || !set.insert(cleaned.to_string()) {
            return false;
        }
        if set.len() == UNSUPPORTED_RPC_MAX {
            // The set never shrinks, so this happens once.
            warn!(
                max = UNSUPPORTED_RPC_MAX,
                "the unsupported-RPC list is full; later method names won't be listed"
            );
        }
        true
    }

    pub fn status(&self) -> Value {
        let now = self.clock.now();
        let (tip_height, tip_hash, base) = {
            let c = self.read_chain();
            (c.tip_height(), c.tip_hash(), c.base_height())
        };
        let sources: Vec<Value> = (0..self.sources.len())
            .map(|i| {
                let healthy = self.healthy(i, now);
                let st = lock(&self.sources[i].state);
                json!({
                    "name": self.sources[i].source.name(),
                    "healthy": healthy,
                    "network_ok": st.genesis_ok,
                    "bad": st.bad_until > now,
                    "bad_reason": st.bad_reason,
                    "lagging": st.lagging,
                    "tip_height": st.tip_height,
                    "last_ok_secs_ago": st.last_ok.map(|t| now.saturating_sub(t)),
                    "last_error": st.last_error,
                    "cooling": st.cooling_until.is_some_and(|u| Instant::now() < u),
                })
            })
            .collect();
        let alarms: Vec<Value> = self
            .alarms()
            .into_iter()
            .map(|(code, a)| json!({"code": code, "level": format!("{:?}", a.level).to_lowercase(), "message": a.message, "since": a.since}))
            .collect();
        json!({
            "network": self.settings.network.to_string(),
            "ready": self.is_ready(),
            "synced": self.is_synced(),
            "checkpoint_height": base,
            "tip": { "height": tip_height, "hash": tip_hash.to_string(), "age_secs": self.tip_age() },
            "healthy_sources": self.healthy_count(),
            "sources": sources,
            "alarms": alarms,
            "unsupported_rpc_methods": lock(&self.unsupported_rpc).iter().cloned().collect::<Vec<_>>(),
            "pending_broadcasts": lock(&self.pending).keys().map(|t| t.to_string()).collect::<Vec<_>>(),
            "fee_estimates_sat_vb": {
                "2": self.estimate_fee(2),
                "6": self.estimate_fee(6),
                "12": self.estimate_fee(12),
                "144": self.estimate_fee(144),
            },
        })
    }
}

/// Esplora forwards bitcoind's rejection, usually as
/// `sendrawtransaction RPC error: {"code":-26,"message":"..."}`.
pub fn parse_reject(body: &str) -> RpcError {
    #[derive(serde::Deserialize)]
    struct Inner {
        code: i32,
        message: String,
    }
    if let Some(start) = body.find('{')
        && let Ok(inner) = serde_json::from_str::<Inner>(&body[start..])
    {
        return RpcError::new(inner.code, crate::source::clean_text(&inner.message));
    }
    let text = crate::source::clean_text(body);
    let code = if text.contains("already in block chain") || text.contains("already-in-chain") {
        RPC_VERIFY_ALREADY_IN_CHAIN
    } else if text.contains("missingorspent") || text.contains("missing-inputs") {
        RPC_VERIFY_ERROR
    } else {
        RPC_VERIFY_REJECTED
    };
    RpcError::new(code, text)
}

fn most_common(errors: Vec<RpcError>) -> Option<RpcError> {
    let mut counts: BTreeMap<(i32, String), usize> = BTreeMap::new();
    for e in errors {
        *counts.entry((e.code, e.message)).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by_key(|(_, n)| *n)
        .map(|((code, message), _)| RpcError { code, message })
}

/// Serialize a header to hex (for `getblockheader` with verbose=false).
pub fn header_hex(h: &Header) -> String {
    serialize(h).to_lower_hex_string()
}
