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
use bitcoin::pow::Work;
use bitcoin::{BlockHash, Network, OutPoint, Transaction, Txid};
use futures::future::join_all;
use futures::stream::{FuturesUnordered, StreamExt};
use serde_json::{Value, json};
use tracing::{info, warn};

use crate::chain::{ChainError, HeaderChain, derive_target};
use crate::fees;
use crate::limits::{BACKOFF_CAP, TokenBucket, backoff};
use crate::proof::{coinbase_height_is, verify_block_for, verify_merkle_branch, verify_tx};
use crate::source::{FeeMap, Source, SourceError};

/// How deep below the agreed tip a bootstrap checkpoint is taken.
pub const BOOTSTRAP_DEPTH: u32 = 6;
/// How far back we follow a source's tip looking for our chain.
pub const MAX_WALK: usize = 2016;
/// How many headers below the checkpoint each round's walk back proves at
/// most (see [`Node::walk_back`]): 2015 take about 32 rounds.
pub const WALK_BACK_PER_TICK: usize = 64;
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
/// How long a caller waits for someone else's download of the same block
/// before fetching it from its own source. Long enough for a healthy
/// download over Tor (a few seconds for a 4 MB block) to finish and be
/// shared; short enough that one stalled explorer (its request budget,
/// then the 90 s HTTP timeout) can't hold up a ready one, well inside
/// LND's and Core Lightning's 60 s RPC timeouts.
pub const IN_FLIGHT_WAIT: Duration = Duration::from_secs(10);

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
    /// At most [`DOWNLOADS_PER_SOURCE`] block downloads from this source
    /// at once, whatever blocks they are (see [`Node::download_turn`]).
    downloads: [futures::lock::Mutex<()>; DOWNLOADS_PER_SOURCE],
}

/// How many block bodies we download from one source at the same time.
pub const DOWNLOADS_PER_SOURCE: usize = 2;

/// One block's download slots: the first download, and at most one extra
/// one when the first takes longer than [`IN_FLIGHT_WAIT`] (see
/// [`Node::fetch_block_from`]).
#[derive(Default)]
struct DownloadSlot {
    first: futures::lock::Mutex<()>,
    extra: futures::lock::Mutex<()>,
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
    /// One block download per hash at a time (see [`Node::fetch_block_from`]).
    in_flight: Mutex<HashMap<BlockHash, Arc<DownloadSlot>>>,
    /// Blocks refused because their signet solution can't be judged here,
    /// with why (see [`Node::fetch_block_from`]).
    unjudged: Mutex<HashMap<BlockHash, String>>,
    /// Unjudgeable blocks that stopped us following a source's chain, with
    /// the work their branch would have and why. The warning stays while
    /// one of them could still be the best chain (see
    /// [`Node::refresh_unjudged_alarm`]).
    blocked_unjudged: Mutex<HashMap<BlockHash, (Work, String)>>,
    /// The retarget height we're holding back at, if any (see
    /// [`Node::poll_tip`]).
    retarget_hold: Mutex<Option<u32>>,
    /// Consensus parameters other than the network's, for tests only (see
    /// [`Node::with_chain_params`]).
    chain_params: Option<bitcoin::params::Params>,
    /// One walk back from the checkpoint at a time (see [`Node::walk_back`]).
    #[cfg_attr(not(feature = "signet-check"), allow(dead_code))]
    walk_lock: futures::lock::Mutex<()>,
}

/// One caller's share of a block's download slot. Dropping it (normally or
/// because the caller gave up) removes the slot once nobody else holds it,
/// so a cancelled download leaves nothing behind.
struct InFlightEntry<'a> {
    map: &'a Mutex<HashMap<BlockHash, Arc<DownloadSlot>>>,
    hash: BlockHash,
    slot: Option<Arc<DownloadSlot>>,
}

impl<'a> InFlightEntry<'a> {
    fn join(map: &'a Mutex<HashMap<BlockHash, Arc<DownloadSlot>>>, hash: BlockHash) -> Self {
        let slot = lock(map).entry(hash).or_default().clone();
        Self {
            map,
            hash,
            slot: Some(slot),
        }
    }

    fn slot(&self) -> &DownloadSlot {
        self.slot.as_ref().expect("held until dropped")
    }
}

impl Drop for InFlightEntry<'_> {
    fn drop(&mut self) {
        // Every clone is made and dropped under the map's lock, so the
        // count is exact: 1 means only the map holds it now.
        let mut map = lock(self.map);
        drop(self.slot.take());
        if map
            .get(&self.hash)
            .is_some_and(|s| Arc::strong_count(s) == 1)
        {
            map.remove(&self.hash);
        }
    }
}

/// How many distinct unsupported RPC method names to remember.
pub const UNSUPPORTED_RPC_MAX: usize = 64;

/// How many unjudgeable blocks to remember (forgotten all at once past this).
const UNJUDGED_MAX: usize = 1024;

/// What fetching a block from one source came to.
enum Fetched {
    /// Proven to be the block (and on signet, signed); now in the cache.
    Verified(Arc<Vec<u8>>),
    /// The source didn't supply it (not found, down, rate-limited).
    Missing,
    /// The source served something provably false and is marked bad.
    Lied,
    /// A real copy of the block, but we can't judge its signet signature.
    Unjudged(String),
}

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
                downloads: Default::default(),
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
            in_flight: Mutex::new(HashMap::new()),
            unjudged: Mutex::new(HashMap::new()),
            blocked_unjudged: Mutex::new(HashMap::new()),
            retarget_hold: Mutex::new(None),
            chain_params: None,
            walk_lock: futures::lock::Mutex::new(()),
        }
    }

    /// Check headers with these consensus parameters instead of the
    /// network's. For tests only: they give regtest a short retarget
    /// interval, so the difficulty rules can be tested on blocks a test can
    /// mine (see [`HeaderChain::with_params`]).
    #[doc(hidden)]
    pub fn with_chain_params(mut self, params: bitcoin::params::Params) -> Self {
        self.chain_params = Some(params);
        self
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
    /// Old headers don't get their signet signature checked here: that
    /// needs the whole block, and LND's birthday search and rescan walk
    /// hundreds of old heights, so it would double the requests of a lookup
    /// that already fails closed on any disagreement. When a wallet then
    /// asks for an old block's contents, [`Node::get_block`] does check its
    /// signature, and a source serving one from another signet is marked
    /// bad there.
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
        // Proven by the walk back from the checkpoint: no vote needed.
        if let Some(h) = self.read_chain().hash_at(height) {
            return Ok(h);
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
        let genesis = bitcoin::constants::genesis_block(self.settings.network).block_hash();
        if winner == genesis && height != 0 {
            // Genesis is the block whose parent is all zeros: height 0 only.
            return Err(RpcError::new(
                RPC_MISC_ERROR,
                "sources gave the genesis block for a later height",
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
        let params = bitcoin::params::Params::new(self.settings.network);
        for &(i, _) in &answers {
            let Ok(header) = self
                .call(i, move |s| async move { s.header(hash).await })
                .await
            else {
                continue;
            };
            let pow_ok =
                derive_target(header.bits, &params).is_some_and(|t| header.validate_pow(t).is_ok());
            if header.block_hash() != hash || !pow_ok {
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
    /// Headers the walk back from the checkpoint proved come first.
    pub fn deep_header(&self, hash: &BlockHash) -> Option<(u32, Header)> {
        if let Some(found) = self.read_chain().walked_header(hash) {
            return Some(found);
        }
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
    ///
    /// A build without the `signet-check` feature (the browser demo) has no
    /// signet signature checker, so it refuses to start on signet at all
    /// rather than follow headers it can't check: it never becomes ready.
    pub async fn start(&self) -> Result<(), String> {
        if self.settings.network == Network::Signet && !cfg!(feature = "signet-check") {
            let why = "this build can't check signet block signatures (no `signet-check` feature); refusing to run on signet";
            self.set_alarm("signet-check-missing", AlarmLevel::Critical, why.into());
            return Err(why.into());
        }
        let unchecked: Vec<usize> = (0..self.sources.len())
            .filter(|&i| lock(&self.sources[i].state).genesis_ok.is_none())
            .collect();
        join_all(unchecked.into_iter().map(|i| self.check_genesis(i))).await;

        let (height, header) = match self.settings.checkpoint {
            Some((h, hash)) => (h, self.fetch_checkpoint_header(h, hash).await?),
            None => self.bootstrap_checkpoint().await?,
        };
        let chain = match &self.chain_params {
            Some(p) => HeaderChain::with_params(p.clone(), height, header),
            None => HeaderChain::new(self.settings.network, height, header),
        };
        *self.chain.write().unwrap_or_else(|e| e.into_inner()) = chain;
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
        if hash == genesis.block_hash() {
            return Err(format!(
                "the genesis block can't be the checkpoint at height {height}"
            ));
        }
        let params = bitcoin::params::Params::new(self.settings.network);
        for i in self.rotated() {
            match self
                .call(i, move |s| async move { s.header(hash).await })
                .await
            {
                Ok(h) if h.block_hash() == hash => {
                    // The header is the one this hash names, so if it
                    // misses its own target the hash itself is no block.
                    if !derive_target(h.bits, &params).is_some_and(|t| h.validate_pow(t).is_ok()) {
                        return Err(format!("the checkpoint {hash} fails its proof of work"));
                    }
                    return Ok(h);
                }
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
        let header = match self.fetch_checkpoint_header(height, hash).await {
            Ok(h) => h,
            Err(why) => {
                self.set_alarm(
                    "starting",
                    AlarmLevel::Critical,
                    format!(
                        "sources agree on block {height} ({hash}), but {why}; not starting from it"
                    ),
                );
                return Err(why);
            }
        };
        if self.settings.network == Network::Signet && height > 0 {
            self.prove_bootstrap_block(height, hash).await?;
        }
        warn!(
            height,
            %hash,
            "no checkpoint configured: starting from the block {} sources agree on (set `checkpoint` to pin one)",
            hashes.len()
        );
        Ok((height, header))
    }

    /// On signet, agreement isn't enough for an automatic starting point:
    /// every signet shares one genesis block, so two explorers following
    /// another signet would agree on a checkpoint from it. Like every block
    /// we follow, the checkpoint's block must be proven and signed for our
    /// signet (it then sits in the block cache, ready for `getblock`), and
    /// its coinbase must name the height the sources gave it (BIP34): a
    /// real block offered at the wrong height would put every later height
    /// off. If no source can give a copy that passes, we don't start from it.
    async fn prove_bootstrap_block(&self, height: u32, hash: BlockHash) -> Result<(), String> {
        let mut why = "no source could supply it".to_string();
        for i in self.rotated() {
            match self.fetch_block_from(i, hash).await {
                Fetched::Verified(raw) => {
                    let at_height = deserialize::<bitcoin::Block>(&raw)
                        .is_ok_and(|b| coinbase_height_is(&b, height));
                    if at_height {
                        return Ok(());
                    }
                    // The block is proven, so its height is a fact; the
                    // sources that put it here all claimed otherwise.
                    why = format!("its coinbase says it isn't at height {height}");
                    break;
                }
                Fetched::Missing => {}
                Fetched::Lied => why = "it isn't signed for our signet or doesn't match".into(),
                Fetched::Unjudged(w) => {
                    why = w;
                    break;
                }
            }
        }
        self.set_alarm(
            "starting",
            AlarmLevel::Critical,
            format!("sources agree on block {height} ({hash}), but {why}; not starting from it"),
        );
        Err(format!(
            "the agreed starting block {hash} couldn't be proven: {why}"
        ))
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
        self.walk_back(WALK_BACK_PER_TICK).await;
        self.refresh_unjudged_alarm();
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
        // Held just below a retarget until the walk back proves its
        // period's first header: nothing past it can be followed yet, so
        // fetching headers up to it would only spend the source's budget.
        let waiting = {
            let chain = self.read_chain();
            lock(&self.retarget_hold)
                .is_some_and(|at| chain.tip_height() + 1 >= at && !chain.walk_back_done())
        };
        if waiting {
            return;
        }
        let mut headers = match self.headers_to_our_chain(i, tip).await {
            Ok(Some(h)) => h,
            Ok(None) => {
                // More than one walk behind (we were held, or down, for a
                // long time): follow the source's chain in steps instead,
                // from the block one walk above our tip. What it names
                // there is checked like any header; a wrong answer just
                // doesn't connect.
                let above = self.read_chain().tip_height() + MAX_WALK as u32;
                let Ok(step) = self
                    .call(i, move |s| async move { s.block_hash_at(above).await })
                    .await
                else {
                    return;
                };
                match self.headers_to_our_chain(i, step).await {
                    Ok(Some(h)) => h,
                    Ok(None) => {
                        lock(&self.sources[i].state).last_error = Some(format!(
                            "its chain doesn't connect to ours within {MAX_WALK} headers"
                        ));
                        return;
                    }
                    Err(()) => return,
                }
            }
            Err(()) => return,
        };
        let now = self.clock.now();
        // The cheap checks first (links, proof of work, difficulty, times),
        // so a bad header never costs us a block download.
        let checked = self.read_chain().check(&headers, now);
        match checked {
            Ok(()) => {}
            Err(ChainError::NeedPeriodStart { height, at }) => {
                // We can't check the retarget header exactly until the walk
                // back reaches its period's first header: follow the
                // headers before it, hold it back, and blame nobody.
                self.hold_retarget(
                    at,
                    format!(
                        "the retarget needs the block at height {height}, below our checkpoint, and the walk back to it (each header proven by its hash) isn't there yet"
                    ),
                );
                let Some(parent) = self.read_chain().height_of(&headers[0].prev_blockhash) else {
                    return;
                };
                headers.truncate(at.saturating_sub(parent + 1) as usize);
                if headers.is_empty() {
                    return;
                }
                if let Err(e) = self.read_chain().check(&headers, now) {
                    self.mark_bad(i, e.to_string());
                    return;
                }
            }
            Err(e) => {
                self.mark_bad(i, e.to_string());
                return;
            }
        }
        if self.settings.network == Network::Signet {
            match self.signed_prefix(i, &headers).await {
                Some(n) => headers.truncate(n),
                None => return,
            }
            if headers.is_empty() {
                return;
            }
        }
        let result = self
            .chain
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .connect(&headers, now);
        match result {
            Ok(c) => {
                if c.new_best {
                    // A getblock refusal is reported until the next block.
                    self.clear_alarm("signet-unjudged-getblock");
                    let chain = self.read_chain();
                    let hold = *lock(&self.retarget_hold);
                    if hold.is_some_and(|at| chain.tip_height() >= at) {
                        *lock(&self.retarget_hold) = None;
                        self.clear_alarm("retarget-held");
                    }
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

    /// Source `i`'s headers from `from` back to the first one whose parent
    /// we know, oldest first: `Ok(None)` if they don't get there within
    /// [`MAX_WALK`], `Err` if the source failed or lied (then it is
    /// already marked bad).
    async fn headers_to_our_chain(
        &self,
        i: usize,
        from: BlockHash,
    ) -> Result<Option<Vec<Header>>, ()> {
        let mut headers = Vec::new();
        let mut cur = from;
        for _ in 0..MAX_WALK {
            let hdr = self
                .call(i, move |s| async move { s.header(cur).await })
                .await
                .map_err(|_| ())?;
            if hdr.block_hash() != cur {
                self.mark_bad(i, format!("served a header that doesn't hash to {cur}"));
                return Err(());
            }
            let parent = hdr.prev_blockhash;
            headers.push(hdr);
            if self.read_chain().contains(&parent) {
                headers.reverse();
                return Ok(Some(headers));
            }
            cur = parent;
        }
        Ok(None)
    }

    /// Walk back from the checkpoint by up to `max` headers (see
    /// [`HeaderChain::walk_back_next`]). Each header is fetched by its
    /// hash, through [`Node::call`] and so the sources' budgets, from the
    /// first usable source (rotating) that has it, and proven by hashing
    /// it: one honest source is enough, and a source serving a header with
    /// another hash is marked bad (the next one is asked). Genesis is
    /// known here and never fetched. If no source has the next header
    /// right now, the walk stops and picks up there next round.
    ///
    /// It runs a step at a time each round, after the tips are polled, so
    /// it never holds up following the chain. It costs at most 2015
    /// requests once per start, spread over the sources. Until it reaches
    /// the period's first header, the first retarget above the checkpoint
    /// waits (see [`Node::poll_tip`]).
    ///
    /// Only a network that retargets needs it, and of ours that's signet
    /// alone, which a build without the `signet-check` feature refuses to
    /// run on; so that build (the browser demo, on regtest) leaves it out
    /// and stays small.
    #[cfg(not(feature = "signet-check"))]
    async fn walk_back(&self, _max: usize) {}

    #[cfg(feature = "signet-check")]
    async fn walk_back(&self, max: usize) {
        let Some(_one_walk) = self.walk_lock.try_lock() else {
            return;
        };
        for _ in 0..max {
            let Some((height, hash)) = self.read_chain().walk_back_next() else {
                return;
            };
            let header = if height == 0 {
                bitcoin::constants::genesis_block(self.settings.network).header
            } else {
                let mut found = None;
                for i in self.rotated() {
                    match self
                        .call(i, move |s| async move { s.header(hash).await })
                        .await
                    {
                        Ok(h) if h.block_hash() == hash => {
                            found = Some(h);
                            break;
                        }
                        Ok(_) => self.mark_bad(
                            i,
                            format!(
                                "served a header that doesn't hash to {hash} (height {height}, below our checkpoint)"
                            ),
                        ),
                        Err(_) => {}
                    }
                }
                let Some(h) = found else {
                    return;
                };
                h
            };
            // Checked again under the lock: the chain may have been
            // replaced meanwhile (then nobody is at fault).
            let added = self
                .chain
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .add_walked(header);
            if let Err(why) = added {
                warn!(height, error = %why, "walk back from the checkpoint stopped");
                return;
            }
        }
    }

    /// On signet, a header is only as good as its block's signature
    /// (BIP325): proof of work there is cheap, and every signet shares one
    /// genesis block, so a source following another signet could otherwise
    /// feed us its chain. For each new header (oldest first) we fetch the
    /// block from the source that offered it, prove it matches the header
    /// and check its signature. The verified block goes into the block
    /// cache, so in steady state this costs no extra requests overall: LND
    /// and Core Lightning fetch every new block right after, and get it
    /// from there.
    ///
    /// Catching up is different: every new block is fetched before its
    /// header is followed, so a long catch-up costs about two requests per
    /// block (its header from each source that offers it, plus one download
    /// of the block, shared between sources). With a bootstrap checkpoint
    /// 6 blocks down, or after a short outage, that's a handful; a node
    /// that was off for a day re-reads about 144 blocks.
    ///
    /// Returns how many headers from the start are proven signed. A block
    /// the source can't supply right now stops the run there (we connect
    /// what's proven and try the rest next round), and so does a block
    /// whose signature we can't judge (see [`Node::fetch_block_from`]). A
    /// block that fails its checks is a provable lie: the source is marked
    /// bad and `None` is returned, so none of its headers are used this
    /// round.
    async fn signed_prefix(&self, i: usize, headers: &[Header]) -> Option<usize> {
        for (n, header) in headers.iter().enumerate() {
            let hash = header.block_hash();
            if self.read_chain().contains(&hash) {
                // Already checked: everything in the chain went through
                // `verify_block_for` on this network.
                continue;
            }
            match self.fetch_block_from(i, hash).await {
                Fetched::Verified(_) => {}
                Fetched::Missing => return Some(n),
                Fetched::Unjudged(why) => {
                    // The work this block's branch would have, to tell
                    // when our chain has gone past it: up to the best
                    // header we know on top of it (this source's tip,
                    // every header after it in this run), not just to it.
                    let chain = self.read_chain();
                    let base = chain.work_of(&headers[0].prev_blockhash);
                    if let Some(base) = base {
                        let work = headers.iter().fold(base, |w, h| w + h.work());
                        let mut blocked = lock(&self.blocked_unjudged);
                        if blocked.len() >= UNJUDGED_MAX {
                            blocked.clear();
                        }
                        // Another source (or round) may know a longer branch.
                        let work = blocked.get(&hash).map_or(work, |(w, _)| work.max(*w));
                        blocked.insert(hash, (work, why));
                    }
                    return Some(n);
                }
                Fetched::Lied => return None,
            }
        }
        Some(headers.len())
    }

    /// The warning about an unjudgeable block stays up while any block we
    /// refused that way could still be the best chain: until our tip has
    /// at least as much work as its branch would. A block refused again
    /// from the cache counts again (it was recorded again).
    fn refresh_unjudged_alarm(&self) {
        let tip_work = self.read_chain().tip_work();
        let mut blocked = lock(&self.blocked_unjudged);
        blocked.retain(|_, (work, _)| *work > tip_work);
        match blocked.values().next() {
            Some((_, why)) => {
                let why = why.clone();
                drop(blocked);
                self.set_alarm(
                    "signet-unjudged",
                    AlarmLevel::Warning,
                    format!(
                        "not following {why}; no source is blamed, since Bitcoin Core may accept it"
                    ),
                );
            }
            None => {
                drop(blocked);
                self.clear_alarm("signet-unjudged");
            }
        }
    }

    /// Hold back the retarget header at `at`, with a warning saying why.
    /// The warning is about our best chain only: once it is past `at`, a
    /// header someone offers there on another branch changes nothing.
    fn hold_retarget(&self, at: u32, why: String) {
        if self.read_chain().tip_height() >= at {
            return;
        }
        *lock(&self.retarget_hold) = Some(at);
        self.set_alarm(
            "retarget-held",
            AlarmLevel::Warning,
            format!("not following past height {at} yet: {why}; no source is blamed"),
        );
    }

    /// Get block `hash` from source `i` and prove it is that block (and, on
    /// signet, signed for our signet) before it goes into the cache.
    /// Usually one download per block runs at a time: sources are polled
    /// together and usually offer the same new block, so the others wait
    /// and then take it from the cache. They wait at most
    /// [`IN_FLIGHT_WAIT`]; then one of them downloads it from its own
    /// source, so a stalled explorer can't hold up a ready one. Only one
    /// such extra download runs per block: everyone else keeps waiting for
    /// whichever of the two finishes first (2026-11-17: 20 callers used to
    /// mean 20 downloads). Every download also needs one of its source's
    /// [`DOWNLOADS_PER_SOURCE`] turns. A body that fails is blamed on the
    /// source that served it, and the next caller asks its own source.
    ///
    /// A signet solution this checker doesn't model is refused but blamed on
    /// nobody (Core might accept it); the callers raise the warning. It's
    /// remembered so the block isn't downloaded again every round. That verdict belongs to the
    /// block, not the copy: the body is proven against the header first,
    /// and the solution is inside the coinbase the header commits to.
    async fn fetch_block_from(&self, i: usize, hash: BlockHash) -> Fetched {
        let entry = InFlightEntry::join(&self.in_flight, hash);
        // Wait our turn, but not for long. Giving up drops our place in the
        // queue (passing any wake-up on), so a stalled download holds up
        // nobody for more than IN_FLIGHT_WAIT.
        use futures::future::{Either, select};
        let slot = entry.slot();
        let _turn = if let Some(guard) = slot.first.try_lock() {
            guard
        } else if !crate::time::has_timer() {
            // No clock to bound the wait by (the demo, driven by hand,
            // where nothing stalls): wait.
            slot.first.lock().await
        } else {
            let turn = std::pin::pin!(slot.first.lock());
            let timer = std::pin::pin!(crate::time::sleep(IN_FLIGHT_WAIT));
            match select(turn, timer).await {
                Either::Left((guard, _)) => guard,
                // Someone else's download is taking too long: one caller
                // gets its own copy (checked and blamed the same way); the
                // rest wait for whichever download ends first.
                Either::Right((_, turn)) => match slot.extra.try_lock() {
                    Some(guard) => guard,
                    None => match select(turn, std::pin::pin!(slot.extra.lock())).await {
                        Either::Left((guard, _)) | Either::Right((guard, _)) => guard,
                    },
                },
            }
        };
        self.fetch_block_once(i, hash).await
        // `_turn`, then `entry`, are dropped here, in that order.
    }

    /// One of source `i`'s [`DOWNLOADS_PER_SOURCE`] download turns, waiting
    /// for one to come free.
    async fn download_turn(&self, i: usize) -> futures::lock::MutexGuard<'_, ()> {
        use futures::future::{Either, select};
        let [a, b] = &self.sources[i].downloads;
        if let Some(guard) = a.try_lock().or_else(|| b.try_lock()) {
            return guard;
        }
        match select(std::pin::pin!(a.lock()), std::pin::pin!(b.lock())).await {
            Either::Left((guard, _)) | Either::Right((guard, _)) => guard,
        }
    }

    /// How many block hashes have a download slot right now. For tests:
    /// it must fall back to zero once no download is running.
    #[doc(hidden)]
    pub fn in_flight_len(&self) -> usize {
        lock(&self.in_flight).len()
    }

    async fn fetch_block_once(&self, i: usize, hash: BlockHash) -> Fetched {
        // Whoever held the slot before us may have settled it.
        if let Some(raw) = lock(&self.blocks).get(&hash) {
            return Fetched::Verified(raw);
        }
        if let Some(why) = lock(&self.unjudged).get(&hash) {
            return Fetched::Unjudged(why.clone());
        }
        let _download = self.download_turn(i).await;
        // The other download of this block may have settled it meanwhile.
        if let Some(raw) = lock(&self.blocks).get(&hash) {
            return Fetched::Verified(raw);
        }
        let Ok(raw) = self
            .call(i, move |s| async move { s.raw_block(hash).await })
            .await
        else {
            return Fetched::Missing;
        };
        match verify_block_for(self.settings.network, &raw, hash) {
            Ok(_) => {
                let raw = Arc::new(raw);
                lock(&self.blocks).insert(hash, raw.clone());
                Fetched::Verified(raw)
            }
            Err(e) if e.proves_a_lie() => {
                self.mark_bad(i, format!("served block {hash} that fails checks: {e}"));
                Fetched::Lied
            }
            Err(e) => {
                let why = format!("block {hash}: {e}");
                warn!(%hash, error = %e, "refusing a block we can't judge; no source blamed");
                let mut unjudged = lock(&self.unjudged);
                if unjudged.len() >= UNJUDGED_MAX {
                    unjudged.clear();
                }
                unjudged.insert(hash, why.clone());
                Fetched::Unjudged(why)
            }
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
    /// are proven against that header (hash, merkle root, witness commitment)
    /// and, on signet, its signature is checked: for old blocks that's the
    /// only signature check they get (see [`Node::deep_hash_at`]).
    pub async fn get_block(&self, hash: BlockHash) -> Result<Arc<Vec<u8>>, RpcError> {
        if !self.read_chain().contains(&hash) && self.deep_header(&hash).is_none() {
            return Err(RpcError::new(RPC_NOT_FOUND, "Block not found"));
        }
        if let Some(raw) = lock(&self.blocks).get(&hash) {
            return Ok(raw);
        }
        for i in self.rotated() {
            match self.fetch_block_from(i, hash).await {
                Fetched::Verified(raw) => return Ok(raw),
                Fetched::Unjudged(why) => {
                    self.set_alarm(
                        "signet-unjudged-getblock",
                        AlarmLevel::Warning,
                        format!("refused to serve {why} (shown until the next new block); no source is blamed, since Bitcoin Core may accept it"),
                    );
                    return Err(RpcError::new(
                        RPC_MISC_ERROR,
                        format!("Block refused (no source blamed): {why}"),
                    ));
                }
                Fetched::Missing | Fetched::Lied => continue,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::verify_block_for;

    fn settings(network: Network) -> Settings {
        Settings {
            network,
            checkpoint: Some((0, bitcoin::constants::genesis_block(network).block_hash())),
            fee_ceiling_sat_vb: 1000.0,
            requests_per_sec: 2.0,
            burst: 10.0,
            jitter: || 0.0,
        }
    }

    fn genesis_raw(network: Network) -> (Vec<u8>, BlockHash) {
        let g = bitcoin::constants::genesis_block(network);
        (serialize(&g), g.block_hash())
    }

    /// The browser build (`--no-default-features`) has no signet checker:
    /// every signet block is refused and a node won't start on signet.
    /// Regtest, which the demo uses, is unaffected.
    #[cfg(not(feature = "signet-check"))]
    #[test]
    fn without_the_signet_check_feature_signet_is_refused() {
        use crate::proof::ProofError;
        use crate::signet::SignetError;

        let (raw, hash) = genesis_raw(Network::Signet);
        assert_eq!(
            verify_block_for(Network::Signet, &raw, hash).unwrap_err(),
            ProofError::BadSignetSignature(SignetError::NotBuilt)
        );
        let node = Node::new(
            settings(Network::Signet),
            Vec::new(),
            Arc::new(ManualClock::new(0)),
        );
        let err = futures::executor::block_on(node.start()).unwrap_err();
        assert!(err.contains("signet-check"), "{err}");
        futures::executor::block_on(node.tick());
        assert!(!node.is_ready());
        assert_eq!(
            node.alarms()["signet-check-missing"].level,
            AlarmLevel::Critical
        );

        let (raw, hash) = genesis_raw(Network::Regtest);
        assert!(verify_block_for(Network::Regtest, &raw, hash).is_ok());
        let node = Node::new(
            settings(Network::Regtest),
            Vec::new(),
            Arc::new(ManualClock::new(0)),
        );
        futures::executor::block_on(node.start()).expect("regtest starts");
        assert!(node.is_ready());
    }

    /// The counterpart: with the checker built in (the real program),
    /// signet starts and its genesis block passes.
    #[cfg(feature = "signet-check")]
    #[tokio::test]
    async fn with_the_signet_check_feature_signet_runs() {
        let (raw, hash) = genesis_raw(Network::Signet);
        assert!(verify_block_for(Network::Signet, &raw, hash).is_ok());
        let node = Node::new(
            settings(Network::Signet),
            Vec::new(),
            Arc::new(ManualClock::new(0)),
        );
        node.start().await.expect("signet starts");
        assert!(node.is_ready());
        assert!(!node.alarms().contains_key("signet-check-missing"));
    }
}
