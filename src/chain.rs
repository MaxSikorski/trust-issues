//! The header chain: every header we serve is checked here first.
//!
//! We start from a checkpoint (a block hash we trust) and only ever accept
//! headers that link back to it, meet their own proof-of-work target, follow
//! the difficulty rules, aren't too far in the future and are later than
//! the median time of the 11 blocks before them. When two branches
//! exist we follow the one with the most work, no matter how many sources
//! vote for the other.

use std::collections::HashMap;
use std::fmt;

use bitcoin::block::Header;
use bitcoin::params::Params;
use bitcoin::pow::Work;
use bitcoin::{BlockHash, CompactTarget, Network, Target};

/// Headers may be at most two hours ahead of our clock (Bitcoin's own rule).
pub const MAX_FUTURE_SECS: u64 = 2 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    UnknownParent(BlockHash),
    BadLink {
        height: u32,
    },
    BadPow {
        hash: BlockHash,
    },
    /// `bits` that Bitcoin Core's `SetCompact` calls negative, zero or
    /// overflowing: no header with them is valid.
    BadBits {
        hash: BlockHash,
    },
    TargetAboveLimit {
        hash: BlockHash,
    },
    BadDifficulty {
        hash: BlockHash,
        height: u32,
    },
    /// The retarget at height `at` needs the header at `height` (its
    /// period's first), which is below our checkpoint and not known yet.
    /// Nobody is at fault: the walk back from the checkpoint hasn't
    /// reached it yet (see [`HeaderChain::walk_back_next`]).
    NeedPeriodStart {
        height: u32,
        at: u32,
    },
    TimeTooNew {
        hash: BlockHash,
    },
    TimeTooOld {
        hash: BlockHash,
    },
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainError::UnknownParent(h) => write!(f, "header's parent {h} is not in our chain"),
            ChainError::BadLink { height } => write!(f, "headers don't link at height {height}"),
            ChainError::BadPow { hash } => write!(f, "header {hash} fails its proof of work"),
            ChainError::BadBits { hash } => write!(
                f,
                "header {hash} has bits that don't decode to a valid target (negative, zero or overflowing)"
            ),
            ChainError::NeedPeriodStart { height, at } => write!(
                f,
                "the retarget at height {at} needs the header at height {height}, below our checkpoint, and the walk back to it isn't finished"
            ),
            ChainError::TargetAboveLimit { hash } => {
                write!(
                    f,
                    "header {hash} claims a target easier than the network allows"
                )
            }
            ChainError::BadDifficulty { hash, height } => {
                write!(
                    f,
                    "header {hash} at height {height} breaks the difficulty rules"
                )
            }
            ChainError::TimeTooNew { hash } => {
                write!(f, "header {hash} is more than two hours in the future")
            }
            ChainError::TimeTooOld { hash } => {
                write!(
                    f,
                    "header {hash} isn't later than the median time of the 11 blocks before it"
                )
            }
        }
    }
}

impl std::error::Error for ChainError {}

#[derive(Debug, Clone)]
struct Entry {
    header: Header,
    height: u32,
    work: Work,
}

/// What happened when headers were connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Connected {
    /// The best chain changed to a new tip.
    pub new_best: bool,
    /// How many blocks of the old best chain were replaced (0 = simple extension).
    pub reorg_depth: u32,
}

pub struct HeaderChain {
    params: Params,
    network: Network,
    base_height: u32,
    base_hash: BlockHash,
    entries: HashMap<BlockHash, Entry>,
    /// `best[i]` is the hash at height `base_height + i`.
    best: Vec<BlockHash>,
    /// The best chain before the last switch, to measure reorg depth.
    old_best: Vec<BlockHash>,
    /// Headers below the checkpoint, proven by hash: `walked[0]` is the
    /// checkpoint's parent, each next one the parent of the one before
    /// (see [`HeaderChain::walk_back_next`]). At most `base_height -
    /// walk_stop` of them (2015 on signet), 80 bytes each.
    walked: Vec<Header>,
    /// The lowest height the walk back goes to.
    walk_stop: u32,
}

/// How many headers below the checkpoint the median-time-past rule needs.
const MTP_BELOW: u32 = 10;

impl HeaderChain {
    /// Start from a trusted checkpoint header at a known height.
    pub fn new(network: Network, base_height: u32, base_header: Header) -> Self {
        Self::with_params(Params::new(network), base_height, base_header)
    }

    /// [`HeaderChain::new`] with the network's consensus parameters
    /// changed. For tests only: real signet retargets every 2016 blocks at
    /// a target far too hard to mine in a test, so the difficulty tests use
    /// a short interval and an easy limit to reach a retarget boundary.
    #[doc(hidden)]
    pub fn with_params(params: Params, base_height: u32, base_header: Header) -> Self {
        let network = params.network;
        let base_hash = base_header.block_hash();
        let mut entries = HashMap::new();
        entries.insert(
            base_hash,
            Entry {
                header: base_header,
                height: base_height,
                work: base_header.work(),
            },
        );
        // A network that retargets needs the first header of the
        // checkpoint's period (for the first retarget above it) and the 10
        // before the checkpoint (for the median-time-past rule). Regtest
        // never retargets, and needs neither walked.
        let walk_stop = if params.no_pow_retargeting {
            base_height
        } else {
            let interval = params.difficulty_adjustment_interval() as u32;
            let period_start = base_height - base_height % interval;
            period_start.min(base_height.saturating_sub(MTP_BELOW))
        };
        Self {
            params,
            network,
            base_height,
            base_hash,
            entries,
            best: vec![base_hash],
            old_best: Vec::new(),
            walked: Vec::new(),
            walk_stop,
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn base_height(&self) -> u32 {
        self.base_height
    }

    pub fn tip_height(&self) -> u32 {
        self.base_height + (self.best.len() as u32 - 1)
    }

    pub fn tip_hash(&self) -> BlockHash {
        *self
            .best
            .last()
            .expect("best chain always holds the checkpoint")
    }

    pub fn tip_header(&self) -> Header {
        self.entries[&self.tip_hash()].header
    }

    pub fn tip_work(&self) -> Work {
        self.entries[&self.tip_hash()].work
    }

    pub fn contains(&self, hash: &BlockHash) -> bool {
        self.entries.contains_key(hash)
    }

    pub fn header(&self, hash: &BlockHash) -> Option<Header> {
        self.entries.get(hash).map(|e| e.header)
    }

    /// Height of any known header, on the best chain or a side branch.
    pub fn height_of(&self, hash: &BlockHash) -> Option<u32> {
        self.entries.get(hash).map(|e| e.height)
    }

    pub fn work_of(&self, hash: &BlockHash) -> Option<Work> {
        self.entries.get(hash).map(|e| e.work)
    }

    pub fn is_best(&self, hash: &BlockHash) -> bool {
        self.height_of(hash)
            .and_then(|h| self.hash_at(h))
            .is_some_and(|best| best == *hash)
    }

    /// Hash on the best chain at `height`. Height 0 always answers the
    /// network's genesis block; other heights below the checkpoint are
    /// known only as far as the walk back has proven them.
    pub fn hash_at(&self, height: u32) -> Option<BlockHash> {
        if height == 0 {
            return Some(bitcoin::constants::genesis_block(self.network).block_hash());
        }
        if height < self.base_height {
            return self.walked_hash_at(height);
        }
        self.best.get((height - self.base_height) as usize).copied()
    }

    /// Confirmations of a best-chain block (1 = the tip), or None if not on the best chain.
    pub fn confirmations(&self, hash: &BlockHash) -> Option<u32> {
        if !self.is_best(hash) {
            return None;
        }
        self.height_of(hash).map(|h| self.tip_height() - h + 1)
    }

    /// The next block on the best chain after `hash`, if any.
    pub fn next_on_best(&self, hash: &BlockHash) -> Option<BlockHash> {
        if !self.is_best(hash) {
            return None;
        }
        self.height_of(hash).and_then(|h| self.hash_at(h + 1))
    }

    /// Median time of the last 11 headers ending at `hash` (as far back as we know).
    pub fn median_time_past(&self, hash: &BlockHash) -> u32 {
        let mut times = Vec::with_capacity(11);
        let mut cur = *hash;
        while times.len() < 11 {
            let Some(e) = self.entries.get(&cur) else {
                break;
            };
            times.push(e.header.time);
            cur = e.header.prev_blockhash;
        }
        times.sort_unstable();
        times.get(times.len() / 2).copied().unwrap_or(0)
    }

    /// The next header the walk back from the checkpoint needs, as its
    /// height and the hash it must have, or `None` once the walk is done.
    ///
    /// The first retarget above a checkpoint needs its period's first
    /// header, which can be up to 2015 blocks below the checkpoint, and the
    /// median-time-past rule needs the 10 before the checkpoint. Nobody's
    /// word is taken for them: each header names its parent's hash, so
    /// starting from the checkpoint (which we trust) every header below it
    /// is proven by hashing it. Any single source will do, and one that
    /// serves a header with another hash is caught lying.
    pub fn walk_back_next(&self) -> Option<(u32, BlockHash)> {
        if self.walked.len() as u32 >= self.base_height - self.walk_stop {
            return None;
        }
        let height = self.base_height - 1 - self.walked.len() as u32;
        let child = self
            .walked
            .last()
            .unwrap_or(&self.entries[&self.base_hash].header);
        Some((height, child.prev_blockhash))
    }

    /// Whether the walk back from the checkpoint is done.
    pub fn walk_back_done(&self) -> bool {
        self.walk_back_next().is_none()
    }

    /// Add the header [`HeaderChain::walk_back_next`] asked for. Refused
    /// (and nothing changes) unless it hashes to exactly that.
    pub fn add_walked(&mut self, header: Header) -> Result<(), String> {
        let Some((height, hash)) = self.walk_back_next() else {
            return Err("the walk back from the checkpoint is already done".into());
        };
        if header.block_hash() != hash {
            return Err(format!(
                "the header given for height {height} doesn't hash to {hash}"
            ));
        }
        self.walked.push(header);
        Ok(())
    }

    /// A header the walk back proved, by hash, with its height.
    pub fn walked_header(&self, hash: &BlockHash) -> Option<(u32, Header)> {
        let mut want = self.entries[&self.base_hash].header.prev_blockhash;
        for (i, h) in self.walked.iter().enumerate() {
            if want == *hash {
                return Some((self.base_height - 1 - i as u32, *h));
            }
            want = h.prev_blockhash;
        }
        None
    }

    /// The hash of the walked header at `height`, if the walk got there.
    pub fn walked_hash_at(&self, height: u32) -> Option<BlockHash> {
        let i = self.base_height.checked_sub(height + 1)? as usize;
        if i >= self.walked.len() {
            return None;
        }
        Some(match i {
            0 => self.entries[&self.base_hash].header.prev_blockhash,
            _ => self.walked[i - 1].prev_blockhash,
        })
    }

    /// How many headers below the checkpoint the walk has proven.
    pub fn walked_len(&self) -> usize {
        self.walked.len()
    }

    /// Check a run of headers (oldest first) whose first header's parent we
    /// already know, add them, and switch to them if they carry more work.
    /// Nothing is added unless every header passes.
    pub fn connect(&mut self, headers: &[Header], now: u64) -> Result<Connected, ChainError> {
        let checked = self.check_run(headers, now)?;
        let Some((tip_hash, tip)) = checked.last().cloned() else {
            return Ok(Connected::default());
        };
        for (hash, entry) in checked {
            self.entries.entry(hash).or_insert(entry);
        }

        if tip.work > self.tip_work() && !self.is_best(&tip_hash) {
            let old_tip = self.tip_height();
            self.rebuild_best(tip_hash);
            let fork_height = self.fork_height_with_old(old_tip);
            return Ok(Connected {
                new_best: true,
                reorg_depth: old_tip.saturating_sub(fork_height),
            });
        }
        Ok(Connected::default())
    }

    /// Every check [`HeaderChain::connect`] makes, without adding anything.
    /// Lets the node refuse bad headers before it spends requests fetching
    /// their blocks (for signet signatures).
    pub fn check(&self, headers: &[Header], now: u64) -> Result<(), ChainError> {
        self.check_run(headers, now).map(|_| ())
    }

    fn check_run(
        &self,
        headers: &[Header],
        now: u64,
    ) -> Result<Vec<(BlockHash, Entry)>, ChainError> {
        let Some(first) = headers.first() else {
            return Ok(Vec::new());
        };
        let mut prev = self
            .entries
            .get(&first.prev_blockhash)
            .cloned()
            .ok_or(ChainError::UnknownParent(first.prev_blockhash))?;

        let mut checked: Vec<(BlockHash, Entry)> = Vec::with_capacity(headers.len());
        for h in headers {
            let height = prev.height + 1;
            if h.prev_blockhash != prev.header.block_hash() {
                return Err(ChainError::BadLink { height });
            }
            let hash = h.block_hash();
            let target = decode_compact(h.bits).ok_or(ChainError::BadBits { hash })?;
            if target > self.params.max_attainable_target {
                return Err(ChainError::TargetAboveLimit { hash });
            }
            // The difficulty before the proof of work: both are cheap, and
            // this way a header with the wrong bits is refused for that.
            self.check_difficulty(&prev, h, height, &checked)?;
            h.validate_pow(target)
                .map_err(|_| ChainError::BadPow { hash })?;
            if u64::from(h.time) > now + MAX_FUTURE_SECS {
                return Err(ChainError::TimeTooNew { hash });
            }
            if let Some(mtp) = self.full_median_time_past(&prev, &checked)
                && h.time <= mtp
            {
                return Err(ChainError::TimeTooOld { hash });
            }
            let entry = Entry {
                header: *h,
                height,
                work: prev.work + h.work(),
            };
            checked.push((hash, entry.clone()));
            prev = entry;
        }
        Ok(checked)
    }

    /// Bitcoin's median-time-past rule needs the times of the 11 blocks
    /// ending at `prev` (fewer only near genesis, where Core uses what
    /// exists). Just above a checkpoint we don't know 11 of them, and the
    /// median of a shorter, more recent run can be later than the real one,
    /// so applying the rule there could refuse an honest header. We skip it
    /// until we know enough; proof of work and the links still apply.
    fn full_median_time_past(&self, prev: &Entry, batch: &[(BlockHash, Entry)]) -> Option<u32> {
        let mut times = Vec::with_capacity(11);
        let mut cur = prev.clone();
        loop {
            times.push(cur.header.time);
            if times.len() == 11 || cur.height == 0 {
                break;
            }
            cur = self.parent_of(&cur, batch)?;
        }
        times.sort_unstable();
        Some(times[times.len() / 2])
    }

    /// The parent of `e`, from the batch being checked, from what we
    /// already know, or (below the checkpoint) from the walk back; `None`
    /// below what the walk has reached.
    fn parent_of(&self, e: &Entry, batch: &[(BlockHash, Entry)]) -> Option<Entry> {
        let parent = e.header.prev_blockhash;
        if let Some((_, p)) = batch.iter().rev().find(|(h, _)| *h == parent) {
            return Some(p.clone());
        }
        if let Some(p) = self.entries.get(&parent) {
            return Some(p.clone());
        }
        // Below the checkpoint: the walked header one lower, if it's this
        // parent. Its work is never used (only its time, bits and height).
        let height = e.height.checked_sub(1)?;
        if self.walked_hash_at(height) != Some(parent) {
            return None;
        }
        let i = (self.base_height - 1 - height) as usize;
        Some(Entry {
            header: self.walked[i],
            height,
            work: Work::from_be_bytes([0; 32]),
        })
    }

    /// Bitcoin Core's difficulty rule for this network (signet has no
    /// minimum-difficulty exception; regtest never retargets): between
    /// retarget boundaries `bits` can't change at all, and at a boundary it
    /// must be exactly what `CalculateNextWorkRequired` gives from the
    /// period's first and last headers.
    ///
    /// Just above a checkpoint the period's first header can be below it.
    /// Then it comes from the walk back from the checkpoint (proven by
    /// hash); until the walk gets there, the retarget header isn't accepted
    /// ([`ChainError::NeedPeriodStart`]). A looser range (Core's
    /// `PermittedDifficultyTransition`) would let a slightly harder target
    /// through, so there is no fallback.
    fn check_difficulty(
        &self,
        prev: &Entry,
        h: &Header,
        height: u32,
        batch: &[(BlockHash, Entry)],
    ) -> Result<(), ChainError> {
        let interval = self.params.difficulty_adjustment_interval() as u32;
        let bad = || ChainError::BadDifficulty {
            hash: h.block_hash(),
            height,
        };
        if self.params.no_pow_retargeting || !height.is_multiple_of(interval) {
            if h.bits != prev.header.bits {
                return Err(bad());
            }
            return Ok(());
        }
        // Core's `pindexFirst`: the block `interval - 1` before `prev`.
        let mut first = prev.clone();
        for _ in 1..interval {
            match self.parent_of(&first, batch) {
                Some(p) => first = p,
                None => {
                    return Err(ChainError::NeedPeriodStart {
                        height: height - interval,
                        at: height,
                    });
                }
            }
        }
        let expected = next_work_required(
            prev.header.bits,
            first.header.time,
            prev.header.time,
            &self.params,
        );
        if h.bits != expected {
            return Err(bad());
        }
        Ok(())
    }

    fn rebuild_best(&mut self, tip: BlockHash) {
        let mut chain = Vec::new();
        let mut cur = tip;
        loop {
            chain.push(cur);
            if cur == self.base_hash {
                break;
            }
            cur = self.entries[&cur].header.prev_blockhash;
        }
        chain.reverse();
        self.old_best = std::mem::replace(&mut self.best, chain);
    }

    fn fork_height_with_old(&self, old_tip: u32) -> u32 {
        let mut h = old_tip.min(self.tip_height());
        while h > self.base_height {
            let i = (h - self.base_height) as usize;
            if self.old_best.get(i) == self.best.get(i) {
                return h;
            }
            h -= 1;
        }
        self.base_height
    }
}

/// Bitcoin Core's `CalculateNextWorkRequired` (src/pow.cpp): the `bits` a
/// retarget block must carry, given the previous block's `bits` and the
/// times of the period's first and last blocks. The time taken is clamped
/// to a quarter and four times the target timespan, the old target is
/// scaled by it, capped at the network's limit, then rounded down into the
/// compact form exactly as Core's `GetCompact` does.
pub fn next_work_required(
    prev_bits: CompactTarget,
    first_time: u32,
    last_time: u32,
    params: &Params,
) -> CompactTarget {
    let timespan = params.pow_target_timespan as i64;
    let actual = (i64::from(last_time) - i64::from(first_time)).clamp(timespan / 4, timespan * 4);
    retarget(prev_bits, actual as u64, params)
}

/// Bitcoin Core's `SetCompact`: the target `bits` encode, or `None` when
/// Core reports it negative or overflowing, or it is zero. Bitcoin Core
/// refuses every such header (`DeriveTarget`). rust-bitcoin's
/// `Target::from_compact` wraps an overflowing shift instead (0x3d14fcee
/// decodes to 0x1d14fcee's target), so every consensus decode goes
/// through here.
pub fn decode_compact(bits: CompactTarget) -> Option<Target> {
    let c = bits.to_consensus();
    let size = c >> 24;
    let mut word = c & 0x007f_ffff;
    if size <= 3 {
        word >>= 8 * (3 - size);
    }
    let negative = word != 0 && c & 0x0080_0000 != 0;
    let overflow =
        word != 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32));
    if negative || overflow || word == 0 {
        return None;
    }
    // Neither negative nor overflowing: rust-bitcoin decodes it exactly.
    Some(Target::from_compact(bits))
}

/// Bitcoin Core's `DeriveTarget`: [`decode_compact`], and no easier than
/// the network allows.
pub fn derive_target(bits: CompactTarget, params: &Params) -> Option<Target> {
    decode_compact(bits).filter(|t| *t <= params.max_attainable_target)
}

/// `bnNew = old target * actual / timespan`, capped at the limit, as compact.
fn retarget(prev_bits: CompactTarget, actual: u64, params: &Params) -> CompactTarget {
    let prev = Target::from_compact(prev_bits).to_be_bytes();
    let scaled = mul_div(prev, actual, params.pow_target_timespan)
        .map(Target::from_be_bytes)
        .unwrap_or(params.max_attainable_target);
    scaled.min(params.max_attainable_target).to_compact_lossy()
}

/// `n * mul / div` for a 256-bit big-endian `n`, exactly (a 320-bit
/// intermediate, so nothing wraps). `None` if the result needs more than
/// 256 bits; the caller caps it at the network's limit anyway.
fn mul_div(n: [u8; 32], mul: u64, div: u64) -> Option<[u8; 32]> {
    // Little-endian 64-bit limbs.
    let mut limbs = [0u64; 5];
    for (i, limb) in limbs.iter_mut().take(4).enumerate() {
        let start = 32 - 8 * (i + 1);
        *limb = u64::from_be_bytes(n[start..start + 8].try_into().expect("8 bytes"));
    }
    let mut carry: u128 = 0;
    for limb in limbs.iter_mut() {
        let v = u128::from(*limb) * u128::from(mul) + carry;
        *limb = v as u64;
        carry = v >> 64;
    }
    let mut rem: u128 = 0;
    for limb in limbs.iter_mut().rev() {
        let v = (rem << 64) | u128::from(*limb);
        *limb = (v / u128::from(div)) as u64;
        rem = v % u128::from(div);
    }
    if limbs[4] != 0 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, limb) in limbs.iter().take(4).enumerate() {
        let start = 32 - 8 * (i + 1);
        out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
    }
    Some(out)
}
