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
use bitcoin::{BlockHash, Network};

/// Headers may be at most two hours ahead of our clock (Bitcoin's own rule).
pub const MAX_FUTURE_SECS: u64 = 2 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    UnknownParent(BlockHash),
    BadLink { height: u32 },
    BadPow { hash: BlockHash },
    TargetAboveLimit { hash: BlockHash },
    BadDifficulty { hash: BlockHash, height: u32 },
    TimeTooNew { hash: BlockHash },
    TimeTooOld { hash: BlockHash },
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainError::UnknownParent(h) => write!(f, "header's parent {h} is not in our chain"),
            ChainError::BadLink { height } => write!(f, "headers don't link at height {height}"),
            ChainError::BadPow { hash } => write!(f, "header {hash} fails its proof of work"),
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
}

impl HeaderChain {
    /// Start from a trusted checkpoint header at a known height.
    pub fn new(network: Network, base_height: u32, base_header: Header) -> Self {
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
        Self {
            params: Params::new(network),
            network,
            base_height,
            base_hash,
            entries,
            best: vec![base_hash],
            old_best: Vec::new(),
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
    /// network's genesis block; other heights below the checkpoint are unknown.
    pub fn hash_at(&self, height: u32) -> Option<BlockHash> {
        if height == 0 {
            return Some(bitcoin::constants::genesis_block(self.network).block_hash());
        }
        if height < self.base_height {
            return None;
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
            let target = h.target();
            if target > self.params.max_attainable_target {
                return Err(ChainError::TargetAboveLimit { hash });
            }
            h.validate_pow(target)
                .map_err(|_| ChainError::BadPow { hash })?;
            self.check_difficulty(&prev, h, height)?;
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
            let parent = cur.header.prev_blockhash;
            cur = match batch.iter().rev().find(|(h, _)| *h == parent) {
                Some((_, e)) => e.clone(),
                None => self.entries.get(&parent)?.clone(),
            };
        }
        times.sort_unstable();
        Some(times[times.len() / 2])
    }

    fn check_difficulty(&self, prev: &Entry, h: &Header, height: u32) -> Result<(), ChainError> {
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
        // A retarget boundary: the new target may move at most 4x either way.
        let prev_t = prev.header.target();
        let new_t = h.target();
        if new_t < prev_t.min_transition_threshold()
            || new_t > prev_t.max_transition_threshold(&self.params)
        {
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
