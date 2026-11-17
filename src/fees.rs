//! Fee estimates can't be proven, only compared. Normal sends use the median
//! across sources; time-critical ones (6 blocks or sooner, which is what
//! force-closes and justice transactions ask for) use the highest.

use crate::source::FeeMap;

/// The relay floor: 1 sat/vB.
pub const FLOOR_SAT_VB: f64 = 1.0;
/// Targets at or below this count as time-critical.
pub const URGENT_TARGET: u16 = 6;
/// Sources further apart than this (highest / lowest) raise an alarm.
pub const DISAGREEMENT_RATIO: f64 = 2.0;

/// One source's estimate for `target`: the entry for the largest target that
/// is not slower than asked for, or its fastest entry if all are slower.
pub fn pick(map: &FeeMap, target: u16) -> Option<f64> {
    map.range(..=target)
        .next_back()
        .or_else(|| map.iter().next())
        .map(|(_, v)| *v)
}

/// Combine sources' estimates for `target` into one sat/vB figure.
pub fn aggregate(values: &[f64], target: u16, ceiling: f64) -> Option<f64> {
    let mut v: Vec<f64> = values
        .iter()
        .copied()
        .filter(|x| x.is_finite() && *x > 0.0)
        .collect();
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.total_cmp(b));
    let chosen = if target <= URGENT_TARGET {
        v[v.len() - 1]
    } else {
        // The upper middle for an even count: when unsure, pay a little more.
        v[v.len() / 2]
    };
    Some(chosen.clamp(FLOOR_SAT_VB, ceiling.max(FLOOR_SAT_VB)))
}

/// True when the sources' estimates are too far apart to trust quietly.
pub fn disagree(values: &[f64]) -> bool {
    let v: Vec<f64> = values
        .iter()
        .copied()
        .filter(|x| x.is_finite() && *x > 0.0)
        .collect();
    let (Some(min), Some(max)) = (
        v.iter().copied().reduce(f64::min),
        v.iter().copied().reduce(f64::max),
    ) else {
        return false;
    };
    max / min > DISAGREEMENT_RATIO
}

/// sat/vB to bitcoind's BTC per kvB, rounded to whole satoshis per kvB.
pub fn sat_vb_to_btc_kvb(sat_vb: f64) -> f64 {
    (sat_vb * 1000.0).round() / 1e8
}
