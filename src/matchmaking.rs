//! Ranked pairing: rating window (Elo) and ping window, both widening with
//! the time spent in the queue. Pure and deterministic so it is easy to test.
//!
//! Latency between two players is estimated before they ever talk: the
//! measured average for their pair of regions (fed by match reports), else
//! [`SAME_REGION_MS`] when they share a region, [`NO_REGION_MS`] when a
//! region is unknown, else [`UNKNOWN_MS`].

use crate::elo;

pub const SAME_REGION_MS: u32 = 30;
pub const UNKNOWN_MS: u32 = 150;
/// Estimate when a region is missing: no information, so it fits the first window.
pub const NO_REGION_MS: u32 = 60;

#[derive(Clone, Debug)]
pub struct Candidate {
    pub id: u64,
    pub rating: i32,
    pub region: String,
    pub waited_secs: u64,
    /// "Accept only good connections": hard ping cap that never widens.
    pub max_ping: Option<u32>,
}

/// Acceptable estimated round trip after waiting `secs`: 60 ms, 120 ms after
/// 10 s, 200 ms after 20 s, anything after 30 s.
pub fn ping_window(secs: u64) -> u32 {
    match secs {
        0..10 => 60,
        10..20 => 120,
        20..30 => 200,
        _ => u32::MAX,
    }
}

/// Estimated round trip from a measured region-pair average.
pub fn estimate(a: &str, b: &str, measured: Option<u32>) -> u32 {
    match measured {
        Some(ms) => ms,
        None if a.is_empty() || b.is_empty() => NO_REGION_MS,
        None if a == b => SAME_REGION_MS,
        None => UNKNOWN_MS,
    }
}

/// Pairs to start, as indices into `queue` (oldest first). Each player is
/// matched with the acceptable partner of lowest estimated ping, then
/// smallest rating gap, then longest wait.
pub fn pairs(
    queue: &[Candidate],
    est: impl Fn(&Candidate, &Candidate) -> u32,
) -> Vec<(usize, usize)> {
    let mut taken = vec![false; queue.len()];
    let mut out = Vec::new();
    for i in 0..queue.len() {
        if taken[i] {
            continue;
        }
        let a = &queue[i];
        let mut best: Option<(u32, i32, usize)> = None;
        for (j, b) in queue.iter().enumerate() {
            if j == i || taken[j] {
                continue;
            }
            let gap = (a.rating - b.rating).abs();
            let rating_ok = gap <= elo::window(a.waited_secs).max(elo::window(b.waited_secs));
            let ping = est(a, b);
            let window = ping_window(a.waited_secs).max(ping_window(b.waited_secs));
            let cap = a
                .max_ping
                .unwrap_or(u32::MAX)
                .min(b.max_ping.unwrap_or(u32::MAX));
            if !rating_ok || ping > window || ping > cap {
                continue;
            }
            let key = (ping, gap, j);
            if best.is_none_or(|b| key < b) {
                best = Some(key);
            }
        }
        if let Some((_, _, j)) = best {
            taken[i] = true;
            taken[j] = true;
            out.push((i, j));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(id: u64, rating: i32, region: &str, waited: u64) -> Candidate {
        Candidate {
            id,
            rating,
            region: region.into(),
            waited_secs: waited,
            max_ping: None,
        }
    }

    fn est(a: &Candidate, b: &Candidate) -> u32 {
        let measured = match (a.region.as_str(), b.region.as_str()) {
            ("FR", "US") | ("US", "FR") => Some(110),
            _ => None,
        };
        estimate(&a.region, &b.region, measured)
    }

    #[test]
    fn window_widens_over_time() {
        assert_eq!(ping_window(0), 60);
        assert_eq!(ping_window(12), 120);
        assert_eq!(ping_window(25), 200);
        assert_eq!(ping_window(31), u32::MAX);
    }

    #[test]
    fn prefers_the_closest_player() {
        let q = [
            c(1, 1200, "FR", 0),
            c(2, 1200, "US", 0),
            c(3, 1250, "FR", 0),
        ];
        assert_eq!(pairs(&q, est), vec![(0, 2)]);
    }

    #[test]
    fn far_players_wait_until_the_window_allows() {
        let q = [c(1, 1200, "FR", 0), c(2, 1200, "US", 0)];
        assert!(pairs(&q, est).is_empty());
        let q = [c(1, 1200, "FR", 11), c(2, 1200, "US", 0)];
        assert_eq!(pairs(&q, est), vec![(0, 1)]);
        // unmeasured region pair: 150 ms estimate, accepted after 20 s
        let q = [c(1, 1200, "DE", 15), c(2, 1200, "JP", 0)];
        assert!(pairs(&q, est).is_empty());
        let q = [c(1, 1200, "DE", 21), c(2, 1200, "JP", 0)];
        assert_eq!(pairs(&q, est), vec![(0, 1)]);
    }

    #[test]
    fn good_connections_only_never_widens() {
        let mut a = c(1, 1200, "FR", 600);
        a.max_ping = Some(80);
        let q = [a, c(2, 1200, "US", 600)];
        assert!(pairs(&q, est).is_empty());
    }

    #[test]
    fn rating_window_still_applies() {
        let q = [c(1, 1000, "FR", 0), c(2, 1500, "FR", 0)];
        assert!(pairs(&q, est).is_empty());
        let q = [c(1, 1000, "FR", 60), c(2, 1500, "FR", 0)];
        assert_eq!(pairs(&q, est), vec![(0, 1)]);
    }
}
