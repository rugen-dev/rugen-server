//! Queue pairing: rating window (Elo, ranked only) and ping window, both
//! widening with the time spent waiting. Match traffic goes through the
//! server, so the round trip between two players is simply the sum of their
//! server-measured round trips. Pure and deterministic.
//!
//! Pairing prefers low ping globally: every acceptable pair is ranked by
//! estimated round trip (then rating gap, then the longest wait) and taken
//! greedily, so the two closest players meet first and nobody grabs a far
//! partner while a near one is queued. Pairs above [`HIGH_PING_MS`] are
//! marked so both clients show the ping before they accept.

use crate::elo;

/// Assumed round trip to the server when it has not been measured yet.
pub const UNMEASURED_RTT: u32 = 60;
/// Estimated player ↔ player round trip above which a matchup is flagged
/// `high_ping` (both players see it on the confirm screen before accepting).
pub const HIGH_PING_MS: u32 = 200;

#[derive(Clone, Debug)]
pub struct Candidate {
    pub rating: i32,
    /// Round trip player ↔ server.
    pub rtt_ms: Option<u32>,
    pub waited_secs: u64,
    /// "Accept only good connections": hard cap that never widens.
    pub max_ping: Option<u32>,
    /// Ranked entries respect the rating window; quick match ignores it.
    pub ranked: bool,
}

/// Acceptable estimated round trip between the two players after waiting
/// `secs`: 80 ms, 150 ms after 10 s, 250 ms after 20 s, anything after 30 s.
pub fn ping_window(secs: u64) -> u32 {
    match secs {
        0..10 => 80,
        10..20 => 150,
        20..30 => 250,
        _ => u32::MAX,
    }
}

/// Estimated player ↔ player round trip through the server.
pub fn estimate(a: Option<u32>, b: Option<u32>) -> u32 {
    a.unwrap_or(UNMEASURED_RTT)
        .saturating_add(b.unwrap_or(UNMEASURED_RTT))
}

/// The pair's estimated round trip when they may meet now.
fn acceptable(a: &Candidate, b: &Candidate) -> Option<u32> {
    if a.ranked != b.ranked {
        return None;
    }
    let gap = (a.rating - b.rating).abs();
    let rating_ok = !a.ranked || gap <= elo::window(a.waited_secs).max(elo::window(b.waited_secs));
    let ping = estimate(a.rtt_ms, b.rtt_ms);
    let mut window = ping_window(a.waited_secs).max(ping_window(b.waited_secs));
    // with no measurement at all the first window must still let people play
    if a.rtt_ms.is_none() && b.rtt_ms.is_none() {
        window = window.max(estimate(None, None));
    }
    let cap = a
        .max_ping
        .unwrap_or(u32::MAX)
        .min(b.max_ping.unwrap_or(u32::MAX));
    (rating_ok && ping <= window && ping <= cap).then_some(ping)
}

/// Pairs to start, as indices into `queue` (oldest first). Only entries of
/// the same kind (ranked / quick) meet. Acceptable pairs are taken lowest
/// estimated ping first, then smallest rating gap, then longest wait.
pub fn pairs(queue: &[Candidate]) -> Vec<(usize, usize)> {
    let mut all: Vec<(u32, i32, std::cmp::Reverse<u64>, usize, usize)> = Vec::new();
    for i in 0..queue.len() {
        for j in i + 1..queue.len() {
            let (a, b) = (&queue[i], &queue[j]);
            if let Some(ping) = acceptable(a, b) {
                let gap = (a.rating - b.rating).abs();
                let wait = std::cmp::Reverse(a.waited_secs.max(b.waited_secs));
                all.push((ping, gap, wait, i, j));
            }
        }
    }
    all.sort_unstable();
    let mut taken = vec![false; queue.len()];
    let mut out = Vec::new();
    for (_, _, _, i, j) in all {
        if !taken[i] && !taken[j] {
            taken[i] = true;
            taken[j] = true;
            out.push((i, j));
        }
    }
    out
}

/// Whether a pair with this estimated round trip must be flagged.
pub fn high_ping(est: u32, threshold: u32) -> bool {
    est > threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(_id: u64, rating: i32, rtt: Option<u32>, waited: u64) -> Candidate {
        Candidate {
            rating,
            rtt_ms: rtt,
            waited_secs: waited,
            max_ping: None,
            ranked: true,
        }
    }

    #[test]
    fn window_widens_over_time() {
        assert_eq!(ping_window(0), 80);
        assert_eq!(ping_window(12), 150);
        assert_eq!(ping_window(25), 250);
        assert_eq!(ping_window(31), u32::MAX);
    }

    #[test]
    fn prefers_the_lowest_combined_ping() {
        let q = [
            c(1, 1200, Some(20), 0),
            c(2, 1200, Some(35), 0),
            c(3, 1250, Some(15), 0),
        ];
        assert_eq!(pairs(&q), vec![(0, 2)]);
    }

    #[test]
    fn far_players_wait_until_the_window_allows() {
        let q = [c(1, 1200, Some(30), 0), c(2, 1200, Some(70), 0)];
        assert!(pairs(&q).is_empty());
        let q = [c(1, 1200, Some(30), 11), c(2, 1200, Some(70), 0)];
        assert_eq!(pairs(&q), vec![(0, 1)]);
        let q = [c(1, 1200, Some(170), 21), c(2, 1200, Some(70), 0)];
        assert_eq!(pairs(&q), vec![(0, 1)]);
        let q = [c(1, 1200, Some(300), 29), c(2, 1200, Some(70), 0)];
        assert!(pairs(&q).is_empty());
        let q = [c(1, 1200, Some(300), 31), c(2, 1200, Some(70), 0)];
        assert_eq!(pairs(&q), vec![(0, 1)]);
    }

    #[test]
    fn the_closest_pair_meets_first_whatever_the_queue_order() {
        // oldest-first greedy would pair 0 with 1 (90 ms) and strand 2;
        // global lowest-ping-first pairs 1 + 2 (20 ms)
        let q = [
            c(1, 1200, Some(80), 15),
            c(2, 1200, Some(10), 15),
            c(3, 1200, Some(10), 15),
        ];
        assert_eq!(pairs(&q), vec![(1, 2)]);
        let q = [
            c(1, 1200, Some(70), 15),
            c(2, 1200, Some(60), 15),
            c(3, 1200, Some(15), 15),
            c(4, 1200, Some(20), 15),
        ];
        assert_eq!(pairs(&q), vec![(2, 3), (0, 1)]);
    }

    #[test]
    fn far_pairs_are_flagged_high_ping() {
        assert!(!high_ping(200, HIGH_PING_MS));
        assert!(high_ping(201, HIGH_PING_MS));
        // after 30 s anything goes, but it is flagged
        let q = [c(1, 1200, Some(150), 31), c(2, 1200, Some(120), 0)];
        assert_eq!(pairs(&q), vec![(0, 1)]);
        assert!(high_ping(estimate(Some(150), Some(120)), HIGH_PING_MS));
    }

    #[test]
    fn unmeasured_players_still_meet() {
        let q = [c(1, 1200, None, 0), c(2, 1200, None, 0)];
        assert_eq!(pairs(&q), vec![(0, 1)]);
    }

    #[test]
    fn good_connections_only_never_widens() {
        let mut a = c(1, 1200, Some(60), 600);
        a.max_ping = Some(80);
        let q = [a, c(2, 1200, Some(60), 600)];
        assert!(pairs(&q).is_empty());
    }

    #[test]
    fn rating_window_only_for_ranked() {
        let q = [c(1, 1000, Some(10), 0), c(2, 1500, Some(10), 0)];
        assert!(pairs(&q).is_empty());
        let q = [c(1, 1000, Some(10), 60), c(2, 1500, Some(10), 0)];
        assert_eq!(pairs(&q), vec![(0, 1)]);
        let mut quick = [c(1, 1000, Some(10), 0), c(2, 1500, Some(10), 0)];
        quick.iter_mut().for_each(|q| q.ranked = false);
        assert_eq!(pairs(&quick), vec![(0, 1)]);
        // ranked and quick never meet
        let mixed = [c(1, 1200, Some(10), 0), quick[1].clone()];
        assert!(pairs(&mixed).is_empty());
    }
}
