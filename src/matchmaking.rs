//! Queue pairing: rating window (Elo, ranked only) and ping window, both
//! widening with the time spent waiting. Match traffic goes through the
//! server, so the round trip between two players is simply the sum of their
//! server-measured round trips. Pure and deterministic.

use crate::elo;

/// Assumed round trip to the server when it has not been measured yet.
pub const UNMEASURED_RTT: u32 = 60;

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
/// `secs`: 60 ms, 120 ms after 10 s, 200 ms after 20 s, anything after 30 s.
pub fn ping_window(secs: u64) -> u32 {
    match secs {
        0..10 => 60,
        10..20 => 120,
        20..30 => 200,
        _ => u32::MAX,
    }
}

/// Estimated player ↔ player round trip through the server.
pub fn estimate(a: Option<u32>, b: Option<u32>) -> u32 {
    a.unwrap_or(UNMEASURED_RTT)
        .saturating_add(b.unwrap_or(UNMEASURED_RTT))
}

/// Pairs to start, as indices into `queue` (oldest first). Only entries of
/// the same kind (ranked / quick) meet. Each player gets the acceptable
/// partner of lowest estimated ping, then smallest rating gap, then longest wait.
pub fn pairs(queue: &[Candidate]) -> Vec<(usize, usize)> {
    let mut taken = vec![false; queue.len()];
    let mut out = Vec::new();
    for i in 0..queue.len() {
        if taken[i] {
            continue;
        }
        let a = &queue[i];
        let mut best: Option<(u32, i32, usize)> = None;
        for (j, b) in queue.iter().enumerate() {
            if j == i || taken[j] || a.ranked != b.ranked {
                continue;
            }
            let gap = (a.rating - b.rating).abs();
            let rating_ok =
                !a.ranked || gap <= elo::window(a.waited_secs).max(elo::window(b.waited_secs));
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
        assert_eq!(ping_window(0), 60);
        assert_eq!(ping_window(12), 120);
        assert_eq!(ping_window(25), 200);
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
        let q = [c(1, 1200, Some(120), 21), c(2, 1200, Some(70), 0)];
        assert_eq!(pairs(&q), vec![(0, 1)]);
        let q = [c(1, 1200, Some(300), 29), c(2, 1200, Some(70), 0)];
        assert!(pairs(&q).is_empty());
        let q = [c(1, 1200, Some(300), 31), c(2, 1200, Some(70), 0)];
        assert_eq!(pairs(&q), vec![(0, 1)]);
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
