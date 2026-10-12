//! Elo rating (K = 32) and matchmaking window.

pub const K: f64 = 32.0;
pub const START_RATING: i32 = 1200;

/// New ratings `(winner, loser)` after a decisive result.
pub fn update(winner: i32, loser: i32) -> (i32, i32) {
    update_k(winner, loser, K)
}

/// [`update`] with another K (community ratings of characters use 16).
pub fn update_k(winner: i32, loser: i32, k: f64) -> (i32, i32) {
    let ew = 1.0 / (1.0 + 10f64.powf((loser - winner) as f64 / 400.0));
    let el = 1.0 - ew;
    let dw = (k * (1.0 - ew)).round() as i32;
    let dl = (k * (0.0 - el)).round() as i32;
    (winner + dw, loser + dl)
}

/// Allowed rating gap after waiting `secs`: 100 points, +50 every 5 seconds, capped.
pub fn window(secs: u64) -> i32 {
    (100 + 50 * (secs / 5) as i32).min(2000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_ratings_move_16() {
        let (w, l) = update(1200, 1200);
        assert_eq!((w, l), (1216, 1184));
    }

    #[test]
    fn upset_moves_more() {
        let (w, _) = update(1000, 1400);
        assert!(w - 1000 > 16);
        let (w2, _) = update(1400, 1000);
        assert!(w2 - 1400 < 16);
    }

    #[test]
    fn window_widens() {
        assert_eq!(window(0), 100);
        assert_eq!(window(10), 200);
        assert_eq!(window(10_000), 2000);
    }
}
