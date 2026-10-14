//! Tournament brackets inside a room: 8 or 16 entrants, single
//! elimination, seeded by rating, one match at a time called by the server.
//!
//! This module is the bracket itself, a pure data structure: seeding,
//! byes, recording results and finding the next match to call. The room
//! code ([`crate::api`]) opens each called match's matchup, reads the
//! settled result and records it here.

use rugen_proto::{BracketMatch, TournamentView};

/// Bracket sizes a room can run.
pub const SIZES: [u8; 2] = [8, 16];
/// A called match that has not started after this long is decided by
/// walkover (seconds).
pub const CALL_TIMEOUT_SECS: u64 = 180;
/// Pause between a result and the next call (players read the bracket).
pub const NEXT_DELAY_SECS: u64 = 8;
/// Times a disputed or failed match is called again before the higher seed
/// goes through.
pub const MAX_REPLAYS: u8 = 1;

/// One entrant, in seed order once the bracket is drawn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seed {
    pub account: u64,
    pub rating: i32,
}

/// One match of the bracket: two slots (seed indices; `None` = a bye or
/// not decided yet), the winner's slot once played.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pair {
    pub slots: [Option<usize>; 2],
    pub winner: Option<usize>,
    /// Rounds won per slot (from the players' reports; 0-0 when unknown).
    pub score: [u8; 2],
    /// The match currently or last played for this pair.
    pub match_id: Option<u64>,
    /// Times this pair was called again (disputed / failed).
    pub replays: u8,
}

/// Standard bracket order of seeds for `n` (a power of two) positions:
/// 1 v n, then the halves mirrored so the top seeds meet last
/// (8: 1 8 4 5 2 7 3 6).
pub fn seed_positions(n: usize) -> Vec<usize> {
    let mut order = vec![0usize];
    let mut size = 1;
    while size < n {
        size *= 2;
        order = order.iter().flat_map(|&s| [s, size - 1 - s]).collect();
    }
    order
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bracket {
    /// Entrants by seed (best rating first).
    pub seeds: Vec<Seed>,
    /// Rounds, first to final; round r has size / 2^(r+1) pairs.
    pub rounds: Vec<Vec<Pair>>,
}

impl Bracket {
    /// Draw a bracket of `size` positions (8 or 16) for `entrants` (at
    /// least 2, at most `size`): seeded by rating (then the earlier entrant),
    /// empty positions are byes for the top seeds.
    pub fn draw(size: usize, entrants: &[Seed]) -> Self {
        let size = size.max(entrants.len()).next_power_of_two().max(2);
        let mut seeds: Vec<(usize, Seed)> = entrants.iter().cloned().enumerate().collect();
        seeds.sort_by_key(|(i, s)| (std::cmp::Reverse(s.rating), *i));
        let seeds: Vec<Seed> = seeds.into_iter().map(|(_, s)| s).collect();
        let pos = seed_positions(size);
        let first: Vec<Pair> = pos
            .chunks(2)
            .map(|c| Pair {
                slots: [c[0], c[1]].map(|s| (s < seeds.len()).then_some(s)),
                ..Default::default()
            })
            .collect();
        let mut rounds = vec![first];
        while rounds.last().is_some_and(|r| r.len() > 1) {
            let n = rounds.last().map_or(0, Vec::len) / 2;
            rounds.push(vec![Pair::default(); n]);
        }
        let mut b = Self { seeds, rounds };
        b.advance_byes();
        b
    }

    /// Positions of the first round (8 or 16).
    #[cfg(test)]
    pub fn size(&self) -> usize {
        self.rounds.first().map_or(0, |r| r.len() * 2)
    }

    /// Pairs with one entrant and nobody who could ever face it (a bye,
    /// or a whole empty half below) go through at once, round after round.
    fn advance_byes(&mut self) {
        loop {
            let mut moved = false;
            // a pair is empty when no entrant can ever reach it
            let mut empty: Vec<Vec<bool>> = Vec::new();
            for r in 0..self.rounds.len() {
                let row: Vec<bool> = (0..self.rounds[r].len())
                    .map(|i| {
                        if r == 0 {
                            self.rounds[0][i].slots.iter().all(Option::is_none)
                        } else {
                            empty[r - 1][2 * i] && empty[r - 1][2 * i + 1]
                        }
                    })
                    .collect();
                empty.push(row);
            }
            for r in 0..self.rounds.len() {
                for i in 0..self.rounds[r].len() {
                    let p = &self.rounds[r][i];
                    if p.winner.is_some() {
                        continue;
                    }
                    let side_empty = |k: usize| {
                        if r == 0 {
                            p.slots[k].is_none()
                        } else {
                            empty[r - 1][2 * i + k]
                        }
                    };
                    let alone = match p.slots {
                        [Some(a), None] if side_empty(1) => Some(a),
                        [None, Some(b)] if side_empty(0) => Some(b),
                        _ => None,
                    };
                    if let Some(a) = alone {
                        self.set_winner(r, i, a);
                        moved = true;
                    }
                }
            }
            if !moved {
                break;
            }
        }
    }

    fn set_winner(&mut self, round: usize, index: usize, seed: usize) {
        self.rounds[round][index].winner = Some(seed);
        if let Some(next) = self.rounds.get_mut(round + 1) {
            next[index / 2].slots[index % 2] = Some(seed);
        }
    }

    /// The next pair to call: the earliest round's first pair with both
    /// entrants and no winner.
    pub fn next(&self) -> Option<(usize, usize)> {
        for (r, round) in self.rounds.iter().enumerate() {
            for (i, p) in round.iter().enumerate() {
                if p.winner.is_none() && p.slots[0].is_some() && p.slots[1].is_some() {
                    return Some((r, i));
                }
            }
        }
        None
    }

    /// The accounts of a pair (P1 = the higher seed).
    pub fn players(&self, round: usize, index: usize) -> Option<[u64; 2]> {
        let p = self.rounds.get(round)?.get(index)?;
        let [Some(a), Some(b)] = p.slots else {
            return None;
        };
        Some([self.seeds[a].account, self.seeds[b].account])
    }

    /// Record a pair's result: `winner` is an account of the pair. False
    /// when it is not one of its players or the pair is already decided.
    pub fn record(&mut self, round: usize, index: usize, winner: u64, score: [u8; 2]) -> bool {
        let Some(p) = self.rounds.get(round).and_then(|r| r.get(index)) else {
            return false;
        };
        if p.winner.is_some() {
            return false;
        }
        let Some(slot) = p
            .slots
            .iter()
            .flatten()
            .copied()
            .find(|&s| self.seeds[s].account == winner)
        else {
            return false;
        };
        self.rounds[round][index].score = score;
        self.set_winner(round, index, slot);
        self.advance_byes();
        true
    }

    /// The pair `account` plays next (not decided yet), if it is still in.
    #[cfg(test)]
    pub fn pair_of(&self, account: u64) -> Option<(usize, usize)> {
        let seed = self.seeds.iter().position(|s| s.account == account)?;
        for (r, round) in self.rounds.iter().enumerate() {
            for (i, p) in round.iter().enumerate() {
                if p.winner.is_none() && p.slots.contains(&Some(seed)) {
                    return Some((r, i));
                }
            }
        }
        None
    }

    pub fn champion(&self) -> Option<u64> {
        let s = self.rounds.last()?.first()?.winner?;
        Some(self.seeds[s].account)
    }

    /// What clients see: every pair by round with its players' accounts,
    /// score, winner and state (`live` for the called one).
    pub fn view(&self, live: Option<(usize, usize)>, called: bool) -> Vec<Vec<BracketMatch>> {
        let acc = |s: Option<usize>| s.map(|s| self.seeds[s].account);
        self.rounds
            .iter()
            .enumerate()
            .map(|(r, round)| {
                round
                    .iter()
                    .enumerate()
                    .map(|(i, p)| {
                        let bye = p.winner.is_some()
                            && p.slots.iter().filter(|s| s.is_some()).count() == 1;
                        let state = if bye {
                            "bye"
                        } else if p.winner.is_some() {
                            "done"
                        } else if live == Some((r, i)) {
                            if called { "called" } else { "live" }
                        } else if p.slots.iter().all(Option::is_some) {
                            "next"
                        } else {
                            "wait"
                        };
                        BracketMatch {
                            p1: acc(p.slots[0]),
                            p2: acc(p.slots[1]),
                            seeds: p.slots.map(|s| s.map_or(0, |s| s as u8 + 1)),
                            score: p.score,
                            winner: acc(p.winner),
                            state: state.into(),
                            match_id: p.match_id.unwrap_or(0),
                        }
                    })
                    .collect()
            })
            .collect()
    }
}

/// The tournament of a room.
#[derive(Clone, Debug, Default)]
pub struct Tournament {
    /// 8 or 16.
    pub size: u8,
    /// Entrants in join order (the host first) until the draw.
    pub entrants: Vec<u64>,
    pub bracket: Option<Bracket>,
    /// The called pair (round, index) and when it was called.
    pub called: Option<(usize, usize, std::time::Instant)>,
    /// The match of the called pair has its relay session (it is live).
    pub started: bool,
    /// No call before then (pause after a result).
    pub next_at: Option<std::time::Instant>,
    /// Rounds won per side reported by the players, by match id.
    pub scores: std::collections::HashMap<u64, [u8; 2]>,
}

impl Tournament {
    pub fn new(size: u8) -> Self {
        Self {
            size,
            ..Default::default()
        }
    }

    /// "open" (taking entrants), "running" or "done".
    pub fn state(&self) -> &'static str {
        match &self.bracket {
            None => "open",
            Some(b) if b.champion().is_some() => "done",
            Some(_) => "running",
        }
    }

    pub fn full(&self) -> bool {
        self.entrants.len() >= self.size as usize
    }

    /// The view for clients; `names` gives each account's profile.
    pub fn view(&self, entrants: Vec<rugen_proto::Entrant>) -> TournamentView {
        let live = self.called.map(|(r, i, _)| (r, i));
        TournamentView {
            size: self.size,
            state: self.state().into(),
            entrants,
            rounds: self
                .bracket
                .as_ref()
                .map(|b| b.view(live, !self.started))
                .unwrap_or_default(),
            live: live.map(|(r, i)| [r as u8, i as u8]),
            champion: self.bracket.as_ref().and_then(Bracket::champion),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeds(ratings: &[i32]) -> Vec<Seed> {
        ratings
            .iter()
            .enumerate()
            .map(|(i, &rating)| Seed {
                account: 100 + i as u64,
                rating,
            })
            .collect()
    }

    #[test]
    fn standard_seed_order() {
        assert_eq!(seed_positions(2), vec![0, 1]);
        assert_eq!(seed_positions(4), vec![0, 3, 1, 2]);
        assert_eq!(seed_positions(8), vec![0, 7, 3, 4, 1, 6, 2, 5]);
        let s16 = seed_positions(16);
        assert_eq!(&s16[..4], &[0, 15, 7, 8]);
        let mut sorted = s16.clone();
        sorted.sort();
        assert_eq!(sorted, (0..16).collect::<Vec<_>>());
    }

    #[test]
    fn eight_players_seeded_by_rating_play_to_a_champion() {
        // entrants in join order; 107 is the best, 100 the worst
        let mut b = Bracket::draw(8, &seeds(&[1000, 1100, 1200, 1300, 1400, 1500, 1600, 1700]));
        assert_eq!(b.size(), 8);
        assert_eq!(b.rounds.len(), 3);
        assert_eq!(b.seeds[0].account, 107, "seed 1 = best rating");
        // quarter-finals: 1 v 8, 4 v 5, 2 v 7, 3 v 6
        assert_eq!(b.players(0, 0), Some([107, 100]));
        assert_eq!(b.players(0, 1), Some([104, 103]));
        assert_eq!(b.players(0, 2), Some([106, 101]));
        assert_eq!(b.players(0, 3), Some([105, 102]));
        assert_eq!(b.next(), Some((0, 0)));
        assert!(!b.record(0, 0, 999, [2, 0]), "not a player of the pair");
        assert!(b.record(0, 0, 107, [2, 0]));
        assert!(!b.record(0, 0, 100, [2, 0]), "already decided");
        assert_eq!(b.next(), Some((0, 1)));
        assert!(b.record(0, 1, 103, [1, 2]), "an upset");
        assert!(b.record(0, 2, 106, [2, 1]));
        assert!(b.record(0, 3, 105, [2, 0]));
        // semi-finals: 107 v 103, 106 v 105
        assert_eq!(b.players(1, 0), Some([107, 103]));
        assert_eq!(b.players(1, 1), Some([106, 105]));
        assert_eq!(b.pair_of(103), Some((1, 0)));
        assert_eq!(b.pair_of(100), None, "out");
        assert!(b.record(1, 0, 103, [2, 1]));
        assert!(b.record(1, 1, 105, [2, 0]));
        assert_eq!(b.players(2, 0), Some([103, 105]));
        assert_eq!(b.champion(), None);
        assert!(b.record(2, 0, 105, [2, 1]));
        assert_eq!(b.champion(), Some(105));
        assert_eq!(b.next(), None);
        let v = b.view(None, false);
        assert_eq!(v[0][1].winner, Some(103));
        assert_eq!(v[0][1].seeds, [4, 5]);
        assert_eq!(v[0][1].score, [1, 2]);
        assert_eq!(v[2][0].state, "done");
    }

    #[test]
    fn missing_entrants_are_byes_for_the_top_seeds() {
        let mut b = Bracket::draw(8, &seeds(&[1500, 1400, 1300, 1200, 1100]));
        // seeds 1-3 face empty positions 8-6: they are through
        let v = b.view(None, false);
        assert_eq!(v[0][0].state, "bye");
        assert_eq!(v[0][0].winner, Some(100));
        assert_eq!(
            v[0][1].state, "next",
            "4 v 5 is the only real quarter-final"
        );
        assert_eq!(b.next(), Some((0, 1)));
        assert!(b.record(0, 1, 104, [2, 0]));
        // seed 1 meets the 4/5 winner, seed 2 meets seed 3
        assert_eq!(b.players(1, 0), Some([100, 104]));
        assert_eq!(b.players(1, 1), Some([101, 102]));
        // two players: straight to the final
        let mut two = Bracket::draw(8, &seeds(&[1200, 1300]));
        assert_eq!(two.size(), 8);
        let (r, i) = two.next().unwrap();
        assert_eq!(r, 2, "everyone else was a bye: the final");
        assert_eq!(two.players(r, i), Some([101, 100]));
        assert!(two.record(r, i, 100, [2, 1]));
        assert_eq!(two.champion(), Some(100));
    }

    #[test]
    fn sixteen_and_ties_by_join_order() {
        let b = Bracket::draw(16, &seeds(&[1200; 16]));
        assert_eq!(b.rounds.len(), 4);
        assert_eq!(b.rounds[0].len(), 8);
        // equal ratings: the earlier entrant is the higher seed
        assert_eq!(b.players(0, 0), Some([100, 115]));
        let mut t = Tournament::new(16);
        assert_eq!(t.state(), "open");
        t.entrants = (0..16).collect();
        assert!(t.full());
        t.bracket = Some(b);
        assert_eq!(t.state(), "running");
        t.called = Some((0, 0, std::time::Instant::now()));
        let v = t.view(Vec::new());
        assert_eq!(v.live, Some([0, 0]));
        assert_eq!(v.rounds[0][0].state, "called");
        t.started = true;
        assert_eq!(t.view(Vec::new()).rounds[0][0].state, "live");
    }
}
