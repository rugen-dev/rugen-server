//! Persistent state: accounts, ratings, seasons, match results. Kept in
//! memory behind a mutex and written to `<data>/state.json` atomically after
//! every change (tiny volumes; no database dependency).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rugen_proto::{ProfileInfo, Season, rank_name};
use serde::{Deserialize, Serialize};

use crate::elo;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub id: u64,
    pub key: String,
    pub name: String,
    pub avatar: u32,
    pub rating: i32,
    pub best_rating: i32,
    pub wins: u32,
    pub losses: u32,
    pub created: u64,
    pub last_seen: u64,
}

impl Account {
    pub fn info(&self) -> ProfileInfo {
        ProfileInfo {
            id: self.id,
            name: self.name.clone(),
            avatar: self.avatar,
            rating: self.rating,
            best_rating: self.best_rating,
            wins: self.wins,
            losses: self.losses,
            rank: rank_name(self.rating).to_string(),
        }
    }
}

/// One side's report for a match.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub reporter: u64,
    pub winner: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatchRecord {
    pub id: u64,
    pub players: [u64; 2],
    pub ranked: bool,
    pub created: u64,
    pub reports: Vec<Report>,
    pub resolved: bool,
    pub winner: Option<u64>,
    pub deltas: [i32; 2],
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub accounts: Vec<Account>,
    pub matches: Vec<MatchRecord>,
    pub season: u32,
    pub season_start: u64,
    pub next_id: u64,
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Seasons last 90 days from the first start.
pub const SEASON_SECS: u64 = 90 * 24 * 3600;

pub struct Store {
    path: Option<PathBuf>,
    pub state: State,
    keys: HashMap<String, usize>,
}

impl Store {
    pub fn open(dir: Option<&Path>) -> std::io::Result<Self> {
        let path = dir.map(|d| d.join("state.json"));
        let mut state = State::default();
        if let Some(p) = &path {
            std::fs::create_dir_all(p.parent().unwrap_or(Path::new(".")))?;
            if let Ok(bytes) = std::fs::read(p) {
                state = serde_json::from_slice(&bytes).unwrap_or_default();
            }
        }
        if state.season == 0 {
            state.season = 1;
            state.season_start = now();
        }
        if state.next_id == 0 {
            state.next_id = 1000;
        }
        let keys = state
            .accounts
            .iter()
            .enumerate()
            .map(|(i, a)| (a.key.clone(), i))
            .collect();
        let mut s = Self { path, state, keys };
        s.roll_season();
        Ok(s)
    }

    pub fn save(&self) {
        let Some(p) = &self.path else { return };
        let tmp = p.with_extension("json.tmp");
        if let Ok(bytes) = serde_json::to_vec(&self.state)
            && std::fs::write(&tmp, bytes).is_ok()
        {
            let _ = std::fs::rename(&tmp, p);
        }
    }

    /// Start a new season when the current one is over: ratings soft-reset toward 1200.
    fn roll_season(&mut self) {
        while now() >= self.state.season_start + SEASON_SECS {
            self.state.season += 1;
            self.state.season_start += SEASON_SECS;
            for a in &mut self.state.accounts {
                a.rating = (a.rating + elo::START_RATING) / 2;
                a.wins = 0;
                a.losses = 0;
            }
        }
    }

    pub fn season(&self) -> Season {
        Season {
            number: self.state.season,
            name: format!("SEASON {}", self.state.season),
            ends_at: self.state.season_start + SEASON_SECS,
        }
    }

    fn fresh_id(&mut self) -> u64 {
        let id = self.state.next_id;
        self.state.next_id += 1;
        id
    }

    pub fn register(&mut self) -> &Account {
        let id = self.fresh_id();
        let key = random_hex(32);
        let t = now();
        self.state.accounts.push(Account {
            id,
            key: key.clone(),
            name: format!("PLAYER{}", id % 10_000),
            avatar: 0,
            rating: elo::START_RATING,
            best_rating: elo::START_RATING,
            wins: 0,
            losses: 0,
            created: t,
            last_seen: t,
        });
        let idx = self.state.accounts.len() - 1;
        self.keys.insert(key, idx);
        self.save();
        &self.state.accounts[idx]
    }

    pub fn by_key(&mut self, key: &str) -> Option<usize> {
        let idx = *self.keys.get(key)?;
        self.state.accounts[idx].last_seen = now();
        Some(idx)
    }

    pub fn by_id(&self, id: u64) -> Option<&Account> {
        self.state.accounts.iter().find(|a| a.id == id)
    }

    pub fn set_profile(&mut self, idx: usize, name: Option<String>, avatar: Option<u32>) {
        let a = &mut self.state.accounts[idx];
        if let Some(n) = name {
            let clean: String = n
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == ' ')
                .take(16)
                .collect();
            if !clean.trim().is_empty() {
                a.name = clean.trim().to_string();
            }
        }
        if let Some(av) = avatar {
            a.avatar = av.min(99);
        }
        self.save();
    }

    pub fn new_match(&mut self, players: [u64; 2], ranked: bool) -> u64 {
        let id = self.fresh_id();
        self.state.matches.push(MatchRecord {
            id,
            players,
            ranked,
            created: now(),
            reports: Vec::new(),
            resolved: false,
            winner: None,
            deltas: [0, 0],
        });
        // keep the log bounded
        if self.state.matches.len() > 50_000 {
            self.state.matches.drain(..10_000);
        }
        self.save();
        id
    }

    /// Record one side's report. Returns `(accepted, resolved delta for reporter)`.
    pub fn report(&mut self, reporter: u64, match_id: u64, winner: u64) -> (bool, Option<i32>) {
        let Some(mi) = self.state.matches.iter().position(|m| m.id == match_id) else {
            return (false, None);
        };
        let m = &self.state.matches[mi];
        if !m.players.contains(&reporter) || !m.players.contains(&winner) {
            return (false, None);
        }
        if m.resolved {
            let side = usize::from(m.players[1] == reporter);
            return (true, Some(m.deltas[side]));
        }
        if m.reports.iter().any(|r| r.reporter == reporter) {
            return (true, None);
        }
        self.state.matches[mi]
            .reports
            .push(Report { reporter, winner });
        let m = &self.state.matches[mi];
        if m.reports.len() < 2 {
            self.save();
            return (true, None);
        }
        if m.reports[0].winner != m.reports[1].winner {
            // disagreement: ignore this match
            self.state.matches[mi].resolved = true;
            self.save();
            return (true, None);
        }
        let (players, ranked) = (m.players, m.ranked);
        let loser = if players[0] == winner {
            players[1]
        } else {
            players[0]
        };
        let mut deltas = [0, 0];
        if ranked {
            let wi = self.state.accounts.iter().position(|a| a.id == winner);
            let li = self.state.accounts.iter().position(|a| a.id == loser);
            if let (Some(wi), Some(li)) = (wi, li) {
                let (nw, nl) = elo::update(
                    self.state.accounts[wi].rating,
                    self.state.accounts[li].rating,
                );
                let dw = nw - self.state.accounts[wi].rating;
                let dl = nl - self.state.accounts[li].rating;
                let w = &mut self.state.accounts[wi];
                w.rating = nw;
                w.best_rating = w.best_rating.max(nw);
                w.wins += 1;
                let l = &mut self.state.accounts[li];
                l.rating = nl;
                l.losses += 1;
                deltas = if players[0] == winner {
                    [dw, dl]
                } else {
                    [dl, dw]
                };
            }
        }
        let m = &mut self.state.matches[mi];
        m.resolved = true;
        m.winner = Some(winner);
        m.deltas = deltas;
        let side = usize::from(players[1] == reporter);
        self.save();
        (true, Some(deltas[side]))
    }

    pub fn leaderboard(&self, limit: usize) -> Vec<ProfileInfo> {
        let mut v: Vec<&Account> = self
            .state
            .accounts
            .iter()
            .filter(|a| a.wins + a.losses > 0)
            .collect();
        v.sort_by(|a, b| b.rating.cmp(&a.rating).then(a.id.cmp(&b.id)));
        v.into_iter().take(limit).map(Account::info).collect()
    }

    pub fn rank_of(&self, id: u64) -> Option<usize> {
        let mut v: Vec<&Account> = self
            .state
            .accounts
            .iter()
            .filter(|a| a.wins + a.losses > 0)
            .collect();
        v.sort_by(|a, b| b.rating.cmp(&a.rating).then(a.id.cmp(&b.id)));
        v.iter().position(|a| a.id == id).map(|p| p + 1)
    }
}

pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    let _ = getrandom::getrandom(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Room / match codes: 5 unambiguous upper-case characters.
pub fn random_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut buf = [0u8; 5];
    let _ = getrandom::getrandom(&mut buf);
    buf.iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agreed_result_moves_ratings_once() {
        let mut s = Store::open(None).unwrap();
        let a = s.register().id;
        let b = s.register().id;
        let m = s.new_match([a, b], true);
        assert_eq!(s.report(a, m, a), (true, None));
        assert_eq!(s.report(b, m, a), (true, Some(-16)));
        assert_eq!(s.by_id(a).unwrap().rating, 1216);
        assert_eq!(s.by_id(b).unwrap().rating, 1184);
        // late duplicate report changes nothing
        assert_eq!(s.report(a, m, a), (true, Some(16)));
        assert_eq!(s.by_id(a).unwrap().rating, 1216);
    }

    #[test]
    fn disagreement_is_ignored_and_outsiders_rejected() {
        let mut s = Store::open(None).unwrap();
        let a = s.register().id;
        let b = s.register().id;
        let c = s.register().id;
        let m = s.new_match([a, b], true);
        assert_eq!(s.report(c, m, a), (false, None));
        s.report(a, m, a);
        s.report(b, m, b);
        assert_eq!(s.by_id(a).unwrap().rating, 1200);
        assert!(s.state.matches[0].resolved);
    }

    #[test]
    fn profile_names_are_sanitized() {
        let mut s = Store::open(None).unwrap();
        s.register();
        s.set_profile(0, Some("<script>Bob Z".into()), Some(500));
        assert_eq!(s.state.accounts[0].name, "scriptBob Z");
        assert_eq!(s.state.accounts[0].avatar, 99);
    }
}
