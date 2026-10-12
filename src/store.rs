//! Persistent state on SQLite: accounts, ratings, seasons, match results.
//!
//! One file, `<data>/rugen.db`, in WAL mode. The schema is versioned with
//! `PRAGMA user_version` and upgraded by the embedded [`MIGRATIONS`] on open.
//! A `state.json` left by the former JSON store is imported once (then
//! renamed to `state.json.migrated`).

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rugen_proto::{ProfileInfo, Season, rank_name};
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::Deserialize;

use crate::elo;

pub type DbResult<T> = rusqlite::Result<T>;

#[derive(Clone, Debug, PartialEq)]
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

    fn from_row(r: &Row<'_>) -> DbResult<Self> {
        Ok(Self {
            id: r.get::<_, i64>(0)? as u64,
            key: r.get(1)?,
            name: r.get(2)?,
            avatar: r.get(3)?,
            rating: r.get(4)?,
            best_rating: r.get(5)?,
            wins: r.get(6)?,
            losses: r.get(7)?,
            created: r.get::<_, i64>(8)? as u64,
            last_seen: r.get::<_, i64>(9)? as u64,
        })
    }
}

const ACCOUNT_COLS: &str =
    "id, key, name, avatar, rating, best_rating, wins, losses, created, last_seen";

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Seasons last 90 days from the first start.
pub const SEASON_SECS: u64 = 90 * 24 * 3600;

/// Schema migrations; entry `i` upgrades `user_version` i to i + 1.
const MIGRATIONS: &[&str] = &[
    // v1: initial schema
    "CREATE TABLE meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL);
     CREATE TABLE accounts (
         id INTEGER PRIMARY KEY,
         key TEXT NOT NULL UNIQUE,
         name TEXT NOT NULL,
         avatar INTEGER NOT NULL DEFAULT 0,
         rating INTEGER NOT NULL,
         best_rating INTEGER NOT NULL,
         wins INTEGER NOT NULL DEFAULT 0,
         losses INTEGER NOT NULL DEFAULT 0,
         created INTEGER NOT NULL,
         last_seen INTEGER NOT NULL
     );
     CREATE INDEX accounts_rating ON accounts(rating DESC, id);
     CREATE TABLE matches (
         id INTEGER PRIMARY KEY,
         p1 INTEGER NOT NULL,
         p2 INTEGER NOT NULL,
         ranked INTEGER NOT NULL,
         created INTEGER NOT NULL,
         resolved INTEGER NOT NULL DEFAULT 0,
         winner INTEGER,
         delta1 INTEGER NOT NULL DEFAULT 0,
         delta2 INTEGER NOT NULL DEFAULT 0
     );
     CREATE TABLE reports (
         match_id INTEGER NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
         reporter INTEGER NOT NULL,
         winner INTEGER NOT NULL,
         PRIMARY KEY (match_id, reporter)
     );",
    // v2: result verification (inputs + checksum per report), disputes, ranked replays
    "ALTER TABLE matches ADD COLUMN disputed INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE matches ADD COLUMN setup TEXT NOT NULL DEFAULT '{}';
     ALTER TABLE reports ADD COLUMN frames INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE reports ADD COLUMN checksum INTEGER;
     ALTER TABLE reports ADD COLUMN inputs BLOB;
     CREATE TABLE replays (
         match_id INTEGER PRIMARY KEY REFERENCES matches(id) ON DELETE CASCADE,
         created INTEGER NOT NULL,
         inputs BLOB NOT NULL
     );",
];

/// Ranked replays kept (oldest are deleted first).
pub const REPLAY_RETENTION: i64 = 2000;
/// Trailing frames a client may not have confirmed when it reports.
const UNCONFIRMED_TAIL: usize = 16;

/// What one side reports at the end of a match.
#[derive(Clone, Debug, Default)]
pub struct ReportData {
    pub winner: u64,
    /// Last simulated frame and the world checksum there.
    pub frames: u32,
    pub checksum: Option<u64>,
    /// Confirmed inputs, 4 bytes per frame.
    pub inputs: Vec<u8>,
}

/// Outcome of [`Store::report`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReportOutcome {
    pub accepted: bool,
    /// Rating change for the reporter once both sides agreed.
    pub delta: Option<i32>,
    pub disputed: bool,
}

/// Do two reports describe the same match? Inputs must agree on their
/// common confirmed prefix, checksums when taken at the same frame.
pub fn reports_agree(a: &ReportData, b: &ReportData) -> bool {
    if a.winner != b.winner {
        return false;
    }
    if !a.inputs.is_empty() && !b.inputs.is_empty() {
        let frames = (a.inputs.len().min(b.inputs.len()) / 4).saturating_sub(UNCONFIRMED_TAIL);
        if a.inputs[..frames * 4] != b.inputs[..frames * 4] {
            return false;
        }
    }
    if let (Some(x), Some(y)) = (a.checksum, b.checksum)
        && a.frames == b.frames
        && x != y
    {
        return false;
    }
    true
}

pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (or create) `<dir>/rugen.db`; `None` keeps everything in memory (tests).
    pub fn open(dir: Option<&Path>) -> DbResult<Self> {
        let conn = match dir {
            Some(d) => {
                std::fs::create_dir_all(d).map_err(|e| {
                    rusqlite::Error::InvalidPath(format!("{}: {e}", d.display()).into())
                })?;
                let c = Connection::open(d.join("rugen.db"))?;
                c.pragma_update(None, "journal_mode", "WAL")?;
                c.pragma_update(None, "synchronous", "NORMAL")?;
                c
            }
            None => Connection::open_in_memory()?,
        };
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let mut s = Self { conn };
        let fresh = s.migrate()?;
        if s.meta("season")?.is_none() {
            s.set_meta("season", 1)?;
            s.set_meta("season_start", now() as i64)?;
        }
        if s.meta("next_id")?.is_none() {
            s.set_meta("next_id", 1000)?;
        }
        if fresh && let Some(d) = dir {
            s.import_json(d)?;
        }
        s.roll_season()?;
        Ok(s)
    }

    /// Apply pending migrations. Returns true when the database was empty.
    fn migrate(&mut self) -> DbResult<bool> {
        let version: usize = self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        let tx = self.conn.transaction()?;
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(version) {
            tx.execute_batch(sql)?;
            tx.pragma_update(None, "user_version", i + 1)?;
            log::info!("database migrated to schema v{}", i + 1);
        }
        tx.commit()?;
        Ok(version == 0)
    }

    pub fn schema_version(&self) -> DbResult<usize> {
        self.conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
    }

    fn meta(&self, k: &str) -> DbResult<Option<i64>> {
        self.conn
            .query_row("SELECT v FROM meta WHERE k = ?1", [k], |r| r.get(0))
            .optional()
    }

    fn set_meta(&self, k: &str, v: i64) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO meta (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = ?2",
            params![k, v],
        )?;
        Ok(())
    }

    /// Import the former `state.json` (accounts, matches, season, id counter).
    fn import_json(&mut self, dir: &Path) -> DbResult<()> {
        #[derive(Deserialize)]
        struct OldAccount {
            id: u64,
            key: String,
            name: String,
            avatar: u32,
            rating: i32,
            best_rating: i32,
            wins: u32,
            losses: u32,
            created: u64,
            last_seen: u64,
        }
        #[derive(Deserialize)]
        struct OldReport {
            reporter: u64,
            winner: u64,
        }
        #[derive(Deserialize)]
        struct OldMatch {
            id: u64,
            players: [u64; 2],
            ranked: bool,
            created: u64,
            reports: Vec<OldReport>,
            resolved: bool,
            winner: Option<u64>,
            deltas: [i32; 2],
        }
        #[derive(Deserialize)]
        struct OldState {
            #[serde(default)]
            accounts: Vec<OldAccount>,
            #[serde(default)]
            matches: Vec<OldMatch>,
            #[serde(default)]
            season: u32,
            #[serde(default)]
            season_start: u64,
            #[serde(default)]
            next_id: u64,
        }
        let path = dir.join("state.json");
        let Ok(bytes) = std::fs::read(&path) else {
            return Ok(());
        };
        let old: OldState = match serde_json::from_slice(&bytes) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("{}: not imported: {e}", path.display());
                return Ok(());
            }
        };
        let tx = self.conn.transaction()?;
        for a in &old.accounts {
            tx.execute(
                &format!("INSERT OR IGNORE INTO accounts ({ACCOUNT_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"),
                params![
                    a.id as i64, a.key, a.name, a.avatar, a.rating, a.best_rating, a.wins,
                    a.losses, a.created as i64, a.last_seen as i64
                ],
            )?;
        }
        for m in &old.matches {
            tx.execute(
                "INSERT OR IGNORE INTO matches (id, p1, p2, ranked, created, resolved, winner, delta1, delta2)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    m.id as i64,
                    m.players[0] as i64,
                    m.players[1] as i64,
                    m.ranked,
                    m.created as i64,
                    m.resolved,
                    m.winner.map(|w| w as i64),
                    m.deltas[0],
                    m.deltas[1]
                ],
            )?;
            for r in &m.reports {
                tx.execute(
                    "INSERT OR IGNORE INTO reports (match_id, reporter, winner) VALUES (?1, ?2, ?3)",
                    params![m.id as i64, r.reporter as i64, r.winner as i64],
                )?;
            }
        }
        let set = |k: &str, v: i64| {
            tx.execute(
                "INSERT INTO meta (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = ?2",
                params![k, v],
            )
        };
        if old.season > 0 {
            set("season", old.season as i64)?;
            set("season_start", old.season_start as i64)?;
        }
        if old.next_id > 0 {
            set("next_id", old.next_id as i64)?;
        }
        tx.commit()?;
        let _ = std::fs::rename(&path, dir.join("state.json.migrated"));
        log::info!(
            "imported {} accounts and {} matches from {}",
            old.accounts.len(),
            old.matches.len(),
            path.display()
        );
        Ok(())
    }

    /// Start a new season when the current one is over: ratings soft-reset toward 1200.
    pub fn roll_season(&mut self) -> DbResult<()> {
        let mut season = self.meta("season")?.unwrap_or(1);
        let mut start = self.meta("season_start")?.unwrap_or(now() as i64);
        let before = season;
        while now() as i64 >= start + SEASON_SECS as i64 {
            season += 1;
            start += SEASON_SECS as i64;
            self.conn.execute(
                "UPDATE accounts SET rating = (rating + ?1) / 2, wins = 0, losses = 0",
                [elo::START_RATING],
            )?;
        }
        if season != before {
            self.set_meta("season", season)?;
            self.set_meta("season_start", start)?;
            log::info!("season {season} started");
        }
        Ok(())
    }

    pub fn season(&self) -> DbResult<Season> {
        let number = self.meta("season")?.unwrap_or(1) as u32;
        let start = self.meta("season_start")?.unwrap_or(0) as u64;
        Ok(Season {
            number,
            name: format!("SEASON {number}"),
            ends_at: start + SEASON_SECS,
        })
    }

    fn fresh_id(&self) -> DbResult<u64> {
        let id = self.conn.query_row(
            "UPDATE meta SET v = v + 1 WHERE k = 'next_id' RETURNING v - 1",
            [],
            |r| r.get::<_, i64>(0),
        )?;
        Ok(id as u64)
    }

    pub fn account_count(&self) -> DbResult<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get::<_, i64>(0))
            .map(|n| n as usize)
    }

    /// Accounts seen within the last `secs` seconds.
    pub fn online_count(&self, secs: u64) -> DbResult<usize> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM accounts WHERE last_seen >= ?1",
                [now().saturating_sub(secs) as i64],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as usize)
    }

    pub fn register(&mut self) -> DbResult<Account> {
        let id = self.fresh_id()?;
        let t = now();
        let a = Account {
            id,
            key: random_hex(32),
            name: format!("PLAYER{}", id % 10_000),
            avatar: 0,
            rating: elo::START_RATING,
            best_rating: elo::START_RATING,
            wins: 0,
            losses: 0,
            created: t,
            last_seen: t,
        };
        self.conn.execute(
            &format!("INSERT INTO accounts ({ACCOUNT_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"),
            params![
                a.id as i64, a.key, a.name, a.avatar, a.rating, a.best_rating, a.wins, a.losses,
                a.created as i64, a.last_seen as i64
            ],
        )?;
        Ok(a)
    }

    /// The account owning `key`; refreshes its `last_seen`.
    pub fn by_key(&mut self, key: &str) -> DbResult<Option<Account>> {
        self.conn
            .query_row(
                &format!(
                    "UPDATE accounts SET last_seen = ?2 WHERE key = ?1 RETURNING {ACCOUNT_COLS}"
                ),
                params![key, now() as i64],
                Account::from_row,
            )
            .optional()
    }

    pub fn by_id(&self, id: u64) -> DbResult<Option<Account>> {
        self.conn
            .query_row(
                &format!("SELECT {ACCOUNT_COLS} FROM accounts WHERE id = ?1"),
                [id as i64],
                Account::from_row,
            )
            .optional()
    }

    pub fn set_profile(
        &mut self,
        id: u64,
        name: Option<String>,
        avatar: Option<u32>,
    ) -> DbResult<Option<Account>> {
        if let Some(n) = name {
            let clean: String = n
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == ' ')
                .take(16)
                .collect();
            if !clean.trim().is_empty() {
                self.conn.execute(
                    "UPDATE accounts SET name = ?2 WHERE id = ?1",
                    params![id as i64, clean.trim()],
                )?;
            }
        }
        if let Some(av) = avatar {
            self.conn.execute(
                "UPDATE accounts SET avatar = ?2 WHERE id = ?1",
                params![id as i64, av.min(99)],
            )?;
        }
        self.by_id(id)
    }

    /// A new match row. `setup` (JSON: characters, stage, rules) is kept for replays.
    pub fn new_match(&mut self, players: [u64; 2], ranked: bool, setup: &str) -> DbResult<u64> {
        let id = self.fresh_id()?;
        self.conn.execute(
            "INSERT INTO matches (id, p1, p2, ranked, created, setup) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                id as i64,
                players[0] as i64,
                players[1] as i64,
                ranked,
                now() as i64,
                setup
            ],
        )?;
        Ok(id)
    }

    /// Record one side's report. The match resolves once both sides
    /// reported: ratings move (ranked) only when the reports agree
    /// ([`reports_agree`]); otherwise the match is marked disputed.
    pub fn report(
        &mut self,
        reporter: u64,
        match_id: u64,
        data: &ReportData,
    ) -> DbResult<ReportOutcome> {
        let rejected = ReportOutcome::default();
        let tx = self.conn.transaction()?;
        let m = tx
            .query_row(
                "SELECT p1, p2, ranked, resolved, delta1, delta2, winner, disputed FROM matches WHERE id = ?1",
                [match_id as i64],
                |r| {
                    Ok((
                        [r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64],
                        r.get::<_, bool>(2)?,
                        r.get::<_, bool>(3)?,
                        [r.get::<_, i32>(4)?, r.get::<_, i32>(5)?],
                        r.get::<_, Option<i64>>(6)?,
                        r.get::<_, bool>(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((players, ranked, resolved, deltas, winner_set, disputed)) = m else {
            return Ok(rejected);
        };
        if !players.contains(&reporter) || !players.contains(&data.winner) {
            return Ok(rejected);
        }
        let side = usize::from(players[1] == reporter);
        if resolved {
            return Ok(ReportOutcome {
                accepted: true,
                delta: winner_set.map(|_| deltas[side]),
                disputed,
            });
        }
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO reports (match_id, reporter, winner, frames, checksum, inputs)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                match_id as i64,
                reporter as i64,
                data.winner as i64,
                data.frames,
                data.checksum.map(|c| c as i64),
                (!data.inputs.is_empty()).then_some(&data.inputs)
            ],
        )?;
        if inserted == 0 {
            tx.commit()?;
            return Ok(ReportOutcome {
                accepted: true,
                ..Default::default()
            });
        }
        let reports: Vec<ReportData> = {
            let mut st = tx.prepare(
                "SELECT winner, frames, checksum, inputs FROM reports WHERE match_id = ?1 ORDER BY reporter",
            )?;
            st.query_map([match_id as i64], |r| {
                Ok(ReportData {
                    winner: r.get::<_, i64>(0)? as u64,
                    frames: r.get(1)?,
                    checksum: r.get::<_, Option<i64>>(2)?.map(|c| c as u64),
                    inputs: r.get::<_, Option<Vec<u8>>>(3)?.unwrap_or_default(),
                })
            })?
            .collect::<DbResult<_>>()?
        };
        if reports.len() < 2 {
            tx.commit()?;
            return Ok(ReportOutcome {
                accepted: true,
                ..Default::default()
            });
        }
        if !reports_agree(&reports[0], &reports[1]) {
            tx.execute(
                "UPDATE matches SET resolved = 1, disputed = 1 WHERE id = ?1",
                [match_id as i64],
            )?;
            tx.commit()?;
            log::warn!("match {match_id}: reports disagree, marked disputed");
            return Ok(ReportOutcome {
                accepted: true,
                delta: None,
                disputed: true,
            });
        }
        let winner = data.winner;
        let loser = if players[0] == winner {
            players[1]
        } else {
            players[0]
        };
        let mut deltas = [0, 0];
        if ranked {
            let rating = |id: u64| -> DbResult<Option<i32>> {
                tx.query_row(
                    "SELECT rating FROM accounts WHERE id = ?1",
                    [id as i64],
                    |r| r.get(0),
                )
                .optional()
            };
            if let (Some(rw), Some(rl)) = (rating(winner)?, rating(loser)?) {
                let (nw, nl) = elo::update(rw, rl);
                tx.execute(
                    "UPDATE accounts SET rating = ?2, best_rating = MAX(best_rating, ?2), wins = wins + 1 WHERE id = ?1",
                    params![winner as i64, nw],
                )?;
                tx.execute(
                    "UPDATE accounts SET rating = ?2, losses = losses + 1 WHERE id = ?1",
                    params![loser as i64, nl],
                )?;
                let (dw, dl) = (nw - rw, nl - rl);
                deltas = if players[0] == winner {
                    [dw, dl]
                } else {
                    [dl, dw]
                };
            }
            // keep the longer confirmed input stream as the replay
            let inputs = if reports[0].inputs.len() >= reports[1].inputs.len() {
                &reports[0].inputs
            } else {
                &reports[1].inputs
            };
            if !inputs.is_empty() {
                tx.execute(
                    "INSERT OR REPLACE INTO replays (match_id, created, inputs) VALUES (?1, ?2, ?3)",
                    params![match_id as i64, now() as i64, inputs],
                )?;
                tx.execute(
                    "DELETE FROM replays WHERE match_id NOT IN
                     (SELECT match_id FROM replays ORDER BY created DESC, match_id DESC LIMIT ?1)",
                    [REPLAY_RETENTION],
                )?;
            }
        }
        tx.execute(
            "UPDATE matches SET resolved = 1, winner = ?2, delta1 = ?3, delta2 = ?4 WHERE id = ?1",
            params![match_id as i64, winner as i64, deltas[0], deltas[1]],
        )?;
        tx.commit()?;
        Ok(ReportOutcome {
            accepted: true,
            delta: Some(deltas[side]),
            disputed: false,
        })
    }

    /// A stored replay: (players, setup JSON, winner, created, inputs).
    #[allow(clippy::type_complexity)]
    pub fn replay(
        &self,
        match_id: u64,
    ) -> DbResult<Option<([u64; 2], String, Option<u64>, u64, Vec<u8>)>> {
        self.conn
            .query_row(
                "SELECT m.p1, m.p2, m.setup, m.winner, r.created, r.inputs
                 FROM replays r JOIN matches m ON m.id = r.match_id WHERE r.match_id = ?1",
                [match_id as i64],
                |r| {
                    Ok((
                        [r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64],
                        r.get(2)?,
                        r.get::<_, Option<i64>>(3)?.map(|w| w as u64),
                        r.get::<_, i64>(4)? as u64,
                        r.get(5)?,
                    ))
                },
            )
            .optional()
    }

    #[cfg(test)]
    pub fn replay_count(&self) -> DbResult<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM replays", [], |r| r.get(0))
    }

    pub fn leaderboard(&self, limit: usize) -> DbResult<Vec<ProfileInfo>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {ACCOUNT_COLS} FROM accounts WHERE wins + losses > 0
             ORDER BY rating DESC, id ASC LIMIT ?1"
        ))?;
        st.query_map([limit as i64], Account::from_row)?
            .map(|a| a.map(|a| a.info()))
            .collect()
    }

    /// 1-based leaderboard position of a player who has played this season.
    pub fn rank_of(&self, id: u64) -> DbResult<Option<usize>> {
        let Some(a) = self.by_id(id)? else {
            return Ok(None);
        };
        if a.wins + a.losses == 0 {
            return Ok(None);
        }
        let ahead: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM accounts WHERE wins + losses > 0
             AND (rating > ?1 OR (rating = ?1 AND id < ?2))",
            params![a.rating, id as i64],
            |r| r.get(0),
        )?;
        Ok(Some(ahead as usize + 1))
    }

    /// Consistent online copy of the database (`VACUUM INTO`), for backups.
    pub fn backup_to(&self, path: &Path) -> DbResult<()> {
        self.conn
            .execute("VACUUM INTO ?1", [path.to_string_lossy().as_ref()])?;
        Ok(())
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

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("rugen-store-{tag}-{}", random_hex(6)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn win(w: u64) -> ReportData {
        ReportData {
            winner: w,
            ..Default::default()
        }
    }

    fn inputs(frames: usize, flip: Option<usize>) -> Vec<u8> {
        (0..frames)
            .flat_map(|f| {
                let p1 = (f % 7) as u16 ^ if flip == Some(f) { 0x400 } else { 0 };
                let p2 = (f % 5) as u16;
                let mut v = p1.to_le_bytes().to_vec();
                v.extend(p2.to_le_bytes());
                v
            })
            .collect()
    }

    #[test]
    fn agreed_result_moves_ratings_once() {
        let mut s = Store::open(None).unwrap();
        let a = s.register().unwrap().id;
        let b = s.register().unwrap().id;
        let m = s.new_match([a, b], true, "{}").unwrap();
        let r1 = s.report(a, m, &win(a)).unwrap();
        assert!(r1.accepted && r1.delta.is_none());
        let r2 = s.report(b, m, &win(a)).unwrap();
        assert_eq!(r2.delta, Some(-16));
        assert_eq!(s.by_id(a).unwrap().unwrap().rating, 1216);
        assert_eq!(s.by_id(b).unwrap().unwrap().rating, 1184);
        // late duplicate report changes nothing
        assert_eq!(s.report(a, m, &win(a)).unwrap().delta, Some(16));
        assert_eq!(s.by_id(a).unwrap().unwrap().rating, 1216);
        assert_eq!(s.by_id(a).unwrap().unwrap().wins, 1);
        assert_eq!(s.rank_of(a).unwrap(), Some(1));
        assert_eq!(s.rank_of(b).unwrap(), Some(2));
    }

    #[test]
    fn disagreement_is_disputed_and_outsiders_rejected() {
        let mut s = Store::open(None).unwrap();
        let a = s.register().unwrap().id;
        let b = s.register().unwrap().id;
        let c = s.register().unwrap().id;
        let m = s.new_match([a, b], true, "{}").unwrap();
        assert!(!s.report(c, m, &win(a)).unwrap().accepted);
        assert!(!s.report(a, 999_999, &win(a)).unwrap().accepted);
        s.report(a, m, &win(a)).unwrap();
        let r = s.report(b, m, &win(b)).unwrap();
        assert!(r.disputed);
        assert_eq!(s.by_id(a).unwrap().unwrap().rating, 1200);
        assert!(s.report(a, m, &win(a)).unwrap().disputed);
        assert!(s.leaderboard(10).unwrap().is_empty());
    }

    #[test]
    fn input_streams_verify_results_and_become_replays() {
        let mut s = Store::open(None).unwrap();
        let a = s.register().unwrap().id;
        let b = s.register().unwrap().id;
        // same inputs (one side a few unconfirmed frames short), same checksum
        let m = s.new_match([a, b], true, r#"{"p1_char":"kfm"}"#).unwrap();
        let ra = ReportData {
            winner: a,
            frames: 600,
            checksum: Some(42),
            inputs: inputs(600, None),
        };
        let rb = ReportData {
            winner: a,
            frames: 590,
            checksum: Some(7),
            inputs: inputs(590, None),
        };
        s.report(a, m, &ra).unwrap();
        let out = s.report(b, m, &rb).unwrap();
        assert!(!out.disputed);
        assert_eq!(out.delta, Some(-16));
        let (players, setup, winner, _, stored) = s.replay(m).unwrap().unwrap();
        assert_eq!((players, winner), ([a, b], Some(a)));
        assert!(setup.contains("kfm"));
        assert_eq!(stored.len(), 600 * 4);

        // tampered input stream: disputed, ratings untouched
        let m2 = s.new_match([a, b], true, "{}").unwrap();
        s.report(
            a,
            m2,
            &ReportData {
                inputs: inputs(600, Some(100)),
                ..ra.clone()
            },
        )
        .unwrap();
        let out = s.report(b, m2, &rb).unwrap();
        assert!(out.disputed);
        assert_eq!(s.by_id(a).unwrap().unwrap().rating, 1216);

        // same frame, different checksum: disputed
        let m3 = s.new_match([a, b], true, "{}").unwrap();
        s.report(a, m3, &ra).unwrap();
        let out = s
            .report(
                b,
                m3,
                &ReportData {
                    checksum: Some(43),
                    ..ra.clone()
                },
            )
            .unwrap();
        assert!(out.disputed);
        assert_eq!(s.replay_count().unwrap(), 1);
    }

    #[test]
    fn profile_names_are_sanitized() {
        let mut s = Store::open(None).unwrap();
        let id = s.register().unwrap().id;
        let a = s
            .set_profile(id, Some("<script>Bob Z".into()), Some(500))
            .unwrap()
            .unwrap();
        assert_eq!(a.name, "scriptBob Z");
        assert_eq!(a.avatar, 99);
    }

    #[test]
    fn persists_in_wal_file_and_reopens() {
        let dir = temp_dir("persist");
        let (key, id) = {
            let mut s = Store::open(Some(&dir)).unwrap();
            assert_eq!(s.schema_version().unwrap(), MIGRATIONS.len());
            let a = s.register().unwrap();
            s.set_profile(a.id, Some("Ryu".into()), None).unwrap();
            (a.key, a.id)
        };
        let mut s = Store::open(Some(&dir)).unwrap();
        let a = s.by_key(&key).unwrap().unwrap();
        assert_eq!((a.id, a.name.as_str()), (id, "Ryu"));
        assert!(s.by_key(&"0".repeat(64)).unwrap().is_none());
        // ids keep increasing across restarts
        assert!(s.register().unwrap().id > id);
        let mode: String = s
            .conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
        let backup = dir.join("backup.db");
        s.backup_to(&backup).unwrap();
        assert!(backup.exists());
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn imports_legacy_json_state() {
        let dir = temp_dir("import");
        let key = "ab".repeat(32);
        let json = serde_json::json!({
            "accounts": [{
                "id": 1000, "key": key, "name": "OLDTIMER", "avatar": 3,
                "rating": 1350, "best_rating": 1400, "wins": 7, "losses": 2,
                "created": 1, "last_seen": 2
            }],
            "matches": [{
                "id": 1001, "players": [1000, 1000], "ranked": false, "created": 5,
                "reports": [{"reporter": 1000, "winner": 1000}],
                "resolved": false, "winner": null, "deltas": [0, 0]
            }],
            "season": 3,
            "season_start": now() - 10,
            "next_id": 1002
        });
        std::fs::write(dir.join("state.json"), json.to_string()).unwrap();
        let mut s = Store::open(Some(&dir)).unwrap();
        let a = s.by_key(&key).unwrap().unwrap();
        assert_eq!(a.name, "OLDTIMER");
        assert_eq!(a.rating, 1350);
        assert_eq!(s.season().unwrap().number, 3);
        assert_eq!(s.register().unwrap().id, 1002);
        assert!(!dir.join("state.json").exists());
        assert!(dir.join("state.json.migrated").exists());
        drop(s);
        // a second open does not import again
        let s = Store::open(Some(&dir)).unwrap();
        assert_eq!(s.account_count().unwrap(), 2);
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn season_rolls_and_soft_resets() {
        let mut s = Store::open(None).unwrap();
        let a = s.register().unwrap().id;
        s.conn
            .execute("UPDATE accounts SET rating = 1600, wins = 3", [])
            .unwrap();
        s.set_meta("season_start", (now() - SEASON_SECS - 5) as i64)
            .unwrap();
        s.roll_season().unwrap();
        assert_eq!(s.season().unwrap().number, 2);
        let acc = s.by_id(a).unwrap().unwrap();
        assert_eq!((acc.rating, acc.wins), (1400, 0));
    }
}
