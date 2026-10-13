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
    // v3: bring-your-own-character: temporary content packages, community
    // ratings per character fingerprint, anti-cheat flags, desync reports
    "CREATE TABLE packages (
         fingerprint TEXT PRIMARY KEY,
         kind TEXT NOT NULL,
         size INTEGER NOT NULL,
         name TEXT NOT NULL DEFAULT '',
         author TEXT NOT NULL DEFAULT '',
         def TEXT NOT NULL,
         profile TEXT,
         uploader INTEGER NOT NULL DEFAULT 0,
         created INTEGER NOT NULL,
         last_used INTEGER NOT NULL,
         keep_until INTEGER NOT NULL DEFAULT 0
     );
     CREATE INDEX packages_lru ON packages(last_used);
     CREATE TABLE char_ratings (
         fingerprint TEXT PRIMARY KEY,
         name TEXT NOT NULL DEFAULT '',
         rating INTEGER NOT NULL,
         games INTEGER NOT NULL DEFAULT 0,
         wins INTEGER NOT NULL DEFAULT 0
     );
     CREATE TABLE flags (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         account INTEGER NOT NULL,
         match_id INTEGER,
         reason TEXT NOT NULL,
         created INTEGER NOT NULL
     );
     ALTER TABLE matches ADD COLUMN desync INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE matches ADD COLUMN resim TEXT;",
    // v4: official server: fingerprint blocklist (operator + automatic
    // entries; `allowed` = cleared by the operator, never re-added
    // automatically) and the fingerprint a flagged lie was about
    "CREATE TABLE blocklist (
         fingerprint TEXT PRIMARY KEY,
         reason TEXT NOT NULL,
         source TEXT NOT NULL,
         allowed INTEGER NOT NULL DEFAULT 0,
         created INTEGER NOT NULL
     );
     ALTER TABLE flags ADD COLUMN fingerprint TEXT;
     CREATE INDEX flags_fingerprint ON flags(fingerprint);",
    // v5: matches that end early: a report's `ending` (flee / disconnect)
    // and when it came; the settled ending and the account that left
    "ALTER TABLE reports ADD COLUMN ending TEXT;
     ALTER TABLE reports ADD COLUMN at INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE matches ADD COLUMN ending TEXT;
     ALTER TABLE matches ADD COLUMN fled INTEGER;",
];

/// Rating every character fingerprint starts from.
pub const CHAR_START_RATING: i32 = 1500;
/// Elo K of community character ratings.
pub const CHAR_K: f64 = 16.0;

/// A stored content package (metadata; the bytes live in `packages/`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PackageRow {
    pub fingerprint: String,
    pub kind: String,
    pub size: u64,
    pub name: String,
    pub author: String,
    pub def: String,
    /// Server-computed fairness profile (characters).
    pub profile: Option<rugen_proto::FairnessProfile>,
    pub uploader: u64,
    pub created: u64,
    pub last_used: u64,
    /// Kept at least until then (ranked replays), Unix seconds.
    pub keep_until: u64,
}

impl PackageRow {
    fn from_row(r: &Row<'_>) -> DbResult<Self> {
        let profile: Option<String> = r.get(6)?;
        Ok(Self {
            fingerprint: r.get(0)?,
            kind: r.get(1)?,
            size: r.get::<_, i64>(2)? as u64,
            name: r.get(3)?,
            author: r.get(4)?,
            def: r.get(5)?,
            profile: profile.and_then(|p| serde_json::from_str(&p).ok()),
            uploader: r.get::<_, i64>(7)? as u64,
            created: r.get::<_, i64>(8)? as u64,
            last_used: r.get::<_, i64>(9)? as u64,
            keep_until: r.get::<_, i64>(10)? as u64,
        })
    }
}

const PACKAGE_COLS: &str =
    "fingerprint, kind, size, name, author, def, profile, uploader, created, last_used, keep_until";

/// The character / stage fingerprints a match was set up with (`setup` JSON).
pub fn setup_fingerprints(setup: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(setup).unwrap_or_default();
    ["p1_fp", "p2_fp", "stage_fp"]
        .iter()
        .filter_map(|k| v.get(*k).and_then(|x| x.as_str()))
        .filter(|s| rugen_proto::is_fingerprint(s))
        .map(str::to_string)
        .collect()
}

/// How long packages of a stored ranked replay are kept (`RUGEN_PKG_REPLAY_TTL`
/// hours, default 30 days).
pub fn replay_keep_secs() -> u64 {
    std::env::var("RUGEN_PKG_REPLAY_TTL")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map_or(30 * 24 * 3600, |h| h * 3600)
}

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
    /// `(frame, world checksum)` every 60 frames (clients with TURN support).
    pub checksums: Vec<(u32, u64)>,
    /// The match ended early ([`rugen_proto::Ending`]): with the other
    /// player as the winner a forfeit (settled at once), with the reporter
    /// as the winner a claim the server checks against the relay
    /// ([`Store::pending_claims`]).
    pub ending: Option<rugen_proto::Ending>,
}

/// Outcome of [`Store::report`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReportOutcome {
    pub accepted: bool,
    /// Rating change for the reporter once both sides agreed.
    pub delta: Option<i32>,
    pub disputed: bool,
}

/// A report that claims the other player fled or disconnected, still
/// waiting for the server to see it on the relay.
#[derive(Clone, Debug, PartialEq)]
pub struct Claim {
    pub match_id: u64,
    /// The claimant (it reported itself as the winner).
    pub winner: u64,
    pub ending: rugen_proto::Ending,
    /// When the claim arrived (Unix seconds).
    pub at: u64,
}

/// How a settled match ended: `(ending, account that left)`.
pub type EndingRow = Option<(String, Option<u64>)>;

/// Do two reports describe the same match? Inputs must agree on their
/// common confirmed prefix, checksums when taken at the same frame.
fn report_row(r: &Row<'_>) -> DbResult<ReportData> {
    Ok(ReportData {
        winner: r.get::<_, i64>(0)? as u64,
        frames: r.get(1)?,
        checksum: r.get::<_, Option<i64>>(2)?.map(|c| c as u64),
        inputs: r.get::<_, Option<Vec<u8>>>(3)?.unwrap_or_default(),
        checksums: checksums_col(r.get(4)?),
        ending: r
            .get::<_, Option<String>>(5)?
            .and_then(|e| rugen_proto::Ending::parse(&e)),
    })
}

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
    // periodic checksums on the frames both confirmed
    let below = a
        .frames
        .min(b.frames)
        .saturating_sub(UNCONFIRMED_TAIL as u32);
    rugen_proto::evidence::checksums_agree(&a.checksums, &b.checksums, below)
}

pub struct Store {
    conn: Connection,
}

/// One month of TURN accounting (bytes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TurnMonth {
    /// Conservative estimate: reservations of issued credentials, settled
    /// down to the reported usage (times a safety factor) when they end.
    pub reserved: u64,
    /// What clients reported moving through TURN.
    pub reported: u64,
    /// Cloudflare's own analytics (when configured).
    pub cloudflare: u64,
    pub credentials: u64,
}

impl TurnMonth {
    /// The number the budget is checked against.
    pub fn used(&self) -> u64 {
        self.reserved.max(self.cloudflare).max(self.reported)
    }
}

fn checksums_col(b: Option<Vec<u8>>) -> Vec<(u32, u64)> {
    b.and_then(|b| rugen_proto::evidence::decode_checksums(&b))
        .unwrap_or_default()
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
        s.ensure_turn_schema()?;
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

    /// TURN budget table and the periodic-checksum column of reports.
    /// Idempotent and outside [`MIGRATIONS`] on purpose (no schema version
    /// clash with other branches; fold into a migration when convenient).
    fn ensure_turn_schema(&self) -> DbResult<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS turn_usage (
                 month TEXT PRIMARY KEY,
                 reserved INTEGER NOT NULL DEFAULT 0,
                 reported INTEGER NOT NULL DEFAULT 0,
                 cloudflare INTEGER NOT NULL DEFAULT 0,
                 credentials INTEGER NOT NULL DEFAULT 0
             );",
        )?;
        let has = self
            .conn
            .prepare("SELECT 1 FROM pragma_table_info('reports') WHERE name = 'checksums'")?
            .exists([])?;
        if !has {
            self.conn
                .execute_batch("ALTER TABLE reports ADD COLUMN checksums BLOB;")?;
        }
        Ok(())
    }

    /// P1 and P2 of a match.
    pub fn match_players(&self, match_id: u64) -> DbResult<Option<[u64; 2]>> {
        self.conn
            .query_row(
                "SELECT p1, p2 FROM matches WHERE id = ?1",
                [match_id as i64],
                |r| Ok([r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64]),
            )
            .optional()
    }

    /// TURN usage of a month (`YYYY-MM`, UTC).
    pub fn turn_usage(&self, month: &str) -> DbResult<TurnMonth> {
        Ok(self
            .conn
            .query_row(
                "SELECT reserved, reported, cloudflare, credentials FROM turn_usage WHERE month = ?1",
                [month],
                |r| {
                    Ok(TurnMonth {
                        reserved: r.get::<_, i64>(0)?.max(0) as u64,
                        reported: r.get::<_, i64>(1)?.max(0) as u64,
                        cloudflare: r.get::<_, i64>(2)?.max(0) as u64,
                        credentials: r.get::<_, i64>(3)?.max(0) as u64,
                    })
                },
            )
            .optional()?
            .unwrap_or_default())
    }

    /// Add to a month's TURN accounting (`reserved` may be negative: a
    /// settled credential gives back part of its reservation).
    pub fn turn_add(
        &self,
        month: &str,
        reserved: i64,
        reported: u64,
        credentials: u64,
    ) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO turn_usage (month, reserved, reported, credentials) VALUES (?1, MAX(?2, 0), ?3, ?4)
             ON CONFLICT(month) DO UPDATE SET reserved = MAX(reserved + ?2, 0),
                 reported = reported + ?3, credentials = credentials + ?4",
            params![month, reserved, reported as i64, credentials as i64],
        )?;
        Ok(())
    }

    /// Usage Cloudflare's analytics report for a month (bytes, both ways).
    pub fn turn_set_cloudflare(&self, month: &str, bytes: u64) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO turn_usage (month, cloudflare) VALUES (?1, ?2)
             ON CONFLICT(month) DO UPDATE SET cloudflare = MAX(cloudflare, ?2)",
            params![month, bytes as i64],
        )?;
        Ok(())
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

    /// Accounts whose name starts with `prefix` (load-test leftovers) and
    /// their unranked matches (reports / replays cascade): counted only when
    /// `dry_run`, deleted otherwise. Ranked matches are kept (they moved
    /// other players' ratings). Returns (accounts, matches).
    pub fn delete_accounts_by_prefix(
        &mut self,
        prefix: &str,
        dry_run: bool,
    ) -> DbResult<(usize, usize)> {
        let esc: String = prefix
            .chars()
            .flat_map(|c| match c {
                '%' | '_' | '\\' => vec!['\\', c],
                c => vec![c],
            })
            .collect();
        let pattern = format!("{esc}%");
        let tx = self.conn.transaction()?;
        tx.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS doomed (id INTEGER PRIMARY KEY); DELETE FROM doomed;",
        )?;
        let accounts = tx.execute(
            "INSERT INTO doomed (id) SELECT id FROM accounts WHERE name LIKE ?1 ESCAPE '\\'",
            [&pattern],
        )?;
        let matches: usize = tx.query_row(
            "SELECT COUNT(*) FROM matches WHERE ranked = 0
               AND (p1 IN (SELECT id FROM doomed) OR p2 IN (SELECT id FROM doomed))",
            [],
            |r| r.get::<_, i64>(0),
        )? as usize;
        if !dry_run {
            tx.execute(
                "DELETE FROM matches WHERE ranked = 0
                   AND (p1 IN (SELECT id FROM doomed) OR p2 IN (SELECT id FROM doomed))",
                [],
            )?;
            tx.execute(
                "DELETE FROM flags WHERE account IN (SELECT id FROM doomed)",
                [],
            )?;
            tx.execute(
                "DELETE FROM accounts WHERE id IN (SELECT id FROM doomed)",
                [],
            )?;
        }
        tx.execute_batch("DROP TABLE doomed;")?;
        tx.commit()?;
        Ok((accounts, matches))
    }

    /// Both sides reported (or the match was otherwise settled).
    pub fn match_resolved(&self, match_id: u64) -> DbResult<bool> {
        self.conn
            .prepare_cached("SELECT resolved FROM matches WHERE id = ?1")?
            .query_row([match_id as i64], |r| r.get::<_, bool>(0))
            .optional()
            .map(|r| r.unwrap_or(false))
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

    /// The account owning `key`; refreshes its `last_seen` (written at
    /// most once a minute: this runs on every authenticated call).
    pub fn by_key(&mut self, key: &str) -> DbResult<Option<Account>> {
        let a = self
            .conn
            .prepare_cached(&format!(
                "SELECT {ACCOUNT_COLS} FROM accounts WHERE key = ?1"
            ))?
            .query_row([key], Account::from_row)
            .optional()?;
        let Some(mut a) = a else { return Ok(None) };
        let t = now();
        if a.last_seen + 60 <= t {
            self.conn
                .prepare_cached("UPDATE accounts SET last_seen = ?2 WHERE id = ?1")?
                .execute(params![a.id as i64, t as i64])?;
            a.last_seen = t;
        }
        Ok(Some(a))
    }

    pub fn by_id(&self, id: u64) -> DbResult<Option<Account>> {
        self.conn
            .prepare_cached(&format!(
                "SELECT {ACCOUNT_COLS} FROM accounts WHERE id = ?1"
            ))?
            .query_row([id as i64], Account::from_row)
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

    /// Replace a match's setup JSON (fingerprints become known at start).
    pub fn set_setup(&mut self, match_id: u64, setup: &str) -> DbResult<()> {
        self.conn.execute(
            "UPDATE matches SET setup = ?2 WHERE id = ?1",
            params![match_id as i64, setup],
        )?;
        Ok(())
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
                "SELECT p1, p2, ranked, resolved, delta1, delta2, winner, disputed, desync, setup FROM matches WHERE id = ?1",
                [match_id as i64],
                |r| {
                    Ok((
                        [r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64],
                        r.get::<_, bool>(2)?,
                        r.get::<_, bool>(3)?,
                        [r.get::<_, i32>(4)?, r.get::<_, i32>(5)?],
                        r.get::<_, Option<i64>>(6)?,
                        r.get::<_, bool>(7)?,
                        r.get::<_, bool>(8)?,
                        r.get::<_, String>(9)?,
                    ))
                },
            )
            .optional()?;
        let Some((players, ranked, resolved, deltas, winner_set, disputed, desync, setup)) = m
        else {
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
            "INSERT OR IGNORE INTO reports (match_id, reporter, winner, frames, checksum, inputs, checksums, ending, at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                match_id as i64,
                reporter as i64,
                data.winner as i64,
                data.frames,
                data.checksum.map(|c| c as i64),
                (!data.inputs.is_empty()).then_some(&data.inputs),
                (!data.checksums.is_empty())
                    .then(|| rugen_proto::evidence::encode_checksums(&data.checksums)),
                data.ending.map(|e| e.as_str()),
                now() as i64
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
                "SELECT winner, frames, checksum, inputs, checksums, ending FROM reports WHERE match_id = ?1 ORDER BY reporter",
            )?;
            st.query_map([match_id as i64], report_row)?
                .collect::<DbResult<_>>()?
        };
        // a forfeit: the reporter names the other player as the winner of
        // a match it left; nobody else needs to agree to a loss
        if reports.len() < 2 && data.ending.is_some() && data.winner != reporter {
            let deltas = Self::settle(
                &tx,
                match_id,
                players,
                ranked,
                &setup,
                data.winner,
                &data.inputs,
            )?;
            Self::set_ending(&tx, match_id, data.ending, Some(reporter))?;
            tx.commit()?;
            log::info!("match {match_id}: {reporter} fled, {} wins", data.winner);
            return Ok(ReportOutcome {
                accepted: true,
                delta: Some(deltas[side]),
                disputed: false,
            });
        }
        if reports.len() < 2 {
            tx.commit()?;
            return Ok(ReportOutcome {
                accepted: true,
                ..Default::default()
            });
        }
        if desync || !reports_agree(&reports[0], &reports[1]) {
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
        let inputs = if reports[0].inputs.len() >= reports[1].inputs.len() {
            reports[0].inputs.clone()
        } else {
            reports[1].inputs.clone()
        };
        let deltas = Self::settle(&tx, match_id, players, ranked, &setup, data.winner, &inputs)?;
        // both agree on the winner; either may say the loser left early
        if let Some(e) = reports.iter().find_map(|r| r.ending) {
            let loser = players.into_iter().find(|&p| p != data.winner);
            Self::set_ending(&tx, match_id, Some(e), loser)?;
        }
        tx.commit()?;
        Ok(ReportOutcome {
            accepted: true,
            delta: Some(deltas[side]),
            disputed: false,
        })
    }

    /// Apply a decided result: player ratings (ranked), the community
    /// ratings of both character fingerprints, the replay (ranked, keeping
    /// its packages longer) and the resolved flag.
    fn settle(
        tx: &rusqlite::Transaction<'_>,
        match_id: u64,
        players: [u64; 2],
        ranked: bool,
        setup: &str,
        winner: u64,
        inputs: &[u8],
    ) -> DbResult<[i32; 2]> {
        let loser = if players[0] == winner {
            players[1]
        } else {
            players[0]
        };
        let fps = setup_fingerprints(setup);
        let v: serde_json::Value = serde_json::from_str(setup).unwrap_or_default();
        let fp = |k: &str| {
            v.get(k)
                .and_then(|x| x.as_str())
                .filter(|s| rugen_proto::is_fingerprint(s))
                .map(str::to_string)
        };
        if let (Some(f1), Some(f2)) = (fp("p1_fp"), fp("p2_fp"))
            && f1 != f2
        {
            let name = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
            let ((fw, nw), (fl, nl)) = if players[0] == winner {
                ((f1, name("p1_char")), (f2, name("p2_char")))
            } else {
                ((f2, name("p2_char")), (f1, name("p1_char")))
            };
            for (f, n) in [(&fw, &nw), (&fl, &nl)] {
                tx.execute(
                    "INSERT OR IGNORE INTO char_ratings (fingerprint, name, rating) VALUES (?1, ?2, ?3)",
                    params![f, n, CHAR_START_RATING],
                )?;
            }
            let get = |f: &str| -> DbResult<i32> {
                tx.query_row(
                    "SELECT rating FROM char_ratings WHERE fingerprint = ?1",
                    [f],
                    |r| r.get(0),
                )
            };
            let (rw, rl) = elo::update_k(get(&fw)?, get(&fl)?, CHAR_K);
            tx.execute(
                "UPDATE char_ratings SET rating = ?2, games = games + 1, wins = wins + 1 WHERE fingerprint = ?1",
                params![fw, rw],
            )?;
            tx.execute(
                "UPDATE char_ratings SET rating = ?2, games = games + 1 WHERE fingerprint = ?1",
                params![fl, rl],
            )?;
        }
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
                // the replay's files stay on the server longer
                for f in &fps {
                    tx.execute(
                        "UPDATE packages SET keep_until = MAX(keep_until, ?2) WHERE fingerprint = ?1",
                        params![f, (now() + replay_keep_secs()) as i64],
                    )?;
                }
            }
        }
        tx.execute(
            "UPDATE matches SET resolved = 1, disputed = 0, winner = ?2, delta1 = ?3, delta2 = ?4 WHERE id = ?1",
            params![match_id as i64, winner as i64, deltas[0], deltas[1]],
        )?;
        Ok(deltas)
    }

    fn set_ending(
        tx: &rusqlite::Transaction<'_>,
        match_id: u64,
        ending: Option<rugen_proto::Ending>,
        fled: Option<u64>,
    ) -> DbResult<()> {
        tx.execute(
            "UPDATE matches SET ending = ?2, fled = ?3 WHERE id = ?1",
            params![
                match_id as i64,
                ending.map(|e| e.as_str()),
                fled.map(|f| f as i64)
            ],
        )?;
        Ok(())
    }

    /// Unsettled matches with a single report, from the player who says it
    /// won because the other one fled or disconnected.
    pub fn pending_claims(&self) -> DbResult<Vec<Claim>> {
        let mut st = self.conn.prepare(
            "SELECT r.match_id, r.reporter, r.ending, r.at FROM reports r
             JOIN matches m ON m.id = r.match_id
             WHERE m.resolved = 0 AND r.ending IS NOT NULL AND r.winner = r.reporter
               AND (SELECT COUNT(*) FROM reports x WHERE x.match_id = r.match_id) = 1",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)? as u64,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)? as u64,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (match_id, winner, ending, at) = row?;
            if let Some(ending) = rugen_proto::Ending::parse(&ending) {
                out.push(Claim {
                    match_id,
                    winner,
                    ending,
                    at,
                });
            }
        }
        Ok(out)
    }

    /// Settle a claim the server confirmed on its own view of the relay:
    /// the claimant wins, the other player fled / disconnected. `None`
    /// when the match is no longer a pending claim (settled meanwhile, or
    /// the other report arrived: agreement or dispute decide then).
    pub fn settle_claim(&mut self, c: &Claim) -> DbResult<Option<[i32; 2]>> {
        let tx = self.conn.transaction()?;
        if !Self::pending_claims_tx(&tx, c)? {
            return Ok(None);
        }
        let (players, ranked, setup) = tx.query_row(
            "SELECT p1, p2, ranked, setup FROM matches WHERE id = ?1",
            [c.match_id as i64],
            |r| {
                Ok((
                    [r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64],
                    r.get::<_, bool>(2)?,
                    r.get::<_, String>(3)?,
                ))
            },
        )?;
        let inputs: Option<Vec<u8>> = tx.query_row(
            "SELECT inputs FROM reports WHERE match_id = ?1 AND reporter = ?2",
            params![c.match_id as i64, c.winner as i64],
            |r| r.get(0),
        )?;
        let deltas = Self::settle(
            &tx,
            c.match_id,
            players,
            ranked,
            &setup,
            c.winner,
            &inputs.unwrap_or_default(),
        )?;
        let loser = players.into_iter().find(|&p| p != c.winner);
        Self::set_ending(&tx, c.match_id, Some(c.ending), loser)?;
        tx.commit()?;
        Ok(Some(deltas))
    }

    /// Still unsettled with only the claimant's report?
    fn pending_claims_tx(tx: &rusqlite::Transaction<'_>, c: &Claim) -> DbResult<bool> {
        let n: i64 = tx.query_row(
            "SELECT COUNT(*) FROM reports r JOIN matches m ON m.id = r.match_id
             WHERE r.match_id = ?1 AND m.resolved = 0 AND r.reporter = ?2 AND r.ending IS NOT NULL
               AND (SELECT COUNT(*) FROM reports x WHERE x.match_id = r.match_id) = 1",
            params![c.match_id as i64, c.winner as i64],
            |r| r.get(0),
        )?;
        Ok(n == 1)
    }

    /// How a settled match ended early (`None` for a match played out).
    pub fn match_ending(&self, match_id: u64) -> DbResult<EndingRow> {
        let row = self
            .conn
            .query_row(
                "SELECT ending, fled FROM matches WHERE id = ?1",
                [match_id as i64],
                |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<i64>>(1)?)),
            )
            .optional()?;
        Ok(row.and_then(|(e, f)| e.map(|e| (e, f.map(|f| f as u64)))))
    }

    /// A client saw a desync (ggrs checksum mismatch): the match can no
    /// longer resolve by agreement.
    pub fn report_desync(&mut self, reporter: u64, match_id: u64, frame: u32) -> DbResult<bool> {
        let n = self.conn.execute(
            "UPDATE matches SET desync = 1 WHERE id = ?1 AND (p1 = ?2 OR p2 = ?2)",
            params![match_id as i64, reporter as i64],
        )?;
        if n > 0 {
            self.conn.execute(
                "UPDATE matches SET disputed = 1 WHERE id = ?1 AND resolved = 1 AND winner IS NULL",
                [match_id as i64],
            )?;
            log::warn!("match {match_id}: desync reported by {reporter} at frame {frame}");
        }
        Ok(n > 0)
    }

    /// A disputed match the server re-simulated: settle it with the
    /// simulated winner (`None` = undecidable, stays disputed).
    pub fn resolve_dispute(
        &mut self,
        match_id: u64,
        winner: Option<u64>,
        note: &str,
    ) -> DbResult<bool> {
        let tx = self.conn.transaction()?;
        let m = tx
            .query_row(
                "SELECT p1, p2, ranked, setup, disputed, winner FROM matches WHERE id = ?1",
                [match_id as i64],
                |r| {
                    Ok((
                        [r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64],
                        r.get::<_, bool>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, bool>(4)?,
                        r.get::<_, Option<i64>>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((players, ranked, setup, disputed, set)) = m else {
            return Ok(false);
        };
        tx.execute(
            "UPDATE matches SET resim = ?2 WHERE id = ?1",
            params![match_id as i64, note],
        )?;
        let settled = match winner {
            Some(w) if disputed && set.is_none() && players.contains(&w) => {
                let inputs: Vec<u8> = tx
                    .query_row(
                        "SELECT inputs FROM reports WHERE match_id = ?1 AND inputs IS NOT NULL
                         ORDER BY length(inputs) DESC LIMIT 1",
                        [match_id as i64],
                        |r| r.get(0),
                    )
                    .optional()?
                    .unwrap_or_default();
                Self::settle(&tx, match_id, players, ranked, &setup, w, &inputs)?;
                true
            }
            _ => false,
        };
        tx.commit()?;
        Ok(settled)
    }

    /// Setup JSON, ranked flag, players and the reports (reporter, data) of a match.
    #[allow(clippy::type_complexity)]
    pub fn match_evidence(
        &self,
        match_id: u64,
    ) -> DbResult<Option<(String, bool, [u64; 2], Vec<(u64, ReportData)>)>> {
        let Some((setup, ranked, players)) = self
            .conn
            .query_row(
                "SELECT setup, ranked, p1, p2 FROM matches WHERE id = ?1",
                [match_id as i64],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, bool>(1)?,
                        [r.get::<_, i64>(2)? as u64, r.get::<_, i64>(3)? as u64],
                    ))
                },
            )
            .optional()?
        else {
            return Ok(None);
        };
        let mut st = self.conn.prepare(
            "SELECT reporter, winner, frames, checksum, inputs, checksums FROM reports WHERE match_id = ?1 ORDER BY reporter",
        )?;
        let reports = st
            .query_map([match_id as i64], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u64,
                    ReportData {
                        winner: r.get::<_, i64>(1)? as u64,
                        frames: r.get(2)?,
                        checksum: r.get::<_, Option<i64>>(3)?.map(|c| c as u64),
                        inputs: r.get::<_, Option<Vec<u8>>>(4)?.unwrap_or_default(),
                        checksums: checksums_col(r.get(5)?),
                        ending: None,
                    },
                ))
            })?
            .collect::<DbResult<Vec<_>>>()?;
        Ok(Some((setup, ranked, players, reports)))
    }

    /// Is a match disputed (and unresolved by agreement)?
    pub fn is_disputed(&self, match_id: u64) -> DbResult<bool> {
        self.conn
            .query_row(
                "SELECT disputed FROM matches WHERE id = ?1",
                [match_id as i64],
                |r| r.get(0),
            )
            .optional()
            .map(|d| d.unwrap_or(false))
    }

    // ---- packages, community ratings, flags

    pub fn package(&self, fp: &str) -> DbResult<Option<PackageRow>> {
        self.conn
            .query_row(
                &format!("SELECT {PACKAGE_COLS} FROM packages WHERE fingerprint = ?1"),
                [fp],
                PackageRow::from_row,
            )
            .optional()
    }

    pub fn put_package(&mut self, p: &PackageRow) -> DbResult<()> {
        let profile = p
            .profile
            .as_ref()
            .and_then(|p| serde_json::to_string(p).ok());
        self.conn.execute(
            &format!(
                "INSERT OR REPLACE INTO packages ({PACKAGE_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
            ),
            params![
                p.fingerprint,
                p.kind,
                p.size as i64,
                p.name,
                p.author,
                p.def,
                profile,
                p.uploader as i64,
                p.created as i64,
                p.last_used as i64,
                p.keep_until as i64
            ],
        )?;
        Ok(())
    }

    /// Mark packages as used now (TTL / LRU bookkeeping).
    pub fn touch_packages(&mut self, fps: &[&str]) -> DbResult<()> {
        for f in fps {
            self.conn.execute(
                "UPDATE packages SET last_used = ?2 WHERE fingerprint = ?1",
                params![f, now() as i64],
            )?;
        }
        Ok(())
    }

    /// All packages, least recently used first.
    pub fn packages_lru(&self) -> DbResult<Vec<PackageRow>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {PACKAGE_COLS} FROM packages ORDER BY last_used ASC, fingerprint"
        ))?;
        st.query_map([], PackageRow::from_row)?.collect()
    }

    pub fn delete_package(&mut self, fp: &str) -> DbResult<()> {
        self.conn
            .execute("DELETE FROM packages WHERE fingerprint = ?1", [fp])?;
        Ok(())
    }

    pub fn char_rating(&self, fp: &str) -> DbResult<Option<rugen_proto::CharRating>> {
        self.conn
            .query_row(
                "SELECT rating, games, wins FROM char_ratings WHERE fingerprint = ?1",
                [fp],
                |r| {
                    Ok(rugen_proto::CharRating {
                        rating: r.get(0)?,
                        games: r.get(1)?,
                        wins: r.get(2)?,
                    })
                },
            )
            .optional()
    }

    /// Record an anti-cheat finding against an account; `fingerprint` =
    /// the content a false profile was declared for (feeds auto-blocking).
    pub fn flag(
        &mut self,
        account: u64,
        match_id: Option<u64>,
        reason: &str,
        fingerprint: Option<&str>,
    ) -> DbResult<()> {
        log::warn!("flag: account {account}: {reason}");
        self.conn.execute(
            "INSERT INTO flags (account, match_id, reason, created, fingerprint) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                account as i64,
                match_id.map(|m| m as i64),
                reason,
                now() as i64,
                fingerprint
            ],
        )?;
        Ok(())
    }

    /// Distinct accounts flagged for a false profile of `fp`.
    pub fn liars_for(&self, fp: &str) -> DbResult<u32> {
        self.conn.query_row(
            "SELECT COUNT(DISTINCT account) FROM flags WHERE fingerprint = ?1",
            [fp],
            |r| r.get(0),
        )
    }

    /// Matches with a reported desync that `fp` was part of.
    pub fn desyncs_for(&self, fp: &str) -> DbResult<u32> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM matches WHERE desync = 1 AND instr(setup, ?1) > 0",
            [fp],
            |r| r.get(0),
        )
    }

    // ---- blocklist (published in the truth feed)

    /// Changes whenever the blocklist does (feed `sequence`).
    pub fn truth_seq(&self) -> DbResult<u64> {
        Ok(self.meta("truth_seq")?.unwrap_or(0) as u64)
    }

    /// Next sequence: at least the current Unix time, so that a database
    /// restored from an older backup still publishes newer sequences than
    /// anything clients already hold once the blocklist changes again.
    fn bump_truth_seq(&self) -> DbResult<()> {
        let n = (self.truth_seq()? + 1).max(now());
        self.set_meta("truth_seq", n as i64)
    }

    /// Block a fingerprint (operator): replaces any entry, clears `allowed`.
    pub fn block(&mut self, fp: &str, reason: &str, source: &str) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO blocklist (fingerprint, reason, source, allowed, created) VALUES (?1, ?2, ?3, 0, ?4)
             ON CONFLICT(fingerprint) DO UPDATE SET reason = ?2, source = ?3, allowed = 0, created = ?4",
            params![fp, reason, source, now() as i64],
        )?;
        self.bump_truth_seq()
    }

    /// Automatic block: only when the fingerprint has no entry at all (an
    /// operator-cleared one stays cleared). True when it was added.
    pub fn auto_block(&mut self, fp: &str, reason: &str) -> DbResult<bool> {
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO blocklist (fingerprint, reason, source, allowed, created) VALUES (?1, ?2, 'auto', 0, ?3)",
            params![fp, reason, now() as i64],
        )?;
        if n > 0 {
            log::warn!(
                "blocklist: {} auto-blocked: {reason}",
                rugen_fair::short(fp)
            );
            self.bump_truth_seq()?;
        }
        Ok(n > 0)
    }

    /// Clear a fingerprint (operator). The row stays as `allowed` so that
    /// automatic rules never block it again. True when it was blocked.
    pub fn unblock(&mut self, fp: &str) -> DbResult<bool> {
        let was = self.blocked(fp)?.is_some();
        self.conn.execute(
            "INSERT INTO blocklist (fingerprint, reason, source, allowed, created) VALUES (?1, 'cleared', 'admin', 1, ?2)
             ON CONFLICT(fingerprint) DO UPDATE SET allowed = 1",
            params![fp, now() as i64],
        )?;
        self.bump_truth_seq()?;
        Ok(was)
    }

    pub fn blocked(&self, fp: &str) -> DbResult<Option<rugen_proto::BlockEntry>> {
        self.conn
            .query_row(
                "SELECT fingerprint, reason, created, source FROM blocklist WHERE fingerprint = ?1 AND allowed = 0",
                [fp],
                Self::block_row,
            )
            .optional()
    }

    /// Every blocked fingerprint, oldest first.
    pub fn blocklist(&self) -> DbResult<Vec<rugen_proto::BlockEntry>> {
        let mut st = self.conn.prepare(
            "SELECT fingerprint, reason, created, source FROM blocklist WHERE allowed = 0 ORDER BY created, fingerprint",
        )?;
        st.query_map([], Self::block_row)?.collect()
    }

    fn block_row(r: &Row<'_>) -> DbResult<rugen_proto::BlockEntry> {
        Ok(rugen_proto::BlockEntry {
            fingerprint: r.get(0)?,
            reason: r.get(1)?,
            since: r.get::<_, i64>(2)? as u64,
            source: r.get(3)?,
        })
    }

    /// Community ratings for the feed, most played first.
    pub fn feed_ratings(&self, limit: usize) -> DbResult<Vec<rugen_proto::FeedRating>> {
        let mut st = self.conn.prepare(
            "SELECT fingerprint, rating, games, wins FROM char_ratings WHERE games > 0
             ORDER BY games DESC, fingerprint LIMIT ?1",
        )?;
        st.query_map([limit as i64], |r| {
            Ok(rugen_proto::FeedRating {
                fingerprint: r.get(0)?,
                rating: r.get(1)?,
                games: r.get(2)?,
                wins: r.get(3)?,
            })
        })?
        .collect()
    }

    /// A match as seen by `account`: (ranked, players, winner, delta of the
    /// account, disputed). None when it is not the account's match.
    #[allow(clippy::type_complexity)]
    pub fn match_result(
        &self,
        match_id: u64,
        account: u64,
    ) -> DbResult<Option<(bool, [u64; 2], Option<u64>, i32, bool)>> {
        let row = self
            .conn
            .query_row(
                "SELECT ranked, p1, p2, winner, delta1, delta2, disputed FROM matches WHERE id = ?1",
                [match_id as i64],
                |r| {
                    Ok((
                        r.get::<_, bool>(0)?,
                        [r.get::<_, i64>(1)? as u64, r.get::<_, i64>(2)? as u64],
                        r.get::<_, Option<i64>>(3)?.map(|w| w as u64),
                        [r.get::<_, i32>(4)?, r.get::<_, i32>(5)?],
                        r.get::<_, bool>(6)?,
                    ))
                },
            )
            .optional()?;
        Ok(row.and_then(|(ranked, players, winner, deltas, disputed)| {
            let side = players.iter().position(|&p| p == account)?;
            Some((ranked, players, winner, deltas[side], disputed))
        }))
    }

    /// Test: make a match's reports `secs` older.
    #[cfg(test)]
    pub fn age_reports(&self, match_id: u64, secs: i64) -> DbResult<()> {
        self.conn.execute(
            "UPDATE reports SET at = at - ?2 WHERE match_id = ?1",
            params![match_id as i64, secs],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub fn flags_of(&self, account: u64) -> DbResult<Vec<String>> {
        let mut st = self
            .conn
            .prepare("SELECT reason FROM flags WHERE account = ?1 ORDER BY id")?;
        st.query_map([account as i64], |r| r.get(0))?.collect()
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

    fn ended(w: u64, e: rugen_proto::Ending) -> ReportData {
        ReportData {
            winner: w,
            frames: 300,
            inputs: inputs(300, None),
            ending: Some(e),
            ..Default::default()
        }
    }

    #[test]
    fn a_forfeit_settles_at_once_as_a_loss() {
        use rugen_proto::Ending;
        let mut s = Store::open(None).unwrap();
        let a = s.register().unwrap().id;
        let b = s.register().unwrap().id;
        let m = s.new_match([a, b], true, "{}").unwrap();
        // b flees: it reports a as the winner of the match it left
        let out = s.report(b, m, &ended(a, Ending::Flee)).unwrap();
        assert_eq!(out.delta, Some(-16), "a normal ranked loss");
        assert_eq!(s.by_id(a).unwrap().unwrap().rating, 1216);
        assert_eq!(s.by_id(b).unwrap().unwrap().losses, 1);
        assert_eq!(
            s.match_ending(m).unwrap(),
            Some(("flee".to_string(), Some(b)))
        );
        // the winner's own claim afterwards: already settled, same result
        let late = s.report(a, m, &ended(a, Ending::Flee)).unwrap();
        assert_eq!(late.delta, Some(16));
        assert_eq!(s.by_id(a).unwrap().unwrap().rating, 1216);
        assert!(s.pending_claims().unwrap().is_empty());
        // casual: no rating, still recorded as a flee
        let m2 = s.new_match([a, b], false, "{}").unwrap();
        let out = s.report(a, m2, &ended(b, Ending::Flee)).unwrap();
        assert_eq!(out.delta, Some(0));
        assert_eq!(s.by_id(a).unwrap().unwrap().rating, 1216);
        assert_eq!(
            s.match_ending(m2).unwrap(),
            Some(("flee".to_string(), Some(a)))
        );
    }

    #[test]
    fn a_claim_waits_for_the_server_and_yields_to_the_other_report() {
        use rugen_proto::Ending;
        let mut s = Store::open(None).unwrap();
        let a = s.register().unwrap().id;
        let b = s.register().unwrap().id;
        // a says b disconnected: nothing moves on its word alone
        let m = s.new_match([a, b], true, "{}").unwrap();
        let out = s.report(a, m, &ended(a, Ending::Disconnect)).unwrap();
        assert!(out.accepted && out.delta.is_none() && !out.disputed);
        assert_eq!(s.by_id(a).unwrap().unwrap().rating, 1200);
        let claims = s.pending_claims().unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].winner, a);
        assert_eq!(claims[0].ending, Ending::Disconnect);
        // the server confirmed it on the relay: settled for a
        assert_eq!(s.settle_claim(&claims[0]).unwrap(), Some([16, -16]));
        assert_eq!(s.by_id(b).unwrap().unwrap().rating, 1184);
        assert_eq!(
            s.match_ending(m).unwrap(),
            Some(("disconnect".to_string(), Some(b)))
        );
        assert_eq!(s.settle_claim(&claims[0]).unwrap(), None, "only once");
        assert!(s.pending_claims().unwrap().is_empty());
        // a false claim: b reports the match it actually won
        let m2 = s.new_match([a, b], true, "{}").unwrap();
        s.report(a, m2, &ended(a, Ending::Flee)).unwrap();
        let claim = s.pending_claims().unwrap().remove(0);
        let out = s
            .report(
                b,
                m2,
                &ReportData {
                    winner: b,
                    frames: 300,
                    inputs: inputs(300, None),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(out.disputed, "two winners: the resim / nobody decides");
        assert!(s.pending_claims().unwrap().is_empty());
        assert_eq!(s.settle_claim(&claim).unwrap(), None);
        assert_eq!(s.by_id(a).unwrap().unwrap().rating, 1216);
        // a claim the other report agrees with settles by agreement
        let m3 = s.new_match([a, b], false, "{}").unwrap();
        s.report(a, m3, &ended(a, Ending::Flee)).unwrap();
        let out = s.report(b, m3, &ended(a, Ending::Flee)).unwrap();
        assert_eq!(out.delta, Some(0));
        assert_eq!(
            s.match_ending(m3).unwrap(),
            Some(("flee".to_string(), Some(b)))
        );
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
    fn periodic_checksums_catch_a_forged_match() {
        let mut s = Store::open(None).unwrap();
        let a = s.register().unwrap().id;
        let b = s.register().unwrap().id;
        let honest = ReportData {
            winner: a,
            frames: 600,
            checksum: None,
            inputs: inputs(600, None),
            checksums: (1..=10).map(|i| (i * 60, i as u64)).collect(),
            ending: None,
        };
        // agreeing logs (the other side a few unconfirmed frames short)
        let m = s.new_match([a, b], true, "{}").unwrap();
        s.report(a, m, &honest).unwrap();
        let short = ReportData {
            frames: 590,
            checksums: honest.checksums[..9].to_vec(),
            ..honest.clone()
        };
        assert!(!s.report(b, m, &short).unwrap().disputed);
        // same inputs, but the world diverged at frame 300: disputed
        let m2 = s.new_match([a, b], true, "{}").unwrap();
        s.report(a, m2, &honest).unwrap();
        let mut forged = honest.clone();
        forged.checksums[4].1 ^= 1;
        assert!(s.report(b, m2, &forged).unwrap().disputed);
        // a difference only in the unconfirmed tail does not count
        let m3 = s.new_match([a, b], true, "{}").unwrap();
        s.report(a, m3, &honest).unwrap();
        let mut tail = honest.clone();
        tail.checksums[9].1 ^= 1; // frame 600 of 600
        assert!(!s.report(b, m3, &tail).unwrap().disputed);
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
            checksums: vec![(60, 1), (120, 2)],
            ending: None,
        };
        let rb = ReportData {
            winner: a,
            frames: 590,
            checksum: Some(7),
            inputs: inputs(590, None),
            checksums: vec![(60, 1), (120, 2)],
            ending: None,
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
    fn blocklist_admin_auto_and_sticky_clearing() {
        let mut s = Store::open(None).unwrap();
        let fp = "a".repeat(64);
        assert_eq!(s.truth_seq().unwrap(), 0);
        assert!(s.auto_block(&fp, "auto: regen").unwrap());
        assert!(!s.auto_block(&fp, "auto: again").unwrap(), "only once");
        assert_eq!(s.blocked(&fp).unwrap().unwrap().source, "auto");
        let seq = s.truth_seq().unwrap();
        assert!(s.unblock(&fp).unwrap());
        assert!(s.blocked(&fp).unwrap().is_none());
        assert!(s.truth_seq().unwrap() > seq);
        // cleared by the operator: automatic rules never block it again
        assert!(!s.auto_block(&fp, "auto: regen").unwrap());
        assert!(s.blocklist().unwrap().is_empty());
        // the operator can still block it
        s.block(&fp, "infinite loop", "admin").unwrap();
        let b = s.blocklist().unwrap();
        assert_eq!(b.len(), 1);
        assert_eq!(
            (b[0].reason.as_str(), b[0].source.as_str()),
            ("infinite loop", "admin")
        );
        // liars are counted per distinct account
        for acc in [1, 1, 2] {
            s.flag(acc, None, "lie", Some(&fp)).unwrap();
        }
        s.flag(3, None, "other", None).unwrap();
        assert_eq!(s.liars_for(&fp).unwrap(), 2);
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

    #[test]
    fn accounts_are_deleted_by_name_prefix() {
        let mut s = Store::open(None).unwrap();
        let mut ids = Vec::new();
        for name in [
            "loadtest-a1",
            "loadtest-b2",
            "loadtester",
            "PLAYER1",
            "load_test-x",
        ] {
            let a = s.register().unwrap();
            s.set_profile(a.id, Some(name.into()), None).unwrap();
            ids.push(a.id);
        }
        s.new_match([ids[0], ids[1]], false, "{}").unwrap();
        s.new_match([ids[0], ids[3]], false, "{}").unwrap();
        let ranked = s.new_match([ids[1], ids[3]], true, "{}").unwrap();
        assert_eq!(
            s.delete_accounts_by_prefix("loadtest-", true).unwrap(),
            (2, 2)
        );
        assert_eq!(s.account_count().unwrap(), 5, "dry run");
        assert_eq!(
            s.delete_accounts_by_prefix("loadtest-", false).unwrap(),
            (2, 2)
        );
        assert_eq!(s.account_count().unwrap(), 3);
        assert!(s.by_id(ids[2]).unwrap().is_some(), "no dash: kept");
        assert!(s.by_id(ids[4]).unwrap().is_some(), "_ is not a wildcard");
        assert!(s.match_players(ranked).unwrap().is_some(), "ranked kept");
        assert_eq!(
            s.delete_accounts_by_prefix("loadtest-", false).unwrap(),
            (0, 0)
        );
    }
}
