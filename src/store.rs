//! Persistent state on SQLite: accounts, ratings, seasons, match results.
//!
//! One file, `<data>/rugen.db`, in WAL mode. The schema is versioned with
//! `PRAGMA user_version` and upgraded by the embedded [`MIGRATIONS`] on open.
//! A `state.json` left by the former JSON store is imported once (then
//! renamed to `state.json.migrated`).

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use rugen_proto::{ProfileInfo, Season, SeasonBadge, Standing, rank_name};
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
    /// Named account (API 5): unique username (`name` equals it).
    pub username: Option<String>,
    /// How the last season it played ended for it (the profile badge).
    pub last_season: Option<SeasonBadge>,
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
            verified: self.username.is_some(),
            last_season: self.last_season.clone(),
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
            username: r.get(10)?,
            last_season: match (
                r.get::<_, Option<i64>>(11)?,
                r.get::<_, Option<i32>>(12)?,
                r.get::<_, Option<i64>>(13)?,
            ) {
                (Some(n), Some(rating), Some(rank)) => {
                    Some(SeasonBadge::new(n as u32, rating, rank as u32))
                }
                _ => None,
            },
        })
    }
}

/// Columns of an account row insert.
const ACCOUNT_COLS: &str =
    "id, key, name, avatar, rating, best_rating, wins, losses, created, last_seen";
/// Columns [`Account::from_row`] reads.
const ACCOUNT_SELECT: &str = "id, key, name, avatar, rating, best_rating, wins, losses, created, \
     last_seen, username, last_season, last_rating, last_rank";

/// Keys (devices) a named account keeps; the least recently used go first.
pub const MAX_SESSIONS: i64 = 10;

/// Why a username cannot be taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameError {
    Taken,
    /// The account already has a username (claim).
    AlreadyNamed,
}

/// What `accounts.key` holds once that key was revoked (never 64 characters,
/// so it can never authenticate: keys are exactly 64).
fn dead_key(tag: &str) -> String {
    format!("{tag}:{}", random_hex(16))
}

/// Session keys are stored as their sha256 (a database leak gives no key).
fn key_hash(key: &str) -> String {
    rugen_fair::sha256_hex(key.as_bytes())
}

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
    // v6: named accounts: a unique username (case-insensitive) and an
    // Argon2id password hash; session keys of named accounts (sha256, one
    // per device). Anonymous accounts keep authenticating with `key`.
    "ALTER TABLE accounts ADD COLUMN username TEXT;
     ALTER TABLE accounts ADD COLUMN password TEXT;
     CREATE UNIQUE INDEX accounts_username ON accounts(username COLLATE NOCASE)
         WHERE username IS NOT NULL;
     CREATE TABLE account_keys (
         hash TEXT PRIMARY KEY,
         account INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
         created INTEGER NOT NULL,
         last_used INTEGER NOT NULL
     );
     CREATE INDEX account_keys_account ON account_keys(account, last_used);",
    // v7: ranked seasons: each finished season (dates, players), its final
    // standings, and the badge of the last season an account finished
    "CREATE TABLE seasons (
         number INTEGER PRIMARY KEY,
         start INTEGER NOT NULL,
         end INTEGER NOT NULL,
         players INTEGER NOT NULL DEFAULT 0
     );
     CREATE TABLE season_results (
         season INTEGER NOT NULL,
         account INTEGER NOT NULL,
         rating INTEGER NOT NULL,
         wins INTEGER NOT NULL,
         losses INTEGER NOT NULL,
         rank INTEGER NOT NULL,
         PRIMARY KEY (season, account)
     );
     CREATE INDEX season_results_rank ON season_results(season, rank);
     ALTER TABLE accounts ADD COLUMN last_season INTEGER;
     ALTER TABLE accounts ADD COLUMN last_rating INTEGER;
     ALTER TABLE accounts ADD COLUMN last_rank INTEGER;",
    // v8: per-fighter leaderboards: each player's rating and record with
    // each fighter (fingerprint), per season
    "CREATE TABLE fighter_ratings (
         season INTEGER NOT NULL,
         fingerprint TEXT NOT NULL,
         account INTEGER NOT NULL,
         name TEXT NOT NULL DEFAULT '',
         rating INTEGER NOT NULL,
         wins INTEGER NOT NULL DEFAULT 0,
         losses INTEGER NOT NULL DEFAULT 0,
         PRIMARY KEY (season, fingerprint, account)
     );
     CREATE INDEX fighter_ratings_board ON fighter_ratings(season, fingerprint, rating DESC);",
    // v9: shared replays: a finished match's header and input stream under
    // a short code, kept 30 days (in every backup)
    "CREATE TABLE shared_replays (
         code TEXT PRIMARY KEY,
         match_id INTEGER NOT NULL UNIQUE,
         header TEXT NOT NULL,
         inputs BLOB NOT NULL,
         frames INTEGER NOT NULL,
         account INTEGER NOT NULL,
         p1_fp TEXT NOT NULL DEFAULT '',
         p2_fp TEXT NOT NULL DEFAULT '',
         stage_fp TEXT NOT NULL DEFAULT '',
         created INTEGER NOT NULL,
         expires INTEGER NOT NULL
     );
     CREATE INDEX shared_replays_expires ON shared_replays(expires);
     CREATE INDEX shared_replays_account ON shared_replays(account, created);",
];

/// A stored shared replay.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SharedRow {
    pub code: String,
    pub match_id: u64,
    /// [`rugen_proto::stream::MatchHeader`] JSON.
    pub header: String,
    /// 4 bytes per frame.
    pub inputs: Vec<u8>,
    pub account: u64,
    pub created: u64,
    pub expires: u64,
}

impl SharedRow {
    fn from_row(r: &Row<'_>) -> DbResult<Self> {
        Ok(Self {
            code: r.get(0)?,
            match_id: r.get::<_, i64>(1)? as u64,
            header: r.get(2)?,
            inputs: r.get(3)?,
            account: r.get::<_, i64>(4)? as u64,
            created: r.get::<_, i64>(5)? as u64,
            expires: r.get::<_, i64>(6)? as u64,
        })
    }
}

const SHARED_COLS: &str = "code, match_id, header, inputs, account, created, expires";

/// Fighters a per-fighter board lists.
pub const BOARD_FIGHTERS: usize = 50;

/// Finished seasons a leaderboard can go back to.
pub const PAST_SEASONS: usize = 12;

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

/// Page cache per connection, KiB (negative `cache_size` = KiB).
const CACHE_KIB: i64 = 16_000;
/// Memory-mapped I/O window: reads come straight from the OS page cache.
const MMAP_BYTES: i64 = 64 << 20;

/// Pragmas of every file connection (on top of WAL + `synchronous=NORMAL`):
/// a 16 MB page cache, 64 MB of mmap, temporary tables / sorts in memory.
fn tune(c: &Connection) -> DbResult<()> {
    c.pragma_update(None, "cache_size", -CACHE_KIB)?;
    c.pragma_update(None, "mmap_size", MMAP_BYTES)?;
    c.pragma_update(None, "temp_store", "MEMORY")?;
    Ok(())
}

/// Prepared statements kept per connection (the store has about 100
/// distinct queries; rusqlite's default of 16 would keep re-parsing them).
const STATEMENT_CACHE: usize = 256;

/// The database: one writer connection driven by one writer thread, and,
/// for a database file, a small pool of read-only connections for the
/// read-only queries (WAL: readers never wait for the writer). An
/// in-memory database (tests) reads through the writer connection.
///
/// Writes are queued to the writer thread (a bounded queue: a full queue
/// makes callers wait), which commits whatever is queued as one
/// transaction (group commit), each write in its own savepoint so a
/// failing one changes nothing and leaves the others alone. A write
/// returns only once its transaction has committed, so a read that
/// follows (from any connection) sees it. A read runs in one read
/// transaction (one consistent snapshot).
pub struct Store {
    writer: Arc<Mutex<Connection>>,
    readers: Option<Pool>,
    queue: Option<SyncSender<Box<dyn Job>>>,
    thread: Option<std::thread::JoinHandle<()>>,
    stats: Arc<WriteStats>,
}

/// Writes waiting for the writer thread before callers have to wait.
const WRITE_QUEUE: usize = 128;
/// Most writes committed in one transaction.
const MAX_BATCH: usize = 256;

/// Group-commit counters.
#[derive(Default)]
#[cfg_attr(not(test), allow(dead_code))]
struct WriteStats {
    batches: AtomicU64,
    writes: AtomicU64,
    last_batch: AtomicU64,
    /// Writes that found the queue full and waited.
    full: AtomicU64,
    /// Writes queued or running, not answered yet.
    pending: AtomicU64,
}

/// One queued write: runs on the writer thread inside the batch
/// transaction, answers its caller once the batch committed.
trait Job: Send {
    fn run(&mut self, d: &Db<'_>);
    fn finish(self: Box<Self>, commit: &DbResult<()>);
}

struct Write<T, F> {
    f: Option<F>,
    out: Option<DbResult<T>>,
    reply: SyncSender<DbResult<T>>,
}

impl<T, F> Job for Write<T, F>
where
    F: FnOnce(&Db<'_>) -> DbResult<T> + Send,
    T: Send,
{
    fn run(&mut self, d: &Db<'_>) {
        let Some(f) = self.f.take() else { return };
        if d.conn.is_autocommit() {
            // the batch transaction is gone (SQLite rolled it back after a
            // severe error): running now would commit on its own
            self.out = Some(Err(failure("batch transaction lost")));
            return;
        }
        let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let tx = d.tx()?;
            let v = f(d)?;
            tx.commit()?;
            Ok(v)
        }))
        .unwrap_or_else(|_| Err(failure("write panicked")));
        self.out = Some(out);
    }

    fn finish(self: Box<Self>, commit: &DbResult<()>) {
        let out = match (self.out, commit) {
            (Some(Ok(_)), Err(e)) => Err(failure(&format!("commit failed: {e}"))),
            (Some(out), _) => out,
            (None, Err(e)) => Err(failure(&format!("not run: {e}"))),
            (None, Ok(())) => Err(failure("not run")),
        };
        let _ = self.reply.send(out);
    }
}

/// An error for a write that could not complete (the batch's own error is
/// not `Clone`).
fn failure(msg: &str) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
        Some(msg.to_string()),
    )
}

/// The writer thread: one transaction per batch of queued writes.
fn writer_loop(conn: Arc<Mutex<Connection>>, rx: Receiver<Box<dyn Job>>, stats: Arc<WriteStats>) {
    while let Ok(first) = rx.recv() {
        let c = lock(&conn);
        // everything queued while we waited joins this transaction
        let mut batch = vec![first];
        while batch.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(j) => batch.push(j),
                Err(_) => break,
            }
        }
        let d = Db { conn: &c };
        let commit = c.execute_batch("BEGIN IMMEDIATE").and_then(|()| {
            for j in batch.iter_mut() {
                j.run(&d);
            }
            c.execute_batch("COMMIT")
        });
        if commit.is_err() && !c.is_autocommit() {
            let _ = c.execute_batch("ROLLBACK");
        }
        drop(c);
        stats.batches.fetch_add(1, Relaxed);
        stats.writes.fetch_add(batch.len() as u64, Relaxed);
        stats.last_batch.store(batch.len() as u64, Relaxed);
        if let Err(e) = &commit {
            log::error!("store: a batch of {} writes failed: {e}", batch.len());
        }
        stats.pending.fetch_sub(batch.len() as u64, Relaxed);
        for j in batch {
            j.finish(&commit);
        }
    }
}

/// Read-only connections; a reader waits for an idle one.
struct Pool {
    idle: Mutex<Vec<Connection>>,
    ready: Condvar,
}

/// Read-only connections of a database file.
const READERS: usize = 3;

/// A session key's hash and when it was last used (Unix seconds).
type KeyUse = (String, u64);

/// The queries, on one connection (the writer inside a write, a reader
/// inside a read).
struct Db<'c> {
    conn: &'c Connection,
}

/// A savepoint that behaves like a transaction: [`Tx::commit`] releases
/// it, dropping it uncommitted rolls it back. Savepoints nest, so a write
/// can run inside a larger transaction.
struct Tx<'c> {
    conn: &'c Connection,
    done: bool,
}

impl std::ops::Deref for Tx<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.conn
    }
}

impl Tx<'_> {
    fn commit(mut self) -> DbResult<()> {
        self.done = true;
        self.conn.prepare_cached("RELEASE store")?.execute([])?;
        Ok(())
    }
}

impl Drop for Tx<'_> {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.conn.execute_batch("ROLLBACK TO store; RELEASE store");
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
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

impl Drop for Store {
    fn drop(&mut self) {
        // the writer finishes what is queued, then closes its connection
        drop(self.queue.take());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Pool {
    fn open(path: &Path, n: usize) -> DbResult<Self> {
        use rusqlite::OpenFlags;
        let mut idle = Vec::with_capacity(n);
        for _ in 0..n {
            let c = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            c.busy_timeout(std::time::Duration::from_secs(5))?;
            c.set_prepared_statement_cache_capacity(STATEMENT_CACHE);
            tune(&c)?;
            idle.push(c);
        }
        Ok(Self {
            idle: Mutex::new(idle),
            ready: Condvar::new(),
        })
    }

    /// Run `f` on an idle connection (waits for one).
    fn with<T>(&self, f: impl FnOnce(&Connection) -> T) -> T {
        struct Back<'p> {
            pool: &'p Pool,
            conn: Option<Connection>,
        }
        impl Drop for Back<'_> {
            fn drop(&mut self) {
                if let Some(c) = self.conn.take() {
                    if !c.is_autocommit() {
                        // a read that panicked left its transaction open
                        let _ = c.execute_batch("ROLLBACK");
                    }
                    lock(&self.pool.idle).push(c);
                    self.pool.ready.notify_one();
                }
            }
        }
        let conn = {
            let mut idle = lock(&self.idle);
            loop {
                if let Some(c) = idle.pop() {
                    break c;
                }
                idle = self.ready.wait(idle).unwrap_or_else(|p| p.into_inner());
            }
        };
        let back = Back {
            pool: self,
            conn: Some(conn),
        };
        f(back.conn.as_ref().expect("connection held"))
    }
}

impl Store {
    /// Open (or create) `<dir>/rugen.db`; `None` keeps everything in memory (tests).
    pub fn open(dir: Option<&Path>) -> DbResult<Self> {
        Self::open_with(dir, WRITE_QUEUE)
    }

    /// [`Self::open`] with `queue` writes waiting before callers wait.
    fn open_with(dir: Option<&Path>, queue: usize) -> DbResult<Self> {
        let conn = match dir {
            Some(d) => {
                std::fs::create_dir_all(d).map_err(|e| {
                    rusqlite::Error::InvalidPath(format!("{}: {e}", d.display()).into())
                })?;
                let c = Connection::open(d.join("rugen.db"))?;
                c.pragma_update(None, "journal_mode", "WAL")?;
                c.pragma_update(None, "synchronous", "NORMAL")?;
                tune(&c)?;
                c
            }
            None => Connection::open_in_memory()?,
        };
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        // every query goes through `prepare_cached`: keep all of them parsed
        conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE);
        {
            let s = Db { conn: &conn };
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
        }
        let readers = match dir {
            Some(d) => Some(Pool::open(&d.join("rugen.db"), READERS)?),
            None => None,
        };
        Self::start(conn, readers, queue)
    }

    /// Start the writer thread on `conn`.
    fn start(conn: Connection, readers: Option<Pool>, queue: usize) -> DbResult<Self> {
        let writer = Arc::new(Mutex::new(conn));
        let stats = Arc::new(WriteStats::default());
        let (tx, rx) = sync_channel(queue);
        let thread = {
            let (w, st) = (writer.clone(), stats.clone());
            std::thread::Builder::new()
                .name("rugen-db-writer".into())
                .spawn(move || writer_loop(w, rx, st))
                .map_err(|e| failure(&format!("writer thread: {e}")))?
        };
        Ok(Self {
            writer,
            readers,
            queue: Some(tx),
            thread: Some(thread),
            stats,
        })
    }

    /// Run a read-only unit on a reader (one read transaction: a consistent
    /// snapshot, and every write that returned before it is visible).
    fn read<T>(&self, f: impl FnOnce(&Db<'_>) -> DbResult<T>) -> DbResult<T> {
        match &self.readers {
            Some(pool) => pool.with(|c| {
                c.prepare_cached("BEGIN")?.execute([])?;
                let out = f(&Db { conn: c });
                match &out {
                    Ok(_) => {
                        c.prepare_cached("COMMIT")?.execute([])?;
                    }
                    Err(_) => {
                        let _ = c.execute_batch("ROLLBACK");
                    }
                }
                out
            }),
            None => f(&Db {
                conn: &lock(&self.writer),
            }),
        }
    }

    /// Run a write unit on the writer, atomically: it has committed when
    /// this returns (or changed nothing when it failed).
    fn write<T, F>(&self, f: F) -> DbResult<T>
    where
        F: FnOnce(&Db<'_>) -> DbResult<T> + Send + 'static,
        T: Send + 'static,
    {
        use std::sync::mpsc::TrySendError;
        let Some(queue) = &self.queue else {
            return Err(failure("store closed"));
        };
        let (reply, answer) = sync_channel(1);
        let job: Box<dyn Job> = Box::new(Write {
            f: Some(f),
            out: None,
            reply,
        });
        self.stats.pending.fetch_add(1, Relaxed);
        let sent = match queue.try_send(job) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(job)) => {
                // backpressure: wait for room, never queue without bound
                self.stats.full.fetch_add(1, Relaxed);
                queue.send(job).map_err(|_| ())
            }
            Err(TrySendError::Disconnected(_)) => Err(()),
        };
        if sent.is_err() {
            self.stats.pending.fetch_sub(1, Relaxed);
            return Err(failure("writer thread gone"));
        }
        answer
            .recv()
            .unwrap_or_else(|_| Err(failure("writer thread gone")))
    }

    /// Writes waiting for (or in) the writer's current transaction.
    pub fn write_queue(&self) -> u64 {
        self.stats.pending.load(Relaxed)
    }

    /// (batches, writes, size of the last batch, writes that waited for room).
    #[cfg(test)]
    fn write_stats(&self) -> (u64, u64, u64, u64) {
        let s = &self.stats;
        (
            s.batches.load(Relaxed),
            s.writes.load(Relaxed),
            s.last_batch.load(Relaxed),
            s.full.load(Relaxed),
        )
    }

    /// The writer connection (tests poke at the schema directly).
    #[cfg(test)]
    fn writer_conn(&self) -> MutexGuard<'_, Connection> {
        lock(&self.writer)
    }

    /// P1 and P2 of a match.
    pub fn match_players(&self, match_id: u64) -> DbResult<Option<[u64; 2]>> {
        self.read(|d| d.match_players(match_id))
    }

    /// TURN usage of a month (`YYYY-MM`, UTC).
    pub fn turn_usage(&self, month: &str) -> DbResult<TurnMonth> {
        self.read(|d| d.turn_usage(month))
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
        let month = month.to_string();
        self.write(move |d| d.turn_add(&month, reserved, reported, credentials))
    }

    /// Usage Cloudflare's analytics report for a month (bytes, both ways).
    pub fn turn_set_cloudflare(&self, month: &str, bytes: u64) -> DbResult<()> {
        let month = month.to_string();
        self.write(move |d| d.turn_set_cloudflare(&month, bytes))
    }

    pub fn schema_version(&self) -> DbResult<usize> {
        self.read(|d| d.schema_version())
    }

    /// Start a new season when the current one is over: ratings soft-reset toward 1200.
    pub fn roll_season(&self) -> DbResult<()> {
        if self.read(|d| d.season_due())? {
            self.write(|d| d.roll_season())?;
        }
        Ok(())
    }

    pub fn season(&self) -> DbResult<Season> {
        self.read(|d| d.season())
    }

    /// End the current season now (operator): standings are kept, ratings
    /// soft-reset, the next season starts at once.
    pub fn end_season_now(&self) -> DbResult<Season> {
        self.write(|d| {
            d.set_meta("season_start", now() as i64 - SEASON_SECS as i64)?;
            d.roll_season()?;
            d.season()
        })
    }

    /// A finished season (`None`: unknown, or the current one).
    pub fn past_season(&self, number: u32) -> DbResult<Option<Season>> {
        self.read(|d| d.past_season(number))
    }

    /// Finished seasons with standings, newest first.
    pub fn past_seasons(&self) -> DbResult<Vec<u32>> {
        self.read(|d| d.past_seasons())
    }

    /// Final standings of a finished season, best first.
    pub fn season_board(&self, number: u32, limit: usize) -> DbResult<Vec<ProfileInfo>> {
        self.read(|d| d.season_board(number, limit))
    }

    /// Fighters with a board in `season`, most played first.
    pub fn board_fighters(&self, season: u32) -> DbResult<Vec<rugen_proto::FighterEntry>> {
        self.read(|d| d.board_fighters(season))
    }

    /// Keep a shared replay; when the match is already shared, its row
    /// stays and is returned instead. Packages of the three fingerprints are
    /// kept as long as the replay.
    pub fn share_replay(&self, row: &SharedRow, fps: [String; 3]) -> DbResult<SharedRow> {
        let (row, fps) = (row.clone(), fps);
        self.write(move |d| d.share_replay(&row, &fps))
    }

    pub fn shared_replay(&self, code: &str) -> DbResult<Option<SharedRow>> {
        let code = code.to_string();
        self.read(move |d| d.shared_replay(&code))
    }

    pub fn shared_of_match(&self, match_id: u64) -> DbResult<Option<SharedRow>> {
        self.read(move |d| d.shared_of_match(match_id))
    }

    /// An unexpired shared replay needs this package.
    pub fn shared_has(&self, fp: &str) -> DbResult<bool> {
        let fp = fp.to_string();
        self.read(move |d| d.shared_has(&fp))
    }

    /// Replays `account` shared since `since` (Unix seconds).
    pub fn shares_since(&self, account: u64, since: u64) -> DbResult<u32> {
        self.read(move |d| d.shares_since(account, since))
    }

    /// Drop expired shared replays, then the oldest while all of them take
    /// more than `max_bytes`. Returns how many went.
    pub fn sweep_shared(&self, max_bytes: u64) -> DbResult<usize> {
        self.write(move |d| d.sweep_shared(max_bytes))
    }

    /// (shared replays, bytes of their streams).
    pub fn shared_usage(&self) -> DbResult<(u64, u64)> {
        self.read(|d| d.shared_usage())
    }

    /// One fighter's board in `season`, best first.
    pub fn fighter_board(&self, season: u32, fp: &str, limit: usize) -> DbResult<Vec<ProfileInfo>> {
        self.read(|d| d.fighter_board(season, fp, limit))
    }

    /// An account's position and line on a fighter's board.
    pub fn fighter_rank_of(
        &self,
        season: u32,
        fp: &str,
        id: u64,
    ) -> DbResult<Option<(usize, ProfileInfo)>> {
        self.read(|d| d.fighter_rank_of(season, fp, id))
    }

    /// An account's final position and line in a finished season.
    pub fn season_rank_of(&self, number: u32, id: u64) -> DbResult<Option<(usize, ProfileInfo)>> {
        self.read(|d| d.season_rank_of(number, id))
    }

    pub fn account_count(&self) -> DbResult<usize> {
        self.read(|d| d.account_count())
    }

    /// Accounts whose name starts with `prefix` (load-test leftovers) and
    /// their unranked matches (reports / replays cascade): counted only when
    /// `dry_run`, deleted otherwise. Ranked matches are kept (they moved
    /// other players' ratings). Returns (accounts, matches).
    pub fn delete_accounts_by_prefix(
        &self,
        prefix: &str,
        dry_run: bool,
    ) -> DbResult<(usize, usize)> {
        let prefix = prefix.to_string();
        self.write(move |d| d.delete_accounts_by_prefix(&prefix, dry_run))
    }

    /// Both sides reported (or the match was otherwise settled).
    pub fn match_resolved(&self, match_id: u64) -> DbResult<bool> {
        self.read(|d| d.match_resolved(match_id))
    }

    pub fn register(&self) -> DbResult<Account> {
        self.write(|d| d.register())
    }

    /// The account owning `key` (an anonymous account's key, or a session
    /// key of a named account); refreshes its `last_seen` (written at most
    /// once a minute: this runs on every authenticated call).
    pub fn by_key(&self, key: &str) -> DbResult<Option<Account>> {
        if key.len() != 64 {
            return Ok(None);
        }
        let Some((mut a, session)) = self.read(|d| d.lookup_key(key))? else {
            return Ok(None);
        };
        let t = now();
        let seen = a.last_seen + 60 <= t;
        let used = session.filter(|(_, used)| used + 60 <= t).map(|(h, _)| h);
        if seen || used.is_some() {
            let id = a.id;
            self.write(move |d| d.touch_key(id, seen, used.as_deref(), t))?;
            if seen {
                a.last_seen = t;
            }
        }
        Ok(Some(a))
    }

    /// The named account called `username` (any case).
    pub fn by_username(&self, username: &str) -> DbResult<Option<Account>> {
        self.read(|d| d.by_username(username))
    }

    /// Account id and password hash of `username` (login).
    pub fn credentials(&self, username: &str) -> DbResult<Option<(u64, Option<String>)>> {
        self.read(|d| d.credentials(username))
    }

    /// Password hash of account `id`.
    pub fn password_of(&self, id: u64) -> DbResult<Option<String>> {
        self.read(|d| d.password_of(id))
    }

    pub fn username_taken(&self, username: &str) -> DbResult<bool> {
        self.read(|d| d.username_taken(username))
    }

    /// A new named account (rating at the start, like an anonymous one).
    /// `username` must already be valid ([`rugen_proto::account::username_error`])
    /// and `phc` an Argon2id hash. Returns the account and its first key.
    pub fn register_named(
        &self,
        username: &str,
        phc: &str,
    ) -> DbResult<Result<(Account, String), NameError>> {
        let (username, phc) = (username.to_string(), phc.to_string());
        self.write(move |d| d.register_named(&username, &phc))
    }

    /// Give anonymous account `id` a username and password: it keeps its
    /// id, rating and history, and the key it already has.
    pub fn claim(
        &self,
        id: u64,
        username: &str,
        phc: &str,
    ) -> DbResult<Result<Account, NameError>> {
        let (username, phc) = (username.to_string(), phc.to_string());
        self.write(move |d| d.claim(id, &username, &phc))
    }

    /// A new session key for account `id` (login on a device). Only the
    /// [`MAX_SESSIONS`] most recently used keys stay valid.
    pub fn issue_key(&self, id: u64) -> DbResult<String> {
        self.write(move |d| d.issue_key(id))
    }

    /// Revoke one key (log out this device).
    pub fn revoke_key(&self, id: u64, key: &str) -> DbResult<()> {
        let key = key.to_string();
        self.write(move |d| d.revoke_key(id, &key))
    }

    /// Revoke every key of account `id` (log out everywhere).
    pub fn revoke_all(&self, id: u64) -> DbResult<()> {
        self.write(move |d| d.revoke_all(id))
    }

    /// Replace the password hash of account `id` and revoke every key it
    /// has, in one transaction; `fresh_key` hands this device a new key.
    pub fn replace_password(
        &self,
        id: u64,
        phc: &str,
        fresh_key: bool,
    ) -> DbResult<Option<String>> {
        let phc = phc.to_string();
        self.write(move |d| {
            d.set_password(id, &phc)?;
            d.revoke_all(id)?;
            fresh_key.then(|| d.issue_key(id)).transpose()
        })
    }

    /// Keys (devices) able to act for account `id`.
    pub fn sessions(&self, id: u64) -> DbResult<u32> {
        self.read(|d| d.sessions(id))
    }

    pub fn by_id(&self, id: u64) -> DbResult<Option<Account>> {
        self.read(|d| d.by_id(id))
    }

    pub fn set_profile(
        &self,
        id: u64,
        name: Option<String>,
        avatar: Option<u32>,
    ) -> DbResult<Option<Account>> {
        self.write(move |d| d.set_profile(id, name, avatar))
    }

    /// A new match row. `setup` (JSON: characters, stage, rules) is kept for replays.
    pub fn new_match(&self, players: [u64; 2], ranked: bool, setup: &str) -> DbResult<u64> {
        let setup = setup.to_string();
        self.write(move |d| d.new_match(players, ranked, &setup))
    }

    /// Replace a match's setup JSON (fingerprints become known at start).
    pub fn set_setup(&self, match_id: u64, setup: &str) -> DbResult<()> {
        let setup = setup.to_string();
        self.write(move |d| d.set_setup(match_id, &setup))
    }

    /// Record one side's report. The match resolves once both sides
    /// reported: ratings move (ranked) only when the reports agree
    /// ([`reports_agree`]); otherwise the match is marked disputed.
    pub fn report(
        &self,
        reporter: u64,
        match_id: u64,
        data: &ReportData,
    ) -> DbResult<ReportOutcome> {
        let data = data.clone();
        self.write(move |d| d.report(reporter, match_id, &data))
    }

    /// Unsettled matches with a single report, from the player who says it
    /// won because the other one fled or disconnected.
    pub fn pending_claims(&self) -> DbResult<Vec<Claim>> {
        self.read(|d| d.pending_claims())
    }

    /// Settle a claim the server confirmed on its own view of the relay:
    /// the claimant wins, the other player fled / disconnected. `None`
    /// when the match is no longer a pending claim (settled meanwhile, or
    /// the other report arrived: agreement or dispute decide then).
    pub fn settle_claim(&self, c: &Claim) -> DbResult<Option<[i32; 2]>> {
        let c = c.clone();
        self.write(move |d| d.settle_claim(&c))
    }

    /// How a settled match ended early (`None` for a match played out).
    pub fn match_ending(&self, match_id: u64) -> DbResult<EndingRow> {
        self.read(|d| d.match_ending(match_id))
    }

    /// A client saw a desync (ggrs checksum mismatch): the match can no
    /// longer resolve by agreement.
    pub fn report_desync(&self, reporter: u64, match_id: u64, frame: u32) -> DbResult<bool> {
        self.write(move |d| d.report_desync(reporter, match_id, frame))
    }

    /// A disputed match the server re-simulated: settle it with the
    /// simulated winner (`None` = undecidable, stays disputed).
    pub fn resolve_dispute(
        &self,
        match_id: u64,
        winner: Option<u64>,
        note: &str,
    ) -> DbResult<bool> {
        let note = note.to_string();
        self.write(move |d| d.resolve_dispute(match_id, winner, &note))
    }

    /// What the re-simulation said about a match (`None`: not run).
    #[cfg(test)]
    pub fn resim_note(&self, match_id: u64) -> DbResult<Option<String>> {
        self.read(|d| d.resim_note(match_id))
    }

    /// Setup JSON, ranked flag, players and the reports (reporter, data) of a match.
    #[allow(clippy::type_complexity)]
    pub fn match_evidence(
        &self,
        match_id: u64,
    ) -> DbResult<Option<(String, bool, [u64; 2], Vec<(u64, ReportData)>)>> {
        self.read(|d| d.match_evidence(match_id))
    }

    /// Is a match disputed (and unresolved by agreement)?
    pub fn is_disputed(&self, match_id: u64) -> DbResult<bool> {
        self.read(|d| d.is_disputed(match_id))
    }

    pub fn package(&self, fp: &str) -> DbResult<Option<PackageRow>> {
        self.read(|d| d.package(fp))
    }

    pub fn put_package(&self, p: &PackageRow) -> DbResult<()> {
        let p = p.clone();
        self.write(move |d| d.put_package(&p))
    }

    /// Mark packages as used now (TTL / LRU bookkeeping).
    pub fn touch_packages(&self, fps: &[&str]) -> DbResult<()> {
        let fps: Vec<String> = fps.iter().map(|f| f.to_string()).collect();
        self.write(move |d| d.touch_packages(&fps.iter().map(String::as_str).collect::<Vec<_>>()))
    }

    /// All packages, least recently used first.
    pub fn packages_lru(&self) -> DbResult<Vec<PackageRow>> {
        self.read(|d| d.packages_lru())
    }

    pub fn delete_package(&self, fp: &str) -> DbResult<()> {
        let fp = fp.to_string();
        self.write(move |d| d.delete_package(&fp))
    }

    pub fn char_rating(&self, fp: &str) -> DbResult<Option<rugen_proto::CharRating>> {
        self.read(|d| d.char_rating(fp))
    }

    /// Record an anti-cheat finding against an account; `fingerprint` =
    /// the content a false profile was declared for (feeds auto-blocking).
    pub fn flag(
        &self,
        account: u64,
        match_id: Option<u64>,
        reason: &str,
        fingerprint: Option<&str>,
    ) -> DbResult<()> {
        let (reason, fingerprint) = (reason.to_string(), fingerprint.map(str::to_string));
        self.write(move |d| d.flag(account, match_id, &reason, fingerprint.as_deref()))
    }

    /// Distinct accounts flagged for a false profile of `fp`.
    pub fn liars_for(&self, fp: &str) -> DbResult<u32> {
        self.read(|d| d.liars_for(fp))
    }

    /// Matches with a reported desync that `fp` was part of.
    pub fn desyncs_for(&self, fp: &str) -> DbResult<u32> {
        self.read(|d| d.desyncs_for(fp))
    }

    /// Changes whenever the blocklist does (feed `sequence`).
    pub fn truth_seq(&self) -> DbResult<u64> {
        self.read(|d| d.truth_seq())
    }

    /// Block a fingerprint (operator): replaces any entry, clears `allowed`.
    pub fn block(&self, fp: &str, reason: &str, source: &str) -> DbResult<()> {
        let (fp, reason, source) = (fp.to_string(), reason.to_string(), source.to_string());
        self.write(move |d| d.block(&fp, &reason, &source))
    }

    /// Automatic block: only when the fingerprint has no entry at all (an
    /// operator-cleared one stays cleared). True when it was added.
    pub fn auto_block(&self, fp: &str, reason: &str) -> DbResult<bool> {
        let (fp, reason) = (fp.to_string(), reason.to_string());
        self.write(move |d| d.auto_block(&fp, &reason))
    }

    /// Clear a fingerprint (operator). The row stays as `allowed` so that
    /// automatic rules never block it again. True when it was blocked.
    pub fn unblock(&self, fp: &str) -> DbResult<bool> {
        let fp = fp.to_string();
        self.write(move |d| d.unblock(&fp))
    }

    pub fn blocked(&self, fp: &str) -> DbResult<Option<rugen_proto::BlockEntry>> {
        self.read(|d| d.blocked(fp))
    }

    /// Every blocked fingerprint, oldest first.
    pub fn blocklist(&self) -> DbResult<Vec<rugen_proto::BlockEntry>> {
        self.read(|d| d.blocklist())
    }

    /// The feed's parts from one snapshot: sequence, blocklist and the
    /// `limit` most played community ratings.
    #[allow(clippy::type_complexity)]
    pub fn feed(
        &self,
        limit: usize,
    ) -> DbResult<(
        u64,
        Vec<rugen_proto::BlockEntry>,
        Vec<rugen_proto::FeedRating>,
    )> {
        self.read(|d| Ok((d.truth_seq()?, d.blocklist()?, d.feed_ratings(limit)?)))
    }

    /// A match as seen by `account`: (ranked, players, winner, delta of the
    /// account, disputed). None when it is not the account's match.
    #[allow(clippy::type_complexity)]
    pub fn match_result(
        &self,
        match_id: u64,
        account: u64,
    ) -> DbResult<Option<(bool, [u64; 2], Option<u64>, i32, bool)>> {
        self.read(|d| d.match_result(match_id, account))
    }

    /// Test: make a match's reports `secs` older.
    #[cfg(test)]
    pub fn age_reports(&self, match_id: u64, secs: i64) -> DbResult<()> {
        self.write(move |d| d.age_reports(match_id, secs))
    }

    #[cfg(test)]
    pub fn flags_of(&self, account: u64) -> DbResult<Vec<String>> {
        self.read(|d| d.flags_of(account))
    }

    /// A stored replay: (players, setup JSON, winner, created, inputs).
    #[allow(clippy::type_complexity)]
    pub fn replay(
        &self,
        match_id: u64,
    ) -> DbResult<Option<([u64; 2], String, Option<u64>, u64, Vec<u8>)>> {
        self.read(|d| d.replay(match_id))
    }

    #[cfg(test)]
    pub fn replay_count(&self) -> DbResult<i64> {
        self.read(|d| d.replay_count())
    }

    pub fn leaderboard(&self, limit: usize) -> DbResult<Vec<ProfileInfo>> {
        self.read(|d| d.leaderboard(limit))
    }

    /// 1-based leaderboard position of a player who has played this season.
    pub fn rank_of(&self, id: u64) -> DbResult<Option<usize>> {
        self.read(|d| d.rank_of(id))
    }

    /// Consistent online copy of the database (`VACUUM INTO`), for backups.
    pub fn backup_to(&self, path: &Path) -> DbResult<()> {
        // outside a read transaction: VACUUM cannot run inside one
        match &self.readers {
            Some(pool) => pool.with(|c| Db { conn: c }.backup_to(path)),
            None => Db {
                conn: &lock(&self.writer),
            }
            .backup_to(path),
        }
    }
}

impl Db<'_> {
    fn tx(&self) -> DbResult<Tx<'_>> {
        self.conn.prepare_cached("SAVEPOINT store")?.execute([])?;
        Ok(Tx {
            conn: self.conn,
            done: false,
        })
    }

    /// Apply pending migrations. Returns true when the database was empty.
    fn migrate(&self) -> DbResult<bool> {
        let version: usize = self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        let tx = self.tx()?;
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
            .prepare_cached("SELECT 1 FROM pragma_table_info('reports') WHERE name = 'checksums'")?
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
            .prepare_cached("SELECT p1, p2 FROM matches WHERE id = ?1")?
            .query_row([match_id as i64], |r| {
                Ok([r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64])
            })
            .optional()
    }

    /// TURN usage of a month (`YYYY-MM`, UTC).
    pub fn turn_usage(&self, month: &str) -> DbResult<TurnMonth> {
        Ok(self
            .conn
            .prepare_cached("SELECT reserved, reported, cloudflare, credentials FROM turn_usage WHERE month = ?1")?.query_row([month],
                |r| {
                    Ok(TurnMonth {
                        reserved: r.get::<_, i64>(0)?.max(0) as u64,
                        reported: r.get::<_, i64>(1)?.max(0) as u64,
                        cloudflare: r.get::<_, i64>(2)?.max(0) as u64,
                        credentials: r.get::<_, i64>(3)?.max(0) as u64,
                    })
                })
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
        self.conn.prepare_cached("INSERT INTO turn_usage (month, reserved, reported, credentials) VALUES (?1, MAX(?2, 0), ?3, ?4)
             ON CONFLICT(month) DO UPDATE SET reserved = MAX(reserved + ?2, 0),
                 reported = reported + ?3, credentials = credentials + ?4")?.execute(params![month, reserved, reported as i64, credentials as i64])?;
        Ok(())
    }

    /// Usage Cloudflare's analytics report for a month (bytes, both ways).
    pub fn turn_set_cloudflare(&self, month: &str, bytes: u64) -> DbResult<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO turn_usage (month, cloudflare) VALUES (?1, ?2)
             ON CONFLICT(month) DO UPDATE SET cloudflare = MAX(cloudflare, ?2)",
            )?
            .execute(params![month, bytes as i64])?;
        Ok(())
    }

    pub fn schema_version(&self) -> DbResult<usize> {
        self.conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
    }

    fn meta(&self, k: &str) -> DbResult<Option<i64>> {
        self.conn
            .prepare_cached("SELECT v FROM meta WHERE k = ?1")?
            .query_row([k], |r| r.get(0))
            .optional()
    }

    fn set_meta(&self, k: &str, v: i64) -> DbResult<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO meta (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = ?2",
            )?
            .execute(params![k, v])?;
        Ok(())
    }

    /// Import the former `state.json` (accounts, matches, season, id counter).
    fn import_json(&self, dir: &Path) -> DbResult<()> {
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
        let tx = self.tx()?;
        for a in &old.accounts {
            tx.prepare_cached(&format!("INSERT OR IGNORE INTO accounts ({ACCOUNT_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"))?.execute(params![
                    a.id as i64, a.key, a.name, a.avatar, a.rating, a.best_rating, a.wins,
                    a.losses, a.created as i64, a.last_seen as i64
                ])?;
        }
        for m in &old.matches {
            tx.prepare_cached("INSERT OR IGNORE INTO matches (id, p1, p2, ranked, created, resolved, winner, delta1, delta2)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)")?.execute(params![
                    m.id as i64,
                    m.players[0] as i64,
                    m.players[1] as i64,
                    m.ranked,
                    m.created as i64,
                    m.resolved,
                    m.winner.map(|w| w as i64),
                    m.deltas[0],
                    m.deltas[1]
                ])?;
            for r in &m.reports {
                tx.prepare_cached("INSERT OR IGNORE INTO reports (match_id, reporter, winner) VALUES (?1, ?2, ?3)")?.execute(params![m.id as i64, r.reporter as i64, r.winner as i64])?;
            }
        }
        let set = |k: &str, v: i64| {
            tx.prepare_cached(
                "INSERT INTO meta (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = ?2",
            )?
            .execute(params![k, v])
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

    /// Start a new season when the current one is over: its standings are
    /// kept, ratings soft-reset toward 1200 ([`rugen_proto::season_reset`]).
    pub fn roll_season(&self) -> DbResult<()> {
        let mut season = self.meta("season")?.unwrap_or(1);
        let mut start = self.meta("season_start")?.unwrap_or(now() as i64);
        let before = season;
        while now() as i64 >= start + SEASON_SECS as i64 {
            let end = start + SEASON_SECS as i64;
            self.end_season(season as u32, start, end)?;
            season += 1;
            start = end;
        }
        if season != before {
            self.set_meta("season", season)?;
            self.set_meta("season_start", start)?;
            log::info!("season {season} started");
        }
        Ok(())
    }

    /// Close season `number` ([`rugen_proto::season_reset`] decides):
    /// final standings and badges of the players who played, then every
    /// rating soft-resets and records restart at 0-0.
    fn end_season(&self, number: u32, start: i64, end: i64) -> DbResult<()> {
        let standings: Vec<Standing> = {
            let mut st = self
                .conn
                .prepare_cached("SELECT id, rating, wins, losses FROM accounts")?;
            st.query_map([], |r| {
                Ok(Standing {
                    account: r.get::<_, i64>(0)? as u64,
                    rating: r.get(1)?,
                    wins: r.get(2)?,
                    losses: r.get(3)?,
                })
            })?
            .collect::<DbResult<_>>()?
        };
        let reset = rugen_proto::season_reset(&standings);
        self.conn
            .prepare_cached(
                "INSERT OR REPLACE INTO seasons (number, start, end, players) VALUES (?1, ?2, ?3, ?4)",
            )?
            .execute(params![number, start, end, reset.results.len() as i64])?;
        for &(account, rating, wins, losses, rank) in &reset.results {
            self.conn
                .prepare_cached(
                    "INSERT OR REPLACE INTO season_results (season, account, rating, wins, losses, rank)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )?
                .execute(params![number, account as i64, rating, wins, losses, rank])?;
            self.conn
                .prepare_cached(
                    "UPDATE accounts SET last_season = ?2, last_rating = ?3, last_rank = ?4 WHERE id = ?1",
                )?
                .execute(params![account as i64, number, rating, rank])?;
        }
        let before: std::collections::HashMap<u64, i32> =
            standings.iter().map(|s| (s.account, s.rating)).collect();
        for &(account, rating) in &reset.ratings {
            if before.get(&account) != Some(&rating) {
                self.conn
                    .prepare_cached("UPDATE accounts SET rating = ?2 WHERE id = ?1")?
                    .execute(params![account as i64, rating])?;
            }
        }
        self.conn
            .prepare_cached("UPDATE accounts SET wins = 0, losses = 0")?
            .execute([])?;
        log::info!(
            "season {number} ended: {} players ranked",
            reset.results.len()
        );
        Ok(())
    }

    fn past_season(&self, number: u32) -> DbResult<Option<Season>> {
        self.conn
            .prepare_cached("SELECT start, end FROM seasons WHERE number = ?1")?
            .query_row([number], |r| {
                Ok(Season {
                    number,
                    name: format!("SEASON {number}"),
                    started_at: r.get::<_, i64>(0)?.max(0) as u64,
                    ends_at: r.get::<_, i64>(1)?.max(0) as u64,
                    secs_left: 0,
                })
            })
            .optional()
    }

    fn past_seasons(&self) -> DbResult<Vec<u32>> {
        let mut st = self.conn.prepare_cached(
            "SELECT number FROM seasons WHERE players > 0 ORDER BY number DESC LIMIT ?1",
        )?;
        st.query_map([PAST_SEASONS as i64], |r| r.get(0))?.collect()
    }

    /// A finished season's line of an account as a profile (its final
    /// rating, record and tier).
    fn season_row(r: &Row<'_>) -> DbResult<(usize, ProfileInfo)> {
        let mut a = Account::from_row(r)?;
        a.rating = r.get(14)?;
        a.wins = r.get(15)?;
        a.losses = r.get(16)?;
        Ok((r.get::<_, i64>(17)? as usize, a.info()))
    }

    fn season_board(&self, number: u32, limit: usize) -> DbResult<Vec<ProfileInfo>> {
        let cols = ACCOUNT_SELECT
            .split(", ")
            .map(|c| format!("a.{}", c.trim()))
            .collect::<Vec<_>>()
            .join(", ");
        let mut st = self.conn.prepare_cached(&format!(
            "SELECT {cols}, s.rating, s.wins, s.losses, s.rank FROM season_results s
             JOIN accounts a ON a.id = s.account WHERE s.season = ?1 ORDER BY s.rank LIMIT ?2"
        ))?;
        st.query_map(params![number, limit as i64], Self::season_row)?
            .map(|r| r.map(|(_, p)| p))
            .collect()
    }

    fn season_rank_of(&self, number: u32, id: u64) -> DbResult<Option<(usize, ProfileInfo)>> {
        let cols = ACCOUNT_SELECT
            .split(", ")
            .map(|c| format!("a.{}", c.trim()))
            .collect::<Vec<_>>()
            .join(", ");
        self.conn
            .prepare_cached(&format!(
                "SELECT {cols}, s.rating, s.wins, s.losses, s.rank FROM season_results s
                 JOIN accounts a ON a.id = s.account WHERE s.season = ?1 AND s.account = ?2"
            ))?
            .query_row(params![number, id as i64], Self::season_row)
            .optional()
    }

    /// The current season is over ([`Self::roll_season`] has work to do).
    fn season_due(&self) -> DbResult<bool> {
        let start = self.meta("season_start")?.unwrap_or(now() as i64);
        Ok(now() as i64 >= start + SEASON_SECS as i64)
    }

    pub fn season(&self) -> DbResult<Season> {
        let number = self.meta("season")?.unwrap_or(1) as u32;
        let start = self.meta("season_start")?.unwrap_or(0) as u64;
        let ends_at = start + SEASON_SECS;
        Ok(Season {
            number,
            name: format!("SEASON {number}"),
            ends_at,
            started_at: start,
            secs_left: ends_at.saturating_sub(now()),
        })
    }

    fn fresh_id(&self) -> DbResult<u64> {
        let id = self
            .conn
            .prepare_cached("UPDATE meta SET v = v + 1 WHERE k = 'next_id' RETURNING v - 1")?
            .query_row([], |r| r.get::<_, i64>(0))?;
        Ok(id as u64)
    }

    pub fn account_count(&self) -> DbResult<usize> {
        self.conn
            .prepare_cached("SELECT COUNT(*) FROM accounts")?
            .query_row([], |r| r.get::<_, i64>(0))
            .map(|n| n as usize)
    }

    /// Accounts whose name starts with `prefix` (load-test leftovers) and
    /// their unranked matches (reports / replays cascade): counted only when
    /// `dry_run`, deleted otherwise. Ranked matches are kept (they moved
    /// other players' ratings). Returns (accounts, matches).
    pub fn delete_accounts_by_prefix(
        &self,
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
        let tx = self.tx()?;
        tx.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS doomed (id INTEGER PRIMARY KEY); DELETE FROM doomed;",
        )?;
        let accounts = tx
            .prepare_cached(
                "INSERT INTO doomed (id) SELECT id FROM accounts WHERE name LIKE ?1 ESCAPE '\\'",
            )?
            .execute([&pattern])?;
        let matches: usize = tx
            .prepare_cached(
                "SELECT COUNT(*) FROM matches WHERE ranked = 0
               AND (p1 IN (SELECT id FROM doomed) OR p2 IN (SELECT id FROM doomed))",
            )?
            .query_row([], |r| r.get::<_, i64>(0))? as usize;
        if !dry_run {
            tx.prepare_cached(
                "DELETE FROM matches WHERE ranked = 0
                   AND (p1 IN (SELECT id FROM doomed) OR p2 IN (SELECT id FROM doomed))",
            )?
            .execute([])?;
            tx.prepare_cached("DELETE FROM flags WHERE account IN (SELECT id FROM doomed)")?
                .execute([])?;
            tx.prepare_cached(
                "DELETE FROM season_results WHERE account IN (SELECT id FROM doomed)",
            )?
            .execute([])?;
            tx.prepare_cached("DELETE FROM accounts WHERE id IN (SELECT id FROM doomed)")?
                .execute([])?;
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

    pub fn register(&self) -> DbResult<Account> {
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
            username: None,
            last_season: None,
        };
        self.conn.prepare_cached(&format!("INSERT INTO accounts ({ACCOUNT_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"))?.execute(params![
                a.id as i64, a.key, a.name, a.avatar, a.rating, a.best_rating, a.wins, a.losses,
                a.created as i64, a.last_seen as i64
            ])?;
        Ok(a)
    }

    /// The account owning `key` (an anonymous account's key, or a session
    /// key of a named account) and, for a session key, its hash and when
    /// it was last used.
    fn lookup_key(&self, key: &str) -> DbResult<Option<(Account, Option<KeyUse>)>> {
        let a = self
            .conn
            .prepare_cached(&format!(
                "SELECT {ACCOUNT_SELECT} FROM accounts WHERE key = ?1"
            ))?
            .query_row([key], Account::from_row)
            .optional()?;
        if let Some(a) = a {
            return Ok(Some((a, None)));
        }
        let h = key_hash(key);
        let row = self
            .conn
            .prepare_cached("SELECT account, last_used FROM account_keys WHERE hash = ?1")?
            .query_row([&h], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)? as u64))
            })
            .optional()?;
        let Some((id, used)) = row else {
            return Ok(None);
        };
        Ok(self.by_id(id as u64)?.map(|a| (a, Some((h, used)))))
    }

    /// Refresh `last_seen` of an account and / or `last_used` of a session key.
    fn touch_key(&self, id: u64, seen: bool, session: Option<&str>, t: u64) -> DbResult<()> {
        if seen {
            self.conn
                .prepare_cached("UPDATE accounts SET last_seen = ?2 WHERE id = ?1")?
                .execute(params![id as i64, t as i64])?;
        }
        if let Some(h) = session {
            self.conn
                .prepare_cached("UPDATE account_keys SET last_used = ?2 WHERE hash = ?1")?
                .execute(params![h, t as i64])?;
        }
        Ok(())
    }

    /// The named account called `username` (any case).
    pub fn by_username(&self, username: &str) -> DbResult<Option<Account>> {
        self.conn
            .prepare_cached(&format!(
                "SELECT {ACCOUNT_SELECT} FROM accounts WHERE username = ?1 COLLATE NOCASE"
            ))?
            .query_row([username], Account::from_row)
            .optional()
    }

    /// Account id and password hash of `username` (login).
    pub fn credentials(&self, username: &str) -> DbResult<Option<(u64, Option<String>)>> {
        self.conn
            .prepare_cached("SELECT id, password FROM accounts WHERE username = ?1 COLLATE NOCASE")?
            .query_row([username], |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?)))
            .optional()
    }

    /// Password hash of account `id`.
    pub fn password_of(&self, id: u64) -> DbResult<Option<String>> {
        Ok(self
            .conn
            .prepare_cached("SELECT password FROM accounts WHERE id = ?1")?
            .query_row([id as i64], |r| r.get::<_, Option<String>>(0))
            .optional()?
            .flatten())
    }

    pub fn username_taken(&self, username: &str) -> DbResult<bool> {
        self.conn
            .prepare_cached("SELECT 1 FROM accounts WHERE username = ?1 COLLATE NOCASE")?
            .exists([username])
    }

    /// A new named account (rating at the start, like an anonymous one).
    /// `username` must already be valid ([`rugen_proto::account::username_error`])
    /// and `phc` an Argon2id hash. Returns the account and its first key.
    pub fn register_named(
        &self,
        username: &str,
        phc: &str,
    ) -> DbResult<Result<(Account, String), NameError>> {
        if self.username_taken(username)? {
            return Ok(Err(NameError::Taken));
        }
        let id = self.fresh_id()?;
        let t = now();
        let inserted = self
            .conn
            .prepare_cached(
                "INSERT INTO accounts (id, key, name, avatar, rating, best_rating, wins, losses,
                 created, last_seen, username, password)
             VALUES (?1, ?2, ?3, 0, ?4, ?4, 0, 0, ?5, ?5, ?3, ?6)",
            )?
            .execute(params![
                id as i64,
                dead_key("named"),
                username,
                elo::START_RATING,
                t as i64,
                phc
            ]);
        match inserted {
            Ok(_) => {}
            // lost a race for the name
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Ok(Err(NameError::Taken));
            }
            Err(e) => return Err(e),
        }
        let key = self.issue_key(id)?;
        let a = self
            .by_id(id)?
            .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        Ok(Ok((a, key)))
    }

    /// Give anonymous account `id` a username and password: it keeps its
    /// id, rating and history, and the key it already has.
    pub fn claim(
        &self,
        id: u64,
        username: &str,
        phc: &str,
    ) -> DbResult<Result<Account, NameError>> {
        if self.by_id(id)?.is_some_and(|a| a.username.is_some()) {
            return Ok(Err(NameError::AlreadyNamed));
        }
        if self.username_taken(username)? {
            return Ok(Err(NameError::Taken));
        }
        let r = self
            .conn
            .prepare_cached(
                "UPDATE accounts SET username = ?2, name = ?2, password = ?3
             WHERE id = ?1 AND username IS NULL",
            )?
            .execute(params![id as i64, username, phc]);
        match r {
            Ok(1) => {}
            Ok(_) => return Ok(Err(NameError::AlreadyNamed)),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Ok(Err(NameError::Taken));
            }
            Err(e) => return Err(e),
        }
        Ok(Ok(self
            .by_id(id)?
            .ok_or(rusqlite::Error::QueryReturnedNoRows)?))
    }

    /// A new session key for account `id` (login on a device). Only the
    /// [`MAX_SESSIONS`] most recently used keys stay valid.
    pub fn issue_key(&self, id: u64) -> DbResult<String> {
        let key = random_hex(32);
        let t = now() as i64;
        let tx = self.tx()?;
        tx.prepare_cached(
            "INSERT INTO account_keys (hash, account, created, last_used) VALUES (?1, ?2, ?3, ?3)",
        )?
        .execute(params![key_hash(&key), id as i64, t])?;
        tx.prepare_cached(
            "DELETE FROM account_keys WHERE account = ?1 AND hash NOT IN (
                 SELECT hash FROM account_keys WHERE account = ?1
                 ORDER BY last_used DESC, created DESC LIMIT ?2)",
        )?
        .execute(params![id as i64, MAX_SESSIONS])?;
        tx.commit()?;
        Ok(key)
    }

    /// Revoke one key (log out this device).
    pub fn revoke_key(&self, id: u64, key: &str) -> DbResult<()> {
        self.conn
            .prepare_cached("UPDATE accounts SET key = ?3 WHERE id = ?1 AND key = ?2")?
            .execute(params![id as i64, key, dead_key("revoked")])?;
        self.conn
            .prepare_cached("DELETE FROM account_keys WHERE account = ?1 AND hash = ?2")?
            .execute(params![id as i64, key_hash(key)])?;
        Ok(())
    }

    /// Revoke every key of account `id` (log out everywhere).
    pub fn revoke_all(&self, id: u64) -> DbResult<()> {
        let tx = self.tx()?;
        tx.prepare_cached("UPDATE accounts SET key = ?2 WHERE id = ?1")?
            .execute(params![id as i64, dead_key("revoked")])?;
        tx.prepare_cached("DELETE FROM account_keys WHERE account = ?1")?
            .execute([id as i64])?;
        tx.commit()
    }

    /// Replace the password hash of account `id` (callers revoke keys).
    pub fn set_password(&self, id: u64, phc: &str) -> DbResult<()> {
        self.conn
            .prepare_cached("UPDATE accounts SET password = ?2 WHERE id = ?1")?
            .execute(params![id as i64, phc])?;
        Ok(())
    }

    /// Keys (devices) able to act for account `id`.
    pub fn sessions(&self, id: u64) -> DbResult<u32> {
        let n: i64 = self
            .conn
            .prepare_cached(
                "SELECT (SELECT COUNT(*) FROM account_keys WHERE account = ?1)
                  + (SELECT COUNT(*) FROM accounts WHERE id = ?1 AND length(key) = 64)",
            )?
            .query_row([id as i64], |r| r.get(0))?;
        Ok(n as u32)
    }

    pub fn by_id(&self, id: u64) -> DbResult<Option<Account>> {
        self.conn
            .prepare_cached(&format!(
                "SELECT {ACCOUNT_SELECT} FROM accounts WHERE id = ?1"
            ))?
            .query_row([id as i64], Account::from_row)
            .optional()
    }

    pub fn set_profile(
        &self,
        id: u64,
        name: Option<String>,
        avatar: Option<u32>,
    ) -> DbResult<Option<Account>> {
        // a named account's name is its username
        let named = self.by_id(id)?.is_some_and(|a| a.username.is_some());
        if let Some(n) = name.filter(|_| !named) {
            let clean: String = n
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == ' ')
                .take(16)
                .collect();
            // nobody else may wear a username (API 4 players keep their own name)
            if !clean.trim().is_empty() && !self.username_taken(clean.trim())? {
                self.conn
                    .prepare_cached("UPDATE accounts SET name = ?2 WHERE id = ?1")?
                    .execute(params![id as i64, clean.trim()])?;
            }
        }
        if let Some(av) = avatar {
            self.conn
                .prepare_cached("UPDATE accounts SET avatar = ?2 WHERE id = ?1")?
                .execute(params![id as i64, av.min(99)])?;
        }
        self.by_id(id)
    }

    /// A new match row. `setup` (JSON: characters, stage, rules) is kept for replays.
    pub fn new_match(&self, players: [u64; 2], ranked: bool, setup: &str) -> DbResult<u64> {
        let id = self.fresh_id()?;
        self.conn.prepare_cached("INSERT INTO matches (id, p1, p2, ranked, created, setup) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")?.execute(params![
                id as i64,
                players[0] as i64,
                players[1] as i64,
                ranked,
                now() as i64,
                setup
            ])?;
        Ok(id)
    }

    /// Replace a match's setup JSON (fingerprints become known at start).
    pub fn set_setup(&self, match_id: u64, setup: &str) -> DbResult<()> {
        self.conn
            .prepare_cached("UPDATE matches SET setup = ?2 WHERE id = ?1")?
            .execute(params![match_id as i64, setup])?;
        Ok(())
    }

    /// Record one side's report. The match resolves once both sides
    /// reported: ratings move (ranked) only when the reports agree
    /// ([`reports_agree`]); otherwise the match is marked disputed.
    pub fn report(
        &self,
        reporter: u64,
        match_id: u64,
        data: &ReportData,
    ) -> DbResult<ReportOutcome> {
        let rejected = ReportOutcome::default();
        let tx = self.tx()?;
        let m = tx
            .prepare_cached("SELECT p1, p2, ranked, resolved, delta1, delta2, winner, disputed, desync, setup FROM matches WHERE id = ?1")?.query_row([match_id as i64],
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
                })
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
        let inserted = tx.prepare_cached("INSERT OR IGNORE INTO reports (match_id, reporter, winner, frames, checksum, inputs, checksums, ending, at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)")?.execute(params![
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
            ])?;
        if inserted == 0 {
            tx.commit()?;
            return Ok(ReportOutcome {
                accepted: true,
                ..Default::default()
            });
        }
        let reports: Vec<ReportData> = {
            let mut st = tx.prepare_cached(
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
            tx.prepare_cached("UPDATE matches SET resolved = 1, disputed = 1 WHERE id = ?1")?
                .execute([match_id as i64])?;
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
        tx: &Connection,
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
                tx.prepare_cached("INSERT OR IGNORE INTO char_ratings (fingerprint, name, rating) VALUES (?1, ?2, ?3)")?.execute(params![f, n, CHAR_START_RATING])?;
            }
            let get = |f: &str| -> DbResult<i32> {
                tx.prepare_cached("SELECT rating FROM char_ratings WHERE fingerprint = ?1")?
                    .query_row([f], |r| r.get(0))
            };
            let (rw, rl) = elo::update_k(get(&fw)?, get(&fl)?, CHAR_K);
            tx.prepare_cached("UPDATE char_ratings SET rating = ?2, games = games + 1, wins = wins + 1 WHERE fingerprint = ?1")?.execute(params![fw, rw])?;
            tx.prepare_cached(
                "UPDATE char_ratings SET rating = ?2, games = games + 1 WHERE fingerprint = ?1",
            )?
            .execute(params![fl, rl])?;
        }
        let mut deltas = [0, 0];
        if ranked && let (Some(f1), Some(f2)) = (fp("p1_fp"), fp("p2_fp")) {
            let name = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
            let (n1, n2) = (name("p1_char"), name("p2_char"));
            Self::settle_fighters(tx, [(&f1, &n1), (&f2, &n2)], players, winner)?;
        }
        if ranked {
            let rating = |id: u64| -> DbResult<Option<i32>> {
                tx.prepare_cached("SELECT rating FROM accounts WHERE id = ?1")?
                    .query_row([id as i64], |r| r.get(0))
                    .optional()
            };
            if let (Some(rw), Some(rl)) = (rating(winner)?, rating(loser)?) {
                let (nw, nl) = elo::update(rw, rl);
                tx.prepare_cached("UPDATE accounts SET rating = ?2, best_rating = MAX(best_rating, ?2), wins = wins + 1 WHERE id = ?1")?.execute(params![winner as i64, nw])?;
                tx.prepare_cached(
                    "UPDATE accounts SET rating = ?2, losses = losses + 1 WHERE id = ?1",
                )?
                .execute(params![loser as i64, nl])?;
                let (dw, dl) = (nw - rw, nl - rl);
                deltas = if players[0] == winner {
                    [dw, dl]
                } else {
                    [dl, dw]
                };
            }
            if !inputs.is_empty() {
                tx.prepare_cached("INSERT OR REPLACE INTO replays (match_id, created, inputs) VALUES (?1, ?2, ?3)")?.execute(params![match_id as i64, now() as i64, inputs])?;
                tx.prepare_cached(
                    "DELETE FROM replays WHERE match_id NOT IN
                     (SELECT match_id FROM replays ORDER BY created DESC, match_id DESC LIMIT ?1)",
                )?
                .execute([REPLAY_RETENTION])?;
                // the replay's files stay on the server longer
                for f in &fps {
                    tx.prepare_cached("UPDATE packages SET keep_until = MAX(keep_until, ?2) WHERE fingerprint = ?1")?.execute(params![f, (now() + replay_keep_secs()) as i64])?;
                }
            }
        }
        tx.prepare_cached("UPDATE matches SET resolved = 1, disputed = 0, winner = ?2, delta1 = ?3, delta2 = ?4 WHERE id = ?1")?.execute(params![match_id as i64, winner as i64, deltas[0], deltas[1]])?;
        Ok(deltas)
    }

    /// Per-fighter boards: each player's rating with its fighter moves like
    /// its own (Elo K = 32) against the other player's with theirs. A
    /// player new to a fighter this season starts from last season's
    /// rating with it, soft-reset, else from the start rating.
    fn settle_fighters(
        tx: &Connection,
        fighters: [(&String, &String); 2],
        players: [u64; 2],
        winner: u64,
    ) -> DbResult<()> {
        let season: i64 = tx
            .prepare_cached("SELECT v FROM meta WHERE k = 'season'")?
            .query_row([], |r| r.get(0))
            .optional()?
            .unwrap_or(1);
        let mut ratings = [0i32; 2];
        for i in 0..2 {
            let (fp, name) = fighters[i];
            let start = tx
                .prepare_cached(
                    "SELECT rating FROM fighter_ratings WHERE fingerprint = ?1 AND account = ?2
                     AND season < ?3 ORDER BY season DESC LIMIT 1",
                )?
                .query_row(params![fp, players[i] as i64, season], |r| {
                    r.get::<_, i32>(0)
                })
                .optional()?
                .map_or(elo::START_RATING, rugen_proto::soft_reset);
            tx.prepare_cached(
                "INSERT INTO fighter_ratings (season, fingerprint, account, name, rating)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(season, fingerprint, account) DO UPDATE SET name = ?4",
            )?
            .execute(params![season, fp, players[i] as i64, name, start])?;
            ratings[i] = tx
                .prepare_cached(
                    "SELECT rating FROM fighter_ratings WHERE season = ?1 AND fingerprint = ?2 AND account = ?3",
                )?
                .query_row(params![season, fp, players[i] as i64], |r| r.get(0))?;
        }
        let w = usize::from(players[1] == winner);
        let (nw, nl) = elo::update(ratings[w], ratings[1 - w]);
        for (i, rating, won) in [(w, nw, true), (1 - w, nl, false)] {
            tx.prepare_cached(
                "UPDATE fighter_ratings SET rating = ?4, wins = wins + ?5, losses = losses + ?6
                 WHERE season = ?1 AND fingerprint = ?2 AND account = ?3",
            )?
            .execute(params![
                season,
                fighters[i].0,
                players[i] as i64,
                rating,
                i64::from(won),
                i64::from(!won)
            ])?;
        }
        Ok(())
    }

    /// Fighters with a board in `season`, most played first.
    pub fn board_fighters(&self, season: u32) -> DbResult<Vec<rugen_proto::FighterEntry>> {
        let mut st = self.conn.prepare_cached(
            "SELECT fingerprint, MAX(name), COUNT(*), SUM(wins + losses) FROM fighter_ratings
             WHERE season = ?1 GROUP BY fingerprint
             ORDER BY SUM(wins + losses) DESC, fingerprint LIMIT ?2",
        )?;
        st.query_map(params![season, BOARD_FIGHTERS as i64], |r| {
            Ok(rugen_proto::FighterEntry {
                fingerprint: r.get(0)?,
                name: r.get(1)?,
                players: r.get::<_, i64>(2)? as u32,
                games: r.get::<_, i64>(3)? as u32,
            })
        })?
        .collect()
    }

    /// One fighter's board in `season`: players by their rating with it.
    pub fn fighter_board(&self, season: u32, fp: &str, limit: usize) -> DbResult<Vec<ProfileInfo>> {
        let cols = Self::prefixed_cols();
        let mut st = self.conn.prepare_cached(&format!(
            "SELECT {cols}, f.rating, f.wins, f.losses, 0 FROM fighter_ratings f
             JOIN accounts a ON a.id = f.account WHERE f.season = ?1 AND f.fingerprint = ?2
             ORDER BY f.rating DESC, a.id LIMIT ?3"
        ))?;
        st.query_map(params![season, fp, limit as i64], Self::season_row)?
            .map(|r| r.map(|(_, p)| p))
            .collect()
    }

    /// An account's position and line on a fighter's board.
    pub fn fighter_rank_of(
        &self,
        season: u32,
        fp: &str,
        id: u64,
    ) -> DbResult<Option<(usize, ProfileInfo)>> {
        let cols = Self::prefixed_cols();
        let row = self
            .conn
            .prepare_cached(&format!(
                "SELECT {cols}, f.rating, f.wins, f.losses, 0 FROM fighter_ratings f
                 JOIN accounts a ON a.id = f.account
                 WHERE f.season = ?1 AND f.fingerprint = ?2 AND f.account = ?3"
            ))?
            .query_row(params![season, fp, id as i64], Self::season_row)
            .optional()?;
        let Some((_, p)) = row else { return Ok(None) };
        let ahead: i64 = self
            .conn
            .prepare_cached(
                "SELECT COUNT(*) FROM fighter_ratings WHERE season = ?1 AND fingerprint = ?2
                 AND (rating > ?3 OR (rating = ?3 AND account < ?4))",
            )?
            .query_row(params![season, fp, p.rating, id as i64], |r| r.get(0))?;
        Ok(Some((ahead as usize + 1, p)))
    }

    pub fn share_replay(&self, row: &SharedRow, fps: &[String; 3]) -> DbResult<SharedRow> {
        if let Some(old) = self.shared_of_match(row.match_id)? {
            return Ok(old);
        }
        self.conn
            .prepare_cached(
                "INSERT INTO shared_replays (code, match_id, header, inputs, frames, account,
                 p1_fp, p2_fp, stage_fp, created, expires)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )?
            .execute(params![
                row.code,
                row.match_id as i64,
                row.header,
                row.inputs,
                (row.inputs.len() / 4) as i64,
                row.account as i64,
                fps[0],
                fps[1],
                fps[2],
                row.created as i64,
                row.expires as i64
            ])?;
        for f in fps.iter().filter(|f| !f.is_empty()) {
            self.conn
                .prepare_cached(
                    "UPDATE packages SET keep_until = MAX(keep_until, ?2) WHERE fingerprint = ?1",
                )?
                .execute(params![f, row.expires as i64])?;
        }
        Ok(row.clone())
    }

    pub fn shared_replay(&self, code: &str) -> DbResult<Option<SharedRow>> {
        self.conn
            .prepare_cached(&format!(
                "SELECT {SHARED_COLS} FROM shared_replays WHERE code = ?1 AND expires > ?2"
            ))?
            .query_row(params![code, now() as i64], SharedRow::from_row)
            .optional()
    }

    pub fn shared_of_match(&self, match_id: u64) -> DbResult<Option<SharedRow>> {
        self.conn
            .prepare_cached(&format!(
                "SELECT {SHARED_COLS} FROM shared_replays WHERE match_id = ?1 AND expires > ?2"
            ))?
            .query_row(params![match_id as i64, now() as i64], SharedRow::from_row)
            .optional()
    }

    pub fn shared_has(&self, fp: &str) -> DbResult<bool> {
        self.conn
            .prepare_cached(
                "SELECT 1 FROM shared_replays WHERE expires > ?2
                 AND (p1_fp = ?1 OR p2_fp = ?1 OR stage_fp = ?1)",
            )?
            .exists(params![fp, now() as i64])
    }

    pub fn shares_since(&self, account: u64, since: u64) -> DbResult<u32> {
        self.conn
            .prepare_cached(
                "SELECT COUNT(*) FROM shared_replays WHERE account = ?1 AND created >= ?2",
            )?
            .query_row(params![account as i64, since as i64], |r| {
                r.get::<_, i64>(0)
            })
            .map(|n| n as u32)
    }

    pub fn sweep_shared(&self, max_bytes: u64) -> DbResult<usize> {
        let mut gone = self
            .conn
            .prepare_cached("DELETE FROM shared_replays WHERE expires <= ?1")?
            .execute([now() as i64])?;
        loop {
            let (_, bytes) = self.shared_usage()?;
            if bytes <= max_bytes {
                break;
            }
            let n = self
                .conn
                .prepare_cached(
                    "DELETE FROM shared_replays WHERE code =
                     (SELECT code FROM shared_replays ORDER BY created, code LIMIT 1)",
                )?
                .execute([])?;
            if n == 0 {
                break;
            }
            gone += n;
        }
        Ok(gone)
    }

    pub fn shared_usage(&self) -> DbResult<(u64, u64)> {
        self.conn
            .prepare_cached(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(inputs)), 0) FROM shared_replays",
            )?
            .query_row([], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64))
            })
    }

    /// [`ACCOUNT_SELECT`] with the `a.` table prefix.
    fn prefixed_cols() -> String {
        ACCOUNT_SELECT
            .split(", ")
            .map(|c| format!("a.{}", c.trim()))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn set_ending(
        tx: &Connection,
        match_id: u64,
        ending: Option<rugen_proto::Ending>,
        fled: Option<u64>,
    ) -> DbResult<()> {
        tx.prepare_cached("UPDATE matches SET ending = ?2, fled = ?3 WHERE id = ?1")?
            .execute(params![
                match_id as i64,
                ending.map(|e| e.as_str()),
                fled.map(|f| f as i64)
            ])?;
        Ok(())
    }

    /// Unsettled matches with a single report, from the player who says it
    /// won because the other one fled or disconnected.
    pub fn pending_claims(&self) -> DbResult<Vec<Claim>> {
        let mut st = self.conn.prepare_cached(
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
    pub fn settle_claim(&self, c: &Claim) -> DbResult<Option<[i32; 2]>> {
        let tx = self.tx()?;
        if !Self::pending_claims_tx(&tx, c)? {
            return Ok(None);
        }
        let (players, ranked, setup) = tx
            .prepare_cached("SELECT p1, p2, ranked, setup FROM matches WHERE id = ?1")?
            .query_row([c.match_id as i64], |r| {
                Ok((
                    [r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64],
                    r.get::<_, bool>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?;
        let inputs: Option<Vec<u8>> = tx
            .prepare_cached("SELECT inputs FROM reports WHERE match_id = ?1 AND reporter = ?2")?
            .query_row(params![c.match_id as i64, c.winner as i64], |r| r.get(0))?;
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
    fn pending_claims_tx(tx: &Connection, c: &Claim) -> DbResult<bool> {
        let n: i64 = tx
            .prepare_cached(
                "SELECT COUNT(*) FROM reports r JOIN matches m ON m.id = r.match_id
             WHERE r.match_id = ?1 AND m.resolved = 0 AND r.reporter = ?2 AND r.ending IS NOT NULL
               AND (SELECT COUNT(*) FROM reports x WHERE x.match_id = r.match_id) = 1",
            )?
            .query_row(params![c.match_id as i64, c.winner as i64], |r| r.get(0))?;
        Ok(n == 1)
    }

    /// How a settled match ended early (`None` for a match played out).
    pub fn match_ending(&self, match_id: u64) -> DbResult<EndingRow> {
        let row = self
            .conn
            .prepare_cached("SELECT ending, fled FROM matches WHERE id = ?1")?
            .query_row([match_id as i64], |r| {
                Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<i64>>(1)?))
            })
            .optional()?;
        Ok(row.and_then(|(e, f)| e.map(|e| (e, f.map(|f| f as u64)))))
    }

    /// A client saw a desync (ggrs checksum mismatch): the match can no
    /// longer resolve by agreement.
    pub fn report_desync(&self, reporter: u64, match_id: u64, frame: u32) -> DbResult<bool> {
        let n = self
            .conn
            .prepare_cached("UPDATE matches SET desync = 1 WHERE id = ?1 AND (p1 = ?2 OR p2 = ?2)")?
            .execute(params![match_id as i64, reporter as i64])?;
        if n > 0 {
            self.conn.prepare_cached("UPDATE matches SET disputed = 1 WHERE id = ?1 AND resolved = 1 AND winner IS NULL")?.execute([match_id as i64])?;
            log::warn!("match {match_id}: desync reported by {reporter} at frame {frame}");
        }
        Ok(n > 0)
    }

    /// A disputed match the server re-simulated: settle it with the
    /// simulated winner (`None` = undecidable, stays disputed).
    pub fn resolve_dispute(
        &self,
        match_id: u64,
        winner: Option<u64>,
        note: &str,
    ) -> DbResult<bool> {
        let tx = self.tx()?;
        let m = tx
            .prepare_cached(
                "SELECT p1, p2, ranked, setup, disputed, winner FROM matches WHERE id = ?1",
            )?
            .query_row([match_id as i64], |r| {
                Ok((
                    [r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64],
                    r.get::<_, bool>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, bool>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                ))
            })
            .optional()?;
        let Some((players, ranked, setup, disputed, set)) = m else {
            return Ok(false);
        };
        tx.prepare_cached("UPDATE matches SET resim = ?2 WHERE id = ?1")?
            .execute(params![match_id as i64, note])?;
        let settled = match winner {
            Some(w) if disputed && set.is_none() && players.contains(&w) => {
                let inputs: Vec<u8> = tx
                    .prepare_cached(
                        "SELECT inputs FROM reports WHERE match_id = ?1 AND inputs IS NOT NULL
                         ORDER BY length(inputs) DESC LIMIT 1",
                    )?
                    .query_row([match_id as i64], |r| r.get(0))
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

    /// What the re-simulation said about a match (`None`: not run).
    #[cfg(test)]
    pub fn resim_note(&self, match_id: u64) -> DbResult<Option<String>> {
        Ok(self
            .conn
            .prepare_cached("SELECT resim FROM matches WHERE id = ?1")?
            .query_row([match_id as i64], |r| r.get::<_, Option<String>>(0))
            .optional()?
            .flatten())
    }

    /// Setup JSON, ranked flag, players and the reports (reporter, data) of a match.
    #[allow(clippy::type_complexity)]
    pub fn match_evidence(
        &self,
        match_id: u64,
    ) -> DbResult<Option<(String, bool, [u64; 2], Vec<(u64, ReportData)>)>> {
        let Some((setup, ranked, players)) = self
            .conn
            .prepare_cached("SELECT setup, ranked, p1, p2 FROM matches WHERE id = ?1")?
            .query_row([match_id as i64], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, bool>(1)?,
                    [r.get::<_, i64>(2)? as u64, r.get::<_, i64>(3)? as u64],
                ))
            })
            .optional()?
        else {
            return Ok(None);
        };
        let mut st = self.conn.prepare_cached(
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
            .prepare_cached("SELECT disputed FROM matches WHERE id = ?1")?
            .query_row([match_id as i64], |r| r.get(0))
            .optional()
            .map(|d| d.unwrap_or(false))
    }

    // ---- packages, community ratings, flags

    pub fn package(&self, fp: &str) -> DbResult<Option<PackageRow>> {
        self.conn
            .prepare_cached(&format!(
                "SELECT {PACKAGE_COLS} FROM packages WHERE fingerprint = ?1"
            ))?
            .query_row([fp], PackageRow::from_row)
            .optional()
    }

    pub fn put_package(&self, p: &PackageRow) -> DbResult<()> {
        let profile = p
            .profile
            .as_ref()
            .and_then(|p| serde_json::to_string(p).ok());
        self.conn.prepare_cached(&format!(
                "INSERT OR REPLACE INTO packages ({PACKAGE_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
            ))?.execute(params![
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
            ])?;
        Ok(())
    }

    /// Mark packages as used now (TTL / LRU bookkeeping).
    pub fn touch_packages(&self, fps: &[&str]) -> DbResult<()> {
        for f in fps {
            self.conn
                .prepare_cached("UPDATE packages SET last_used = ?2 WHERE fingerprint = ?1")?
                .execute(params![f, now() as i64])?;
        }
        Ok(())
    }

    /// All packages, least recently used first.
    pub fn packages_lru(&self) -> DbResult<Vec<PackageRow>> {
        let mut st = self.conn.prepare_cached(&format!(
            "SELECT {PACKAGE_COLS} FROM packages ORDER BY last_used ASC, fingerprint"
        ))?;
        st.query_map([], PackageRow::from_row)?.collect()
    }

    pub fn delete_package(&self, fp: &str) -> DbResult<()> {
        self.conn
            .prepare_cached("DELETE FROM packages WHERE fingerprint = ?1")?
            .execute([fp])?;
        Ok(())
    }

    pub fn char_rating(&self, fp: &str) -> DbResult<Option<rugen_proto::CharRating>> {
        self.conn
            .prepare_cached("SELECT rating, games, wins FROM char_ratings WHERE fingerprint = ?1")?
            .query_row([fp], |r| {
                Ok(rugen_proto::CharRating {
                    rating: r.get(0)?,
                    games: r.get(1)?,
                    wins: r.get(2)?,
                })
            })
            .optional()
    }

    /// Record an anti-cheat finding against an account; `fingerprint` =
    /// the content a false profile was declared for (feeds auto-blocking).
    pub fn flag(
        &self,
        account: u64,
        match_id: Option<u64>,
        reason: &str,
        fingerprint: Option<&str>,
    ) -> DbResult<()> {
        log::warn!("flag: account {account}: {reason}");
        self.conn.prepare_cached("INSERT INTO flags (account, match_id, reason, created, fingerprint) VALUES (?1, ?2, ?3, ?4, ?5)")?.execute(params![
                account as i64,
                match_id.map(|m| m as i64),
                reason,
                now() as i64,
                fingerprint
            ])?;
        Ok(())
    }

    /// Distinct accounts flagged for a false profile of `fp`.
    pub fn liars_for(&self, fp: &str) -> DbResult<u32> {
        self.conn
            .prepare_cached("SELECT COUNT(DISTINCT account) FROM flags WHERE fingerprint = ?1")?
            .query_row([fp], |r| r.get(0))
    }

    /// Matches with a reported desync that `fp` was part of.
    pub fn desyncs_for(&self, fp: &str) -> DbResult<u32> {
        self.conn
            .prepare_cached(
                "SELECT COUNT(*) FROM matches WHERE desync = 1 AND instr(setup, ?1) > 0",
            )?
            .query_row([fp], |r| r.get(0))
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
    pub fn block(&self, fp: &str, reason: &str, source: &str) -> DbResult<()> {
        self.conn.prepare_cached("INSERT INTO blocklist (fingerprint, reason, source, allowed, created) VALUES (?1, ?2, ?3, 0, ?4)
             ON CONFLICT(fingerprint) DO UPDATE SET reason = ?2, source = ?3, allowed = 0, created = ?4")?.execute(params![fp, reason, source, now() as i64])?;
        self.bump_truth_seq()
    }

    /// Automatic block: only when the fingerprint has no entry at all (an
    /// operator-cleared one stays cleared). True when it was added.
    pub fn auto_block(&self, fp: &str, reason: &str) -> DbResult<bool> {
        let n = self.conn.prepare_cached("INSERT OR IGNORE INTO blocklist (fingerprint, reason, source, allowed, created) VALUES (?1, ?2, 'auto', 0, ?3)")?.execute(params![fp, reason, now() as i64])?;
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
    pub fn unblock(&self, fp: &str) -> DbResult<bool> {
        let was = self.blocked(fp)?.is_some();
        self.conn.prepare_cached("INSERT INTO blocklist (fingerprint, reason, source, allowed, created) VALUES (?1, 'cleared', 'admin', 1, ?2)
             ON CONFLICT(fingerprint) DO UPDATE SET allowed = 1")?.execute(params![fp, now() as i64])?;
        self.bump_truth_seq()?;
        Ok(was)
    }

    pub fn blocked(&self, fp: &str) -> DbResult<Option<rugen_proto::BlockEntry>> {
        self.conn
            .prepare_cached("SELECT fingerprint, reason, created, source FROM blocklist WHERE fingerprint = ?1 AND allowed = 0")?.query_row([fp],
                Self::block_row)
            .optional()
    }

    /// Every blocked fingerprint, oldest first.
    pub fn blocklist(&self) -> DbResult<Vec<rugen_proto::BlockEntry>> {
        let mut st = self.conn.prepare_cached(
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
        let mut st = self.conn.prepare_cached(
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
            .prepare_cached("SELECT ranked, p1, p2, winner, delta1, delta2, disputed FROM matches WHERE id = ?1")?.query_row([match_id as i64],
                |r| {
                    Ok((
                        r.get::<_, bool>(0)?,
                        [r.get::<_, i64>(1)? as u64, r.get::<_, i64>(2)? as u64],
                        r.get::<_, Option<i64>>(3)?.map(|w| w as u64),
                        [r.get::<_, i32>(4)?, r.get::<_, i32>(5)?],
                        r.get::<_, bool>(6)?,
                    ))
                })
            .optional()?;
        Ok(row.and_then(|(ranked, players, winner, deltas, disputed)| {
            let side = players.iter().position(|&p| p == account)?;
            Some((ranked, players, winner, deltas[side], disputed))
        }))
    }

    /// Test: make a match's reports `secs` older.
    #[cfg(test)]
    pub fn age_reports(&self, match_id: u64, secs: i64) -> DbResult<()> {
        self.conn
            .prepare_cached("UPDATE reports SET at = at - ?2 WHERE match_id = ?1")?
            .execute(params![match_id as i64, secs])?;
        Ok(())
    }

    #[cfg(test)]
    pub fn flags_of(&self, account: u64) -> DbResult<Vec<String>> {
        let mut st = self
            .conn
            .prepare_cached("SELECT reason FROM flags WHERE account = ?1 ORDER BY id")?;
        st.query_map([account as i64], |r| r.get(0))?.collect()
    }

    /// A stored replay: (players, setup JSON, winner, created, inputs).
    #[allow(clippy::type_complexity)]
    pub fn replay(
        &self,
        match_id: u64,
    ) -> DbResult<Option<([u64; 2], String, Option<u64>, u64, Vec<u8>)>> {
        self.conn
            .prepare_cached(
                "SELECT m.p1, m.p2, m.setup, m.winner, r.created, r.inputs
                 FROM replays r JOIN matches m ON m.id = r.match_id WHERE r.match_id = ?1",
            )?
            .query_row([match_id as i64], |r| {
                Ok((
                    [r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64],
                    r.get(2)?,
                    r.get::<_, Option<i64>>(3)?.map(|w| w as u64),
                    r.get::<_, i64>(4)? as u64,
                    r.get(5)?,
                ))
            })
            .optional()
    }

    #[cfg(test)]
    pub fn replay_count(&self) -> DbResult<i64> {
        self.conn
            .prepare_cached("SELECT COUNT(*) FROM replays")?
            .query_row([], |r| r.get(0))
    }

    pub fn leaderboard(&self, limit: usize) -> DbResult<Vec<ProfileInfo>> {
        let mut st = self.conn.prepare_cached(&format!(
            "SELECT {ACCOUNT_SELECT} FROM accounts WHERE wins + losses > 0
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
        let ahead: i64 = self
            .conn
            .prepare_cached(
                "SELECT COUNT(*) FROM accounts WHERE wins + losses > 0
             AND (rating > ?1 OR (rating = ?1 AND id < ?2))",
            )?
            .query_row(params![a.rating, id as i64], |r| r.get(0))?;
        Ok(Some(ahead as usize + 1))
    }

    /// Consistent online copy of the database (`VACUUM INTO`), for backups.
    pub fn backup_to(&self, path: &Path) -> DbResult<()> {
        self.conn
            .prepare_cached("VACUUM INTO ?1")?
            .execute([path.to_string_lossy().as_ref()])?;
        Ok(())
    }
}

pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    let _ = getrandom::getrandom(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Room / match codes: 5 upper-case characters without lookalikes (no
/// `0 O 1 I 5 S 2 Z 8 B`, see [`rugen_proto::room_code`]). Codes of older
/// servers stay valid: lookups only upper-case what players type.
pub fn random_code() -> String {
    rugen_proto::room_code::generate(|| {
        let mut b = [0u8; 1];
        let _ = getrandom::getrandom(&mut b);
        b[0]
    })
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
        let s = Store::open(None).unwrap();
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
        let s = Store::open(None).unwrap();
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
        let s = Store::open(None).unwrap();
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
        let s = Store::open(None).unwrap();
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
        let s = Store::open(None).unwrap();
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
        let s = Store::open(None).unwrap();
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
        let s = Store::open(None).unwrap();
        let id = s.register().unwrap().id;
        let a = s
            .set_profile(id, Some("<script>Bob Z".into()), Some(500))
            .unwrap()
            .unwrap();
        assert_eq!(a.name, "scriptBob Z");
        assert_eq!(a.avatar, 99);
    }

    #[test]
    fn named_accounts_store_hashes_only() {
        let s = Store::open(None).unwrap();
        let (a, key) = s.register_named("Axel", "$argon2id$fake").unwrap().unwrap();
        assert_eq!(
            (a.name.as_str(), a.username.as_deref()),
            ("Axel", Some("Axel"))
        );
        assert!(a.info().verified);
        assert_ne!(a.key.len(), 64, "the row key never authenticates");
        assert_eq!(s.by_key(&key).unwrap().unwrap().id, a.id);
        // session keys are stored hashed
        let stored: String = s
            .writer_conn()
            .query_row("SELECT hash FROM account_keys", [], |r| r.get(0))
            .unwrap();
        assert_ne!(stored, key);
        assert_eq!(stored, key_hash(&key));
        assert_eq!(
            s.register_named("AXEL", "$argon2id$fake")
                .unwrap()
                .unwrap_err(),
            NameError::Taken
        );
        assert_eq!(s.credentials("axel").unwrap().unwrap().0, a.id);
        assert!(s.credentials("nobody").unwrap().is_none());
        // claim: same id and key, now named
        let old = s.register().unwrap();
        let c = s.claim(old.id, "Ryu", "$argon2id$x").unwrap().unwrap();
        assert_eq!(
            (c.id, c.key.as_str(), c.name.as_str()),
            (old.id, old.key.as_str(), "Ryu")
        );
        assert_eq!(
            s.claim(old.id, "Ken", "$argon2id$x").unwrap().unwrap_err(),
            NameError::AlreadyNamed
        );
        assert_eq!(s.sessions(old.id).unwrap(), 1);
        let k2 = s.issue_key(old.id).unwrap();
        assert_eq!(s.sessions(old.id).unwrap(), 2);
        s.revoke_key(old.id, &old.key).unwrap();
        assert!(s.by_key(&old.key).unwrap().is_none());
        assert!(s.by_key(&k2).unwrap().is_some());
        s.revoke_all(old.id).unwrap();
        assert!(s.by_key(&k2).unwrap().is_none());
        assert_eq!(s.sessions(old.id).unwrap(), 0);
        // deleting accounts takes their keys along
        let (_, k) = s
            .register_named("loadtest-1", "$argon2id$x")
            .unwrap()
            .unwrap();
        s.delete_accounts_by_prefix("loadtest-", false).unwrap();
        assert!(s.by_key(&k).unwrap().is_none());
        let left: i64 = s
            .writer_conn()
            .query_row("SELECT COUNT(*) FROM account_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 1, "only Axel's key is left");
    }

    #[test]
    fn schema_v5_databases_upgrade_in_place() {
        let dir = temp_dir("v5");
        {
            let mut c = Connection::open(dir.join("rugen.db")).unwrap();
            let tx = c.transaction().unwrap();
            for sql in &MIGRATIONS[..5] {
                tx.execute_batch(sql).unwrap();
            }
            tx.pragma_update(None, "user_version", 5).unwrap();
            tx.execute(
                &format!("INSERT INTO accounts ({ACCOUNT_COLS}) VALUES (1000, ?1, 'OLD', 0, 1300, 1300, 3, 1, 1, 1)"),
                ["cd".repeat(32)],
            )
            .unwrap();
            tx.commit().unwrap();
        }
        let s = Store::open(Some(&dir)).unwrap();
        assert_eq!(s.schema_version().unwrap(), MIGRATIONS.len());
        let a = s.by_key(&"cd".repeat(32)).unwrap().unwrap();
        assert_eq!((a.name.as_str(), a.rating, a.username), ("OLD", 1300, None));
        assert!(a.last_season.is_none(), "no season finished yet");
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_connections_are_tuned() {
        let dir = temp_dir("tuned");
        let s = Store::open(Some(&dir)).unwrap();
        let get = |k: &str| -> String {
            s.writer_conn()
                .pragma_query_value(None, k, |r| {
                    r.get::<_, rusqlite::types::Value>(0).map(|v| match v {
                        rusqlite::types::Value::Integer(i) => i.to_string(),
                        rusqlite::types::Value::Text(t) => t,
                        other => format!("{other:?}"),
                    })
                })
                .unwrap()
        };
        assert_eq!(get("journal_mode"), "wal");
        assert_eq!(get("synchronous"), "1", "NORMAL");
        assert_eq!(get("cache_size"), (-CACHE_KIB).to_string());
        assert_eq!(get("mmap_size"), MMAP_BYTES.to_string());
        assert_eq!(get("temp_store"), "2", "MEMORY");
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn readers_see_every_committed_write() {
        let dir = temp_dir("readers");
        let s = Arc::new(Store::open(Some(&dir)).unwrap());
        assert!(
            s.readers.is_some(),
            "a database file reads through the pool"
        );
        // each thread writes, then reads it back at once through a reader
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let s = s.clone();
                std::thread::spawn(move || {
                    for _ in 0..40 {
                        let a = s.register().unwrap();
                        assert_eq!(s.by_key(&a.key).unwrap().unwrap().id, a.id);
                        s.set_profile(a.id, None, Some(i)).unwrap();
                        assert_eq!(s.by_id(a.id).unwrap().unwrap().avatar, i);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(s.account_count().unwrap(), 8 * 40);
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_panicking_read_hands_its_connection_back_clean() {
        let dir = temp_dir("panic");
        let s = Arc::new(Store::open(Some(&dir)).unwrap());
        let id = s.register().unwrap().id;
        for _ in 0..READERS + 1 {
            let r = s.clone();
            let panicked = std::thread::spawn(move || {
                let _ = r.read(|d| -> DbResult<()> {
                    d.by_id(id)?;
                    panic!("boom")
                });
            })
            .join();
            assert!(panicked.is_err());
        }
        // every reader is back, outside any transaction
        for _ in 0..READERS * 2 {
            assert!(s.by_id(id).unwrap().is_some());
        }
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reads_never_wait_for_the_writer() {
        let dir = temp_dir("nowait");
        let s = Arc::new(Store::open(Some(&dir)).unwrap());
        let id = s.register().unwrap().id;
        // the writer is in the middle of a transaction
        let w = s.writer_conn();
        w.execute_batch("BEGIN IMMEDIATE; UPDATE accounts SET name = 'HALFWAY'")
            .unwrap();
        let r = s.clone();
        let read = std::thread::spawn(move || r.by_id(id).unwrap().unwrap().name);
        let name = read.join().unwrap();
        assert_ne!(name, "HALFWAY", "readers see committed data only");
        w.execute_batch("ROLLBACK").unwrap();
        drop(w);
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Wait until `f` holds (a background thread got somewhere).
    fn eventually(f: impl Fn() -> bool) {
        let t = std::time::Instant::now();
        while !f() {
            assert!(t.elapsed().as_secs() < 10, "timed out");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    #[test]
    fn group_commit_keeps_good_writes_of_a_failing_batch() {
        let dir = temp_dir("group");
        let s = Arc::new(Store::open(Some(&dir)).unwrap());
        // hold the writer: everything below queues up for one batch
        let w = s.writer_conn();
        let done = Arc::new(AtomicU64::new(0));
        let spawn = |f: Box<dyn FnOnce(&Store) -> bool + Send>| {
            let (s, done) = (s.clone(), done.clone());
            std::thread::spawn(move || {
                let ok = f(&s);
                done.fetch_add(1, Relaxed);
                ok
            })
        };
        let mut threads = Vec::new();
        for i in 0..6 {
            threads.push(spawn(Box::new(move |s: &Store| {
                s.write(move |d| d.set_meta(&format!("good{i}"), i)).is_ok()
            })));
        }
        // writes something, then fails: its savepoint rolls back
        let bad = spawn(Box::new(|s: &Store| {
            s.write(|d| {
                d.set_meta("bad", 1)?;
                d.conn.execute("INSERT INTO no_such_table VALUES (1)", [])?;
                Ok(())
            })
            .is_ok()
        }));
        // a constraint violation in the middle of the batch
        let dup = spawn(Box::new(|s: &Store| {
            s.write(|d| {
                d.conn
                    .execute("INSERT INTO meta (k, v) VALUES ('next_id', 1)", [])?;
                Ok(())
            })
            .is_ok()
        }));
        std::thread::sleep(std::time::Duration::from_millis(500));
        assert_eq!(done.load(Relaxed), 0, "nobody hears back before COMMIT");
        let (batches, ..) = s.write_stats();
        drop(w);
        for t in threads {
            assert!(t.join().unwrap(), "good writes commit");
        }
        assert!(!bad.join().unwrap() && !dup.join().unwrap());
        let (after, writes, last, _) = s.write_stats();
        assert_eq!(
            (after - batches, last, writes),
            (1, 8, 8),
            "one transaction"
        );
        for i in 0..6 {
            assert_eq!(s.read(|d| d.meta(&format!("good{i}"))).unwrap(), Some(i));
        }
        assert_eq!(s.read(|d| d.meta("bad")).unwrap(), None, "rolled back");
        assert!(s.read(|d| d.meta("next_id")).unwrap().unwrap() >= 1000);
        // and the writer carries on
        assert!(s.register().is_ok());
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_full_write_queue_makes_writers_wait() {
        let s = Arc::new(Store::open_with(None, 2).unwrap());
        let w = s.writer_conn();
        let done = Arc::new(AtomicU64::new(0));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (s, done) = (s.clone(), done.clone());
                std::thread::spawn(move || {
                    s.register().unwrap();
                    done.fetch_add(1, Relaxed);
                })
            })
            .collect();
        // the writer took one write and waits for its connection, two wait
        // in the queue: the others wait for room instead of piling up
        eventually(|| s.write_stats().3 >= 5);
        assert_eq!(done.load(Relaxed), 0);
        drop(w);
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(s.account_count().unwrap(), 8);
    }

    #[test]
    fn persists_in_wal_file_and_reopens() {
        let dir = temp_dir("persist");
        let (key, id) = {
            let s = Store::open(Some(&dir)).unwrap();
            assert_eq!(s.schema_version().unwrap(), MIGRATIONS.len());
            let a = s.register().unwrap();
            s.set_profile(a.id, Some("Ryu".into()), None).unwrap();
            (a.key, a.id)
        };
        let s = Store::open(Some(&dir)).unwrap();
        let a = s.by_key(&key).unwrap().unwrap();
        assert_eq!((a.id, a.name.as_str()), (id, "Ryu"));
        assert!(s.by_key(&"0".repeat(64)).unwrap().is_none());
        // ids keep increasing across restarts
        assert!(s.register().unwrap().id > id);
        let mode: String = s
            .writer_conn()
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
        let s = Store::open(Some(&dir)).unwrap();
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
        let s = Store::open(None).unwrap();
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
        let s = Store::open(None).unwrap();
        let a = s.register().unwrap().id;
        s.writer_conn()
            .execute("UPDATE accounts SET rating = 1600, wins = 3", [])
            .unwrap();
        s.write(move |d| d.set_meta("season_start", (now() - SEASON_SECS - 5) as i64))
            .unwrap();
        s.roll_season().unwrap();
        assert_eq!(s.season().unwrap().number, 2);
        let acc = s.by_id(a).unwrap().unwrap();
        assert_eq!((acc.rating, acc.wins), (1400, 0));
        // season 1's standings stay, and the badge rides on the profile
        assert_eq!(s.past_seasons().unwrap(), vec![1]);
        let badge = acc.info().last_season.unwrap();
        assert_eq!((badge.season, badge.rating, badge.rank), (1, 1600, 1));
        assert_eq!(badge.tier, "PLATINUM");
        let board = s.season_board(1, 10).unwrap();
        assert_eq!(board.len(), 1);
        assert_eq!((board[0].rating, board[0].wins), (1600, 3));
        let (pos, line) = s.season_rank_of(1, a).unwrap().unwrap();
        assert_eq!((pos, line.rating), (1, 1600));
        let past = s.past_season(1).unwrap().unwrap();
        assert_eq!(past.ends_at - past.started_at, SEASON_SECS);
        assert!(s.past_season(2).unwrap().is_none(), "season 2 is running");
        let now_s = s.season().unwrap();
        assert_eq!(now_s.started_at, past.ends_at);
        assert!(now_s.secs_left > 0 && now_s.secs_left <= SEASON_SECS);
    }

    #[test]
    fn an_operator_ends_a_season_with_only_players_ranked() {
        let s = Store::open(None).unwrap();
        let a = s.register().unwrap().id;
        let b = s.register().unwrap().id;
        let idle = s.register().unwrap().id;
        s.writer_conn()
            .execute_batch(&format!(
                "UPDATE accounts SET rating = 1300, wins = 2, losses = 1 WHERE id = {a};
                 UPDATE accounts SET rating = 1500, wins = 4 WHERE id = {b};
                 UPDATE accounts SET rating = 1000 WHERE id = {idle};"
            ))
            .unwrap();
        let next = s.end_season_now().unwrap();
        assert_eq!(next.number, 2);
        let board = s.season_board(1, 10).unwrap();
        assert_eq!(
            board.iter().map(|p| p.id).collect::<Vec<_>>(),
            vec![b, a],
            "best first, idle accounts not ranked"
        );
        let ratings: Vec<i32> = [a, b, idle]
            .iter()
            .map(|&i| s.by_id(i).unwrap().unwrap().rating)
            .collect();
        assert_eq!(ratings, vec![1250, 1350, 1100]);
        assert!(s.by_id(idle).unwrap().unwrap().last_season.is_none());
        assert_eq!(s.by_id(a).unwrap().unwrap().last_season.unwrap().rank, 2);
        assert_eq!(s.leaderboard(10).unwrap().len(), 0, "records restart");
        // the profile of an account that never finished a season is unchanged
        assert!(
            !serde_json::to_string(&s.by_id(idle).unwrap().unwrap().info())
                .unwrap()
                .contains("last_season")
        );
    }

    #[test]
    fn accounts_are_deleted_by_name_prefix() {
        let s = Store::open(None).unwrap();
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
