//! JSON API routes. Mutating calls carry the account `key` in the JSON body;
//! reads that need identity take `?key=`.
//!
//! ```text
//! GET  /  (or /health)          ServerInfo: name, motd, version, players online
//! POST /register                → {id, key}
//! POST /profile                 {key, name?, avatar?}
//! GET  /profile/{id}
//! GET  /rooms                   public lobby (RoomSummary[])
//! POST /room                    {key, char, name?, public?, password?, rules?, max_spectators?,
//!                               tournament?: 8 | 16}
//! POST /room/{code}/join        {key, char, password?, spectate?, tournament?: true (the
//!                               client knows brackets; required for tournament rooms)}
//! GET  /room/{code}?key=        RoomInfo (also a heartbeat); with no key at all, a
//!                               tournament room's public view (no side, opponent,
//!                               ticket, matchup or pings; `server_hosted`): the
//!                               website mirrors the bracket
//! POST /room/{code}/leave       {key}
//! POST /room/{code}/kick        {key, id}       host only
//! POST /room/{code}/rematch     {key}           both players → new match
//! POST /room/{code}/start       {key}           host of a tournament room: draw the
//!                               bracket (≥ 2 entrants, seeded by rating); the server
//!                               then calls each match (room.tournament)
//! POST /queue                   {key, char, ranked?, max_ping?, rtt_ms?}
//! GET  /queue?key=              QueueStatus (found match once paired)
//! DELETE /queue (or POST /queue/leave) {key}
//! POST /result                  {key, match_id, winner, frames?, checksum?, inputs? | inputs_rle?, checksums?, turn?}
//! GET  /replay/{match_id}       stored ranked replay
//! GET  /v1/live?key=            public live matches (LiveMatch[])
//! POST /v1/replays             {key, match_id} → SharedReplay {code, expires, title, frames}
//!                               (a player shares a finished match; kept RUGEN_REPLAY_DAYS)
//! GET  /v1/replays/{code}       a shared replay: binary stream chunk (header + every frame)
//! GET  /v1/live/{id}?key=&from= a live match's input stream from frame N, binary
//!                               (rugen_proto::stream chunk, the header when N = 0);
//!                               private rooms: members only; 409 "this match is full"
//!                               past RUGEN_LIVE_VIEWERS (500) viewers
//! GET  /leaderboard?key=&season=  the live board, or a finished season's final
//!                               standings (`finished`, `past` = seasons kept)
//!      &fighter=FP | &fighters=1  a per-fighter board (players by their rating
//!                               with that fighter; the most played one with
//!                               `fighters=1`), plus `fighters` with a board
//! GET  /seasons/current
//! GET  /ws?key=                 WebSocket: presence pushes + server-side RTT
//! GET  /relay                   WebSocket: relayed match datagrams (fallback for UDP)
//!
//! bring-your-own-character matchup (rooms and queue; see crate::matchup)
//! GET  /matchup/{id}?key=       MatchupView (also pushed on /ws)
//! POST /matchup/{id}/pick       {key, fighter: FighterDecl, stage?: FighterDecl,
//!                               uploads?: false (no online consent: never uploads)}
//! POST /matchup/{id}/accept     {key, unbalanced?}
//! POST /matchup/{id}/ready      {key, ready: ReadyReport}
//! POST /matchup/{id}/leave      {key, reason?: "missing", fingerprint?} (we lack a
//!                               fighter that is never uploaded: the failure says so)
//! GET  /pkg/{fp}?key=           PackageStatus ("HAS")
//! POST /pkg/{fp}/upload?key=&offset=&total=&consent=1   raw chunk, resumable; refused
//!                               (403) with consent other than 1, and without it from
//!                               rugen 0.6.4+ (0.6.0-0.6.3 never send it: accepted)
//! GET  /pkg/{fp}/data?key=&offset=&len=       raw bytes, resumable
//! GET  /pkg/{fp}/url?key=       PackageUrl: a presigned bucket URL (RUGEN_PKG_S3, valid
//!                               15 min) with the file's sha256 and size, or url "" when
//!                               the package is only here (download /data); rugen 0.6.4+
//! GET  /char/{fp}               community rating of a character fingerprint
//! POST /match/{id}/desync       {key, frame}    a client saw a desync
//! GET  /match/{id}/result?key=  ResultAck (signed once settled)
//!
//! official server, truth feed, moderation (see crate::truth)
//! GET  /v1/truth                this server's blocklist + ratings, signed
//! GET  /v1/truth/official       the verified official feed this server holds
//! GET  /v1/identity?nonce=      IdentityStatement signed (proves the key)
//! POST /v1/admin/block          {token, fingerprint, reason}   RUGEN_ADMIN_TOKEN
//! POST /v1/admin/unblock        {token, fingerprint}
//! GET  /v1/admin/blocklist?token=
//! POST /v1/admin/reset_password {token, username} → {username, password} (temporary;
//!                               every key of the account is revoked)
//! POST /v1/admin/season_end     {token} → Season (the next one; ends the
//!                               current season now: standings kept, soft reset)
//! POST /v1/admin/link           {token, code} → {account_id, username, profile}
//!                               (redeems a link_code once; 404 unknown / expired)
//! POST /v1/admin/tournament     {token, size: 8 | 16, name?, rules?, public?,
//!                               entrants: [account_id...], seed?: "order" | "rating"}
//!                               → {code, tournament} a bracket hosted by the server
//!                               (no host member) for those accounts, seeded in the
//!                               order given (or by rating); entrants join the room
//!                               by its code, each pair is called once both are here
//!                               (one here for 3 min: walkover)
//! POST /v1/admin/tournament/{code}/cancel  {token} → {code, cancelled}
//! POST /v1/admin/backup         {token} → 202 {job} | 409 running | 429 (1 per 10 min)
//! GET  /v1/admin/backups?token= backups in the bucket {backups: [{key, name, time, size, complete, legacy}]}
//! GET  /v1/admin/backup/status?token=  the health `backup` object + job, includes
//!   (admin calls also take `Authorization: Bearer <RUGEN_ADMIN_TOKEN>`; see crate::backup)
//!
//! named accounts, API 5 only (see crate::api::accounts, rugen_proto::account)
//! POST /v1/account/register     {username, password}             → Session
//! POST /v1/account/login        {username, password}             → Session (new key)
//! POST /v1/account/claim        {key, username, password}        → Session (same key)
//! GET  /v1/account?key=         AccountInfo
//! POST /v1/account/password     {key, password, new_password}    → Session (fresh key)
//! POST /v1/account/logout       {key}
//! POST /v1/account/logout_all   {key}
//! POST /v1/account/link_code    {key} → {code, expires_at, expires_in} (6 characters
//!                               for the website, valid 10 min, one per account)
//! ```
//!
//! Additive JSON fields (older clients ignore them; typed `rugen_proto`
//! payloads parse unchanged):
//!
//! ```text
//! MatchupView of a queue match   est_ping_ms: u32, high_ping: bool
//!   (GET/POST /matchup/{id}..., the `matchup` lobby push, found.matchup)
//! MatchInfo (`found` of GET/POST /queue and the `found` push)
//!                                high_ping: bool
//! GET /health                    pkg_days (days packages are kept after upload)
//!                                packages_r2: {configured, objects, bytes, max_bytes, full,
//!                                  pending, last_error} (also in /admin/stats)
//!                                relay: {sessions, forwarded, dropped, queue_drops}
//!                                backup: {configured, status, provider, retention_days,
//!                                  last_success, last_error, last_size_bytes, next_at, running}
//! ProfileInfo (profiles, boards, room members)
//!                                last_season: {season, rating, rank, tier} (the badge
//!                                  of the last season the player finished)
//! Season (GET /seasons/current, leaderboard.season)
//!                                started_at, secs_left
//! RoomInfo                       tournament: {size, state, entrants, rounds, live, champion}
//! RoomSummary                    tournament: {size, entrants, state}, live_match
//! SessionTicket                  live: true (players send confirmed inputs on the relay)
//! POST /result                   rounds: [p1, p2] (rounds won; the bracket's score)
//! MatchupView                    offline: [fp] (never uploaded: their players
//!                                  play without online consent)
//! Leaderboard                    past: [season], finished: bool, fighter, fighters
//!                                  (per-fighter boards)
//! ```
//!
//! `high_ping` is true when the estimated player ↔ player round trip is
//! above `RUGEN_HIGH_PING_MS` (200): clients should show the ping on the
//! confirm screen (accepting the matchup is required for every match).
//! `/health` → `matches` counts running matches (a slot connected and
//! relay traffic within the last 10 s); it is cached for one second.
//!
//! Privacy: requests carry no client address at all (the HTTP layer keeps
//! it for rate limiting only), so no response can leak one. Match traffic is
//! relayed by the server ([`crate::relay`]); players never learn each
//! other's endpoints.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use rugen_fair::verdict::Thresholds;
use rugen_proto::{
    API_VERSION, FighterDecl, Leaderboard, MatchInfo, PackageStatus, ProfileInfo, QueueStatus,
    ReadyReport, Replay, ResultAck, RoomInfo, RoomMember, RoomSummary, Rules, ServerInfo,
    ServerMsg, SessionTicket, is_fingerprint, to_hex,
};
use serde_json::{Value, json};

use crate::backup::{BackupSetting, Backups, Snapshot, StartError, Trigger};
use crate::hub::Hub;
use crate::matchmaking::{self, Candidate};
use crate::matchup::{Matchup, Running, check_decl};
use crate::packages::{Packages, PkgConfig, UploadError, Verified};
use crate::password;
use crate::relay::Relay;
use crate::resim::ResimConfig;
use crate::store::{Account, DbResult, ReportData, Store, random_code, setup_fingerprints};
use crate::tournament::{self, Bracket, Seed, Tournament};
use crate::truth::{Truth, TruthConfig};
use crate::turn::{Turn, TurnConfig};
use crate::workers::Workers;

mod accounts;
pub use accounts::LoginGuard;

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub body: Vec<u8>,
    /// Client address, for per-IP limits only (never stored or echoed).
    pub ip: Option<std::net::IpAddr>,
    /// The client's lobby API ([`crate::compat::api_of`]: 4 unless it says).
    pub api: u32,
    /// The client's game version from its `User-Agent`
    /// ([`crate::compat::engine_version`]); `None` for other clients.
    pub engine: Option<String>,
    /// `Authorization: Bearer` (admin calls).
    pub bearer: Option<String>,
}

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
    pub content_type: &'static str,
}

impl Response {
    pub fn json(status: u16, v: &Value) -> Self {
        Self {
            status,
            body: serde_json::to_vec(v).unwrap_or_default(),
            content_type: "application/json",
        }
    }

    pub fn bytes(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            body,
            content_type: "application/octet-stream",
        }
    }
}

/// Members not heard from (poll or lobby WebSocket) for this long leave.
const MEMBER_TIMEOUT_SECS: u64 = 45;
const ROOM_MAX_AGE_SECS: u64 = 6 * 3600;
const MAX_ROOMS: usize = 5_000;
const MAX_SPECTATORS: u8 = 6;
/// Spectator seats of a tournament room (besides the entrants, who watch
/// when they do not play).
const TOURNAMENT_SPECTATORS: u8 = 16;
/// Role of a tournament entrant (members: 0 host, 1 challenger, 2
/// spectator, 3 entrant).
const ROLE_ENTRANT: u8 = 3;

struct Member {
    account: u64,
    /// 0 = host, 1 = challenger, 2 = spectator.
    role: u8,
    char_id: String,
    last_seen: Instant,
    /// Wants a rematch.
    ready: bool,
}

struct Room {
    name: String,
    public: bool,
    password: Option<String>,
    rules: Rules,
    max_spectators: u8,
    members: Vec<Member>,
    kicked: Vec<u64>,
    created: Instant,
    running: Option<Running>,
    /// Match in its matchup phase (pick / confirm / sync).
    matchup: Option<u64>,
    /// The host's API: only clients of the same API may join.
    api: u32,
    /// The host's game version: only clients of the same version may join
    /// (both sides run the same simulation).
    engine: Option<String>,
    /// A tournament room: its bracket (see [`crate::tournament`]).
    tournament: Option<Tournament>,
    /// Hosted by the server itself (`POST /v1/admin/tournament`): no host
    /// member; the room lives until its bracket is done, cancelled or
    /// [`ROOM_MAX_AGE_SECS`] old, and its pairs are called once both
    /// players are here.
    server_hosted: bool,
}

impl Room {
    fn member(&self, account: u64) -> Option<&Member> {
        self.members.iter().find(|m| m.account == account)
    }

    fn player(&self, role: u8) -> Option<&Member> {
        self.members.iter().find(|m| m.role == role)
    }

    fn spectators(&self) -> u8 {
        self.members.iter().filter(|m| m.role == 2).count() as u8
    }
}

struct QueueEntry {
    id: u64,
    rating: i32,
    ranked: bool,
    max_ping: Option<u32>,
    reported_rtt: Option<u32>,
    char_id: String,
    since: Instant,
    last_poll: Instant,
    /// Only entries of the same API meet.
    api: u32,
    /// Only entries of the same game version meet (unknown meets anyone).
    engine: Option<String>,
}

#[derive(Default)]
pub struct ApiConfig {
    pub name: String,
    pub motd: String,
    /// Public `host:port` of the UDP relay (the server's own address).
    pub udp_public: Option<String>,
    /// `RUGEN_DATA` (packages live in `packages/` under it); `None` = temp dir.
    pub data: Option<PathBuf>,
    pub pkg: PkgConfig,
    pub thresholds: Thresholds,
    pub resim: Option<ResimConfig>,
    /// Signing key, official key, feed source, admin token, auto-block rules.
    pub truth: TruthConfig,
    /// Cloudflare Realtime TURN credentials ([`crate::turn`]).
    pub turn: Option<TurnConfig>,
    /// `RUGEN_HIGH_PING_MS`: queue pairs estimated above this are flagged
    /// `high_ping` (0 = [`matchmaking::HIGH_PING_MS`]).
    pub high_ping_ms: u32,
    /// `RUGEN_BACKUP_*` ([`crate::backup`]).
    pub backup: BackupSetting,
    /// `RUGEN_BENCH=1`: `POST /admin/bench` may run self-benchmarks.
    pub bench: bool,
    /// `RUGEN_PKG_S3*`: packages served from a bucket ([`crate::pkg_r2`]).
    pub pkg_r2: crate::pkg_r2::R2Setting,
}

/// Matchups not started and untouched for this long fail.
const MATCHUP_IDLE: Duration = Duration::from_secs(15 * 60);
/// A claim that the other player fled waits this long for that player's
/// own report before the relay's view settles it.
pub const CLAIM_GRACE_SECS: u64 = 15;
/// A slot silent this long on the relay has left (HELLOs come every 2 s,
/// whatever path the match uses).
const SLOT_GONE: Duration = Duration::from_secs(10);
/// The claimant must have stayed connected this much longer than the
/// player it says left.
const OUTLASTED: Duration = Duration::from_secs(2);

/// The relay saw `theirs` leave the match before `mine`: it said BYE or
/// went silent for [`SLOT_GONE`], while `mine` was still heard at least
/// [`OUTLASTED`] later. Both must have joined (a slot that never connected
/// is a failed start, not a flee).
pub fn left_first(
    mine: &crate::relay::Presence,
    theirs: &crate::relay::Presence,
    now: Instant,
) -> bool {
    mine.joined
        && theirs.joined
        && (theirs.bye || now.saturating_duration_since(theirs.heard) >= SLOT_GONE)
        && mine.heard >= theirs.heard + OUTLASTED
}
/// Replays one account may share in a day.
const SHARES_PER_DAY: u32 = 50;

/// Days a shared replay is kept (`RUGEN_REPLAY_DAYS`, default 30).
pub fn replay_days() -> u64 {
    std::env::var("RUGEN_REPLAY_DAYS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|d| *d > 0)
        .unwrap_or(30)
}

/// All shared replays together keep at most this much (`RUGEN_REPLAY_MB`,
/// default 256 MB; the oldest go first).
fn replay_max_bytes() -> u64 {
    std::env::var("RUGEN_REPLAY_MB")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(256)
        << 20
}

/// Started / failed matchups are forgotten after this long.
const MATCHUP_KEEP: Duration = Duration::from_secs(4 * 3600);
/// Largest chunk of an upload / download.
pub const MAX_CHUNK: u64 = 4 << 20;

pub struct Api {
    store: Store,
    rooms: Mutex<HashMap<String, Room>>,
    queue: Mutex<Vec<QueueEntry>>,
    /// Matches found for queued players, consumed on poll (with the
    /// additive `high_ping` flag).
    found: Mutex<HashMap<u64, (MatchInfo, bool)>>,
    pub hub: Mutex<Hub>,
    pub relay: Arc<Relay>,
    /// Input logs of live matches, for viewers ([`crate::live`]).
    pub live: Arc<crate::live::Live>,
    matchups: Mutex<HashMap<u64, Matchup>>,
    pub packages: Packages,
    /// Upload bytes per account in the current hour.
    upload_budget: Mutex<HashMap<u64, (Instant, u64)>>,
    /// Signatures, official feed, blocklist rules.
    pub truth: Truth,
    me: Weak<Api>,
    cfg: ApiConfig,
    pub turn: Option<Arc<Turn>>,
    /// Accounts by when they last made an authenticated call (the
    /// `online` count of `/health` without a table scan).
    seen: Mutex<HashMap<u64, Instant>>,
    /// The `/health` body, rebuilt at most every [`HEALTH_TTL`].
    health: Mutex<Option<(Instant, Value)>>,
    /// Failed logins per username / address ([`accounts`]).
    logins: Mutex<LoginGuard>,
    /// Website link codes by code ([`accounts`]).
    links: Mutex<HashMap<String, accounts::LinkCode>>,
    /// S3 backups: configuration, running job, schedule.
    pub backups: Arc<Backups>,
    /// Re-simulations of disputed matches: one low-priority thread
    /// (when the server can re-simulate).
    resim: Option<Workers<u64>>,
    /// Self-benchmark runs (`/admin/bench`).
    bench: crate::bench::Bench,
    started: Instant,
    /// API requests handled (`/admin/stats` req/s).
    requests: std::sync::atomic::AtomicU64,
    /// (when, CPU seconds, requests, relayed datagrams), every few seconds.
    samples: Mutex<std::collections::VecDeque<(Instant, f64, u64, u64)>>,
}

/// Disputes waiting for the re-simulation thread (match ids: a full queue
/// leaves a dispute as an ordinary, unsimulated one).
const RESIM_QUEUE: usize = 4096;
/// Nice value of the re-simulation thread: request handling comes first.
const RESIM_NICE: i32 = 10;

/// How long a computed `/health` body is served from the cache.
const HEALTH_TTL: Duration = Duration::from_secs(1);
/// Accounts count as online this long after their last call.
const ONLINE_SECS: u64 = 300;

type Res = Result<Response, Response>;

fn err(status: u16, msg: &str) -> Response {
    Response::json(status, &json!({ "error": msg }))
}

fn ok<T: serde::Serialize>(v: &T) -> Res {
    Ok(Response::json(
        200,
        &serde_json::to_value(v).unwrap_or(Value::Null),
    ))
}

/// Database errors become a 500 (logged), never a panic.
fn db<T>(r: DbResult<T>) -> Result<T, Response> {
    r.map_err(|e| {
        log::error!("database: {e}");
        err(500, "database error")
    })
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn body(req: &Request) -> Value {
    serde_json::from_slice(&req.body).unwrap_or(Value::Null)
}

/// The account key of a request: the JSON body's `key`, else `?key=`.
fn request_key(req: &Request, v: &Value) -> Option<String> {
    v.get("key")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| req.query.get("key").cloned())
}

fn str_field(v: &Value, k: &str, max: usize) -> Option<String> {
    v.get(k)
        .and_then(Value::as_str)
        .map(|s| s.chars().take(max).collect::<String>())
        .filter(|s| !s.is_empty())
}

/// Character / stage ids are file stems: letters, digits, `_`, `-`, `.` and spaces.
fn clean_id(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | ' '))
        .take(64)
        .collect()
}

fn clean_name(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | ' ' | '!' | '?' | '.' | '\''))
        .take(24)
        .collect::<String>()
        .trim()
        .to_string()
}

fn clean_rules(v: Option<&Value>) -> Rules {
    let mut r: Rules = v
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    r.rounds = r.rounds.clamp(1, 5);
    r.round_time = r.round_time.min(999);
    if r.mode != "arena" {
        r.mode = "classic".into();
    }
    if r.chars != "mirror" {
        r.chars = "free".into();
    }
    r.stage = clean_id(&r.stage);
    // FIGHTER SIZE is simulated: only the known values; anything else (or
    // missing, from clients before it) is normal
    r.fighter_size = r.fighter_size.trim().to_ascii_lowercase();
    if !rugen_proto::FIGHTER_SIZES.contains(&r.fighter_size.as_str()) {
        r.fighter_size = "normal".into();
    }
    // LIFE is simulated: 0 (each fighter's own) or the 1000..=10000 grid of
    // 500; missing (clients before it) is the default 5000
    r.life = crate::resim::room_life(u64::from(r.life)).map_or(0, |l| l as u16);
    r
}

/// Additive fields of a queue match ([`MatchInfo`] JSON): `high_ping` on
/// the match and `est_ping_ms` / `high_ping` on its `matchup`.
fn extend_found(found: &mut Value, est: u32, high: bool) {
    if let Some(obj) = found.as_object_mut() {
        obj.insert("high_ping".into(), high.into());
    }
    if let Some(obj) = found.get_mut("matchup").and_then(Value::as_object_mut) {
        obj.insert("est_ping_ms".into(), est.into());
        obj.insert("high_ping".into(), high.into());
    }
}

fn ticket(r: &Running, slot: usize, udp: &Option<String>) -> SessionTicket {
    let mut transports = rugen_proto::relay_transports(udp.as_deref());
    // TURN first for the two players when the server got credentials
    if let Some(Some(t)) = r.turn.get(slot) {
        transports.insert(0, t.clone());
    }
    SessionTicket {
        session: r.session,
        slot: slot as u8,
        token: to_hex(&r.tokens[slot]),
        spectators: r.slots.len().saturating_sub(2) as u8,
        udp: udp.clone(),
        transports,
        // the server keeps the input log: the players feed it
        live: slot < 2,
    }
}

impl Api {
    pub fn new(store: Store, mut cfg: ApiConfig, relay: Arc<Relay>) -> Arc<Self> {
        let truth = Truth::new(
            std::mem::take(&mut cfg.truth),
            &cfg.name,
            cfg.data.as_deref(),
        );
        let mut packages = Packages::open(cfg.data.as_deref(), cfg.pkg.clone())
            .or_else(|e| {
                log::error!("packages directory: {e}; using a temporary one");
                Packages::open(None, cfg.pkg.clone())
            })
            .expect("a temporary packages directory");
        match &cfg.pkg_r2 {
            crate::pkg_r2::R2Setting::On { target, max_bytes } => {
                log::info!(
                    "packages: also served from a bucket ({} under chars/, up to {} MB)",
                    target.host,
                    max_bytes >> 20
                );
                packages.r2 = Some(crate::pkg_r2::R2::new(
                    target.clone(),
                    *max_bytes,
                    cfg.pkg.max_age_secs,
                ));
            }
            crate::pkg_r2::R2Setting::Invalid(e) => log::error!("{e}; packages served directly"),
            crate::pkg_r2::R2Setting::Off => {}
        }
        let turn = cfg.turn.clone().map(Turn::new);
        let backups = Backups::new(std::mem::take(&mut cfg.backup), cfg.data.as_deref());
        let resim = cfg.resim.is_some();
        let live = Arc::new(crate::live::Live::from_env());
        relay.set_live(live.clone());
        Arc::new_cyclic(|me| Self {
            live,
            store,
            rooms: Mutex::new(HashMap::new()),
            queue: Mutex::new(Vec::new()),
            found: Mutex::new(HashMap::new()),
            hub: Mutex::new(Hub::default()),
            relay,
            matchups: Mutex::new(HashMap::new()),
            packages,
            upload_budget: Mutex::new(HashMap::new()),
            truth,
            me: me.clone(),
            cfg,
            turn,
            seen: Mutex::new(HashMap::new()),
            health: Mutex::new(None),
            logins: Mutex::new(LoginGuard::default()),
            links: Mutex::new(HashMap::new()),
            backups,
            resim: resim
                .then(|| {
                    let me = me.clone();
                    Workers::spawn("rugen-resim", 1, RESIM_QUEUE, RESIM_NICE, move |id: u64| {
                        if let Some(api) = me.upgrade() {
                            api.resim_match(id);
                        }
                    })
                    .map_err(|e| {
                        log::error!("re-simulation thread: {e}; disputes stay unsimulated")
                    })
                    .ok()
                })
                .flatten(),
            bench: crate::bench::Bench::default(),
            started: Instant::now(),
            requests: std::sync::atomic::AtomicU64::new(0),
            samples: Mutex::new(std::collections::VecDeque::new()),
        })
    }

    /// A consistent copy of the database at `out`: through a second
    /// connection when the store is on disk (the store lock is never held),
    /// else (in-memory tests) through the store itself.
    pub fn snapshot(&self, out: &std::path::Path) -> Result<(), String> {
        match &self.cfg.data {
            Some(d) => crate::backup::snapshot_file(&d.join("rugen.db"), out),
            None => {
                let _ = std::fs::remove_file(out);
                self.store
                    .backup_to(out)
                    .map_err(|e| format!("snapshot: {e}"))
            }
        }
    }

    fn snapshotter(&self) -> Snapshot {
        let me = self.me.clone();
        Arc::new(move |out: &std::path::Path| match me.upgrade() {
            Some(api) => api.snapshot(out),
            None => Err("server stopping".into()),
        })
    }

    /// Start the daily backup schedule (no-op when backups are off).
    pub fn start_backup_schedule(&self) {
        self.backups.spawn_scheduler(self.snapshotter());
    }

    fn high_ping_ms(&self) -> u32 {
        match self.cfg.high_ping_ms {
            0 => matchmaking::HIGH_PING_MS,
            v => v,
        }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// TURN housekeeping (revocations, ceilings, analytics), every few
    /// seconds from the server's timer.
    pub fn sweep_turn(&self) {
        if let Some(t) = &self.turn {
            t.sweep(&self.store, &self.relay);
        }
    }

    /// Expire / evict stored packages (TTL, LRU size cap).
    pub fn sweep_packages(&self) -> Vec<String> {
        // matchups pick, touch and check packages under this lock: none
        // of that interleaves with an eviction
        let _ms = lock(&self.matchups);
        if let Some(r2) = &self.packages.r2 {
            r2.reconcile();
        }
        self.packages.sweep(&self.store)
    }

    /// `packages_r2` of `/health` and `/admin/stats`.
    fn r2_health(&self) -> Value {
        match &self.packages.r2 {
            Some(r) => r.health(),
            None => crate::pkg_r2::health_off(&self.cfg.pkg_r2),
        }
    }

    /// The account owning a key (WebSocket upgrade).
    pub fn account_for_key(&self, key: &str) -> Option<Account> {
        if key.len() != 64 {
            return None;
        }
        let a = self.store.by_key(key).ok().flatten()?;
        self.note_seen(a.id);
        Some(a)
    }

    fn note_seen(&self, id: u64) {
        let mut seen = lock(&self.seen);
        if seen.len() > 200_000 {
            seen.retain(|_, t| t.elapsed().as_secs() < ONLINE_SECS);
        }
        seen.insert(id, Instant::now());
    }

    /// Relay housekeeping, every few seconds from the server's timer (UDP
    /// or not): idle sessions go.
    pub fn sweep_relay(&self) {
        let n = self.relay.expire(Instant::now());
        if n > 0 {
            log::debug!("relay: {n} idle sessions expired");
        }
        let n = self.live.sweep();
        if n > 0 {
            log::debug!("live: {n} finished match logs dropped");
        }
    }

    /// Close the relay session of match `match_id` (result settled).
    fn close_match_session(&self, match_id: u64) {
        let session = lock(&self.matchups)
            .get(&match_id)
            .and_then(|m| m.started.as_ref().map(|r| r.session));
        if let Some(session) = session {
            self.relay.close(session);
            log::info!("match {match_id}: result settled, relay session {session:08x} closed");
        }
        // the players were in the fight, not polling the room: they are
        // fresh members now (a match outlasts MEMBER_TIMEOUT_SECS, and the
        // challenger used to be dropped from the room, no REMATCH possible)
        let now = Instant::now();
        for r in lock(&self.rooms).values_mut() {
            let Some(run) = r.running.as_ref().filter(|run| run.match_id == match_id) else {
                continue;
            };
            let slots = run.slots.clone();
            for m in r.members.iter_mut().filter(|m| slots.contains(&m.account)) {
                m.last_seen = m.last_seen.max(now);
            }
        }
    }

    /// Account for the key in `v` (body) or `?key=`.
    fn auth(&self, store: &Store, req: &Request, v: &Value) -> Result<Account, Response> {
        let key = request_key(req, v).ok_or_else(|| err(401, "bad key"))?;
        if key.len() != 64 {
            return Err(err(401, "bad key"));
        }
        let a = db(store.by_key(&key))?.ok_or_else(|| err(401, "bad key"))?;
        self.note_seen(a.id);
        if let (Some(t), Some(ip)) = (&self.turn, req.ip) {
            t.note_ip(a.id, ip);
        }
        Ok(a)
    }

    fn me(&self, req: &Request, v: &Value) -> Result<Account, Response> {
        let s = &self.store;
        self.auth(s, req, v)
    }

    pub fn handle(&self, req: Request) -> Response {
        self.requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.route(req).unwrap_or_else(|e| e)
    }

    /// Remember CPU / request / relay counters for `/admin/stats` (every
    /// few seconds from the server's timer; the last 15 s are kept).
    pub fn sample_stats(&self) {
        let p = crate::loadgen::proc_sample(None);
        let mut s = lock(&self.samples);
        s.push_back((
            Instant::now(),
            p.cpu_secs,
            self.requests.load(std::sync::atomic::Ordering::Relaxed),
            self.relay
                .forwarded
                .load(std::sync::atomic::Ordering::Relaxed),
        ));
        while s.len() > 1
            && s.front()
                .is_some_and(|f| f.0.elapsed() > Duration::from_secs(15))
        {
            s.pop_front();
        }
    }

    /// Admin routes of the self-benchmark and live stats: `bench` routes
    /// exist only with `RUGEN_BENCH=1`; all need the admin token (401).
    fn ops_auth(&self, req: &Request, v: &Value, bench: bool) -> Result<(), Response> {
        if bench && !self.cfg.bench {
            return Err(err(404, "no such route"));
        }
        if self.truth.cfg.admin_token.is_none() {
            return Err(err(404, "admin api disabled (set RUGEN_ADMIN_TOKEN)"));
        }
        let token = req
            .bearer
            .clone()
            .or_else(|| v.get("token").and_then(Value::as_str).map(str::to_string))
            .or_else(|| req.query.get("token").cloned())
            .unwrap_or_default();
        if !self.truth.admin_ok(&token) {
            return Err(err(401, "admin token required"));
        }
        Ok(())
    }

    /// `POST /admin/bench`: 202 {id} | 400 bad plan | 409 a run is going on.
    fn bench_start(&self, req: &Request, v: &Value) -> Res {
        self.ops_auth(req, v, true)?;
        let plan = crate::bench::Plan::parse(v).map_err(|e| err(400, &e))?;
        let secs = plan.duration().as_secs();
        match self.bench.start(plan, self.cfg.data.clone()) {
            Some(id) => {
                log::warn!("admin: bench {id} started (about {secs} s)");
                Ok(Response::json(
                    202,
                    &json!({ "id": id, "state": "running", "max_secs": secs, "note": crate::bench::NOTE }),
                ))
            }
            None => Err(err(409, "a bench is running")),
        }
    }

    /// `GET /admin/bench`: the last run.
    fn bench_status(&self, req: &Request, v: &Value) -> Res {
        self.ops_auth(req, v, true)?;
        ok(&crate::bench::status_json(self.bench.status()))
    }

    /// `GET /admin/stats`: live numbers of this process.
    fn admin_stats(&self, req: &Request, v: &Value) -> Res {
        self.ops_auth(req, v, false)?;
        let p = crate::loadgen::proc_sample(None);
        let now = (
            Instant::now(),
            p.cpu_secs,
            self.requests.load(std::sync::atomic::Ordering::Relaxed),
            self.relay
                .forwarded
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        let first = lock(&self.samples).front().copied();
        let (start_t, start_cpu, start_req, start_fwd) = first.unwrap_or((self.started, 0.0, 0, 0));
        let secs = now.0.duration_since(start_t).as_secs_f64().max(0.001);
        ok(&json!({
            "uptime_secs": self.started.elapsed().as_secs(),
            "threads": p.threads,
            "rss_mb": (p.rss_mb * 10.0).round() / 10.0,
            "cpu_pct": ((now.1 - start_cpu) / secs * 1000.0).round() / 10.0,
            "req_s": ((now.2 - start_req) as f64 / secs * 10.0).round() / 10.0,
            "window_secs": (secs * 10.0).round() / 10.0,
            "ws": lock(&self.hub).online(),
            "relay_sessions": self.relay.session_count(),
            "live_logs": self.live.usage().0,
            "live_bytes": self.live.usage().1,
            "relay_pkt_s": ((now.3 - start_fwd) as f64 / secs * 10.0).round() / 10.0,
            "open_files": crate::sys::open_fds(),
            "max_open_files": crate::sys::fd_limit().map(|l| l.0),
            "memory_limit_mb": crate::sys::memory_limit_mb().map(|m| m.round()),
            "write_queue": self.store.write_queue(),
            "resim_queue": self.resim.as_ref().map_or(0, |w| w.queued()),
            "bench": self.bench.status().map(|r| r.state),
            "packages_r2": self.r2_health(),
        }))
    }

    pub fn info(&self) -> DbResult<ServerInfo> {
        let accounts_online = {
            let mut seen = lock(&self.seen);
            seen.retain(|_, t| t.elapsed().as_secs() < ONLINE_SECS);
            seen.len()
        };
        let rooms = lock(&self.rooms).len();
        let queued = lock(&self.queue).len();
        let ws = lock(&self.hub).online();
        Ok(ServerInfo {
            api: API_VERSION,
            name: self.cfg.name.clone(),
            motd: self.cfg.motd.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            online: accounts_online.max(ws),
            queued,
            rooms,
            // running matches: a slot connected and traffic in the last seconds
            matches: self.relay.active_count(Instant::now()),
            udp: self.cfg.udp_public.clone(),
            transports: rugen_proto::relay_transports(self.cfg.udp_public.as_deref()),
            key: self.truth.public_key().map(|k| k.hex()),
            official: self.truth.is_official(),
            // API 4 (0.5) clients never read `api`: both generations play here
            api_min: crate::compat::LEGACY_API,
            // named accounts (API 5)
            accounts: true,
            // the game's consent dialog tells players this
            pkg_days: self.packages.days(),
        })
    }

    fn route(&self, req: Request) -> Res {
        let path: Vec<&str> = req.path.trim_matches('/').split('/').collect();
        let v = body(&req);
        match (req.method.as_str(), path.as_slice()) {
            ("GET", [""]) | ("GET", ["health"]) | ("GET", ["info"]) => {
                // health checks and server lists poll this: served from a
                // short cache so they never queue behind the store
                if let Some((t, v)) = &*lock(&self.health)
                    && t.elapsed() < HEALTH_TTL
                {
                    return Ok(Response::json(200, v));
                }
                let mut v = serde_json::to_value(db(self.info())?).unwrap_or(Value::Null);
                // TURN budget, numbers only (older clients ignore it)
                if let Some(t) = &self.turn {
                    v["turn"] = t.status(&self.store);
                }
                // relay counters (additive)
                v["relay"] = json!({
                    "sessions": self.relay.session_count(),
                    "forwarded": self.relay.forwarded.load(std::sync::atomic::Ordering::Relaxed),
                    "dropped": self.relay.dropped.load(std::sync::atomic::Ordering::Relaxed),
                    "queue_drops": self.relay.queue_drops.load(std::sync::atomic::Ordering::Relaxed),
                });
                // backup state: no endpoint, bucket or credentials
                v["backup"] = self.backups.health();
                // packages bucket: counts and the last error only
                v["packages_r2"] = self.r2_health();
                *lock(&self.health) = Some((Instant::now(), v.clone()));
                Ok(Response::json(200, &v))
            }
            ("POST", ["register"]) => {
                let s = &self.store;
                if db(s.account_count())? >= 1_000_000 {
                    return Err(err(409, "server full"));
                }
                let a = db(s.register())?;
                ok(&rugen_proto::Registered {
                    id: a.id,
                    key: a.key,
                })
            }
            ("POST", ["profile"]) => {
                let s = &self.store;
                let a = self.auth(s, &req, &v)?;
                let name = str_field(&v, "name", 32);
                let avatar = v.get("avatar").and_then(Value::as_u64).map(|a| a as u32);
                let a = db(s.set_profile(a.id, name, avatar))?.ok_or_else(|| err(404, "gone"))?;
                ok(&a.info())
            }
            ("GET", ["profile", id]) => {
                let id = id.parse::<u64>().map_err(|_| err(400, "bad id"))?;
                match db(self.store.by_id(id))? {
                    Some(a) => ok(&a.info()),
                    None => Err(err(404, "no such player")),
                }
            }
            ("GET", ["seasons", "current"]) => {
                let s = &self.store;
                db(s.roll_season())?;
                ok(&db(s.season())?)
            }
            ("GET", ["leaderboard"]) => self.leaderboard(&req, &v),
            ("GET", ["replay", id]) => self.replay(id),
            ("GET", ["v1", "live"]) => ok(&self.live.list()),
            ("GET", ["v1", "live", id]) => self.live_chunk(&req, &v, id),
            ("POST", ["v1", "replays"]) => self.share_replay(&req, &v),
            ("GET", ["v1", "replays", code]) => self.shared_replay(code),
            ("GET", ["rooms"]) => self.list_rooms(&req),
            ("POST", ["room"]) => self.create_room(&req, &v),
            ("POST", ["room", code, "join"]) => self.join_room(&req, &v, code),
            ("GET", ["room", code]) => self.poll_room(&req, &v, code),
            ("POST", ["room", code, "leave"]) => self.leave_room(&req, &v, code),
            ("POST", ["room", code, "kick"]) => self.kick(&req, &v, code),
            ("POST", ["room", code, "rematch"]) => self.rematch(&req, &v, code),
            ("POST", ["room", code, "start"]) => self.start_tournament(&req, &v, code),
            ("POST", ["queue"]) => self.enter_queue(&req, &v),
            ("GET", ["queue"]) => self.poll_queue(&req, &v),
            ("DELETE", ["queue"]) | ("POST", ["queue", "leave"]) => self.leave_queue(&req, &v),
            ("POST", ["result"]) => self.result(&req, &v),
            ("GET", ["matchup", id]) => self.matchup_get(&req, &v, id),
            ("POST", ["matchup", id, op]) => self.matchup_op(&req, &v, id, op),
            ("GET", ["pkg", fp]) => self.pkg_status(&req, &v, fp),
            ("POST", ["pkg", fp, "upload"]) => self.pkg_upload(&req, fp),
            ("GET", ["pkg", fp, "data"]) => self.pkg_data(&req, &v, fp),
            ("GET", ["pkg", fp, "url"]) => self.pkg_url(&req, &v, fp),
            ("GET", ["char", fp]) => {
                let r = db(self.store.char_rating(fp))?;
                ok(&r)
            }
            ("POST", ["match", id, "desync"]) => self.desync(&req, &v, id),
            ("GET", ["match", id, "result"]) => {
                let id = id.parse::<u64>().map_err(|_| err(400, "bad id"))?;
                let s = &self.store;
                let me = self.auth(s, &req, &v)?.id;
                ok(&self.result_ack(s, id, me)?)
            }
            ("GET", ["v1", "truth"]) => {
                let s = &self.store;
                match db(self.truth.own_feed(s))? {
                    Some(b) => ok(&b),
                    None => Err(err(404, "this server does not sign")),
                }
            }
            ("GET", ["v1", "truth", "official"]) => {
                let blob = if self.truth.is_official() {
                    db(self.truth.own_feed(&self.store))?
                } else {
                    self.truth.official_blob()
                };
                blob.map_or_else(|| Err(err(404, "no official feed held")), |b| ok(&b))
            }
            ("POST", ["admin", "bench"]) | ("POST", ["v1", "admin", "bench"]) => {
                self.bench_start(&req, &v)
            }
            ("GET", ["admin", "bench"]) | ("GET", ["v1", "admin", "bench"]) => {
                self.bench_status(&req, &v)
            }
            ("GET", ["admin", "stats"]) | ("GET", ["v1", "admin", "stats"]) => {
                self.admin_stats(&req, &v)
            }
            ("GET", ["v1", "identity"]) => self.identity(&req),
            ("GET", ["v1", "account"]) => self.account(&req, &v, "info"),
            ("POST", ["v1", "account", op]) => self.account(&req, &v, op),
            ("POST", ["v1", "admin", "tournament", code, "cancel"]) => {
                self.admin_auth(&req, &v)?;
                self.admin_cancel_tournament(code)
            }
            ("POST", ["v1", "admin", op]) => self.admin(&req, &v, op),
            ("GET", ["v1", "admin", "blocklist"]) => self.admin(&req, &v, "blocklist"),
            ("GET", ["v1", "admin", "backups"]) => self.admin(&req, &v, "backups"),
            ("GET", ["v1", "admin", "backup", "status"]) => self.admin(&req, &v, "backup_status"),
            _ => Err(err(404, "no such route")),
        }
    }

    // ---- leaderboards

    /// `GET /leaderboard?key=&season=N`: the live board of the current
    /// season, or a finished season's final standings (`finished`); `past`
    /// lists the finished seasons kept.
    fn leaderboard(&self, req: &Request, v: &Value) -> Res {
        let s = &self.store;
        db(s.roll_season())?;
        let current = db(s.season())?;
        let me = self.auth(s, req, v).ok();
        let past = db(s.past_seasons())?;
        let asked = req
            .query
            .get("season")
            .and_then(|n| n.parse::<u32>().ok())
            .filter(|&n| n != current.number);
        // a per-fighter board: `fighter=FP`, or `fighters=1` for the most played
        let fighter = req.query.get("fighter").map(|f| f.to_ascii_lowercase());
        if fighter.is_some() || req.query.contains_key("fighters") {
            let (season, finished) = match asked {
                Some(n) => (
                    db(s.past_season(n))?.ok_or_else(|| err(404, "no such season"))?,
                    true,
                ),
                None => (current, false),
            };
            let fighters = db(s.board_fighters(season.number))?;
            let chosen = match fighter.filter(|f| !f.is_empty()) {
                Some(fp) => {
                    if !is_fingerprint(&fp) {
                        return Err(err(400, "bad fingerprint"));
                    }
                    fighters
                        .iter()
                        .find(|f| f.fingerprint == fp)
                        .cloned()
                        .unwrap_or(rugen_proto::FighterEntry {
                            fingerprint: fp,
                            ..Default::default()
                        })
                }
                None => match fighters.first() {
                    Some(f) => f.clone(),
                    None => {
                        return ok(&Leaderboard {
                            season,
                            rows: Vec::new(),
                            me: None,
                            past,
                            finished,
                            fighter: None,
                            fighters,
                        });
                    }
                },
            };
            let n = season.number;
            let me = match me {
                Some(a) => db(s.fighter_rank_of(n, &chosen.fingerprint, a.id))?,
                None => None,
            };
            return ok(&Leaderboard {
                rows: db(s.fighter_board(n, &chosen.fingerprint, 50))?,
                season,
                me,
                past,
                finished,
                fighter: Some(chosen),
                fighters,
            });
        }
        if let Some(n) = asked {
            let season = db(s.past_season(n))?.ok_or_else(|| err(404, "no such season"))?;
            let me = match me {
                Some(a) => db(s.season_rank_of(n, a.id))?,
                None => None,
            };
            return ok(&Leaderboard {
                season,
                rows: db(s.season_board(n, 50))?,
                me,
                past,
                finished: true,
                fighter: None,
                fighters: Vec::new(),
            });
        }
        let me = match me {
            Some(a) => db(s.rank_of(a.id))?.map(|pos| (pos, a.info())),
            None => None,
        };
        ok(&Leaderboard {
            season: current,
            rows: db(s.leaderboard(50))?,
            me,
            past,
            finished: false,
            fighter: None,
            fighters: Vec::new(),
        })
    }

    // ---- rooms

    /// Drop silent members and empty / host-less / ancient rooms (their
    /// relay sessions close). The players of a match whose relay session is
    /// alive never time out (a client in a match does not poll the room);
    /// spectators count as heard while their relay slot carries traffic.
    fn expire_rooms(&self, rooms: &mut HashMap<String, Room>) {
        let hub = lock(&self.hub);
        let now = Instant::now();
        for r in rooms.values_mut() {
            let live = r
                .running
                .as_ref()
                .and_then(|run| Some((run.slots.clone(), self.relay.heard(run.session)?)));
            for m in &mut r.members {
                if hub.is_online(m.account) {
                    m.last_seen = now;
                }
                if let Some((slots, heard)) = &live
                    && let Some(i) = slots.iter().position(|&a| a == m.account)
                {
                    if i < 2 {
                        m.last_seen = now;
                    } else if let Some(&t) = heard.get(i) {
                        m.last_seen = m.last_seen.max(t);
                    }
                }
            }
            r.members
                .retain(|m| m.last_seen.elapsed().as_secs() < MEMBER_TIMEOUT_SECS);
        }
        rooms.retain(|code, r| {
            let hosted = r.server_hosted || r.player(0).is_some();
            let keep = hosted && r.created.elapsed().as_secs() < ROOM_MAX_AGE_SECS;
            if !keep && let Some(run) = &r.running {
                self.relay.close(run.session);
                log::info!(
                    "room {code} closed: relay session {:08x} closed",
                    run.session
                );
            }
            keep
        });
    }

    fn profile(store: &Store, id: u64) -> ProfileInfo {
        store
            .by_id(id)
            .ok()
            .flatten()
            .map(|a| a.info())
            .unwrap_or_default()
    }

    fn room_view(&self, store: &Store, code: &str, r: &Room, me: u64) -> RoomInfo {
        // matchups before (never under) the hub lock: push_matchup takes
        // the hub with matchups held
        let matchup = r.matchup.and_then(|id| {
            let ms = lock(&self.matchups);
            ms.get(&id).map(|m| self.matchup_view(store, m, me))
        });
        let hub = lock(&self.hub);
        let my_role = r.member(me).map_or(2, |m| m.role);
        // a tournament room: the called pair plays as host / challenger
        let called = r.tournament.as_ref().and_then(|t| {
            let (round, i, _) = t.called?;
            t.bracket.as_ref()?.players(round, i)
        });
        let my_role = match (&r.tournament, called) {
            (Some(_), Some(p)) if p.contains(&me) => u8::from(p[1] == me),
            (Some(_), _) => 2,
            (None, _) => my_role,
        };
        let host = r.player(0);
        let chal = r.player(1);
        let p1_char = host.map(|m| m.char_id.clone()).unwrap_or_default();
        let p2_char = match (chal, r.rules.chars.as_str()) {
            (Some(_), "mirror") => p1_char.clone(),
            (Some(c), _) => c.char_id.clone(),
            (None, _) => String::new(),
        };
        let opponent = match (called, my_role) {
            (Some(p), 0 | 1) if r.tournament.is_some() => {
                Some(Self::profile(store, p[1 - my_role as usize]))
            }
            (_, 0) => chal.map(|m| Self::profile(store, m.account)),
            (_, 1) => host.map(|m| Self::profile(store, m.account)),
            _ => None,
        };
        let est_ping_ms = match (host, chal) {
            (Some(h), Some(c)) => Some(matchmaking::estimate(
                hub.rtt(h.account),
                hub.rtt(c.account),
            )),
            _ => None,
        };
        let members = r
            .members
            .iter()
            .map(|m| RoomMember {
                profile: Self::profile(store, m.account),
                role: m.role,
                rtt_ms: hub.rtt(m.account),
            })
            .collect();
        let my_ticket = r.running.as_ref().and_then(|run| {
            let slot = run.slots.iter().position(|&a| a == me)?;
            Some(ticket(run, slot, &self.cfg.udp_public))
        });
        RoomInfo {
            code: code.to_string(),
            name: r.name.clone(),
            public: r.public,
            locked: r.password.is_some(),
            rules: r.rules.clone(),
            side: my_role + 1,
            ready: r.running.is_some(),
            p1_char,
            p2_char,
            stage: r.rules.stage.clone(),
            opponent,
            members,
            max_spectators: r.max_spectators,
            match_id: r.running.as_ref().map_or(0, |run| run.match_id),
            est_ping_ms,
            ticket: my_ticket,
            matchup,
            tournament: r.tournament.as_ref().map(|t| {
                let seeds: Vec<(u64, u8)> = match &t.bracket {
                    Some(b) => b
                        .seeds
                        .iter()
                        .enumerate()
                        .map(|(i, s)| (s.account, i as u8 + 1))
                        .collect(),
                    None => t.entrants.iter().map(|&a| (a, 0)).collect(),
                };
                let entrants = seeds
                    .into_iter()
                    .map(|(a, seed)| {
                        let p = Self::profile(store, a);
                        rugen_proto::Entrant {
                            id: a,
                            name: p.name,
                            verified: p.verified,
                            rating: p.rating,
                            seed,
                        }
                    })
                    .collect();
                Box::new(t.view(entrants))
            }),
        }
    }

    /// Push every member its own view of the room.
    fn broadcast(&self, store: &Store, code: &str, r: &Room) {
        let views: Vec<(u64, RoomInfo)> = r
            .members
            .iter()
            .map(|m| (m.account, self.room_view(store, code, r, m.account)))
            .collect();
        let hub = lock(&self.hub);
        for (account, room) in views {
            hub.push(account, &ServerMsg::Room { room });
        }
    }

    /// Open the matchup phase of a new match between host and challenger
    /// (the relay session starts once both fighters are confirmed and synced).
    fn start_match(&self, store: &Store, r: &mut Room, code: &str) -> Result<(), Response> {
        let (Some(host), Some(chal)) = (r.player(0), r.player(1)) else {
            return Ok(());
        };
        let players = [host.account, chal.account];
        let setup = json!({ "p1_char": host.char_id, "p2_char": chal.char_id, "rules": r.rules })
            .to_string();
        let match_id = db(store.new_match(players, false, &setup))?;
        if let Some(old) = r.running.take() {
            self.relay.close(old.session);
        }
        let m = Matchup::new(
            match_id,
            players,
            false,
            r.rules.clone(),
            Some(code.to_string()),
        );
        let mut ms = lock(&self.matchups);
        if let Some(old) = r.matchup.and_then(|id| ms.get_mut(&id)) {
            old.fail("a new match replaced this one".into());
        }
        ms.insert(match_id, m);
        r.matchup = Some(match_id);
        for m in &mut r.members {
            m.ready = false;
        }
        log::info!("room {code}: match {match_id} in matchup phase");
        Ok(())
    }

    /// Public rooms, newest first, rooms of the caller's API before the
    /// others. Each carries the additive `api` of its host; API 4 callers
    /// (who ignore that field) see other rooms with a `[0.6]` name prefix.
    fn list_rooms(&self, req: &Request) -> Res {
        let s = &self.store;
        let mut rooms = lock(&self.rooms);
        self.expire_rooms(&mut rooms);
        let mut list: Vec<(bool, std::cmp::Reverse<Instant>, RoomSummary)> = rooms
            .iter()
            .filter(|(_, r)| r.public)
            .map(|(code, r)| {
                let mut host = r.player(0).map(|m| Self::profile(s, m.account));
                if r.server_hosted {
                    // the lobby shows who hosts: the server itself
                    host = Some(ProfileInfo {
                        name: self.cfg.name.clone(),
                        ..ProfileInfo::default()
                    });
                }
                (
                    r.api != req.api,
                    std::cmp::Reverse(r.created),
                    RoomSummary {
                        code: code.clone(),
                        name: crate::compat::listed_name(&r.name, r.api, req.api),
                        host: host.as_ref().map(|p| p.name.clone()).unwrap_or_default(),
                        host_verified: host.as_ref().is_some_and(|p| p.verified),
                        rules: r.rules.clone(),
                        players: r.members.iter().filter(|m| m.role < 2).count() as u8,
                        spectators: r.spectators(),
                        max_spectators: r.max_spectators,
                        locked: r.password.is_some(),
                        in_match: r.running.is_some(),
                        live_match: r.running.as_ref().map_or(0, |run| run.match_id),
                        api: r.api,
                        tournament: r.tournament.as_ref().map(|t| rugen_proto::TournamentBrief {
                            size: t.size,
                            entrants: match &t.bracket {
                                Some(b) => b.seeds.len(),
                                None => t.entrants.len(),
                            } as u8,
                            state: t.state().into(),
                        }),
                    },
                )
            })
            .collect();
        list.sort_by_key(|(other, t, _)| (*other, *t));
        let list: Vec<RoomSummary> = list.into_iter().take(100).map(|(.., r)| r).collect();
        ok(&list)
    }

    fn create_room(&self, req: &Request, v: &Value) -> Res {
        let s = &self.store;
        let me = self.auth(s, req, v)?;
        let char_id = clean_id(&str_field(v, "char", 64).unwrap_or_default());
        let password = match str_field(v, "password", 64) {
            Some(p) => Some(password::hash(&p).ok_or_else(|| err(500, "hash failed"))?),
            None => None,
        };
        let mut rules = clean_rules(v.get("rules"));
        if let Some(st) = str_field(v, "stage", 64) {
            rules.stage = clean_id(&st);
        }
        let name = str_field(v, "name", 64)
            .map(|n| clean_name(&n))
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| format!("{}'S ROOM", me.name.to_uppercase()));
        let mut rooms = lock(&self.rooms);
        self.expire_rooms(&mut rooms);
        if rooms.len() >= MAX_ROOMS {
            return Err(err(409, "too many rooms"));
        }
        // one hosted room per player
        rooms.retain(|_, r| r.player(0).is_none_or(|h| h.account != me.id));
        let mut code = random_code();
        while rooms.contains_key(&code) {
            code = random_code();
        }
        let tour = v
            .get("tournament")
            .and_then(Value::as_u64)
            .filter(|n| *n > 0)
            .map(|n| {
                tournament::SIZES
                    .iter()
                    .copied()
                    .find(|s| u64::from(*s) == n)
                    .ok_or_else(|| err(400, "a tournament has 8 or 16 players"))
            })
            .transpose()?
            .map(|size| {
                let mut t = Tournament::new(size);
                t.entrants.push(me.id);
                t
            });
        let room = Room {
            name,
            public: v.get("public").and_then(Value::as_bool).unwrap_or(true),
            password,
            rules,
            max_spectators: if tour.is_some() {
                TOURNAMENT_SPECTATORS
            } else {
                v.get("max_spectators")
                    .and_then(Value::as_u64)
                    .map_or(2, |n| n.min(MAX_SPECTATORS as u64) as u8)
            },
            members: vec![Member {
                account: me.id,
                role: 0,
                char_id,
                last_seen: Instant::now(),
                ready: true,
            }],
            kicked: Vec::new(),
            created: Instant::now(),
            running: None,
            matchup: None,
            api: req.api,
            engine: req.engine.clone(),
            tournament: tour,
            server_hosted: false,
        };
        let view = self.room_view(s, &code, &room, me.id);
        rooms.insert(code.clone(), room);
        log::info!("room {code} created by {}", me.id);
        ok(&view)
    }

    fn join_room(&self, req: &Request, v: &Value, code: &str) -> Res {
        let s = &self.store;
        let me = self.auth(s, req, v)?;
        let char_id = clean_id(&str_field(v, "char", 64).unwrap_or_default());
        let spectate = v.get("spectate").and_then(Value::as_bool).unwrap_or(false);
        let code = code.trim().to_ascii_uppercase();
        let mut rooms = lock(&self.rooms);
        self.expire_rooms(&mut rooms);
        let r = rooms
            .get_mut(&code)
            .ok_or_else(|| err(404, "no such room"))?;
        if r.kicked.contains(&me.id) {
            return Err(err(403, "you were removed from this room"));
        }
        if r.member(me.id).is_none() {
            // players and spectators alike need to read the host's fighters
            if r.api != req.api {
                return Err(err(409, &crate::compat::room_refusal(req.api, r.api)));
            }
            // a server-hosted room runs the game version of its first player
            if r.server_hosted && r.engine.is_none() {
                r.engine = req.engine.clone();
            }
            // and simulate them the same way
            if let (Some(mine), Some(host)) = (&req.engine, &r.engine)
                && mine != host
            {
                return Err(err(409, &crate::compat::engine_refusal(mine, host)));
            }
            if let Some(phc) = &r.password {
                let given = str_field(v, "password", 64).unwrap_or_default();
                if !password::verify(&given, phc) {
                    return Err(err(403, "wrong password"));
                }
            }
            // a bracket needs a client that knows brackets (0.6 does not)
            if r.tournament.is_some() && v.get("tournament").and_then(Value::as_bool) != Some(true)
            {
                return Err(err(
                    409,
                    "this room runs a tournament bracket: update rugen to join",
                ));
            }
            // (an admin tournament's bracket is drawn: its entrants come
            // back to their seats whenever they arrive)
            let entrant = r.tournament.as_ref().is_some_and(|t| {
                (t.state() == "open" && !t.full())
                    || (r.server_hosted && t.state() != "done" && t.entrants.contains(&me.id))
            });
            let role = if r.tournament.is_some() && !spectate && entrant {
                ROLE_ENTRANT
            } else if r.tournament.is_none() && !spectate && r.player(1).is_none() {
                1
            } else if r.spectators() < r.max_spectators {
                2
            } else if spectate {
                return Err(err(409, "no spectator seats left"));
            } else {
                return Err(err(409, "room is full"));
            };
            r.members.push(Member {
                account: me.id,
                role,
                char_id,
                last_seen: Instant::now(),
                ready: true,
            });
            log::info!("room {code}: {} joined as role {role}", me.id);
            if role == ROLE_ENTRANT
                && let Some(t) = r.tournament.as_mut()
                && !t.entrants.contains(&me.id)
            {
                t.entrants.push(me.id);
            }
            if role == 1 && r.running.is_none() && r.matchup.is_none() {
                self.start_match(s, r, &code)?;
            }
            self.broadcast(s, &code, r);
        }
        ok(&self.room_view(s, &code, r, me.id))
    }

    fn poll_room(&self, req: &Request, v: &Value, code: &str) -> Res {
        let s = &self.store;
        let code = code.trim().to_ascii_uppercase();
        if request_key(req, v).is_none() {
            // no key at all: a tournament room's bracket is public (the
            // website mirrors it); anything else still needs a member
            let rooms = lock(&self.rooms);
            let r = rooms.get(&code).ok_or_else(|| err(404, "no such room"))?;
            if r.tournament.is_none() {
                return Err(err(401, "bad key"));
            }
            return Ok(Response::json(200, &self.public_room_view(s, &code, r)));
        }
        let me = self.auth(s, req, v)?;
        let mut rooms = lock(&self.rooms);
        if let Some(m) = rooms
            .get_mut(&code)
            .and_then(|r| r.members.iter_mut().find(|m| m.account == me.id))
        {
            m.last_seen = Instant::now();
        }
        self.expire_rooms(&mut rooms);
        if let Some(r) = rooms.get_mut(&code)
            && r.tournament.is_some()
        {
            self.tick_tournament(s, &code, r)?;
        }
        let r = rooms.get(&code).ok_or_else(|| err(404, "no such room"))?;
        if r.member(me.id).is_none() {
            return Err(err(401, "not in this room"));
        }
        ok(&self.room_view(s, &code, r, me.id))
    }

    fn leave_room(&self, req: &Request, v: &Value, code: &str) -> Res {
        let s = &self.store;
        let me = self.auth(s, req, v)?;
        let code = code.trim().to_ascii_uppercase();
        let mut rooms = lock(&self.rooms);
        if let Some(r) = rooms.get_mut(&code) {
            self.fail_matchup_of(s, r, me.id, "your opponent left");
            r.members.retain(|m| m.account != me.id);
            if let Some(t) = r.tournament.as_mut()
                && t.bracket.is_none()
            {
                t.entrants.retain(|&a| a != me.id);
            }
            // a player left (or the host closed the room): the match is over
            let gone = match r.running.as_ref() {
                Some(run) if r.tournament.is_some() => run.slots[..2].contains(&me.id),
                _ => r.player(0).is_none() || r.player(1).is_none(),
            };
            if gone {
                if let Some(run) = r.running.take() {
                    self.relay.close(run.session);
                }
            }
            if r.player(0).is_none() && !r.server_hosted {
                // the host left: the room closes
                let others: Vec<u64> = r.members.iter().map(|m| m.account).collect();
                rooms.remove(&code);
                let hub = lock(&self.hub);
                for a in others {
                    hub.push(a, &ServerMsg::Kicked { code: code.clone() });
                }
            } else {
                self.broadcast(s, &code, r);
            }
        }
        ok(&json!({ "left": true }))
    }

    fn kick(&self, req: &Request, v: &Value, code: &str) -> Res {
        let s = &self.store;
        let me = self.auth(s, req, v)?;
        let target = v
            .get("id")
            .and_then(Value::as_u64)
            .ok_or_else(|| err(400, "id required"))?;
        let code = code.trim().to_ascii_uppercase();
        let mut rooms = lock(&self.rooms);
        let r = rooms
            .get_mut(&code)
            .ok_or_else(|| err(404, "no such room"))?;
        if r.player(0).is_none_or(|h| h.account != me.id) {
            return Err(err(403, "only the host can kick"));
        }
        if target == me.id {
            return Err(err(400, "use leave"));
        }
        self.fail_matchup_of(s, r, target, "a player was removed");
        r.members.retain(|m| m.account != target);
        if let Some(t) = r.tournament.as_mut()
            && t.bracket.is_none()
        {
            t.entrants.retain(|&a| a != target);
        }
        r.kicked.push(target);
        if r.running
            .as_ref()
            .is_some_and(|run| run.slots[..2].contains(&target))
        {
            if let Some(run) = r.running.take() {
                self.relay.close(run.session);
            }
        }
        lock(&self.hub).push(target, &ServerMsg::Kicked { code: code.clone() });
        self.broadcast(s, &code, r);
        ok(&self.room_view(s, &code, r, me.id))
    }

    fn rematch(&self, req: &Request, v: &Value, code: &str) -> Res {
        let s = &self.store;
        let me = self.auth(s, req, v)?;
        let code = code.trim().to_ascii_uppercase();
        let mut rooms = lock(&self.rooms);
        let r = rooms
            .get_mut(&code)
            .ok_or_else(|| err(404, "no such room"))?;
        if r.tournament.is_some() {
            return Err(err(409, "the server calls the matches of a bracket"));
        }
        let m = r
            .members
            .iter_mut()
            .find(|m| m.account == me.id && m.role < 2)
            .ok_or_else(|| err(403, "not a player of this room"))?;
        m.ready = true;
        m.last_seen = Instant::now();
        let both = r.members.iter().filter(|m| m.role < 2 && m.ready).count() == 2;
        if both {
            self.start_match(s, r, &code)?;
            self.broadcast(s, &code, r);
        }
        ok(&self.room_view(s, &code, r, me.id))
    }

    // ---- live matches

    /// `GET /v1/live/{id}?key=&from=N`: a live (or just finished) match's
    /// stream from frame N, binary ([`rugen_proto::stream::Chunk`]; the
    /// header when N is 0). Private rooms' matches: members only.
    fn live_chunk(&self, req: &Request, v: &Value, id: &str) -> Res {
        let id = id.parse::<u64>().map_err(|_| err(400, "bad id"))?;
        let me = self.auth(&self.store, req, v)?;
        let from = req
            .query
            .get("from")
            .and_then(|f| f.parse::<u32>().ok())
            .unwrap_or(0);
        match self
            .live
            .chunk_for(id, from, crate::live::MAX_CHUNK_FRAMES, me.id)
        {
            Ok(c) => Ok(Response::bytes(rugen_proto::stream::encode_chunk(&c))),
            // RUGEN_LIVE_VIEWERS are watching already
            Err(crate::live::Refused::Full) => Err(err(409, crate::live::FULL)),
            Err(_) if self.live.may_watch(id, me.id) => Err(err(404, "no such live match")),
            Err(_) => Err(err(404, "no such live match (or a private room's)")),
        }
    }

    // ---- shared replays

    /// `POST /v1/replays {key, match_id}`: a player of a finished match
    /// shares it under a short code, kept [`replay_days`] days. The stream
    /// is the server's input log of the match, else the longest input
    /// stream the players reported. Sharing a match again gives its code.
    fn share_replay(&self, req: &Request, v: &Value) -> Res {
        use rugen_proto::stream::{SharedReplay, inputs_from_bytes, replay_code};
        let s = &self.store;
        let me = self.auth(s, req, v)?;
        let id = v
            .get("match_id")
            .and_then(Value::as_u64)
            .ok_or_else(|| err(400, "match_id required"))?;
        let players = db(s.match_players(id))?.ok_or_else(|| err(404, "no such match"))?;
        if !players.contains(&me.id) {
            return Err(err(403, "only its players share a match"));
        }
        let answer = |row: &crate::store::SharedRow| {
            let title = serde_json::from_str::<rugen_proto::stream::MatchHeader>(&row.header)
                .map(|h| h.title())
                .unwrap_or_default();
            ok(&SharedReplay {
                code: row.code.clone(),
                expires: row.expires,
                match_id: row.match_id,
                title,
                frames: (row.inputs.len() / 4) as u32,
            })
        };
        if let Some(row) = db(s.shared_of_match(id))? {
            return answer(&row);
        }
        if self.live.running(id) {
            return Err(err(409, "the match is still running"));
        }
        let day = crate::store::now().saturating_sub(24 * 3600);
        if db(s.shares_since(me.id, day))? >= SHARES_PER_DAY {
            return Err(err(429, "too many shared replays today"));
        }
        let (header, frames) = match self.live.finished(id) {
            Some(x) => x,
            None => {
                let Some((setup, ranked, players, reports)) = db(s.match_evidence(id))? else {
                    return Err(err(404, "no such match"));
                };
                let longest = reports
                    .iter()
                    .map(|(_, r)| &r.inputs)
                    .max_by_key(|i| i.len())
                    .cloned()
                    .unwrap_or_default();
                (
                    self.header_from_setup(s, id, &setup, ranked, players),
                    inputs_from_bytes(&longest),
                )
            }
        };
        if frames.is_empty() {
            return Err(err(404, "this server kept no input stream of that match"));
        }
        let mut code = String::new();
        for _ in 0..16 {
            let c = replay_code::generate(|| {
                let mut b = [0u8; 1];
                let _ = getrandom::getrandom(&mut b);
                b[0]
            });
            if db(s.shared_replay(&c))?.is_none() {
                code = c;
                break;
            }
        }
        let t = crate::store::now();
        let row = crate::store::SharedRow {
            code,
            match_id: id,
            header: serde_json::to_string(&header).unwrap_or_default(),
            inputs: rugen_proto::stream::inputs_to_bytes(&frames),
            account: me.id,
            created: t,
            expires: t + replay_days() * 24 * 3600,
        };
        let fps = [
            header.fighters[0].fingerprint.clone(),
            header.fighters[1].fingerprint.clone(),
            header.stage.fingerprint.clone(),
        ];
        let row = db(s.share_replay(&row, fps))?;
        log::info!("match {id}: shared as replay {}", row.code);
        answer(&row)
    }

    /// `GET /v1/replays/{code}`: a shared replay, binary (a stream chunk
    /// with the header and every frame). No account needed to read it.
    fn shared_replay(&self, code: &str) -> Res {
        let code = rugen_proto::stream::replay_code::normalize(code)
            .ok_or_else(|| err(400, "not a replay code"))?;
        let row = db(self.store.shared_replay(&code))?
            .ok_or_else(|| err(404, "no such replay (it may have expired)"))?;
        let header = serde_json::from_str(&row.header).ok();
        let inputs = rugen_proto::stream::inputs_from_bytes(&row.inputs);
        let c = rugen_proto::stream::Chunk {
            header,
            ended: true,
            total: inputs.len() as u32,
            from: 0,
            inputs,
        };
        Ok(Response::bytes(rugen_proto::stream::encode_chunk(&c)))
    }

    /// A match header from its stored setup (the live log is gone).
    fn header_from_setup(
        &self,
        s: &Store,
        id: u64,
        setup: &str,
        ranked: bool,
        players: [u64; 2],
    ) -> rugen_proto::stream::MatchHeader {
        let v: Value = serde_json::from_str(setup).unwrap_or_default();
        let st = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let content = |fp: String, name: String| rugen_proto::stream::StreamContent {
            size: s.package(&fp).ok().flatten().map_or(0, |p| p.size),
            fingerprint: fp,
            name,
        };
        let player = |id: u64| {
            let p = Self::profile(s, id);
            rugen_proto::stream::StreamPlayer {
                id,
                name: p.name,
                verified: p.verified,
            }
        };
        rugen_proto::stream::MatchHeader {
            v: rugen_proto::stream::STREAM_VERSION,
            match_id: id,
            engine: v
                .get("engine")
                .and_then(Value::as_str)
                .map(|e| format!("rugen {e}"))
                .unwrap_or_default(),
            seed: rugen_proto::stream::online_seed(id),
            rules: v
                .get("rules")
                .and_then(|r| serde_json::from_value(r.clone()).ok())
                .unwrap_or_default(),
            fighters: [
                content(st("p1_fp"), st("p1_char")),
                content(st("p2_fp"), st("p2_char")),
            ],
            stage: content(st("stage_fp"), st("stage")),
            players: [player(players[0]), player(players[1])],
            ranked,
            created: crate::store::now(),
            machines: v
                .get("machines")
                .and_then(|m| serde_json::from_value(m.clone()).ok())
                .unwrap_or_default(),
        }
    }

    /// The players' machine summaries from their ready reports, as shared
    /// replays and viewers get them ([`rugen_proto::MachineSummary::shared`]:
    /// version, OS, architecture). Empty for clients that send none.
    fn machines(m: &Matchup) -> [Option<rugen_proto::MachineSummary>; 2] {
        [0, 1].map(|i| {
            m.ready[i]
                .as_ref()
                .and_then(|r| r.machine.as_ref())
                .map(|s| s.clone().clean().shared())
                .filter(|s| !s.is_empty())
        })
    }

    /// Shared replays past their days or their total size go.
    pub fn sweep_replays(&self) {
        match self.store.sweep_shared(replay_max_bytes()) {
            Ok(0) => {}
            Ok(n) => log::info!("replays: {n} shared replays expired"),
            Err(e) => log::warn!("replays: {e}"),
        }
    }

    // ---- tournaments

    /// `POST /room/{code}/start`: the host draws the bracket with the
    /// entrants so far (at least two; seeded by rating) and the server
    /// starts calling matches. A finished tournament starts again.
    fn start_tournament(&self, req: &Request, v: &Value, code: &str) -> Res {
        let s = &self.store;
        let me = self.auth(s, req, v)?;
        let code = code.trim().to_ascii_uppercase();
        let mut rooms = lock(&self.rooms);
        let r = rooms
            .get_mut(&code)
            .ok_or_else(|| err(404, "no such room"))?;
        if r.player(0).is_none_or(|h| h.account != me.id) {
            return Err(err(403, "only the host starts the bracket"));
        }
        let members: Vec<u64> = r.members.iter().map(|m| m.account).collect();
        let t = r
            .tournament
            .as_mut()
            .ok_or_else(|| err(409, "not a tournament room"))?;
        if t.state() == "running" {
            return Err(err(409, "the bracket is running"));
        }
        if t.state() == "done" {
            // a new tournament with whoever is still in the room
            let old = t.bracket.take().map(|b| b.seeds).unwrap_or_default();
            t.entrants = old
                .iter()
                .map(|s| s.account)
                .filter(|a| members.contains(a))
                .collect();
            t.scores.clear();
        }
        t.entrants.retain(|a| members.contains(a));
        if t.entrants.len() < 2 {
            return Err(err(409, "a bracket needs at least two players"));
        }
        let mut seeds = Vec::new();
        for &a in &t.entrants {
            let rating = db(s.by_id(a))?.map_or(crate::elo::START_RATING, |x| x.rating);
            seeds.push(Seed { account: a, rating });
        }
        t.bracket = Some(Bracket::draw(t.size as usize, &seeds));
        t.called = None;
        t.started = false;
        t.next_at = None;
        log::info!(
            "room {code}: bracket of {} drawn ({} places)",
            seeds.len(),
            t.size
        );
        self.tick_tournament(s, &code, r)?;
        self.broadcast(s, &code, r);
        ok(&self.room_view(s, &code, r, me.id))
    }

    /// Every tournament room moves on (the server's timer).
    pub fn sweep_tournaments(&self) {
        let s = &self.store;
        let mut rooms = lock(&self.rooms);
        let codes: Vec<String> = rooms
            .iter()
            .filter(|(_, r)| {
                r.tournament
                    .as_ref()
                    .is_some_and(|t| t.state() == "running")
            })
            .map(|(c, _)| c.clone())
            .collect();
        for code in codes {
            if let Some(r) = rooms.get_mut(&code)
                && let Err(e) = self.tick_tournament(s, &code, r)
            {
                log::warn!("room {code}: bracket not advanced ({})", e.status);
            }
        }
    }

    /// Move a running bracket on: record the called match's settled result
    /// (or a walkover), then call the next match after a pause. Broadcasts
    /// when something changed.
    fn tick_tournament(&self, store: &Store, code: &str, r: &mut Room) -> Result<(), Response> {
        let members: Vec<u64> = r.members.iter().map(|m| m.account).collect();
        let Some(t) = r.tournament.as_mut() else {
            return Ok(());
        };
        if t.state() != "running" {
            return Ok(());
        }
        let mut changed = false;
        if let Some((round, i, at)) = t.called {
            let Some(b) = t.bracket.as_mut() else {
                return Ok(());
            };
            let Some(players) = b.players(round, i) else {
                t.called = None;
                return Ok(());
            };
            let match_id = b.rounds[round][i].match_id.unwrap_or(0);
            let (started, failed, progress) = {
                let ms = lock(&self.matchups);
                match ms.get(&match_id) {
                    Some(m) => (
                        m.started.is_some(),
                        m.failed.is_some(),
                        [0, 1].map(|s| {
                            u8::from(m.picks[s].is_some())
                                + u8::from(m.accepted[s])
                                + u8::from(m.ready[s].is_some())
                        }),
                    ),
                    None => (false, true, [0, 0]),
                }
            };
            if started && !t.started {
                t.started = true;
                changed = true;
            }
            let outcome = db(store.match_result(match_id, players[0]))?;
            let decided: Option<u64> = match outcome {
                Some((_, _, Some(w), _, _)) => Some(w),
                Some((_, _, None, _, true)) => {
                    // disputed: called again once, then the higher seed
                    if b.rounds[round][i].replays < tournament::MAX_REPLAYS {
                        b.rounds[round][i].replays += 1;
                        t.called = None;
                        t.started = false;
                        t.next_at = Some(Instant::now());
                        changed = true;
                        None
                    } else {
                        Some(players[0])
                    }
                }
                _ => None,
            };
            let walkover = || -> u64 {
                // the one still here, else the one further on, else the higher seed
                match (members.contains(&players[0]), members.contains(&players[1])) {
                    (true, false) => players[0],
                    (false, true) => players[1],
                    _ if progress[1] > progress[0] => players[1],
                    _ => players[0],
                }
            };
            let gone = players.iter().any(|p| !members.contains(p));
            let decided = decided.or_else(|| {
                if t.called.is_none() {
                    None
                } else if failed && !started {
                    if b.rounds[round][i].replays < tournament::MAX_REPLAYS && !gone {
                        b.rounds[round][i].replays += 1;
                        t.called = None;
                        t.next_at = Some(Instant::now());
                        changed = true;
                        None
                    } else {
                        Some(walkover())
                    }
                } else if !started
                    && (gone || at.elapsed().as_secs() > tournament::CALL_TIMEOUT_SECS)
                {
                    Some(walkover())
                } else {
                    None
                }
            });
            if let Some(w) = decided {
                let score = t.scores.get(&match_id).copied().unwrap_or([0, 0]);
                b.record(round, i, w, score);
                log::info!("room {code}: bracket match {match_id} won by {w}");
                t.called = None;
                t.started = false;
                t.next_at = Some(Instant::now() + Duration::from_secs(tournament::NEXT_DELAY_SECS));
                if let Some(c) = b.champion() {
                    log::info!("room {code}: {c} wins the tournament");
                }
                changed = true;
                // the room is free for the next match
                if let Some(run) = r.running.take() {
                    self.relay.close(run.session);
                }
                r.matchup = None;
            }
        }
        let Some(t) = r.tournament.as_mut() else {
            return Ok(());
        };
        let due = t.next_at.is_none_or(|n| Instant::now() >= n);
        if t.called.is_none() && due && t.state() == "running" {
            let Some(b) = t.bracket.as_mut() else {
                return Ok(());
            };
            let next = if r.server_hosted {
                // nobody hosts: the first pending pair with both players
                // here is called; a pair with one player here for
                // CALL_TIMEOUT_SECS is that player's walkover
                let now = Instant::now();
                let mut call = None;
                let mut decided = Vec::new();
                for (round, i) in b.pending() {
                    let Some(players) = b.players(round, i) else {
                        continue;
                    };
                    match players.map(|p| members.contains(&p)) {
                        [true, true] => {
                            t.waiting.remove(&(round, i));
                            call.get_or_insert((round, i));
                        }
                        [here, _] if here || members.contains(&players[1]) => {
                            let since = *t.waiting.entry((round, i)).or_insert(now);
                            if since.elapsed().as_secs() > tournament::CALL_TIMEOUT_SECS {
                                decided.push((round, i, players[usize::from(!here)]));
                            }
                        }
                        _ => {
                            t.waiting.remove(&(round, i));
                        }
                    }
                }
                for (round, i, w) in decided {
                    t.waiting.remove(&(round, i));
                    b.record(round, i, w, [0, 0]);
                    log::info!(
                        "room {code}: bracket match {round}/{i} walkover for {w} (opponent absent)"
                    );
                    changed = true;
                }
                if let Some(c) = b.champion() {
                    log::info!("room {code}: {c} wins the tournament");
                }
                call.filter(|_| b.champion().is_none())
            } else {
                b.next()
            };
            if let Some((round, i)) = next
                && let Some(players) = b.players(round, i)
            {
                let setup = json!({ "rules": r.rules, "tournament": true }).to_string();
                let match_id = db(store.new_match(players, false, &setup))?;
                b.rounds[round][i].match_id = Some(match_id);
                let m = Matchup::new(
                    match_id,
                    players,
                    false,
                    r.rules.clone(),
                    Some(code.to_string()),
                );
                lock(&self.matchups).insert(match_id, m);
                if let Some(old) = r.running.take() {
                    self.relay.close(old.session);
                }
                r.matchup = Some(match_id);
                t.called = Some((round, i, Instant::now()));
                t.started = false;
                t.next_at = None;
                log::info!(
                    "room {code}: bracket calls {} v {} (match {match_id})",
                    players[0],
                    players[1]
                );
                changed = true;
            }
        }
        if changed {
            self.broadcast(store, code, r);
        }
        Ok(())
    }

    // ---- queue (quick match and ranked)

    fn enter_queue(&self, req: &Request, v: &Value) -> Res {
        let a = self.me(req, v)?;
        let char_id = clean_id(&str_field(v, "char", 64).unwrap_or_default());
        let ranked = v.get("ranked").and_then(Value::as_bool).unwrap_or(true);
        let max_ping = v
            .get("max_ping")
            .and_then(Value::as_u64)
            .filter(|&p| p > 0)
            .map(|p| p.min(10_000) as u32);
        let reported_rtt = v
            .get("rtt_ms")
            .and_then(Value::as_u64)
            .filter(|&p| p > 0)
            .map(|p| p.min(5_000) as u32);
        {
            let mut q = lock(&self.queue);
            if q.len() > 10_000 {
                return Err(err(409, "queue full"));
            }
            q.retain(|e| e.id != a.id);
            // a match found earlier and learned from the hub push (the
            // `found` entry only clears on a poll) is over for a player who
            // queues again: never hand it back as this search's result
            lock(&self.found).remove(&a.id);
            q.push(QueueEntry {
                id: a.id,
                rating: a.rating,
                ranked,
                max_ping,
                reported_rtt,
                char_id,
                since: Instant::now(),
                last_poll: Instant::now(),
                api: req.api,
                engine: req.engine.clone(),
            });
        }
        log::info!(
            "{} queued ({}, {})",
            a.id,
            if ranked { "ranked" } else { "quick" },
            a.rating
        );
        self.pair()?;
        self.status_for(a.id)
    }

    fn leave_queue(&self, req: &Request, v: &Value) -> Res {
        let me = self.me(req, v)?.id;
        lock(&self.queue).retain(|e| e.id != me);
        lock(&self.found).remove(&me);
        ok(&json!({ "queued": false }))
    }

    fn poll_queue(&self, req: &Request, v: &Value) -> Res {
        let me = self.me(req, v)?.id;
        if let Some(e) = lock(&self.queue).iter_mut().find(|e| e.id == me) {
            e.last_poll = Instant::now();
        }
        self.pair()?;
        self.status_for(me)
    }

    fn status_for(&self, me: u64) -> Res {
        let found = lock(&self.found).remove(&me);
        let q = lock(&self.queue);
        if let Some((m, high)) = found {
            let est = m.est_ping_ms.unwrap_or(0);
            let mut v = serde_json::to_value(QueueStatus {
                queued: false,
                waiting_secs: 0,
                players_in_queue: q.len(),
                found: Some(m),
            })
            .unwrap_or(Value::Null);
            extend_found(&mut v["found"], est, high);
            return Ok(Response::json(200, &v));
        }
        let mine = q.iter().find(|e| e.id == me);
        ok(&QueueStatus {
            queued: mine.is_some(),
            waiting_secs: mine.map_or(0, |e| e.since.elapsed().as_secs()),
            players_in_queue: q.len(),
            found: None,
        })
    }

    /// Pair queued players (see [`matchmaking::pairs`]) and open relay sessions.
    pub fn pair(&self) -> Result<(), Response> {
        let s = &self.store;
        let mut q = lock(&self.queue);
        // drop entries nobody polled for a while (client gone)
        q.retain(|e| e.last_poll.elapsed().as_secs() < 60);
        if q.len() < 2 {
            return Ok(());
        }
        let cands: Vec<Candidate> = {
            let hub = lock(&self.hub);
            q.iter()
                .map(|e| Candidate {
                    rating: e.rating,
                    rtt_ms: hub.rtt(e.id).or(e.reported_rtt),
                    waited_secs: e.since.elapsed().as_secs(),
                    max_ping: e.max_ping,
                    ranked: e.ranked,
                    api: e.api,
                    engine: e.engine.clone(),
                })
                .collect()
        };
        let pairs = matchmaking::pairs(&cands);
        let mut remove = Vec::new();
        for (i, j) in pairs {
            let (a, b) = (&q[i], &q[j]);
            let est = matchmaking::estimate(cands[i].rtt_ms, cands[j].rtt_ms);
            let setup = json!({ "p1_char": a.char_id, "p2_char": b.char_id }).to_string();
            let match_id = db(s.new_match([a.id, b.id], a.ranked, &setup))?;
            let code = random_code();
            let mut m = Matchup::new(match_id, [a.id, b.id], a.ranked, Rules::default(), None);
            let high = matchmaking::high_ping(est, self.high_ping_ms());
            m.est_ping_ms = Some(est);
            m.high_ping = high;
            let views = [
                self.matchup_view(s, &m, a.id),
                self.matchup_view(s, &m, b.id),
            ];
            lock(&self.matchups).insert(match_id, m);
            let [va, vb] = views;
            let info = |side: u8,
                        me: &QueueEntry,
                        opp: &QueueEntry,
                        view: rugen_proto::MatchupView| MatchInfo {
                match_id,
                code: code.clone(),
                side,
                my_char: me.char_id.clone(),
                opponent: Self::profile(s, opp.id),
                opponent_char: opp.char_id.clone(),
                stage: String::new(),
                ranked: me.ranked,
                est_ping_ms: Some(est),
                ticket: None,
                matchup: Some(view),
            };
            let (ma, mb) = (info(1, a, b, va), info(2, b, a, vb));
            {
                let hub = lock(&self.hub);
                for (id, found) in [(a.id, &ma), (b.id, &mb)] {
                    let mut msg = serde_json::to_value(ServerMsg::Found {
                        found: found.clone(),
                    })
                    .unwrap_or(Value::Null);
                    extend_found(&mut msg["found"], est, high);
                    hub.push_json(id, &msg);
                }
            }
            let mut found = lock(&self.found);
            found.insert(a.id, (ma, high));
            found.insert(b.id, (mb, high));
            log::info!(
                "{} match {match_id}: {} vs {} (est {est} ms{}), matchup phase",
                if a.ranked { "ranked" } else { "quick" },
                a.id,
                b.id,
                if high { ", HIGH PING" } else { "" }
            );
            remove.extend([i, j]);
        }
        remove.sort_unstable();
        for i in remove.into_iter().rev() {
            q.remove(i);
        }
        Ok(())
    }

    // ---- results and replays

    fn result(&self, req: &Request, v: &Value) -> Res {
        let s = &self.store;
        let me = self.auth(s, req, v)?.id;
        let (Some(match_id), Some(winner)) = (
            v.get("match_id").and_then(Value::as_u64),
            v.get("winner").and_then(Value::as_u64),
        ) else {
            return Err(err(400, "match_id and winner required"));
        };
        const MAX_FRAMES: usize = 60 * 60 * 15;
        let mut inputs = match v.get("inputs").and_then(Value::as_str) {
            Some(h) if h.len() <= 8 * MAX_FRAMES => {
                rugen_proto::from_hex(h).ok_or_else(|| err(400, "inputs must be hex"))?
            }
            Some(_) => return Err(err(413, "inputs too long")),
            None => Vec::new(),
        };
        // run-length encoded inputs (clients of TURN-capable servers)
        if let Some(h) = v.get("inputs_rle").and_then(Value::as_str) {
            let rle = rugen_proto::from_hex(h)
                .filter(|b| b.len() <= 5 * MAX_FRAMES)
                .ok_or_else(|| err(400, "bad inputs_rle"))?;
            inputs = rugen_proto::evidence::decode_inputs(&rle, MAX_FRAMES)
                .ok_or_else(|| err(400, "bad inputs_rle"))?;
        }
        let checksums = match v.get("checksums").and_then(Value::as_str) {
            Some(h) => rugen_proto::from_hex(h)
                .filter(|b| b.len() <= 12 * (MAX_FRAMES / 60 + 1))
                .and_then(|b| rugen_proto::evidence::decode_checksums(&b))
                .ok_or_else(|| err(400, "bad checksums"))?,
            None => Vec::new(),
        };
        let data = ReportData {
            winner,
            frames: v.get("frames").and_then(Value::as_u64).unwrap_or(0) as u32,
            checksum: v.get("checksum").and_then(Value::as_u64),
            inputs,
            checksums,
            // additive: older clients never send it (a match ended early
            // simply never resolves for them, as before)
            ending: v
                .get("ending")
                .and_then(Value::as_str)
                .and_then(rugen_proto::Ending::parse),
        };
        let out = db(s.report(me, match_id, &data))?;
        if !out.accepted {
            return Err(err(404, "not your match"));
        }
        // a bracket shows the score (rounds won by P1, P2: additive)
        if let Some(r) = v
            .get("rounds")
            .and_then(|r| serde_json::from_value::<[u8; 2]>(r.clone()).ok())
        {
            for room in lock(&self.rooms).values_mut() {
                if let Some(t) = room.tournament.as_mut()
                    && t.bracket.as_ref().is_some_and(|b| {
                        b.rounds
                            .iter()
                            .flatten()
                            .any(|p| p.match_id == Some(match_id))
                    })
                {
                    t.scores.insert(match_id, r.map(|n| n.min(9)));
                }
            }
        }
        // this player is done with TURN: settle and revoke its credential
        if let Some(t) = &self.turn {
            let reported = v
                .get("turn")
                .map(|b| b["rx"].as_u64().unwrap_or(0) + b["tx"].as_u64().unwrap_or(0));
            if let Some(slot) =
                db(s.match_players(match_id))?.and_then(|p| p.iter().position(|&a| a == me))
            {
                t.finished(s, match_id, slot as u8, reported);
            }
        }
        if out.disputed {
            self.spawn_resim(match_id);
        }
        // both sides reported: nobody needs the relay session any more
        if db(s.match_resolved(match_id))? {
            self.close_match_session(match_id);
        }
        let rating = match out.delta {
            Some(_) => db(s.by_id(me))?.map(|a| a.rating),
            None => None,
        };
        let signed = match out.delta {
            Some(_) => self.result_ack(s, match_id, me)?.signed,
            None => None,
        };
        let (ending, fled) = Self::ending_fields(db(s.match_ending(match_id))?);
        ok(&ResultAck {
            accepted: true,
            rating,
            delta: out.delta,
            disputed: out.disputed,
            signed,
            ending,
            fled,
        })
    }

    /// A match's outcome for `me`, signed once settled (`GET /match/{id}/result`).
    fn result_ack(&self, s: &Store, match_id: u64, me: u64) -> Result<ResultAck, Response> {
        let (ranked, players, winner, delta, disputed) =
            db(s.match_result(match_id, me))?.ok_or_else(|| err(404, "not your match"))?;
        let Some(winner) = winner else {
            return Ok(ResultAck {
                accepted: true,
                rating: None,
                delta: None,
                disputed,
                signed: None,
                ending: None,
                fled: None,
            });
        };
        let (ending, fled) = Self::ending_fields(db(s.match_ending(match_id))?);
        let rating = if ranked {
            db(s.by_id(me))?.map(|a| a.rating)
        } else {
            None
        };
        let signed = self.truth.sign(
            rugen_proto::purpose::RESULT,
            &rugen_proto::ResultStatement {
                v: rugen_proto::TRUST_VERSION,
                match_id,
                ranked,
                account: me,
                players,
                winner,
                rating,
                delta: ranked.then_some(delta),
                season: db(s.season())?.number,
                issued_at: rugen_fair::trust::now(),
            },
        );
        Ok(ResultAck {
            accepted: true,
            rating,
            delta: Some(delta),
            disputed,
            signed,
            ending,
            fled,
        })
    }

    fn ending_fields(row: crate::store::EndingRow) -> (Option<String>, Option<u64>) {
        match row {
            Some((e, f)) => (Some(e), f),
            None => (None, None),
        }
    }

    /// Settle the claims "the other player fled / disconnected" that the
    /// relay confirms (every few seconds from the server's timer). A claim
    /// waits [`CLAIM_GRACE_SECS`] for the other player's own report (then
    /// agreement or a dispute decide), and is settled only when the
    /// relay saw the other slot leave first ([`left_first`]): a client's
    /// word alone never moves a rating.
    pub fn sweep_claims(&self) {
        let s = &self.store;
        let claims = match s.pending_claims() {
            Ok(c) => c,
            Err(e) => {
                log::warn!("claims: {e}");
                return;
            }
        };
        let t = crate::store::now();
        for c in claims {
            if t < c.at + CLAIM_GRACE_SECS {
                continue;
            }
            let running = lock(&self.matchups)
                .get(&c.match_id)
                .and_then(|m| m.started.clone());
            let Some(run) = running else { continue };
            let Some(seen) = self.relay.presence(run.session) else {
                continue;
            };
            let Some(me) = run.slots.iter().take(2).position(|&a| a == c.winner) else {
                continue;
            };
            let (Some(mine), Some(theirs)) = (seen.get(me), seen.get(1 - me)) else {
                continue;
            };
            if !left_first(mine, theirs, Instant::now()) {
                continue;
            }
            match s.settle_claim(&c) {
                Ok(Some(d)) => {
                    log::info!(
                        "match {}: the relay confirms the other player left ({}), {} wins ({:+})",
                        c.match_id,
                        c.ending.as_str(),
                        c.winner,
                        d[me]
                    );
                    self.close_match_session(c.match_id);
                }
                Ok(None) => {}
                Err(e) => log::warn!("match {}: claim not settled: {e}", c.match_id),
            }
        }
    }

    // ---- official server: identity, admin

    /// `GET /v1/identity?nonce=`: sign the caller's challenge.
    fn identity(&self, req: &Request) -> Res {
        let nonce = req.query.get("nonce").cloned().unwrap_or_default();
        if !(16..=128).contains(&nonce.len()) || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(err(400, "nonce: 16 to 128 hex digits"));
        }
        let st = rugen_proto::IdentityStatement {
            v: rugen_proto::TRUST_VERSION,
            nonce,
            name: self.cfg.name.clone(),
            official: self.truth.is_official(),
            issued_at: rugen_fair::trust::now(),
        };
        match self.truth.sign(rugen_proto::purpose::IDENTITY, &st) {
            Some(b) => ok(&b),
            None => Err(err(404, "this server does not sign")),
        }
    }

    /// Admin API (`RUGEN_ADMIN_TOKEN`): block / unblock / list fingerprints.
    /// `RUGEN_ADMIN_TOKEN` as `Authorization: Bearer`, the body's `token`
    /// or `?token=`.
    fn admin_auth(&self, req: &Request, v: &Value) -> Result<(), Response> {
        if self.truth.cfg.admin_token.is_none() {
            return Err(err(404, "admin api disabled (set RUGEN_ADMIN_TOKEN)"));
        }
        let token = req
            .bearer
            .clone()
            .or_else(|| v.get("token").and_then(Value::as_str).map(str::to_string))
            .or_else(|| req.query.get("token").cloned())
            .unwrap_or_default();
        if !self.truth.admin_ok(&token) {
            return Err(err(403, "bad admin token"));
        }
        Ok(())
    }

    fn admin(&self, req: &Request, v: &Value, op: &str) -> Res {
        self.admin_auth(req, v)?;
        match op {
            "backup" => return self.backup_now(),
            "link" => return self.admin_link(v),
            "tournament" => return self.admin_tournament(v),
            "season_end" => {
                let next = db(self.store.end_season_now())?;
                log::warn!("admin: season ended early, {} started", next.name);
                return ok(&next);
            }
            "backups" => {
                if self.backups.config().is_none() {
                    return Err(err(404, "backups are not configured (RUGEN_BACKUP_S3)"));
                }
                return self
                    .backups
                    .list()
                    .map(|l| Response::json(200, &l))
                    .map_err(|e| err(502, &e));
            }
            "backup_status" => {
                // shared replays live in the database: every backup holds them
                let mut st = serde_json::to_value(self.backups.status()).unwrap_or_default();
                if let (Some(o), Ok((count, bytes))) =
                    (st.as_object_mut(), self.store.shared_usage())
                {
                    o.insert(
                        "shared_replays".into(),
                        json!({ "count": count, "bytes": bytes }),
                    );
                }
                return Ok(Response::json(200, &st));
            }
            _ => {}
        }
        if op == "reset_password" {
            let username = str_field(v, "username", 64).unwrap_or_default();
            let (username, password) = self.reset_password(&username)?;
            return ok(&json!({ "username": username, "password": password }));
        }
        let fp = || -> Result<String, Response> {
            let fp = v
                .get("fingerprint")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            if is_fingerprint(&fp) {
                Ok(fp)
            } else {
                Err(err(400, "fingerprint: 64 hex digits"))
            }
        };
        let s = &self.store;
        let changed = match op {
            "block" => {
                let fp = fp()?;
                let reason =
                    str_field(v, "reason", 200).unwrap_or_else(|| "blocked by the operator".into());
                db(s.block(&fp, &reason, "admin"))?;
                log::warn!("admin: blocked {} ({reason})", rugen_fair::short(&fp));
                true
            }
            "unblock" => {
                let fp = fp()?;
                let was = db(s.unblock(&fp))?;
                log::warn!("admin: unblocked {}", rugen_fair::short(&fp));
                was
            }
            "blocklist" => false,
            _ => return Err(err(404, "no such admin action")),
        };
        if changed {
            self.refresh_verdicts(s);
        }
        let official = self.truth.official_feed();
        ok(&json!({
            "official": self.truth.is_official(),
            "key": self.truth.public_key().map(|k| k.hex()),
            "sequence": db(s.truth_seq())?,
            "blocked": db(s.blocklist())?,
            "official_feed": official.map(|f| json!({
                "sequence": f.sequence, "issued_at": f.issued_at, "blocked": f.blocked.len(),
            })),
        }))
    }

    /// `POST /v1/admin/tournament`: a bracket of 8 or 16 hosted by the
    /// server for the accounts given (seeded in that order, or by rating
    /// with `seed: "rating"`). Players enter the room code in the ONLINE
    /// lobby; the bracket calls each pair once both are in the room.
    fn admin_tournament(&self, v: &Value) -> Res {
        let s = &self.store;
        let size = v.get("size").and_then(Value::as_u64).unwrap_or(0);
        let size = tournament::SIZES
            .iter()
            .copied()
            .find(|z| u64::from(*z) == size)
            .ok_or_else(|| err(400, "size: 8 or 16"))?;
        let ids: Vec<u64> = v
            .get("entrants")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_u64).collect())
            .unwrap_or_default();
        if ids.len() < 2 || ids.len() > usize::from(size) {
            return Err(err(400, "entrants: 2 to size account ids"));
        }
        let mut seeds = Vec::with_capacity(ids.len());
        for &id in &ids {
            if seeds.iter().any(|x: &Seed| x.account == id) {
                return Err(err(400, "entrants: an account is listed twice"));
            }
            let a = db(s.by_id(id))?.ok_or_else(|| err(404, "no such account"))?;
            seeds.push(Seed {
                account: id,
                rating: a.rating,
            });
        }
        let bracket = match v.get("seed").and_then(Value::as_str) {
            Some("rating") => Bracket::draw(usize::from(size), &seeds),
            Some("order") | None => Bracket::draw_seeded(usize::from(size), seeds),
            Some(_) => return Err(err(400, "seed: \"order\" or \"rating\"")),
        };
        let name = str_field(v, "name", 64)
            .map(|n| clean_name(&n))
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "TOURNAMENT".into());
        let mut t = Tournament::new(size);
        t.entrants = bracket.seeds.iter().map(|x| x.account).collect();
        t.bracket = Some(bracket);
        let mut rooms = lock(&self.rooms);
        self.expire_rooms(&mut rooms);
        if rooms.len() >= MAX_ROOMS {
            return Err(err(409, "too many rooms"));
        }
        let mut code = random_code();
        while rooms.contains_key(&code) {
            code = random_code();
        }
        let mut room = Room {
            name,
            public: v.get("public").and_then(Value::as_bool).unwrap_or(true),
            password: None,
            rules: clean_rules(v.get("rules")),
            max_spectators: TOURNAMENT_SPECTATORS,
            members: Vec::new(),
            kicked: Vec::new(),
            created: Instant::now(),
            running: None,
            matchup: None,
            api: crate::compat::API,
            engine: None,
            tournament: Some(t),
            server_hosted: true,
        };
        log::warn!(
            "admin: tournament room {code} of {} ({} entrants) hosted by the server",
            size,
            ids.len()
        );
        self.tick_tournament(s, &code, &mut room)?;
        let view = self.public_room_view(s, &code, &room);
        rooms.insert(code.clone(), room);
        Ok(Response::json(
            200,
            &json!({ "code": code, "tournament": view["tournament"] }),
        ))
    }

    /// `POST /v1/admin/tournament/{code}/cancel`: the server-hosted room
    /// closes; its members are told.
    fn admin_cancel_tournament(&self, code: &str) -> Res {
        let s = &self.store;
        let code = code.trim().to_ascii_uppercase();
        let mut rooms = lock(&self.rooms);
        let r = rooms
            .get_mut(&code)
            .filter(|r| r.tournament.is_some())
            .ok_or_else(|| err(404, "no such tournament room"))?;
        if !r.server_hosted {
            return Err(err(409, "a player hosts this room"));
        }
        let members: Vec<u64> = r.members.iter().map(|m| m.account).collect();
        for &m in &members {
            self.fail_matchup_of(s, r, m, "the tournament was cancelled");
        }
        if let Some(run) = r.running.take() {
            self.relay.close(run.session);
        }
        rooms.remove(&code);
        let hub = lock(&self.hub);
        for a in &members {
            hub.push(*a, &ServerMsg::Kicked { code: code.clone() });
        }
        log::warn!(
            "admin: tournament room {code} cancelled ({} members)",
            members.len()
        );
        ok(&json!({ "code": code, "cancelled": true }))
    }

    /// What anyone may see of a tournament room (`GET /room/{code}` with no
    /// key): the room, its bracket and who is here, nothing of a player's
    /// own (ticket, matchup, opponent, ping).
    fn public_room_view(&self, store: &Store, code: &str, r: &Room) -> Value {
        let mut v = serde_json::to_value(self.room_view(store, code, r, 0)).unwrap_or(Value::Null);
        if let Some(o) = v.as_object_mut() {
            for k in ["side", "opponent", "est_ping_ms", "ticket", "matchup"] {
                o.remove(k);
            }
            o.insert("server_hosted".into(), r.server_hosted.into());
        }
        if let Some(ms) = v.get_mut("members").and_then(Value::as_array_mut) {
            for m in ms.iter_mut().filter_map(Value::as_object_mut) {
                m.remove("rtt_ms");
            }
        }
        v
    }

    /// `POST /v1/admin/backup`: start one now (202 + job id).
    fn backup_now(&self) -> Res {
        match self.backups.start(Trigger::Manual, self.snapshotter()) {
            Ok(job) => {
                log::info!("admin: backup {job} started");
                Ok(Response::json(
                    202,
                    &json!({ "job": job, "state": "running" }),
                ))
            }
            Err(StartError::Running(job)) => Err(Response::json(
                409,
                &json!({ "error": "a backup is running", "job": job }),
            )),
            Err(StartError::Cooldown(secs)) => Err(Response::json(
                429,
                &json!({ "error": "one manual backup per 10 minutes", "retry_after": secs }),
            )),
            Err(StartError::Off) => Err(match &self.backups.setting {
                BackupSetting::Invalid(e) => err(503, e),
                _ => err(404, "backups are not configured (RUGEN_BACKUP_S3)"),
            }),
        }
    }

    /// Re-judge every matchup still being decided (the blocklist or the
    /// official feed changed) and push the new views.
    pub fn refresh_verdicts(&self, s: &Store) {
        let mut ms = lock(&self.matchups);
        for m in ms.values_mut() {
            if m.failed.is_none() && m.started.is_none() && m.verdict.is_some() {
                let before = m.verdict.clone();
                m.recompute_verdict(s, &self.cfg.thresholds, &self.truth);
                if m.verdict != before {
                    self.push_matchup(s, m);
                }
            }
        }
    }

    /// Pull the official feed now (community servers), then re-judge.
    pub fn pull_official(&self) -> Result<rugen_proto::TruthFeed, String> {
        let f = self.truth.pull_official()?;
        let s = &self.store;
        self.refresh_verdicts(s);
        Ok(f)
    }

    /// Automatic blocklist rules after a flagged lie / desync / analysis.
    fn auto_block(&self, s: &Store, fp: &str, cause: AutoCause) -> Result<(), Response> {
        let rules = &self.truth.cfg.auto;
        let reason = match cause {
            AutoCause::Liar if rules.liars > 0 => {
                let n = db(s.liars_for(fp))?;
                (n >= rules.liars).then(|| format!("auto: {n} players declared a false profile"))
            }
            AutoCause::Desync if rules.desyncs > 0 => {
                let n = db(s.desyncs_for(fp))?;
                (n >= rules.desyncs).then(|| format!("auto: desynced in {n} matches"))
            }
            AutoCause::Analysis(detail) if rules.analysis => Some(format!("auto: {detail}")),
            _ => None,
        };
        if let Some(r) = reason {
            db(s.auto_block(fp, &r))?;
        }
        Ok(())
    }

    fn replay(&self, id: &str) -> Res {
        let id = id.parse::<u64>().map_err(|_| err(400, "bad id"))?;
        let s = &self.store;
        let (players, setup_text, winner, created, inputs) =
            db(s.replay(id))?.ok_or_else(|| err(404, "no replay"))?;
        let setup: Value = serde_json::from_str(&setup_text).unwrap_or(Value::Null);
        let field = |k: &str| {
            setup
                .get(k)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        ok(&Replay {
            match_id: id,
            created,
            p1: Self::profile(s, players[0]),
            p2: Self::profile(s, players[1]),
            p1_char: field("p1_char"),
            p2_char: field("p2_char"),
            stage: field("stage"),
            winner,
            inputs: to_hex(&inputs),
            files_available: {
                let fps = setup_fingerprints(&setup_text);
                fps.len() == 3 && fps.iter().all(|f| self.packages.has(f))
            },
            fingerprints: setup_fingerprints(&setup_text),
        })
    }
}

// ---- matchup phase, packages, desync, re-simulation

/// The game version a match was played with (its setup's `engine`,
/// recorded since 0.6.2 servers; older setups have none).
fn setup_engine(setup: &str) -> Option<String> {
    serde_json::from_str::<Value>(setup)
        .ok()?
        .get("engine")?
        .as_str()
        .map(str::to_string)
}

/// What may put a fingerprint on the blocklist automatically.
enum AutoCause<'a> {
    Liar,
    Desync,
    Analysis(&'a str),
}

/// The profile as declared by a client, for a "did it lie" comparison.
fn comparable(p: &rugen_proto::FairnessProfile) -> rugen_proto::FairnessProfile {
    let mut c = p.comparable();
    c.reasons.clear();
    c
}

impl Api {
    fn stored(&self, store: &Store, fp: &str) -> bool {
        self.packages.has(fp) && store.package(fp).ok().flatten().is_some()
    }

    fn matchup_view(&self, store: &Store, m: &Matchup, me: u64) -> rugen_proto::MatchupView {
        let ticket = m.started.as_ref().and_then(|run| {
            let slot = run.slots.iter().position(|&a| a == me)?;
            Some(ticket(run, slot, &self.cfg.udp_public))
        });
        m.view(me, store, &|fp| self.stored(store, fp), ticket)
    }

    /// [`Self::matchup_view`] as JSON with the additive fields
    /// ([`Matchup::extend_view`]).
    fn matchup_json(&self, store: &Store, m: &Matchup, me: u64) -> Value {
        let mut v = serde_json::to_value(self.matchup_view(store, m, me)).unwrap_or(Value::Null);
        m.extend_view(&mut v);
        v
    }

    /// Push every player / spectator its view of the matchup.
    fn push_matchup(&self, store: &Store, m: &Matchup) {
        let mut who: Vec<u64> = m.players.to_vec();
        who.extend(&m.spectators);
        let views: Vec<(u64, Value)> = who
            .into_iter()
            .map(|a| {
                let mut v = serde_json::to_value(ServerMsg::Matchup {
                    matchup: self.matchup_view(store, m, a),
                })
                .unwrap_or(Value::Null);
                m.extend_view(&mut v["matchup"]);
                (a, v)
            })
            .collect();
        let hub = lock(&self.hub);
        for (a, msg) in views {
            hub.push_json(a, &msg);
        }
    }

    fn fail_matchup_of(&self, store: &Store, r: &Room, account: u64, why: &str) {
        let Some(id) = r.matchup else { return };
        let mut ms = lock(&self.matchups);
        if let Some(m) = ms.get_mut(&id)
            && m.side_of(account).is_some()
            && m.started.is_none()
        {
            m.fail(why.into());
            self.push_matchup(store, m);
        }
    }

    fn expire_matchups(ms: &mut HashMap<u64, Matchup>) {
        for m in ms.values_mut() {
            if m.started.is_none() && m.failed.is_none() && m.touched.elapsed() > MATCHUP_IDLE {
                m.fail("timed out".into());
            }
        }
        ms.retain(|_, m| m.created.elapsed() < MATCHUP_KEEP);
    }

    fn matchup_id(id: &str) -> Result<u64, Response> {
        id.parse::<u64>().map_err(|_| err(400, "bad matchup id"))
    }

    fn matchup_get(&self, req: &Request, v: &Value, id: &str) -> Res {
        let id = Self::matchup_id(id)?;
        let s = &self.store;
        let me = self.auth(s, req, v)?;
        let mut ms = lock(&self.matchups);
        Self::expire_matchups(&mut ms);
        let m = ms.get_mut(&id).ok_or_else(|| err(404, "no such matchup"))?;
        if !m.involves(me.id) {
            return Err(err(403, "not your matchup"));
        }
        if m.side_of(me.id).is_some() {
            m.touched = Instant::now();
        }
        // a player that never gets an offline fighter (older clients poll)
        if m.started.is_none() && m.failed.is_none() {
            m.check_offline_wait(&|fp| self.stored(s, fp));
            if m.failed.is_some() {
                self.push_matchup(s, m);
            }
        }
        Ok(Response::json(200, &self.matchup_json(s, m, me.id)))
    }

    fn matchup_op(&self, req: &Request, v: &Value, id: &str, op: &str) -> Res {
        let id = Self::matchup_id(id)?;
        let s = &self.store;
        let me = self.auth(s, req, v)?;
        let mut rooms = lock(&self.rooms);
        let mut ms = lock(&self.matchups);
        Self::expire_matchups(&mut ms);
        let m = ms.get_mut(&id).ok_or_else(|| err(404, "no such matchup"))?;
        let side = m
            .side_of(me.id)
            .ok_or_else(|| err(403, "not a player of this matchup"))?;
        if let Some(f) = &m.failed {
            return Err(err(409, &format!("matchup failed: {f}")));
        }
        if m.started.is_some() {
            return Ok(Response::json(200, &self.matchup_json(s, m, me.id)));
        }
        m.touched = Instant::now();
        match op {
            "pick" => {
                let decl = |k: &str, kind: &str| -> Result<Option<FighterDecl>, Response> {
                    match v.get(k) {
                        None | Some(Value::Null) => Ok(None),
                        Some(x) => {
                            let d: FighterDecl = serde_json::from_value(x.clone())
                                .map_err(|e| err(400, &format!("{k}: {e}")))?;
                            check_decl(&d, kind, self.cfg.pkg.max_pkg)
                                .map(Some)
                                .map_err(|e| err(400, &e))
                        }
                    }
                };
                let fighter = decl("fighter", "char")?;
                let stage = if side == 0 {
                    decl("stage", "stage")?
                } else {
                    None
                };
                if fighter.is_none() && !(m.mirror && side == 1) {
                    return Err(err(400, "fighter required"));
                }
                // a known fingerprint: the declaration must match the server's analysis
                for d in fighter.iter() {
                    if let Some(row) = db(s.package(&d.fingerprint))?
                        && let (Some(server), Some(claimed)) = (&row.profile, &d.profile)
                        && server.version == claimed.version
                        && comparable(server) != comparable(claimed)
                    {
                        let why =
                            format!("P{}'s fighter profile does not match its files", side + 1);
                        db(s.flag(me.id, Some(id), &why, Some(&d.fingerprint)))?;
                        self.auto_block(s, &d.fingerprint, AutoCause::Liar)?;
                        m.fail(why);
                        self.push_matchup(s, m);
                        return Ok(Response::json(200, &self.matchup_json(s, m, me.id)));
                    }
                }
                if let Some(f) = fighter {
                    m.picks[side] = Some(f);
                }
                // `uploads: false`: this player sends nothing (no online
                // consent); absent (older clients) = it uploads
                m.no_upload[side] = v.get("uploads").and_then(Value::as_bool) == Some(false);
                if let Some(st) = stage {
                    m.stage = Some(st);
                }
                let fps: Vec<String> = m.declared().into_iter().map(str::to_string).collect();
                let refs: Vec<&str> = fps.iter().map(String::as_str).collect();
                db(s.touch_packages(&refs))?;
                m.reset_progress();
                m.recompute_verdict(s, &self.cfg.thresholds, &self.truth);
            }
            "accept" => {
                let unbalanced = v
                    .get("unbalanced")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                m.accept(side, unbalanced).map_err(|e| err(409, &e))?;
            }
            "ready" => {
                if m.phase() != "sync" {
                    return Err(err(409, "confirm the matchup first"));
                }
                let r: ReadyReport = v
                    .get("ready")
                    .cloned()
                    .and_then(|x| serde_json::from_value(x).ok())
                    .ok_or_else(|| err(400, "ready report required"))?;
                m.ready[side] = Some(r);
                if let Err(e) = m.ready_agreed() {
                    m.fail(e);
                }
            }
            "leave" => match v.get("reason").and_then(Value::as_str) {
                // it lacks a fighter whose owner sends nothing
                Some("missing") => {
                    let fp = v.get("fingerprint").and_then(Value::as_str).unwrap_or("");
                    let offline = m.offline(&|f| self.stored(s, f));
                    match offline.iter().find(|f| *f == fp) {
                        Some(fp) => m.fail(m.missing_offline(side, fp)),
                        None => m.fail(format!("P{} left", side + 1)),
                    }
                }
                _ => m.fail(format!("P{} left", side + 1)),
            },
            _ => return Err(err(404, "no such matchup action")),
        }
        self.try_start(s, &mut rooms, m)?;
        self.push_matchup(s, m);
        let view = self.matchup_json(s, m, me.id);
        if let Some(code) = m.room.clone()
            && let Some(r) = rooms.get(&code)
        {
            drop(ms);
            self.broadcast(s, &code, r);
        }
        Ok(Response::json(200, &view))
    }

    /// Start the relay session once the matchup is confirmed, every package
    /// is on the server (verified) and both clients are ready with the same
    /// files, rules and game version.
    fn try_start(
        &self,
        store: &Store,
        rooms: &mut HashMap<String, Room>,
        m: &mut Matchup,
    ) -> Result<bool, Response> {
        // fetch TURN credentials while the clients sync files
        if m.phase() == "sync"
            && let Some(t) = &self.turn
        {
            t.prepare(store, m.id, m.players, m.ranked, &m.rules);
        }
        if m.phase() != "sync" {
            return Ok(false);
        }
        // every file on the server, or both players hold every file
        // already (the fighter's owner plays without online consent: a
        // client reports ready only once it has every file)
        let missing = m.missing(&|fp| self.stored(store, fp));
        if !missing.is_empty() && (m.ready.iter().any(Option::is_none) || !m.offline_only(&missing))
        {
            m.check_offline_wait(&|fp| self.stored(store, fp));
            return Ok(false);
        }
        match m.ready_agreed() {
            Ok(true) => {}
            Ok(false) => return Ok(false),
            Err(e) => {
                m.fail(e);
                return Ok(false);
            }
        }
        let Some([p1, p2, st]) = m.fingerprints() else {
            return Ok(false);
        };
        let code = m.room.clone();
        let room = code.as_ref().and_then(|c| rooms.get_mut(c));
        let mut slots = m.players.to_vec();
        if let Some(r) = &room
            && r.tournament.is_none()
        {
            m.spectators = r
                .members
                .iter()
                .filter(|x| x.role == 2)
                .map(|x| x.account)
                .collect();
            slots.extend(&m.spectators);
        }
        let name = |i: usize| m.fighter(i).map(|d| d.name.clone()).unwrap_or_default();
        let setup = json!({
            "p1_char": name(0), "p2_char": name(1),
            "stage": m.stage.as_ref().map(|d| d.name.clone()).unwrap_or_default(),
            "p1_fp": p1, "p2_fp": p2, "stage_fp": st,
            "rules": m.rules,
            "verdict": m.verdict.as_ref().map(|v| v.kind),
            // the game version both clients run (equal, see ready_agreed):
            // only a server simulating that version may re-simulate it
            "engine": m.ready[0].as_ref().and_then(|r| crate::compat::engine_version(&r.engine)),
            // each player's machine summary for replays: version, OS and
            // architecture only (no graphics details, nothing personal)
            "machines": Self::machines(m),
        })
        .to_string();
        db(store.set_setup(m.id, &setup))?;
        db(store.touch_packages(&[&p1, &p2, &st]))?;
        let (session, tokens) = self
            .relay
            .create(&slots)
            .ok_or_else(|| err(503, "relay full"))?;
        let turn = self
            .turn
            .as_ref()
            .map(|t| t.take(store, m.id, session))
            .unwrap_or_default();
        // the input log viewers watch (players feed it on the relay)
        {
            let content = |d: Option<&FighterDecl>| rugen_proto::stream::StreamContent {
                fingerprint: d.map(|d| d.fingerprint.clone()).unwrap_or_default(),
                name: d.map(|d| d.name.clone()).unwrap_or_default(),
                size: d
                    .and_then(|d| store.package(&d.fingerprint).ok().flatten())
                    .map_or_else(|| d.map_or(0, |d| d.size), |p| p.size),
            };
            let player = |id: u64| {
                let p = Self::profile(store, id);
                rugen_proto::stream::StreamPlayer {
                    id,
                    name: p.name,
                    verified: p.verified,
                }
            };
            let header = rugen_proto::stream::MatchHeader {
                v: rugen_proto::stream::STREAM_VERSION,
                match_id: m.id,
                engine: m
                    .ready
                    .iter()
                    .flatten()
                    .next()
                    .map(|r| r.engine.clone())
                    .unwrap_or_default(),
                seed: rugen_proto::stream::online_seed(m.id),
                rules: m.rules.clone(),
                fighters: [content(m.fighter(0)), content(m.fighter(1))],
                stage: content(m.stage.as_ref()),
                players: [player(m.players[0]), player(m.players[1])],
                ranked: m.ranked,
                created: crate::store::now(),
                machines: Self::machines(m),
            };
            let (public, members) = match &room {
                Some(r) => (r.public, r.members.iter().map(|x| x.account).collect()),
                None => (true, m.players.to_vec()),
            };
            self.live
                .start(session, header, public, code.clone(), members);
        }
        let run = Running {
            match_id: m.id,
            session,
            slots,
            tokens,
            turn,
        };
        if let Some(r) = room {
            r.running = Some(run.clone());
            r.matchup = None;
        }
        m.started = Some(run);
        log::info!(
            "match {} started on relay session {session:08x}: {} vs {}",
            m.id,
            rugen_fair::short(&p1),
            rugen_fair::short(&p2)
        );
        Ok(true)
    }

    // ---- packages

    fn fp_arg(fp: &str) -> Result<String, Response> {
        let fp = fp.to_ascii_lowercase();
        if is_fingerprint(&fp) {
            Ok(fp)
        } else {
            Err(err(400, "bad fingerprint"))
        }
    }

    fn pkg_status(&self, req: &Request, v: &Value, fp: &str) -> Res {
        let fp = Self::fp_arg(fp)?;
        let s = &self.store;
        let me = self.auth(s, req, v)?;
        let row = db(s.package(&fp))?;
        let complete = row.is_some() && self.packages.has(&fp);
        ok(&PackageStatus {
            fingerprint: fp.clone(),
            complete,
            size: row.map_or(0, |r| r.size),
            offset: if complete {
                0
            } else {
                self.packages.partial_len(&fp, me.id)
            },
        })
    }

    fn pkg_upload(&self, req: &Request, fp: &str) -> Res {
        let fp = Self::fp_arg(fp)?;
        let me = self.me(req, &Value::Null)?;
        let q = |k: &str| req.query.get(k).and_then(|x| x.parse::<u64>().ok());
        let (Some(offset), Some(total)) = (q("offset"), q("total")) else {
            return Err(err(400, "offset and total required"));
        };
        if req.body.len() as u64 > MAX_CHUNK {
            return Err(err(413, "chunk too large"));
        }
        if let Err(why) = crate::compat::upload_consent(
            req.query.get("consent").map(String::as_str),
            req.engine.as_deref(),
        ) {
            return Err(err(403, why));
        }
        if total > self.cfg.pkg.max_pkg {
            return Err(err(
                413,
                &format!("package larger than {} MB", self.cfg.pkg.max_pkg >> 20),
            ));
        }
        // only what this account brings to a live matchup
        {
            let mut ms = lock(&self.matchups);
            Self::expire_matchups(&mut ms);
            let declared = ms.values().any(|m| {
                m.failed.is_none()
                    && m.started.is_none()
                    && m.side_of(me.id)
                        .is_some_and(|side| m.declarers(&fp).contains(&side))
            });
            if !declared {
                return Err(err(403, "upload only what you picked for a matchup"));
            }
        }
        if self.packages.has(&fp) && db(self.store.package(&fp))?.is_some() {
            self.packages.drop_partial(&fp, me.id);
            return self.pkg_status(req, &json!({ "key": req.query.get("key") }), &fp);
        }
        {
            let mut b = lock(&self.upload_budget);
            let e = b.entry(me.id).or_insert((Instant::now(), 0));
            if e.0.elapsed() > Duration::from_secs(3600) {
                *e = (Instant::now(), 0);
            }
            if e.1 + req.body.len() as u64 > self.cfg.pkg.account_rate {
                return Err(err(429, "upload limit reached, try again later"));
            }
            e.1 += req.body.len() as u64;
        }
        let len = match self.packages.append(&fp, me.id, offset, total, &req.body) {
            Ok(n) => n,
            Err(UploadError::Offset(cur)) => {
                return Err(Response::json(
                    409,
                    &json!({ "error": "resume from offset", "offset": cur }),
                ));
            }
            Err(UploadError::TooLarge) => return Err(err(413, "package too large")),
            Err(UploadError::Io(e)) => {
                log::error!("packages: {e}");
                return Err(err(500, "storage error"));
            }
        };
        if len < total {
            return ok(&PackageStatus {
                fingerprint: fp,
                complete: false,
                size: 0,
                offset: len,
            });
        }
        // complete: verify outside the locks (open + hash + analysis)
        let verified = self.packages.finalize(&fp, me.id, req.api);
        self.after_upload(&fp, me.id, verified)?;
        let mut st = PackageStatus {
            fingerprint: fp.clone(),
            ..Default::default()
        };
        if let Some(row) = db(self.store.package(&fp))? {
            st.complete = true;
            st.size = row.size;
        }
        ok(&st)
    }

    /// Store a verified package, catch lying clients, move matchups on.
    fn after_upload(&self, fp: &str, uploader: u64, verified: Verified) -> Result<(), Response> {
        let s = &self.store;
        let mut rooms = lock(&self.rooms);
        let mut ms = lock(&self.matchups);
        let failure = match &verified {
            Verified::Stored(row) => {
                db(s.put_package(row))?;
                // the server's own analysis finds a block-level cheat
                if let Some(f) = row.profile.as_ref().and_then(|p| {
                    p.flags
                        .iter()
                        .find(|f| f.severity == rugen_proto::Severity::Block)
                }) {
                    let detail = format!("{}: {}", f.code, f.detail);
                    self.auto_block(s, fp, AutoCause::Analysis(&detail))?;
                }
                log::info!(
                    "package {} stored ({} KB, {})",
                    rugen_fair::short(fp),
                    row.size >> 10,
                    row.name
                );
                None
            }
            Verified::Mismatch { actual } => Some(format!(
                "uploaded files are {} instead of the declared {}",
                rugen_fair::short(actual),
                rugen_fair::short(fp)
            )),
            Verified::Invalid(e) => Some(format!("invalid package: {e}")),
        };
        let row = db(s.package(fp))?;
        let mut touched = Vec::new();
        for m in ms.values_mut() {
            if m.failed.is_some() || m.started.is_some() || !m.declared().contains(&fp) {
                continue;
            }
            if let Some(why) = &failure {
                if m.side_of(uploader)
                    .is_some_and(|side| m.declarers(fp).contains(&side))
                {
                    db(s.flag(uploader, Some(m.id), why, None))?;
                    m.fail(why.clone());
                    touched.push(m.id);
                }
                continue;
            }
            // compare what each declarer claimed with what the files say
            let server = row.as_ref().and_then(|r| r.profile.clone());
            for side in m.declarers(fp) {
                let claimed = m.picks[side]
                    .as_ref()
                    .filter(|d| d.fingerprint == fp)
                    .and_then(|d| d.profile.clone());
                if let (Some(sp), Some(cp)) = (&server, &claimed)
                    && sp.version == cp.version
                    && comparable(sp) != comparable(cp)
                {
                    let why = format!("P{}'s fighter profile does not match its files", side + 1);
                    db(s.flag(m.players[side], Some(m.id), &why, Some(fp)))?;
                    self.auto_block(s, fp, AutoCause::Liar)?;
                    m.fail(why);
                }
            }
            if m.failed.is_none() {
                m.recompute_verdict(s, &self.cfg.thresholds, &self.truth);
                self.try_start(s, &mut rooms, m)?;
            }
            touched.push(m.id);
        }
        for id in touched {
            if let Some(m) = ms.get(&id) {
                self.push_matchup(s, m);
            }
        }
        drop(rooms);
        // still under the matchups lock (see `sweep_packages`)
        let _ = self.packages.sweep(s);
        drop(ms);
        match verified {
            Verified::Stored(_) => Ok(()),
            Verified::Mismatch { .. } => Err(err(422, "the files do not match their fingerprint")),
            Verified::Invalid(e) => Err(err(400, &format!("invalid package: {e}"))),
        }
    }

    /// Who may download package `fp`: players and spectators of a matchup
    /// declaring it, viewers of a live match (who opened its stream), and
    /// anyone for the files of a shared replay.
    fn may_download(&self, s: &Store, fp: &str, me: u64) -> Result<(), Response> {
        let ms = lock(&self.matchups);
        if !ms
            .values()
            .any(|m| m.involves(me) && m.declared().contains(&fp))
            && !self.live.watches_content(fp, me)
            && !s.shared_has(fp).unwrap_or(false)
        {
            return Err(err(403, "not part of your matchup"));
        }
        Ok(())
    }

    /// `GET /pkg/{fp}/url`: a presigned bucket URL for the package
    /// ([`crate::pkg_r2`]), or `url: ""` (download it from `/data`).
    fn pkg_url(&self, req: &Request, v: &Value, fp: &str) -> Res {
        let fp = Self::fp_arg(fp)?;
        let s = &self.store;
        let me = self.auth(s, req, v)?;
        self.may_download(s, &fp, me.id)?;
        if !self.stored(s, &fp) {
            return Err(err(404, "not on the server (yet)"));
        }
        if self.packages.is_legacy(&fp) != crate::compat::is_legacy(req.api) {
            return Err(err(409, &crate::compat::package_refusal(req.api)));
        }
        let path = self.packages.path(&fp);
        let found = self.packages.r2.as_ref().and_then(|r| r.url(&fp, &path));
        db(s.touch_packages(&[&fp]))?;
        let out = match found {
            Some((url, sha256, size)) => rugen_proto::PackageUrl {
                fingerprint: fp,
                url,
                sha256,
                size,
                expires_secs: crate::pkg_r2::URL_SECS,
            },
            None => rugen_proto::PackageUrl {
                fingerprint: fp,
                ..Default::default()
            },
        };
        ok(&out)
    }

    fn pkg_data(&self, req: &Request, v: &Value, fp: &str) -> Res {
        let fp = Self::fp_arg(fp)?;
        let s = &self.store;
        let me = self.auth(s, req, v)?;
        self.may_download(s, &fp, me.id)?;
        if !self.stored(s, &fp) {
            return Err(err(404, "not on the server (yet)"));
        }
        // never hand a package to a client that cannot read it
        if self.packages.is_legacy(&fp) != crate::compat::is_legacy(req.api) {
            return Err(err(409, &crate::compat::package_refusal(req.api)));
        }
        let q = |k: &str| req.query.get(k).and_then(|x| x.parse::<u64>().ok());
        let offset = q("offset").unwrap_or(0);
        let len = q("len").unwrap_or(MAX_CHUNK).min(MAX_CHUNK);
        db(s.touch_packages(&[&fp]))?;
        let bytes = self.packages.read(&fp, offset, len).map_err(|e| {
            log::error!("packages: {e}");
            err(500, "storage error")
        })?;
        Ok(Response::bytes(bytes))
    }

    fn desync(&self, req: &Request, v: &Value, id: &str) -> Res {
        let id = id.parse::<u64>().map_err(|_| err(400, "bad id"))?;
        let s = &self.store;
        let me = self.auth(s, req, v)?;
        let frame = v.get("frame").and_then(Value::as_u64).unwrap_or(0) as u32;
        if !db(s.report_desync(me.id, id, frame))? {
            return Err(err(404, "not your match"));
        }
        if let Some((setup, ..)) = db(s.match_evidence(id))? {
            for fp in setup_fingerprints(&setup).iter().take(2) {
                self.auto_block(s, fp, AutoCause::Desync)?;
            }
        }
        self.spawn_resim(id);
        ok(&json!({ "recorded": true }))
    }

    /// Re-simulate a disputed match in the background when the server can
    /// (`--features resim` + `RUGEN_RESIM_DATA`), settling it with the
    /// simulated winner.
    fn spawn_resim(&self, match_id: u64) {
        if let Some(w) = &self.resim
            && !w.submit(match_id)
        {
            log::warn!("match {match_id}: re-simulation queue full, left disputed");
        }
    }

    /// Re-simulate one disputed match (on the re-simulation thread).
    fn resim_match(&self, match_id: u64) {
        let Some(cfg) = self.cfg.resim.clone() else {
            return;
        };
        let evidence = self.store.match_evidence(match_id).ok().flatten();
        let Some((setup, _ranked, players, reports)) = evidence else {
            return;
        };
        if reports.len() < 2 || !self.store.is_disputed(match_id).unwrap_or(false) {
            return;
        }
        let Some((_, longest)) = reports.iter().max_by_key(|(_, r)| r.inputs.len()) else {
            return;
        };
        // another engine version may simulate the match differently:
        // its result stays as the reports leave it (an ordinary
        // dispute), nobody is judged by a simulation they did not run
        let engine = setup_engine(&setup);
        if !crate::compat::can_resimulate(engine.as_deref()) {
            let note = format!(
                "unverified (version): played on rugen {}, this server simulates rugen {}",
                engine.as_deref().unwrap_or("?"),
                crate::compat::SIM_ENGINE.unwrap_or("?")
            );
            log::info!("match {match_id}: {note}");
            if let Err(e) = self.store.resolve_dispute(match_id, None, &note) {
                log::error!("match {match_id}: {e}");
            }
            return;
        }
        let note;
        let winner = match crate::resim::replay(
            &self.packages,
            &cfg,
            match_id,
            &setup,
            &longest.inputs,
            None,
        ) {
            Ok(o) => {
                // which report's checksum the simulation reproduces
                let honest: Vec<u64> = reports
                    .iter()
                    .filter(|(_, r)| {
                        r.checksum.is_some_and(|c| {
                            crate::resim::replay(
                                &self.packages,
                                &cfg,
                                match_id,
                                &setup,
                                &longest.inputs,
                                Some(r.frames),
                            )
                            .is_ok_and(|x| x.checksum == c)
                        })
                    })
                    .map(|(who, _)| *who)
                    .collect();
                note = format!(
                    "resim: {} frames, winner {:?}, matching reports {honest:?}",
                    o.frames, o.winner
                );
                o.winner.map(|w| players[w])
            }
            Err(e) => {
                note = format!("resim failed: {e}");
                None
            }
        };
        log::info!("match {match_id}: {note}");
        if let Err(e) = self.store.resolve_dispute(match_id, winner, &note) {
            log::error!("match {match_id}: {e}");
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn rooms_keep_a_known_fighter_size() {
        let size = |v: Value| clean_rules(Some(&v)).fighter_size;
        assert_eq!(size(json!({"fighter_size": "chibi"})), "chibi");
        assert_eq!(size(json!({"fighter_size": " None "})), "none");
        // API 5 clients from before the option send none: normal
        assert_eq!(size(json!({"rounds": 3})), "normal");
        assert_eq!(size(json!({"fighter_size": "giant"})), "normal");
        assert_eq!(clean_rules(None).fighter_size, "normal");
    }

    #[test]
    fn rooms_keep_a_known_life() {
        let life = |v: Value| clean_rules(Some(&v)).life;
        assert_eq!(life(json!({"life": 3000})), 3000);
        assert_eq!(life(json!({"life": 4321})), 4500);
        assert_eq!(life(json!({"life": 60000})), 10000);
        assert_eq!(life(json!({"life": 0})), 0);
        // clients from before the setting send none: 5000, as they play it
        assert_eq!(life(json!({"rounds": 3})), 5000);
        assert_eq!(clean_rules(None).life, 5000);
    }
    use crate::testkit::{declare, declare_legacy, tiny_char, tiny_stage, tmp};
    use rugen_fair::Kind;

    thread_local! {
        /// The API test requests announce (each test runs on its own thread).
        static CLIENT_API: std::cell::Cell<u32> = const { std::cell::Cell::new(crate::compat::API) };
    }

    thread_local! {
        /// The game version test requests announce (`None`: no `User-Agent`).
        static CLIENT_ENGINE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
    }

    /// Requests of the rest of this test come from rugen `v` (`None`: unknown).
    pub fn client_engine(v: Option<&str>) {
        CLIENT_ENGINE.with(|c| *c.borrow_mut() = v.map(str::to_string));
    }

    /// Requests of the rest of this test come from clients of `api`.
    pub fn client_api(api: u32) {
        CLIENT_API.with(|c| c.set(api));
    }

    pub fn req(method: &str, path: &str, body: Value) -> Request {
        raw(method, path, serde_json::to_vec(&body).unwrap())
    }

    fn raw(method: &str, path: &str, body: Vec<u8>) -> Request {
        let (path, query) = match path.split_once('?') {
            Some((p, q)) => (
                p.to_string(),
                q.split('&')
                    .filter_map(|kv| kv.split_once('='))
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
            None => (path.to_string(), HashMap::new()),
        };
        Request {
            method: method.into(),
            path,
            query,
            body,
            ip: None,
            api: CLIENT_API.with(|c| c.get()),
            engine: CLIENT_ENGINE.with(|c| c.borrow().clone()),
            bearer: None,
        }
    }

    fn json_of(r: Response) -> Value {
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        serde_json::from_slice(&r.body).unwrap()
    }

    fn api() -> Arc<Api> {
        api_with(PkgConfig::default())
    }

    fn api_with(pkg: PkgConfig) -> Arc<Api> {
        Api::new(
            Store::open(None).unwrap(),
            ApiConfig {
                name: "test".into(),
                motd: "hello".into(),
                udp_public: Some("relay.example.com:7001".into()),
                pkg,
                ..Default::default()
            },
            Arc::new(Relay::default()),
        )
    }

    fn register(api: &Api) -> (u64, String) {
        let a = json_of(api.handle(req("POST", "/register", Value::Null)));
        (
            a["id"].as_u64().unwrap(),
            a["key"].as_str().unwrap().to_string(),
        )
    }

    /// Content for a matchup: two distinct fair fighters and a stage.
    pub(crate) struct Kit {
        a: (FighterDecl, Vec<u8>),
        b: (FighterDecl, Vec<u8>),
        stage: (FighterDecl, Vec<u8>),
        root: std::path::PathBuf,
    }

    impl Kit {
        pub(crate) fn new() -> Self {
            let root = tmp("kit");
            let a = declare(&tiny_char(&root.join("a"), "Alpha", ""), Kind::Char);
            let b = declare(
                &tiny_char(&root.join("b"), "Beta", "; another fighter\n"),
                Kind::Char,
            );
            let stage = declare(&tiny_stage(&root.join("s")), Kind::Stage);
            Self { a, b, stage, root }
        }

        /// The same content as an API 4 (rugen 0.5) client brings it.
        pub(crate) fn legacy() -> Self {
            let root = tmp("kit-legacy");
            let a = declare_legacy(&tiny_char(&root.join("a"), "Alpha", ""), Kind::Char);
            let b = declare_legacy(
                &tiny_char(&root.join("b"), "Beta", "; another fighter\n"),
                Kind::Char,
            );
            let stage = declare_legacy(&tiny_stage(&root.join("s")), Kind::Stage);
            Self { a, b, stage, root }
        }
    }

    impl Drop for Kit {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn upload(api: &Api, key: &str, d: &FighterDecl, pkg: &[u8], chunk: usize) -> Response {
        let mut off = 0usize;
        loop {
            let end = (off + chunk).min(pkg.len());
            let r = api.handle(raw(
                "POST",
                &format!(
                    "/pkg/{}/upload?key={key}&offset={off}&total={}",
                    d.fingerprint,
                    pkg.len()
                ),
                pkg[off..end].to_vec(),
            ));
            if r.status != 200 || end == pkg.len() {
                return r;
            }
            off = end;
        }
    }

    fn pick(api: &Api, id: u64, key: &str, f: &FighterDecl, stage: Option<&FighterDecl>) -> Value {
        json_of(api.handle(req(
            "POST",
            &format!("/matchup/{id}/pick"),
            json!({"key": key, "fighter": f, "stage": stage}),
        )))
    }

    fn ready(api: &Api, id: u64, key: &str, view: &Value, engine: &str) -> Response {
        let fp = |i: usize| {
            view["fighters"][i]["decl"]["fingerprint"]
                .as_str()
                .unwrap()
                .to_string()
        };
        api.handle(req(
            "POST",
            &format!("/matchup/{id}/ready"),
            json!({"key": key, "ready": {
                "p1": fp(0), "p2": fp(1),
                "stage": view["stage"]["decl"]["fingerprint"],
                "engine": engine, "rules": view["rules"],
            }}),
        ))
    }

    /// Pick, verdict, accept, upload, ready → the view with a ticket.
    pub(crate) fn play_matchup(api: &Api, id: u64, keys: [&str; 2], kit: &Kit) -> [Value; 2] {
        let v = pick(api, id, keys[0], &kit.a.0, Some(&kit.stage.0));
        assert_eq!(v["phase"], "pick", "{v}");
        let v = pick(api, id, keys[1], &kit.b.0, None);
        assert_eq!(v["phase"], "confirm", "{v}");
        assert_eq!(v["verdict"]["kind"], "fair", "{v}");
        assert_eq!(v["fighters"][0]["decl"]["name"], "Alpha");
        for k in keys {
            json_of(api.handle(req(
                "POST",
                &format!("/matchup/{id}/accept"),
                json!({"key": k}),
            )));
        }
        let v = json_of(api.handle(req(
            "GET",
            &format!("/matchup/{id}?key={}", keys[0]),
            Value::Null,
        )));
        assert_eq!(v["phase"], "sync");
        // ready before the files are on the server: waits
        let fresh = !v["missing"].as_array().unwrap().is_empty();
        json_of(ready(api, id, keys[0], &v, "rugen 9"));
        json_of(ready(api, id, keys[1], &v, "rugen 9"));
        if fresh {
            assert_eq!(v["missing"].as_array().unwrap().len(), 3);
            upload_kit(api, keys, kit);
        }
        let va = json_of(api.handle(req(
            "GET",
            &format!("/matchup/{id}?key={}", keys[0]),
            Value::Null,
        )));
        let vb = json_of(api.handle(req(
            "GET",
            &format!("/matchup/{id}?key={}", keys[1]),
            Value::Null,
        )));
        assert_eq!(va["phase"], "started", "{va}");
        assert_eq!(va["fighters"][1]["verified"], true);
        [va, vb]
    }

    /// The kit's packages, uploaded by the players that bring them.
    fn upload_kit(api: &Api, keys: [&str; 2], kit: &Kit) {
        // HAS: missing, then upload (P1 brings its fighter + stage, P2 its fighter)
        let has = json_of(api.handle(req(
            "GET",
            &format!("/pkg/{}?key={}", kit.a.0.fingerprint, keys[0]),
            Value::Null,
        )));
        assert_eq!(has["complete"], false);
        json_of(upload(api, keys[0], &kit.a.0, &kit.a.1, 100));
        json_of(upload(api, keys[0], &kit.stage.0, &kit.stage.1, 1 << 20));
        let last = json_of(upload(api, keys[1], &kit.b.0, &kit.b.1, 1 << 20));
        assert_eq!(last["complete"], true);
    }

    /// A match learned from the hub push leaves its `found` entry behind
    /// (only a poll clears it): queueing again must start a new search,
    /// not hand back that old match.
    #[test]
    fn queueing_again_never_returns_an_old_match() {
        let api = api();
        let (_, ka) = register(&api);
        let (_, kb) = register(&api);
        let (_, kc) = register(&api);
        let q = |k: &str| {
            json_of(api.handle(req("POST", "/queue", json!({"key": k, "ranked": false}))))
        };
        q(&ka);
        let first = q(&kb)["found"]["match_id"].as_u64().unwrap();
        // A never polls (it saw the push), leaves that matchup and queues again
        let again = q(&ka);
        assert!(
            again["found"].is_null(),
            "old match {first} handed back: {again}"
        );
        assert_eq!(again["queued"], true);
        let next = q(&kc)["found"]["match_id"].as_u64().unwrap();
        assert_ne!(next, first);
        let fa = json_of(api.handle(req("GET", &format!("/queue?key={ka}"), Value::Null)));
        assert_eq!(fa["found"]["match_id"].as_u64(), Some(next));
    }

    #[test]
    fn ranked_queue_matchup_reports_rates_characters_and_keeps_files() {
        let kit = Kit::new();
        let api = api();
        let (aid, ka) = register(&api);
        let (_, kb) = register(&api);
        let st = json_of(api.handle(req("POST", "/queue", json!({"key": ka}))));
        assert_eq!(st["queued"], true);
        let fb = json_of(api.handle(req("POST", "/queue", json!({"key": kb}))));
        let fa = json_of(api.handle(req("GET", &format!("/queue?key={ka}"), Value::Null)));
        assert_eq!(fa["found"]["side"], 1);
        assert_eq!(fb["found"]["side"], 2);
        assert!(
            fa["found"]["ticket"].is_null(),
            "no relay before the matchup"
        );
        assert_eq!(fa["found"]["matchup"]["phase"], "pick");
        let mid = fa["found"]["match_id"].as_u64().unwrap();
        let [va, vb] = play_matchup(&api, mid, [&ka, &kb], &kit);
        let (ta, tb) = (&va["ticket"], &vb["ticket"]);
        assert_eq!(ta["session"], tb["session"]);
        assert_eq!(
            (ta["slot"].as_u64(), tb["slot"].as_u64()),
            (Some(0), Some(1))
        );
        assert_ne!(ta["token"], tb["token"]);
        assert_eq!(ta["udp"], "relay.example.com:7001");
        // the opponent downloads P1's package, resumable by ranges
        let fp = &kit.a.0.fingerprint;
        let mut got = Vec::new();
        while got.len() < kit.a.1.len() {
            let r = api.handle(req(
                "GET",
                &format!("/pkg/{fp}/data?key={kb}&offset={}&len=64", got.len()),
                Value::Null,
            ));
            assert_eq!(r.status, 200);
            assert_eq!(r.content_type, "application/octet-stream");
            got.extend(r.body);
        }
        assert_eq!(got, kit.a.1);
        // outsiders cannot download
        let (_, kc) = register(&api);
        let r = api.handle(req("GET", &format!("/pkg/{fp}/data?key={kc}"), Value::Null));
        assert_eq!(r.status, 403);
        // results: player Elo + community rating of both fingerprints
        let inputs = "01000200".repeat(100);
        for k in [&ka, &kb] {
            json_of(api.handle(req(
                "POST",
                "/result",
                json!({"key": k, "match_id": mid, "winner": aid, "inputs": inputs, "frames": 100, "checksum": 9}),
            )));
        }
        let lb = json_of(api.handle(req("GET", "/leaderboard", Value::Null)));
        assert_eq!(lb["rows"][0]["id"], aid);
        let ca = json_of(api.handle(req("GET", &format!("/char/{fp}"), Value::Null)));
        assert_eq!(
            (ca["games"].as_u64(), ca["wins"].as_u64()),
            (Some(1), Some(1))
        );
        assert_eq!(ca["rating"], 1508);
        let rp = json_of(api.handle(req("GET", &format!("/replay/{mid}"), Value::Null)));
        assert_eq!(rp["p1_char"], "Alpha");
        assert_eq!(rp["files_available"], true);
        assert_eq!(rp["fingerprints"][0], fp.as_str());
        let row = api.store.package(fp).unwrap().unwrap();
        assert!(
            row.keep_until > crate::store::now() + 86400,
            "kept for the replay"
        );
    }

    #[test]
    fn blocked_and_unbalanced_rules() {
        let root = tmp("rules");
        let cheat = declare(
            &tiny_char(
                &root.join("cheat"),
                "Cheater",
                "[Statedef -2]\n[State -2, regen]\ntype = LifeAdd\ntrigger1 = Life < LifeMax\nvalue = 10\n",
            ),
            Kind::Char,
        );
        let fair = declare(&tiny_char(&root.join("fair"), "Fair", ""), Kind::Char);
        let strong = declare(
            &tiny_char(
                &root.join("strong"),
                "Strong",
                "[Statedef 210]\nmovetype = A\n[State 210, h]\ntype = HitDef\ntrigger1 = 1\ndamage = 380\nguardflag = MA\n[Statedef 220]\nmovetype = A\n[State 220, h]\ntype = HitDef\ntrigger1 = 1\ndamage = 300\nguardflag = MA\n[Statedef 230]\nmovetype = A\n[State 230, p]\ntype = Projectile\ntrigger1 = 1\ndamage = 100\n[State 230, p2]\ntype = Projectile\ntrigger1 = 1\ndamage = 100\n[State 230, p3]\ntype = Projectile\ntrigger1 = 1\ndamage = 100\n[State 230, h]\ntype = HitDef\ntrigger1 = 1\ndamage = 10\n",
            ),
            Kind::Char,
        );
        let stage = declare(&tiny_stage(&root.join("s")), Kind::Stage);
        let api = api();
        let (_, ka) = register(&api);
        let (_, kb) = register(&api);
        // ranked: blocked never, unbalanced refused
        json_of(api.handle(req("POST", "/queue", json!({"key": ka, "ranked": true}))));
        let f = json_of(api.handle(req("POST", "/queue", json!({"key": kb, "ranked": true}))));
        let id = f["found"]["match_id"].as_u64().unwrap();
        pick(&api, id, &ka, &fair.0, Some(&stage.0));
        let v = pick(&api, id, &kb, &cheat.0, None);
        assert_eq!(v["verdict"]["kind"], "blocked", "{v}");
        assert!(
            v["verdict"]["reasons"][0]
                .as_str()
                .unwrap()
                .contains("CHEATER")
        );
        let r = api.handle(req(
            "POST",
            &format!("/matchup/{id}/accept"),
            json!({"key": ka, "unbalanced": true}),
        ));
        assert_eq!(r.status, 409);
        let v = pick(&api, id, &kb, &strong.0, None);
        assert_eq!(v["verdict"]["kind"], "unbalanced", "{v}");
        let r = api.handle(req(
            "POST",
            &format!("/matchup/{id}/accept"),
            json!({"key": ka, "unbalanced": true}),
        ));
        assert_eq!(r.status, 409, "ranked needs fair");
        // casual room: unbalanced needs an explicit accept from both
        let (_, kc) = register(&api);
        let (_, kd) = register(&api);
        let room = json_of(api.handle(req("POST", "/room", json!({"key": kc}))));
        let code = room["code"].as_str().unwrap().to_string();
        let joined = json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/join"),
            json!({"key": kd}),
        )));
        assert_eq!(joined["ready"], false);
        let id = joined["matchup"]["id"].as_u64().unwrap();
        pick(&api, id, &kc, &fair.0, Some(&stage.0));
        pick(&api, id, &kd, &strong.0, None);
        let r = api.handle(req(
            "POST",
            &format!("/matchup/{id}/accept"),
            json!({"key": kc}),
        ));
        assert_eq!(r.status, 409);
        for k in [&kc, &kd] {
            json_of(api.handle(req(
                "POST",
                &format!("/matchup/{id}/accept"),
                json!({"key": k, "unbalanced": true}),
            )));
        }
        let v = json_of(api.handle(req("GET", &format!("/matchup/{id}?key={kc}"), Value::Null)));
        assert_eq!(v["phase"], "sync");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn lying_clients_are_caught_and_flagged() {
        let kit = Kit::new();
        let api = api();
        let (aid, ka) = register(&api);
        let (bid, kb) = register(&api);
        json_of(api.handle(req("POST", "/queue", json!({"key": ka, "ranked": false}))));
        let f = json_of(api.handle(req("POST", "/queue", json!({"key": kb, "ranked": false}))));
        let id = f["found"]["match_id"].as_u64().unwrap();
        // B claims a weaker profile than its files have
        let mut liar = kit.b.0.clone();
        liar.profile.as_mut().unwrap().max_hit_damage = 1;
        pick(&api, id, &ka, &kit.a.0, Some(&kit.stage.0));
        let v = pick(&api, id, &kb, &liar, None);
        assert_eq!(v["phase"], "confirm");
        for k in [&ka, &kb] {
            json_of(api.handle(req(
                "POST",
                &format!("/matchup/{id}/accept"),
                json!({"key": k}),
            )));
        }
        json_of(upload(&api, &kb, &kit.b.0, &kit.b.1, 1 << 20));
        let v = json_of(api.handle(req("GET", &format!("/matchup/{id}?key={ka}"), Value::Null)));
        assert_eq!(v["phase"], "failed");
        assert!(v["error"].as_str().unwrap().contains("P2"), "{v}");
        assert_eq!(api.store.flags_of(bid).unwrap().len(), 1);
        // once known, the same lie is caught at pick time
        json_of(api.handle(req("POST", "/queue", json!({"key": ka, "ranked": false}))));
        let f = json_of(api.handle(req("POST", "/queue", json!({"key": kb, "ranked": false}))));
        let id = f["found"]["match_id"].as_u64().unwrap();
        let v = pick(&api, id, &kb, &liar, None);
        assert_eq!(v["phase"], "failed");
        // uploading other files under a declared fingerprint
        json_of(api.handle(req("POST", "/queue", json!({"key": ka, "ranked": false}))));
        let f = json_of(api.handle(req("POST", "/queue", json!({"key": kb, "ranked": false}))));
        let id = f["found"]["match_id"].as_u64().unwrap();
        let mut fake = kit.stage.0.clone();
        fake.fingerprint = "ab".repeat(32);
        pick(&api, id, &ka, &kit.a.0, Some(&fake));
        let r = upload(&api, &ka, &fake, &kit.stage.1, 1 << 20);
        assert_eq!(r.status, 422, "{}", String::from_utf8_lossy(&r.body));
        let v = json_of(api.handle(req("GET", &format!("/matchup/{id}?key={kb}"), Value::Null)));
        assert_eq!(v["phase"], "failed");
        assert!(!api.packages.has(&fake.fingerprint));
        assert_eq!(api.store.flags_of(aid).unwrap().len(), 1);
        // and nobody may upload what they did not pick
        let r = upload(&api, &kb, &kit.a.0, &kit.a.1, 1 << 20);
        assert_eq!(r.status, 403);
    }

    #[test]
    fn uploads_resume_and_respect_limits() {
        let kit = Kit::new();
        let api = api_with(PkgConfig {
            max_pkg: 1 << 20,
            ..Default::default()
        });
        let (aid, ka) = register(&api);
        let (_, kb) = register(&api);
        json_of(api.handle(req("POST", "/queue", json!({"key": ka, "ranked": false}))));
        let f = json_of(api.handle(req("POST", "/queue", json!({"key": kb, "ranked": false}))));
        let id = f["found"]["match_id"].as_u64().unwrap();
        pick(&api, id, &ka, &kit.a.0, Some(&kit.stage.0));
        let (d, pkg) = &kit.a;
        let n = pkg.len();
        let up = |off: usize, end: usize| {
            api.handle(raw(
                "POST",
                &format!(
                    "/pkg/{}/upload?key={ka}&offset={off}&total={n}",
                    d.fingerprint
                ),
                pkg[off..end].to_vec(),
            ))
        };
        // online consent: a client that predates it (0.6.3) uploads without
        // saying; a newer one must say yes
        client_engine(Some("0.6.4"));
        assert_eq!(up(0, 50).status, 403, "a 0.6.4 client must send consent");
        let refused = api.handle(raw(
            "POST",
            &format!(
                "/pkg/{}/upload?key={ka}&offset=0&total={n}&consent=0",
                d.fingerprint
            ),
            pkg[..50].to_vec(),
        ));
        assert_eq!(refused.status, 403);
        assert_eq!(
            api.packages.partial_len(&d.fingerprint, aid),
            0,
            "nothing kept"
        );
        client_engine(Some("0.6.3"));
        json_of(up(0, 50));
        // a lost chunk: the server says where to resume
        let r = up(80, 100);
        assert_eq!(r.status, 409);
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["offset"], 50);
        let has = json_of(api.handle(req(
            "GET",
            &format!("/pkg/{}?key={ka}", d.fingerprint),
            Value::Null,
        )));
        assert_eq!(has["offset"], 50);
        let done = json_of(up(50, n));
        assert_eq!(done["complete"], true);
        // over the per-package cap
        let r = api.handle(raw(
            "POST",
            &format!(
                "/pkg/{}/upload?key={ka}&offset=0&total={}",
                kit.stage.0.fingerprint,
                2 << 20
            ),
            vec![0; 10],
        ));
        assert_eq!(r.status, 413);
        // a declaration bigger than the server accepts is refused at pick
        let mut big = kit.b.0.clone();
        big.size = 2 << 20;
        let r = api.handle(req(
            "POST",
            &format!("/matchup/{id}/pick"),
            json!({"key": kb, "fighter": big}),
        ));
        assert_eq!(r.status, 400);
    }

    #[test]
    fn retention_expires_and_evicts() {
        let kit = Kit::new();
        let api = api_with(PkgConfig {
            ttl_secs: 3600,
            max_total: 0,
            ..Default::default()
        });
        let s = &api.store;
        let t = crate::store::now();
        for (i, (d, pkg)) in [&kit.a, &kit.b, &kit.stage].into_iter().enumerate() {
            std::fs::write(api.packages.path(&d.fingerprint), pkg).unwrap();
            s.put_package(&crate::store::PackageRow {
                fingerprint: d.fingerprint.clone(),
                kind: d.kind.clone(),
                size: pkg.len() as u64,
                def: d.def.clone(),
                created: t,
                // a: expired, b: fresh, stage: expired but kept for a replay
                last_used: if i == 1 { t } else { t - 7200 },
                keep_until: if i == 2 { t + 3600 } else { 0 },
                ..Default::default()
            })
            .unwrap();
        }
        // a stray file without a row is an orphan (once it is not brand new:
        // a fresh one may be an upload whose row is being written)
        let young = api.packages.path(&"ef".repeat(32));
        std::fs::write(&young, b"x").unwrap();
        std::fs::write(api.packages.path(&"cd".repeat(32)), b"x").unwrap();
        std::fs::File::options()
            .write(true)
            .open(api.packages.path(&"cd".repeat(32)))
            .unwrap()
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(3600))
            .unwrap();
        let mut pk = PkgConfig {
            ttl_secs: 3600,
            max_total: 10 << 20,
            ..Default::default()
        };
        // TTL pass with a roomy cap
        let pkgs = Packages::at(api.packages.dir(), pk.clone());
        let gone = pkgs.sweep(s);
        assert_eq!(gone, vec![kit.a.0.fingerprint.clone()]);
        assert!(!pkgs.has(&kit.a.0.fingerprint) && pkgs.has(&kit.b.0.fingerprint));
        assert!(!pkgs.path(&"cd".repeat(32)).exists(), "orphan removed");
        assert!(young.exists(), "a fresh upload is not an orphan");
        // size cap 0: LRU eviction, replay-kept last
        pk.max_total = kit.stage.1.len() as u64;
        let pkgs = Packages::at(api.packages.dir(), pk);
        let gone = pkgs.sweep(s);
        assert_eq!(gone, vec![kit.b.0.fingerprint.clone()]);
        assert!(pkgs.has(&kit.stage.0.fingerprint));
    }

    /// The consent dialog's promise: a package goes `RUGEN_PKG_DAYS` after
    /// its upload, even while it is used every day or kept for a replay.
    #[test]
    fn packages_go_days_after_upload_whatever_uses_them() {
        let kit = Kit::new();
        let api = api_with(PkgConfig::default());
        assert_eq!(
            api.packages.cfg.max_age_secs,
            3 * 86400,
            "3 days by default"
        );
        assert_eq!(api.packages.days(), 3);
        let info = json_of(api.handle(req("GET", "/health", Value::Null)));
        assert_eq!(
            info["pkg_days"], 3,
            "the game shows it in its consent dialog"
        );
        let s = &api.store;
        let t = crate::store::now();
        for (i, (d, pkg)) in [&kit.a, &kit.b].into_iter().enumerate() {
            std::fs::write(api.packages.path(&d.fingerprint), pkg).unwrap();
            s.put_package(&crate::store::PackageRow {
                fingerprint: d.fingerprint.clone(),
                kind: d.kind.clone(),
                size: pkg.len() as u64,
                def: d.def.clone(),
                // a: uploaded 3 days and a minute ago, b: 2 days ago
                created: if i == 0 {
                    t - 3 * 86400 - 60
                } else {
                    t - 2 * 86400
                },
                // both used a moment ago, and kept for a replay
                last_used: t,
                keep_until: t + 30 * 86400,
                ..Default::default()
            })
            .unwrap();
        }
        let gone = api.packages.sweep(s);
        assert_eq!(gone, vec![kit.a.0.fingerprint.clone()]);
        assert!(!api.packages.has(&kit.a.0.fingerprint));
        assert!(api.packages.has(&kit.b.0.fingerprint));
    }

    #[test]
    fn room_codes_skip_lookalikes_and_ignore_case() {
        let api = api();
        let (_, ka) = register(&api);
        let (_, kb) = register(&api);
        let room = json_of(api.handle(req(
            "POST",
            "/room",
            json!({"key": ka, "name": "AXEL'S ROOM"}),
        )));
        // apostrophes survive ("PLAYER'S ROOM", not "PLAYERS ROOM")
        assert_eq!(room["name"], "AXEL'S ROOM");
        let code = room["code"].as_str().unwrap().to_string();
        assert_eq!(code.len(), 5);
        assert!(
            code.chars()
                .all(|c| rugen_proto::room_code::ALPHABET.contains(c)),
            "{code}"
        );
        // typed in lower case, with stray spaces
        let joined = json_of(api.handle(req(
            "POST",
            &format!("/room/{}/join", code.to_ascii_lowercase()),
            json!({"key": kb}),
        )));
        assert_eq!(joined["code"], code.as_str());
        for _ in 0..200 {
            let c = random_code();
            assert!(
                !c.contains(['0', 'O', '1', 'I', '5', 'S', '2', 'Z', '8', 'B']),
                "{c}"
            );
        }
    }

    #[test]
    fn room_lifecycle_password_spectators_kick() {
        let kit = Kit::new();
        let api = api();
        let (_, ka) = register(&api);
        let (bid, kb) = register(&api);
        let (cid, kc) = register(&api);
        let (_, kd) = register(&api);
        let room = json_of(api.handle(req(
            "POST",
            "/room",
            json!({"key": ka, "name": "Friday <b>Night</b>", "password": "s3cret",
                   "rules": {"rounds": 9, "mode": "arena"}, "max_spectators": 1}),
        )));
        let code = room["code"].as_str().unwrap().to_string();
        assert_eq!(room["name"], "Friday bNightb");
        assert_eq!(room["locked"], true);
        assert_eq!(room["rules"]["rounds"], 5);
        assert_eq!(room["rules"]["mode"], "arena");
        let list = json_of(api.handle(req("GET", "/rooms", Value::Null)));
        assert_eq!(list[0]["code"], code.as_str());
        assert!(!list.to_string().contains("argon2"));
        let r = api.handle(req(
            "POST",
            &format!("/room/{code}/join"),
            json!({"key": kb, "password": "nope"}),
        ));
        assert_eq!(r.status, 403);
        let joined = json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/join"),
            json!({"key": kb, "password": "s3cret"}),
        )));
        assert_eq!(joined["side"], 2);
        assert_eq!(joined["ready"], false);
        assert_eq!(joined["matchup"]["phase"], "pick");
        // spectator joins during the matchup and gets slot 2 when it starts
        let spec = json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/join"),
            json!({"key": kc, "spectate": true, "password": "s3cret"}),
        )));
        assert_eq!(spec["side"], 3);
        let full = api.handle(req(
            "POST",
            &format!("/room/{code}/join"),
            json!({"key": kd, "spectate": true, "password": "s3cret"}),
        ));
        assert_eq!(full.status, 409);
        let id = joined["matchup"]["id"].as_u64().unwrap();
        let [va, _] = play_matchup(&api, id, [&ka, &kb], &kit);
        assert_eq!(va["ticket"]["spectators"], 1);
        let rv = json_of(api.handle(req("GET", &format!("/room/{code}?key={kc}"), Value::Null)));
        assert_eq!(rv["ready"], true);
        assert_eq!(rv["ticket"]["slot"], 2);
        // the server keeps the input log: players feed it, spectators do not
        assert_eq!(va["ticket"]["live"], true);
        assert!(rv["ticket"].get("live").is_none());
        let live = json_of(api.handle(req("GET", "/v1/live", Value::Null)));
        assert_eq!(live[0]["match_id"].as_u64(), Some(id));
        assert_eq!(live[0]["room"], code.as_str());
        let list = json_of(api.handle(req("GET", "/rooms", Value::Null)));
        assert_eq!(list[0]["live_match"].as_u64(), Some(id));
        let r = api.handle(req(
            "GET",
            &format!("/v1/live/{id}?key={kd}&from=0"),
            Value::Null,
        ));
        assert_eq!(r.status, 200, "a public room's match: anyone");
        let c = rugen_proto::stream::decode_chunk(&r.body).unwrap();
        let h = c.header.unwrap();
        assert_eq!(h.match_id, id);
        assert_eq!(h.seed, rugen_proto::stream::online_seed(id));
        assert_eq!(h.fighters[0].fingerprint, kit.a.0.fingerprint);
        assert!(h.fighters[0].size > 0);
        assert_eq!((c.total, c.ended), (0, false));
        // its packages: a viewer may download them
        let r = api.handle(req(
            "GET",
            &format!("/pkg/{}/data?key={kd}&offset=0&len=16", kit.a.0.fingerprint),
            Value::Null,
        ));
        assert_eq!(r.status, 200);
        assert_eq!(
            api.handle(req(
                "GET",
                "/v1/live/123?key=".to_string().as_str(),
                Value::Null
            ))
            .status,
            401
        );
        // rematch: both players → a new matchup (files already on the server)
        json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/rematch"),
            json!({"key": ka}),
        )));
        let again = json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/rematch"),
            json!({"key": kb}),
        )));
        let id2 = again["matchup"]["id"].as_u64().unwrap();
        assert_ne!(id2, id);
        assert_eq!(again["ready"], false);
        pick(&api, id2, &ka, &kit.a.0, Some(&kit.stage.0));
        let v = pick(&api, id2, &kb, &kit.b.0, None);
        assert!(
            v["missing"].as_array().unwrap().is_empty(),
            "cached on the server"
        );
        // only the host kicks; kicked players cannot come back
        let r = api.handle(req(
            "POST",
            &format!("/room/{code}/kick"),
            json!({"key": kb, "id": cid}),
        ));
        assert_eq!(r.status, 403);
        json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/kick"),
            json!({"key": ka, "id": bid}),
        )));
        let v = json_of(api.handle(req("GET", &format!("/matchup/{id2}?key={ka}"), Value::Null)));
        assert_eq!(v["phase"], "failed");
        let r = api.handle(req(
            "POST",
            &format!("/room/{code}/join"),
            json!({"key": kb, "password": "s3cret"}),
        ));
        assert_eq!(r.status, 403);
        json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/leave"),
            json!({"key": ka}),
        )));
        let r = api.handle(req("GET", &format!("/room/{code}?key={kc}"), Value::Null));
        assert_eq!(r.status, 404);
    }

    #[test]
    fn mirror_rooms_and_version_mismatch() {
        let kit = Kit::new();
        let api = api();
        let (_, ka) = register(&api);
        let (_, kb) = register(&api);
        let room = json_of(api.handle(req(
            "POST",
            "/room",
            json!({"key": ka, "rules": {"chars": "mirror"}}),
        )));
        let code = room["code"].as_str().unwrap().to_string();
        let joined = json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/join"),
            json!({"key": kb}),
        )));
        let id = joined["matchup"]["id"].as_u64().unwrap();
        pick(&api, id, &ka, &kit.a.0, Some(&kit.stage.0));
        let v = json_of(api.handle(req("GET", &format!("/matchup/{id}?key={kb}"), Value::Null)));
        assert_eq!(v["mirror"], true);
        assert_eq!(
            v["fighters"][1]["decl"]["name"], "Alpha",
            "P2 plays P1's fighter"
        );
        assert_eq!(v["phase"], "confirm");
        for k in [&ka, &kb] {
            json_of(api.handle(req(
                "POST",
                &format!("/matchup/{id}/accept"),
                json!({"key": k}),
            )));
        }
        json_of(ready(&api, id, &ka, &v, "rugen 1"));
        json_of(ready(&api, id, &kb, &v, "rugen 2"));
        let v = json_of(api.handle(req("GET", &format!("/matchup/{id}?key={ka}"), Value::Null)));
        assert_eq!(v["phase"], "failed");
        assert!(v["error"].as_str().unwrap().contains("versions"));
    }

    #[test]
    fn quick_match_ignores_rating_and_never_meets_ranked() {
        let api = api();
        let (_, ka) = register(&api);
        let (_, kb) = register(&api);
        let (_, kc) = register(&api);
        json_of(api.handle(req("POST", "/queue", json!({"key": ka, "ranked": false}))));
        let st = json_of(api.handle(req("POST", "/queue", json!({"key": kb, "ranked": true}))));
        assert!(st["found"].is_null());
        let st = json_of(api.handle(req("POST", "/queue", json!({"key": kc, "ranked": false}))));
        assert_eq!(st["found"]["ranked"], false);
    }

    #[test]
    fn private_rooms_are_unlisted() {
        let api = api();
        let (_, ka) = register(&api);
        json_of(api.handle(req("POST", "/room", json!({"key": ka, "public": false}))));
        let list = json_of(api.handle(req("GET", "/rooms", Value::Null)));
        assert_eq!(list.as_array().unwrap().len(), 0);
    }

    #[test]
    fn bad_keys_are_rejected_and_info_is_public() {
        let api = api();
        let r = api.handle(req("POST", "/queue", json!({"key": "nope", "char": "kfm"})));
        assert_eq!(r.status, 401);
        let r = api.handle(req("GET", "/nothing", Value::Null));
        assert_eq!(r.status, 404);
        let info = json_of(api.handle(req("GET", "/health", Value::Null)));
        assert_eq!(info["motd"], "hello");
        assert_eq!(info["name"], "test");
        assert!(info["version"].as_str().is_some());
    }

    /// A disputed ranked match is re-simulated from the stored packages and
    /// settled with the simulated winner (needs `--features resim` and the
    /// MUGEN 1.1 reference tree).
    #[cfg(feature = "resim")]
    #[test]
    fn disputed_match_is_resimulated_and_settled() {
        let Some(root) = crate::e2e::reference() else {
            eprintln!("reference tree missing; skipping");
            return;
        };
        let data = root.join("data");
        let api = Api::new(
            Store::open(None).unwrap(),
            ApiConfig {
                name: "t".into(),
                resim: Some(ResimConfig {
                    data: data.clone(),
                    motif: data.clone(),
                }),
                ..Default::default()
            },
            Arc::new(Relay::default()),
        );
        // packages of KFM and stage0, stored as if uploaded
        let mut fps = Vec::new();
        for (kind, def) in [
            (Kind::Char, root.join("chars/kfm/kfm.def")),
            (Kind::Stage, root.join("stages/stage0.def")),
        ] {
            let files = rugen_fair::files::content_files(kind, &def, Some(&data)).unwrap();
            let fp = rugen_fair::fingerprint(&files).unwrap();
            let src = rugen_content::convert::Source {
                root: def.parent().unwrap().to_path_buf(),
                def: files.def.clone(),
                kind: match kind {
                    Kind::Char => rugen_formats::rgc::Kind::Char,
                    Kind::Stage => rugen_formats::rgc::Kind::Stage,
                },
                name: "reference".into(),
            };
            let r = rugen_content::convert::convert(
                &src,
                &api.packages.path_for(&fp, kind),
                &data,
                None,
            )
            .unwrap();
            assert_eq!(r.fingerprint.as_deref(), Some(fp.as_str()));
            api.store
                .put_package(&crate::store::PackageRow {
                    fingerprint: fp.clone(),
                    kind: kind.as_str().into(),
                    size: 1,
                    def: files.def.clone(),
                    created: crate::store::now(),
                    last_used: crate::store::now(),
                    ..Default::default()
                })
                .unwrap();
            fps.push(fp);
        }
        let (aid, ka) = register(&api);
        let (bid, kb) = register(&api);
        // played on the version this server simulates
        let setup = json!({"p1_fp": fps[0], "p2_fp": fps[0], "stage_fp": fps[1],
            "rules": Rules::default(), "engine": crate::compat::SIM_ENGINE});
        let mid = api
            .store
            .new_match([aid, bid], true, &setup.to_string())
            .unwrap();
        // play it locally: P1 walks in and punches, P2 stands
        let spec = rugen_sim::headless::MatchSpec {
            p1: &root.join("chars/kfm/kfm.def"),
            p2: &root.join("chars/kfm/kfm.def"),
            stage: Some(&root.join("stages/stage0.def")),
            data_dir: &data,
            motif: &data,
            zoom: (0.6, 1.25),
            movement: Default::default(),
            round_time: None,
            ai: [0, 0],
            fighter_size: rugen_sim::scale::FighterSize::Normal,
            // the default rules' LIFE, as the clients play it
            life: Some(5000),
            // as the clients do: the seed of the match id
            seed: rugen_sim::headless::online_seed(mid),
        };
        let mut world = rugen_sim::headless::build_world(&spec).unwrap();
        let mut inputs = Vec::new();
        let mut f = 0u32;
        while !world.round.match_over && f < 30_000 {
            let b = rugen_sim::Buttons {
                r: f % 40 < 20,
                x: f % 40 >= 20 && f % 6 < 2,
                ..Default::default()
            };
            let p1 = b.bits();
            inputs.extend(p1.to_le_bytes());
            inputs.extend(0u16.to_le_bytes());
            world.step(&[b, rugen_sim::Buttons::default()]);
            f += 1;
        }
        let mut again = rugen_sim::headless::build_world(&spec).unwrap();
        let local = rugen_sim::headless::replay(&mut again, &inputs, None);
        assert!(local.match_over, "P1 wins in {} frames", local.frames);
        assert_eq!(
            local.winner,
            Some(0),
            "{local:?} wins {:?} life {:?}",
            again.round.wins,
            again.players.iter().map(|p| p.life).collect::<Vec<_>>()
        );
        let hex = to_hex(&inputs);
        // A tells the truth, B claims the win with a wrong checksum
        json_of(api.handle(req(
            "POST",
            "/result",
            json!({"key": ka, "match_id": mid, "winner": aid,
            "inputs": hex, "frames": local.frames, "checksum": local.checksum}),
        )));
        let r = json_of(api.handle(req(
            "POST",
            "/result",
            json!({"key": kb, "match_id": mid, "winner": bid,
            "inputs": hex, "frames": local.frames, "checksum": local.checksum ^ 1}),
        )));
        assert_eq!(r["disputed"], true);
        let t = Instant::now();
        while api.store.is_disputed(mid).unwrap() && t.elapsed() < Duration::from_secs(120) {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            !api.store.is_disputed(mid).unwrap(),
            "settled by re-simulation"
        );
        let a = api.store.by_id(aid).unwrap().unwrap();
        assert_eq!(a.wins, 1);
        assert!(a.rating > 1200);
    }

    /// A disputed match played on another game version (or one recorded
    /// before setups carried it) is never re-simulated: it stays an
    /// ordinary dispute, noted "unverified (version)", nobody's rating moves
    /// and nothing is flagged or blocked.
    #[test]
    fn other_versions_are_not_resimulated() {
        let api = Api::new(
            Store::open(None).unwrap(),
            ApiConfig {
                name: "t".into(),
                resim: Some(ResimConfig {
                    data: "/nonexistent".into(),
                    motif: "/nonexistent".into(),
                }),
                ..Default::default()
            },
            Arc::new(Relay::default()),
        );
        let fp = |c: char| format!("rugen-fp-2:{}", c.to_string().repeat(64));
        for engine in [json!("0.0.1"), Value::Null] {
            let (aid, ka) = register(&api);
            let (bid, kb) = register(&api);
            let setup = json!({"p1_fp": fp('a'), "p2_fp": fp('b'), "stage_fp": fp('c'),
                "rules": Rules::default(), "engine": engine});
            let mid = api
                .store
                .new_match([aid, bid], true, &setup.to_string())
                .unwrap();
            for (key, winner, checksum) in [(&ka, aid, 1u64), (&kb, bid, 2u64)] {
                json_of(api.handle(req(
                    "POST",
                    "/result",
                    json!({"key": key, "match_id": mid, "winner": winner,
                    "inputs": "00000000", "frames": 1, "checksum": checksum}),
                )));
            }
            let t = Instant::now();
            let note = loop {
                if let Some(n) = api.store.resim_note(mid).unwrap() {
                    break n;
                }
                assert!(
                    t.elapsed() < Duration::from_secs(10),
                    "resim never answered"
                );
                std::thread::sleep(Duration::from_millis(20));
            };
            assert!(note.starts_with("unverified (version)"), "{note}");
            let s = &api.store;
            assert!(s.is_disputed(mid).unwrap(), "stays an ordinary dispute");
            for id in [aid, bid] {
                let a = s.by_id(id).unwrap().unwrap();
                assert_eq!((a.wins, a.losses, a.rating), (0, 0, 1200));
            }
            for f in [fp('a'), fp('b'), fp('c')] {
                assert_eq!(s.desyncs_for(&f).unwrap(), 0);
                assert_eq!(s.liars_for(&f).unwrap(), 0);
            }
            assert!(s.blocklist().unwrap().is_empty());
        }
    }

    /// Players on different game versions never meet: the queue keeps them
    /// apart and a room refuses the other version, with who must update.
    #[test]
    fn other_game_versions_never_meet() {
        let api = api();
        let (_, ka) = register(&api);
        let (_, kb) = register(&api);
        let (_, kc) = register(&api);
        let queue = |key: &str, engine: Option<&str>| {
            client_engine(engine);
            json_of(api.handle(req(
                "POST",
                "/queue",
                json!({"key": key, "char": "kfm", "ranked": true}),
            )))
        };
        assert!(queue(&ka, Some("0.6.1"))["found"].is_null());
        assert!(
            queue(&kb, Some("0.6.2"))["found"].is_null(),
            "0.6.1 vs 0.6.2"
        );
        assert!(
            !queue(&kc, Some("0.6.2"))["found"].is_null(),
            "0.6.2 vs 0.6.2"
        );
        // rooms: a 0.6.2 host
        let (_, kh) = register(&api);
        client_engine(Some("0.6.2"));
        let room = json_of(api.handle(req("POST", "/room", json!({"key": kh, "name": "R"}))));
        let code = room["code"].as_str().unwrap().to_string();
        let (_, kj) = register(&api);
        client_engine(Some("0.6.1"));
        let r = api.handle(req(
            "POST",
            &format!("/room/{code}/join"),
            json!({"key": kj, "char": "kfm"}),
        ));
        assert_eq!(r.status, 409);
        assert!(String::from_utf8_lossy(&r.body).contains("NEWER RUGEN (0.6.2)"));
        client_engine(Some("0.6.2"));
        let r = api.handle(req(
            "POST",
            &format!("/room/{code}/join"),
            json!({"key": kj, "char": "kfm"}),
        ));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        client_engine(None);
    }

    // ---- official vs community servers

    use rugen_fair::trust::{PublicKey, SigningKey};
    use rugen_proto::{IdentityStatement, ResultStatement, SignedBlob, VerdictStatement, purpose};

    fn api_truth(name: &str, truth: TruthConfig) -> Arc<Api> {
        Api::new(
            Store::open(None).unwrap(),
            ApiConfig {
                name: name.into(),
                truth,
                ..Default::default()
            },
            Arc::new(Relay::default()),
        )
    }

    /// A season ends (operator): the live board restarts, the finished
    /// season's final standings stay under `?season=`, and the badge rides
    /// on profiles; a client that ignores the new fields reads it as before.
    #[test]
    fn finished_seasons_keep_their_board_and_badges() {
        let api = official_api();
        let (a, ka) = register(&api);
        let (b, _) = register(&api);
        {
            let s = api.store();
            for _ in 0..3 {
                let m = s.new_match([a, b], true, "{}").unwrap();
                let w = ReportData {
                    winner: a,
                    ..Default::default()
                };
                s.report(a, m, &w).unwrap();
                s.report(b, m, &w).unwrap();
            }
        }
        let live = json_of(api.handle(req("GET", &format!("/leaderboard?key={ka}"), Value::Null)));
        assert_eq!(live["season"]["number"], 1);
        assert_eq!(live["finished"], false);
        assert_eq!(live["past"], json!([]));
        assert!(live["season"]["secs_left"].as_u64().unwrap() > 0);
        assert_eq!(live["rows"].as_array().unwrap().len(), 2);
        // only the operator ends a season
        assert_eq!(
            api.handle(req("POST", "/v1/admin/season_end", json!({"token": "bad"})))
                .status,
            403
        );
        let next =
            json_of(api.handle(req("POST", "/v1/admin/season_end", json!({"token": "tok"}))));
        assert_eq!(next["number"], 2);
        let live = json_of(api.handle(req("GET", &format!("/leaderboard?key={ka}"), Value::Null)));
        assert_eq!(live["season"]["number"], 2);
        assert_eq!(live["rows"], json!([]), "records restart");
        assert_eq!(live["past"], json!([1]));
        let old = json_of(api.handle(req(
            "GET",
            &format!("/leaderboard?key={ka}&season=1"),
            Value::Null,
        )));
        assert_eq!(old["finished"], true);
        assert_eq!(old["season"]["number"], 1);
        let rows = old["rows"].as_array().unwrap();
        assert_eq!(rows[0]["id"].as_u64(), Some(a));
        assert_eq!(rows[0]["wins"], 3);
        assert_eq!(rows[0]["rating"], 1244);
        assert_eq!(old["me"][0], 1);
        // the profile keeps season 1's badge; the rating soft-reset
        let p = json_of(api.handle(req("GET", &format!("/profile/{a}"), Value::Null)));
        assert_eq!(p["rating"], 1222);
        assert_eq!(
            p["last_season"],
            json!({"season": 1, "rating": 1244, "rank": 1, "tier": "SILVER"})
        );
        // typed as a client of 0.6 reads it
        let typed: Leaderboard = serde_json::from_value(old).unwrap();
        assert_eq!(typed.rows.len(), 2);
        assert_eq!(
            api.handle(req("GET", "/leaderboard?season=9", Value::Null))
                .status,
            404
        );
    }

    /// Ranked results move each player's rating with its fighter: the
    /// FIGHTERS board lists the fighters by appearances and ranks the
    /// players of one; a new season starts them from a soft reset.
    #[test]
    fn per_fighter_boards_rank_players_of_each_fighter() {
        let api = official_api();
        let (a, ka) = register(&api);
        let (b, _) = register(&api);
        let (c, _) = register(&api);
        let (naruto, sasuke) = ("a".repeat(64), "b".repeat(64));
        let play = |p1: u64, f1: &str, p2: u64, f2: &str, winner: u64| {
            let s = api.store();
            let setup = json!({"p1_fp": f1, "p2_fp": f2, "p1_char": "Naruto",
                "p2_char": if f2 == naruto { "Naruto" } else { "Sasuke" }})
            .to_string();
            let m = s.new_match([p1, p2], true, &setup).unwrap();
            let w = ReportData {
                winner,
                ..Default::default()
            };
            s.report(p1, m, &w).unwrap();
            s.report(p2, m, &w).unwrap();
        };
        play(a, &naruto, b, &sasuke, a);
        play(a, &naruto, b, &sasuke, a);
        play(c, &naruto, a, &naruto, c);
        let board = |q: &str| {
            json_of(api.handle(req(
                "GET",
                &format!("/leaderboard?key={ka}&{q}"),
                Value::Null,
            )))
        };
        let top = board("fighters=1");
        assert_eq!(top["fighter"]["fingerprint"], naruto, "most played first");
        assert_eq!(top["fighter"]["name"], "Naruto");
        assert_eq!(top["fighters"][0]["games"], 4);
        assert_eq!(top["fighters"][0]["players"], 2);
        assert_eq!(top["fighters"][1]["fingerprint"], sasuke);
        let rows = top["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        // a: 2 wins then a loss with Naruto (1214); c: one win over a (1218)
        let line = |id: u64| rows.iter().find(|r| r["id"].as_u64() == Some(id)).unwrap();
        assert_eq!(
            (line(a)["wins"].as_u64(), line(a)["losses"].as_u64()),
            (Some(2), Some(1))
        );
        assert_eq!(
            (line(c)["wins"].as_u64(), line(c)["losses"].as_u64()),
            (Some(1), Some(0))
        );
        assert_eq!(rows[0]["id"].as_u64(), Some(c));
        assert_eq!(top["me"][0], 2);
        let sb = board(&format!("fighter={sasuke}"));
        assert_eq!(sb["rows"][0]["id"].as_u64(), Some(b));
        assert_eq!(sb["rows"][0]["losses"], 2);
        assert!(sb["me"].is_null(), "a never played Sasuke");
        // the players' board is untouched by the new fields
        assert!(board("").get("fighters").is_none());
        let rating = line(a)["rating"].as_i64().unwrap() as i32;
        // a new season: the board restarts, a returning player starts soft-reset
        api.handle(req("POST", "/v1/admin/season_end", json!({"token": "tok"})));
        assert!(
            board("fighters=1").get("fighters").is_none(),
            "no fighter played yet"
        );
        let old = board("fighters=1&season=1");
        assert_eq!(old["finished"], true);
        assert_eq!(old["rows"][1]["id"].as_u64(), Some(a));
        play(a, &naruto, b, &sasuke, b);
        let now = board(&format!("fighter={naruto}"));
        let nw = rugen_proto::soft_reset(rating);
        let after = now["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"].as_u64() == Some(a))
            .unwrap()["rating"]
            .as_i64()
            .unwrap() as i32;
        // b's Sasuke rating starts season 2 soft-reset too
        let b_start = rugen_proto::soft_reset(sb["rows"][0]["rating"].as_i64().unwrap() as i32);
        assert_eq!(
            after,
            crate::elo::update(b_start, nw).1,
            "lost from the soft-reset rating"
        );
        assert_eq!(
            api.handle(req("GET", "/leaderboard?fighter=nope", Value::Null))
                .status,
            400
        );
    }

    /// A tournament room: entrants join (clients that know brackets only),
    /// the host draws the bracket, the server calls each match, records
    /// settled results (with the reported score) and walkovers, and crowns
    /// a champion.
    #[test]
    fn tournament_rooms_call_matches_to_a_champion() {
        let api = api();
        let people: Vec<(u64, String)> = (0..4).map(|_| register(&api)).collect();
        let kh = people[0].1.clone();
        let room = json_of(api.handle(req(
            "POST",
            "/room",
            json!({"key": kh, "name": "Friday", "tournament": 8}),
        )));
        let code = room["code"].as_str().unwrap().to_string();
        assert_eq!(room["tournament"]["state"], "open");
        assert_eq!(room["tournament"]["size"], 8);
        assert_eq!(room["max_spectators"], 16);
        // a 0.6 client (no `tournament` flag) is told to update
        let (_, old) = register(&api);
        let r = api.handle(req(
            "POST",
            &format!("/room/{code}/join"),
            json!({"key": old}),
        ));
        assert_eq!(r.status, 409);
        for (_, k) in &people[1..] {
            let v = json_of(api.handle(req(
                "POST",
                &format!("/room/{code}/join"),
                json!({"key": k, "tournament": true}),
            )));
            assert_eq!(v["side"], 3, "entrants watch until called");
            assert!(v["matchup"].is_null(), "joining starts no match");
        }
        let list = json_of(api.handle(req("GET", "/rooms", Value::Null)));
        assert_eq!(list[0]["tournament"]["entrants"], 4);
        // only the host starts
        let r = api.handle(req(
            "POST",
            &format!("/room/{code}/start"),
            json!({"key": people[1].1}),
        ));
        assert_eq!(r.status, 403);
        let v = json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/start"),
            json!({"key": kh}),
        )));
        let t = &v["tournament"];
        assert_eq!(t["state"], "running");
        assert_eq!(t["rounds"].as_array().unwrap().len(), 3);
        // equal ratings: seeds in join order; 4 players in 8 places: seeds
        // 1-4 face the empty places 8-5, so the semi-finals are called
        assert_eq!(t["live"], json!([1, 0]));
        let semi = &t["rounds"][1][0];
        assert_eq!(semi["state"], "called");
        let (p1, p2) = (semi["p1"].as_u64().unwrap(), semi["p2"].as_u64().unwrap());
        assert_eq!((p1, p2), (people[0].0, people[3].0), "1 v 4");
        let mid = semi["match_id"].as_u64().unwrap();
        let view = |k: &str| {
            json_of(api.handle(req("GET", &format!("/room/{code}?key={k}"), Value::Null)))
        };
        let key_of = |id: u64| people.iter().find(|p| p.0 == id).unwrap().1.clone();
        let v1 = view(&key_of(p1));
        assert_eq!(v1["side"], 1);
        assert_eq!(v1["matchup"]["id"].as_u64(), Some(mid));
        assert_eq!(v1["opponent"]["id"].as_u64(), Some(p2));
        assert_eq!(view(&key_of(p2))["side"], 2);
        assert_eq!(view(&people[1].1)["side"], 3);
        // both report P2 won 2-1: recorded with the score after the sweep
        for k in [key_of(p1), key_of(p2)] {
            json_of(api.handle(req(
                "POST",
                "/result",
                json!({"key": k, "match_id": mid, "winner": p2, "rounds": [1, 2]}),
            )));
        }
        api.sweep_tournaments();
        let t = view(&kh)["tournament"].clone();
        assert_eq!(t["rounds"][1][0]["winner"].as_u64(), Some(p2));
        assert_eq!(t["rounds"][1][0]["score"], json!([1, 2]));
        assert_eq!(t["rounds"][2][0]["p1"].as_u64(), Some(p2));
        assert!(t["live"].is_null(), "a pause before the next call");
        // skip the pause: the other semi-final is called
        for r in lock(&api.rooms).values_mut() {
            if let Some(t) = r.tournament.as_mut() {
                t.next_at = None;
            }
        }
        api.sweep_tournaments();
        let t = view(&kh)["tournament"].clone();
        assert_eq!(t["live"], json!([1, 1]));
        // its P2 leaves the room: a walkover for the one still here
        let semi2 = t["rounds"][1][1].clone();
        let (q1, q2) = (semi2["p1"].as_u64().unwrap(), semi2["p2"].as_u64().unwrap());
        json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/leave"),
            json!({"key": key_of(q2)}),
        )));
        api.sweep_tournaments();
        let t = view(&kh)["tournament"].clone();
        assert_eq!(t["rounds"][1][1]["winner"].as_u64(), Some(q1));
        for r in lock(&api.rooms).values_mut() {
            if let Some(t) = r.tournament.as_mut() {
                t.next_at = None;
            }
        }
        api.sweep_tournaments();
        let t = view(&kh)["tournament"].clone();
        assert_eq!(t["live"], json!([2, 0]), "the final");
        let fin = t["rounds"][2][0]["match_id"].as_u64().unwrap();
        for k in [key_of(p2), key_of(q1)] {
            json_of(api.handle(req(
                "POST",
                "/result",
                json!({"key": k, "match_id": fin, "winner": q1}),
            )));
        }
        api.sweep_tournaments();
        let t = view(&kh)["tournament"].clone();
        assert_eq!(t["state"], "done");
        assert_eq!(t["champion"].as_u64(), Some(q1));
    }

    /// A player shares a finished match: a short code, the stream from the
    /// reports when the live log is gone, the same code again, nobody else
    /// may share it, anyone may read it, its packages stay downloadable;
    /// expired replays go.
    #[test]
    fn finished_matches_are_shared_by_code() {
        let api = official_api();
        let (a, ka) = register(&api);
        let (b, kb) = register(&api);
        let (_, kc) = register(&api);
        let fp = "c".repeat(64);
        let setup = json!({"p1_fp": fp, "p2_fp": fp, "stage_fp": "d".repeat(64),
            "p1_char": "Naruto", "p2_char": "Sasuke", "rules": Rules::default(), "engine": "0.7.0"})
        .to_string();
        let s = api.store();
        let m = s.new_match([a, b], false, &setup).unwrap();
        let inputs: Vec<u8> = (0..400u32)
            .flat_map(|i| (i as u16).to_le_bytes().repeat(2))
            .collect();
        for (who, n) in [(a, 300 * 4), (b, 400 * 4)] {
            s.report(
                who,
                m,
                &ReportData {
                    winner: a,
                    inputs: inputs[..n].to_vec(),
                    ..Default::default()
                },
            )
            .unwrap();
        }
        let share =
            |k: &str| api.handle(req("POST", "/v1/replays", json!({"key": k, "match_id": m})));
        assert_eq!(share(&kc).status, 403, "not a player of it");
        let r = json_of(share(&ka));
        let code = r["code"].as_str().unwrap().to_string();
        assert_eq!(code.len(), 8);
        assert_eq!(r["title"], "NARUTO VS SASUKE");
        assert_eq!(r["frames"], 400, "the longest report");
        let days = (r["expires"].as_u64().unwrap() - crate::store::now()) / 86_400;
        assert!((29..=30).contains(&days), "{days}");
        assert_eq!(
            json_of(share(&kb))["code"],
            code.as_str(),
            "one code per match"
        );
        // anyone reads it, with any spelling of the code
        let shown = rugen_proto::stream::replay_code::display(&code).to_lowercase();
        let r = api.handle(req("GET", &format!("/v1/replays/{shown}"), Value::Null));
        assert_eq!(r.status, 200);
        let c = rugen_proto::stream::decode_chunk(&r.body).unwrap();
        assert!(c.ended);
        assert_eq!(c.inputs.len(), 400);
        assert_eq!(rugen_proto::stream::inputs_to_bytes(&c.inputs), inputs);
        let h = c.header.unwrap();
        assert_eq!((h.match_id, h.engine.as_str()), (m, "rugen 0.7.0"));
        assert_eq!(h.seed, rugen_proto::stream::online_seed(m));
        assert!(s.shared_has(&fp).unwrap());
        assert_eq!(s.shared_usage().unwrap(), (1, 1600));
        assert_eq!(
            api.handle(req("GET", "/v1/replays/AAAAAAAA", Value::Null))
                .status,
            404
        );
        assert_eq!(
            api.handle(req("GET", "/v1/replays/nope", Value::Null))
                .status,
            400
        );
        // the backup status counts them
        let st = json_of(api.handle(req("GET", "/v1/admin/backup/status?token=tok", Value::Null)));
        assert_eq!(st["shared_replays"]["count"], 1);
        // size cap, then expiry
        assert_eq!(s.sweep_shared(1 << 20).unwrap(), 0);
        assert_eq!(
            s.sweep_shared(100).unwrap(),
            1,
            "over the cap: the oldest goes"
        );
        assert!(!s.shared_has(&fp).unwrap());
        let m2 = s.new_match([a, b], false, &setup).unwrap();
        assert_eq!(
            share(&ka).status,
            200,
            "the first match again (its row went with the cap)"
        );
        let r = api.handle(req(
            "POST",
            "/v1/replays",
            json!({"key": ka, "match_id": m2}),
        ));
        assert_eq!(r.status, 404, "nobody reported inputs of this one");
    }

    fn official_api() -> Arc<Api> {
        api_truth(
            "official",
            TruthConfig {
                key: Some(SigningKey::dev()),
                official_key: Some(SigningKey::dev().public()),
                admin_token: Some("tok".into()),
                ..TruthConfig::default()
            },
        )
    }

    /// Serve `api` over HTTP on loopback (another server pulls from it).
    fn serve(api: Arc<Api>) -> (String, tokio::runtime::Runtime) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let listener = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let addr = listener.local_addr().unwrap();
        rt.spawn(async move { crate::http::serve(listener, api, std::future::pending()).await });
        (format!("http://{addr}"), rt)
    }

    fn blob(v: &Value) -> SignedBlob {
        serde_json::from_value(v.clone()).unwrap()
    }

    #[test]
    fn official_mode_signs_identity_verdicts_and_results() {
        let dev = SigningKey::dev().public();
        let kit = Kit::new();
        let api = official_api();
        let info = json_of(api.handle(req("GET", "/", Value::Null)));
        assert_eq!(info["official"], true);
        assert_eq!(info["key"], dev.hex());
        // identity: the caller's nonce, signed by the official key
        let nonce = "0123456789abcdef0123456789abcdef";
        let id = json_of(api.handle(req(
            "GET",
            &format!("/v1/identity?nonce={nonce}"),
            Value::Null,
        )));
        let (st, _) =
            rugen_fair::trust::open::<IdentityStatement>(&blob(&id), purpose::IDENTITY, Some(&dev))
                .unwrap();
        assert!(st.official && st.nonce == nonce);
        let r = api.handle(req("GET", "/v1/identity?nonce=xyz", Value::Null));
        assert_eq!(r.status, 400);
        // a ranked match: signed verdict, then a signed result
        let (aid, ka) = register(&api);
        let (bid, kb) = register(&api);
        json_of(api.handle(req("POST", "/queue", json!({"key": ka, "ranked": true}))));
        let f = json_of(api.handle(req("POST", "/queue", json!({"key": kb, "ranked": true}))));
        let mid = f["found"]["match_id"].as_u64().unwrap();
        let [va, _] = play_matchup(&api, mid, [&ka, &kb], &kit);
        let (vs, _) = rugen_fair::trust::open::<VerdictStatement>(
            &blob(&va["signed"]),
            purpose::VERDICT,
            Some(&dev),
        )
        .unwrap();
        assert_eq!(vs.match_id, mid);
        assert!(vs.ranked);
        assert_eq!(vs.verdict, rugen_proto::VerdictKind::Fair);
        assert_eq!(vs.fingerprints[0], kit.a.0.fingerprint);
        let inputs = "01000200".repeat(100);
        let mut acks = Vec::new();
        for k in [&ka, &kb] {
            acks.push(json_of(api.handle(req(
                "POST",
                "/result",
                json!({"key": k, "match_id": mid, "winner": aid, "inputs": inputs, "frames": 100, "checksum": 9}),
            ))));
        }
        assert!(acks[0]["signed"].is_null(), "first report: not settled yet");
        let (rs, _) = rugen_fair::trust::open::<ResultStatement>(
            &blob(&acks[1]["signed"]),
            purpose::RESULT,
            Some(&dev),
        )
        .unwrap();
        assert_eq!((rs.account, rs.winner, rs.players), (bid, aid, [aid, bid]));
        assert_eq!(rs.delta, acks[1]["delta"].as_i64().map(|d| d as i32));
        // the first reporter fetches its signed result later
        let late = json_of(api.handle(req(
            "GET",
            &format!("/match/{mid}/result?key={ka}"),
            Value::Null,
        )));
        let (rs, _) = rugen_fair::trust::open::<ResultStatement>(
            &blob(&late["signed"]),
            purpose::RESULT,
            Some(&dev),
        )
        .unwrap();
        assert_eq!(rs.account, aid);
        assert!(rs.rating.unwrap() > 1200 && rs.delta.unwrap() > 0);
        let r = api.handle(req(
            "GET",
            &format!("/match/{mid}/result?key={}", register(&api).1),
            Value::Null,
        ));
        assert_eq!(r.status, 404, "only the players");
    }

    fn bench_api(bench: bool, data: Option<&std::path::Path>) -> Arc<Api> {
        Api::new(
            Store::open(data).unwrap(),
            ApiConfig {
                name: "bench-test".into(),
                bench,
                data: data.map(std::path::Path::to_path_buf),
                truth: TruthConfig {
                    admin_token: Some("tok".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
            Arc::new(Relay::default()),
        )
    }

    #[test]
    fn bench_routes_need_the_env_and_the_token() {
        let off = bench_api(false, None);
        let start = json!({"token": "tok", "steps": [10]});
        for (m, p) in [("POST", "/admin/bench"), ("GET", "/admin/bench")] {
            assert_eq!(off.handle(req(m, p, start.clone())).status, 404, "{m} {p}");
        }
        // live stats exist without RUGEN_BENCH, the token still counts
        assert_eq!(
            off.handle(req("GET", "/admin/stats", json!({"token": "tok"})))
                .status,
            200
        );
        let on = bench_api(true, None);
        for token in [None, Some("wrong")] {
            let body = json!({"token": token, "steps": [10]});
            for (m, p) in [
                ("POST", "/admin/bench"),
                ("GET", "/admin/bench"),
                ("GET", "/admin/stats"),
                ("POST", "/v1/admin/bench"),
            ] {
                assert_eq!(on.handle(req(m, p, body.clone())).status, 401, "{m} {p}");
            }
        }
        let st = json_of(on.handle(req("GET", "/admin/bench", json!({"token": "tok"}))));
        assert_eq!(st["state"], "none");
        let stats = json_of(on.handle(req("GET", "/admin/stats", json!({"token": "tok"}))));
        for k in [
            "uptime_secs",
            "threads",
            "rss_mb",
            "cpu_pct",
            "req_s",
            "ws",
            "relay_sessions",
            "relay_pkt_s",
            "write_queue",
            "resim_queue",
        ] {
            assert!(stats.get(k).is_some(), "{k} in {stats}");
        }
    }

    #[test]
    fn bench_plans_are_limited() {
        let api = bench_api(true, None);
        for bad in [
            json!({"token": "tok"}),
            json!({"token": "tok", "steps": [5001]}),
            json!({"token": "tok", "steps": [100], "mix": "spicy"}),
            // 6 steps of 52 s: over 5 minutes
            json!({"token": "tok", "steps": [1, 2, 3, 4, 5, 6]}),
        ] {
            assert_eq!(
                api.handle(req("POST", "/admin/bench", bad.clone())).status,
                400,
                "{bad}"
            );
        }
        let st = json_of(api.handle(req("GET", "/admin/bench", json!({"token": "tok"}))));
        assert_eq!(st["state"], "none", "nothing started");
    }

    #[test]
    fn a_bench_runs_alone_on_its_own_data_and_cleans_up() {
        let data = std::env::temp_dir().join(format!("rugen-bench-main-{}", random_code()));
        std::fs::create_dir_all(&data).unwrap();
        let api = bench_api(true, Some(&data));
        let a = api.store().register().unwrap();
        let listing = |d: &std::path::Path| -> Vec<(String, u64)> {
            let mut v: Vec<(String, u64)> = walk(d);
            v.sort();
            v
        };
        fn walk(d: &std::path::Path) -> Vec<(String, u64)> {
            let mut out = Vec::new();
            for e in std::fs::read_dir(d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    out.extend(walk(&p));
                } else {
                    let m = e.metadata().unwrap();
                    let t = m
                        .modified()
                        .unwrap()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64;
                    out.push((p.display().to_string(), t));
                }
            }
            out
        }
        // settle the main database's files before looking at them
        std::thread::sleep(Duration::from_millis(50));
        let before = listing(&data);
        let accounts = api.store().account_count().unwrap();
        let plan =
            json!({"token": "tok", "steps": [4], "viewers": 6, "hold_secs": 6, "ramp_secs": 0});
        let r = api.handle(req("POST", "/admin/bench", plan.clone()));
        assert_eq!(r.status, 202);
        let id = serde_json::from_slice::<Value>(&r.body).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            api.handle(req("POST", "/admin/bench", plan)).status,
            409,
            "one run at a time"
        );
        let t = Instant::now();
        let st = loop {
            let st = json_of(api.handle(req("GET", "/admin/bench", json!({"token": "tok"}))));
            if st["state"] != "running" {
                break st;
            }
            assert!(t.elapsed() < Duration::from_secs(90), "bench never ended");
            std::thread::sleep(Duration::from_millis(200));
        };
        assert_eq!(st["state"], "done", "{st}");
        assert_eq!(st["id"], id.as_str());
        let row = &st["rows"][0];
        assert_eq!(row["clients"], 4);
        assert_eq!(row["viewers"], 6);
        assert_eq!(st["viewers"], json!([6]));
        assert!(row["req_s"].as_f64().unwrap() > 0.0, "{row}");
        assert!(st["note"].as_str().unwrap().contains("lower bound"));
        // its temporary directory is gone, the real data untouched
        assert!(
            !std::env::temp_dir()
                .join(format!("rugen-bench-{id}"))
                .exists()
        );
        assert_eq!(
            listing(&data),
            before,
            "nothing written to the data directory"
        );
        assert_eq!(api.store().account_count().unwrap(), accounts);
        assert!(api.store().by_key(&a.key).unwrap().is_some());
        drop(api);
        let _ = std::fs::remove_dir_all(&data);
    }

    #[test]
    fn admin_blocks_and_unblocks_with_a_token() {
        let kit = Kit::new();
        let fp = kit.b.0.fingerprint.clone();
        let api = official_api();
        let block = |token: &str| {
            api.handle(req(
                "POST",
                "/v1/admin/block",
                json!({"token": token, "fingerprint": fp, "reason": "infinite regen"}),
            ))
        };
        assert_eq!(block("wrong").status, 403);
        assert_eq!(block("").status, 403);
        let r = json_of(block("tok"));
        assert_eq!(r["blocked"][0]["fingerprint"], fp.as_str());
        assert_eq!(r["blocked"][0]["source"], "admin");
        // the feed carries it, signed by the official key
        let feed = json_of(api.handle(req("GET", "/v1/truth", Value::Null)));
        let f = rugen_fair::trust::open_feed(
            &blob(&feed),
            &SigningKey::dev().public(),
            rugen_fair::trust::now(),
            0,
        )
        .unwrap();
        assert_eq!(f.blocked.len(), 1);
        assert_eq!(f.blocked[0].reason, "infinite regen");
        // a matchup on the official server is BLOCKED with the official reason
        let (_, ka) = register(&api);
        let (_, kb) = register(&api);
        json_of(api.handle(req("POST", "/queue", json!({"key": ka}))));
        let q = json_of(api.handle(req("POST", "/queue", json!({"key": kb}))));
        let id = q["found"]["match_id"].as_u64().unwrap();
        pick(&api, id, &ka, &kit.a.0, Some(&kit.stage.0));
        let v = pick(&api, id, &kb, &kit.b.0, None);
        assert_eq!(v["verdict"]["kind"], "blocked", "{v}");
        assert_eq!(
            v["verdict"]["reasons"][0],
            "BETA: blocked by the official server (infinite regen)"
        );
        // unblock: the live matchup is judged again
        let r = json_of(api.handle(req(
            "POST",
            "/v1/admin/unblock",
            json!({"token": "tok", "fingerprint": fp}),
        )));
        assert!(r["blocked"].as_array().unwrap().is_empty());
        let v = json_of(api.handle(req("GET", &format!("/matchup/{id}?key={ka}"), Value::Null)));
        assert_eq!(v["verdict"]["kind"], "fair", "{v}");
        let list = json_of(api.handle(req("GET", "/v1/admin/blocklist?token=tok", Value::Null)));
        assert_eq!(list["official"], true);
        // no token configured: the admin API does not exist
        let community = api_truth("c", TruthConfig::default());
        let r = community.handle(req(
            "POST",
            "/v1/admin/block",
            json!({"token": "", "fingerprint": fp}),
        ));
        assert_eq!(r.status, 404);
    }

    /// Two servers in process: the official one blocks a fingerprint, the
    /// community one pulls the signed feed over HTTP and enforces it.
    #[test]
    fn community_server_enforces_the_pulled_official_blocklist() {
        let kit = Kit::new();
        let official = official_api();
        json_of(official.handle(req(
            "POST",
            "/v1/admin/block",
            json!({"token": "tok", "fingerprint": kit.b.0.fingerprint, "reason": "wallhack"}),
        )));
        let (url, _rt) = serve(official.clone());
        let community = api_truth(
            "community",
            TruthConfig {
                key: Some(SigningKey::generate().unwrap()),
                official_key: Some(SigningKey::dev().public()),
                official_url: Some(url.clone()),
                ..TruthConfig::default()
            },
        );
        let info = json_of(community.handle(req("GET", "/", Value::Null)));
        assert_eq!(info["official"], false);
        assert_ne!(info["key"], SigningKey::dev().public().hex());
        // nothing held yet: the matchup is fair
        let (_, ka) = register(&community);
        let (_, kb) = register(&community);
        let room = json_of(community.handle(req("POST", "/room", json!({"key": ka}))));
        let code = room["code"].as_str().unwrap().to_string();
        let joined = json_of(community.handle(req(
            "POST",
            &format!("/room/{code}/join"),
            json!({"key": kb}),
        )));
        let id = joined["matchup"]["id"].as_u64().unwrap();
        pick(&community, id, &ka, &kit.a.0, Some(&kit.stage.0));
        let v = pick(&community, id, &kb, &kit.b.0, None);
        assert_eq!(v["verdict"]["kind"], "fair");
        // pull: the live matchup turns BLOCKED, signed by the community key
        let f = community.pull_official().unwrap();
        assert_eq!(f.blocked.len(), 1);
        let v =
            json_of(community.handle(req("GET", &format!("/matchup/{id}?key={ka}"), Value::Null)));
        assert_eq!(v["verdict"]["kind"], "blocked", "{v}");
        assert_eq!(
            v["verdict"]["reasons"][0],
            "BETA: blocked by the official server (wallhack)"
        );
        let signed = blob(&v["signed"]);
        let community_key = PublicKey::parse(info["key"].as_str().unwrap()).unwrap();
        assert!(rugen_fair::trust::verify(&signed, purpose::VERDICT, Some(&community_key)).is_ok());
        assert!(
            rugen_fair::trust::verify(&signed, purpose::VERDICT, Some(&SigningKey::dev().public()))
                .is_err(),
            "a community verdict never passes as official"
        );
        let r = community.handle(req(
            "POST",
            &format!("/matchup/{id}/accept"),
            json!({"key": ka}),
        ));
        assert_eq!(r.status, 409);
        // the community server mirrors the verified official blob verbatim
        let mirror = json_of(community.handle(req("GET", "/v1/truth/official", Value::Null)));
        assert!(
            rugen_fair::trust::open_feed(
                &blob(&mirror),
                &SigningKey::dev().public(),
                rugen_fair::trust::now(),
                0
            )
            .is_ok()
        );
        // a server pretending to be official (own key) is rejected
        let rogue = api_truth(
            "rogue",
            TruthConfig {
                key: Some(SigningKey::generate().unwrap()),
                official_key: Some(SigningKey::dev().public()),
                ..TruthConfig::default()
            },
        );
        let (rogue_url, _rt2) = serve(rogue);
        let victim = api_truth(
            "victim",
            TruthConfig {
                key: Some(SigningKey::generate().unwrap()),
                official_key: Some(SigningKey::dev().public()),
                official_url: Some(rogue_url),
                ..TruthConfig::default()
            },
        );
        let e = victim.pull_official().unwrap_err();
        assert!(e.contains("rejected"), "{e}");
        assert!(victim.truth.official_feed().is_none());
    }

    #[test]
    fn automatic_blocks_from_analysis_and_liars() {
        let root = tmp("auto");
        let cheat = declare(
            &tiny_char(
                &root.join("cheat"),
                "Cheater",
                "[Statedef -2]\n[State -2, regen]\ntype = LifeAdd\ntrigger1 = Life < LifeMax\nvalue = 10\n",
            ),
            Kind::Char,
        );
        let fair = declare(&tiny_char(&root.join("fair"), "Fair", ""), Kind::Char);
        let stage = declare(&tiny_stage(&root.join("s")), Kind::Stage);
        let api = official_api();
        let (_, ka) = register(&api);
        let (_, kb) = register(&api);
        let room = json_of(api.handle(req("POST", "/room", json!({"key": ka}))));
        let code = room["code"].as_str().unwrap().to_string();
        let joined = json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/join"),
            json!({"key": kb}),
        )));
        let id = joined["matchup"]["id"].as_u64().unwrap();
        pick(&api, id, &ka, &fair.0, Some(&stage.0));
        pick(&api, id, &kb, &cheat.0, None);
        // the cheater's package reaches the server: its own analysis blocks it
        let _ = upload(&api, &kb, &cheat.0, &cheat.1, 1 << 20);
        let b = api.store.blocked(&cheat.0.fingerprint).unwrap().unwrap();
        assert_eq!(b.source, "auto");
        assert!(b.reason.starts_with("auto: regen"), "{}", b.reason);
        // three different players lying about the same fighter
        let s = &api.store;
        for acc in [11, 12, 13] {
            s.flag(acc, None, "lie", Some(&fair.0.fingerprint)).unwrap();
            assert!(
                api.auto_block(s, &fair.0.fingerprint, AutoCause::Liar)
                    .is_ok()
            );
        }
        assert!(
            s.blocked(&fair.0.fingerprint)
                .unwrap()
                .unwrap()
                .reason
                .contains("3 players")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A private room with a started match; returns (room code, match id).
    fn started_room(api: &Api, ka: &str, kb: &str, kit: &Kit) -> (String, u64) {
        let room = json_of(api.handle(req("POST", "/room", json!({"key": ka, "public": false}))));
        let code = room["code"].as_str().unwrap().to_string();
        let joined = json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/join"),
            json!({"key": kb}),
        )));
        let id = joined["matchup"]["id"].as_u64().unwrap();
        play_matchup(api, id, [ka, kb], kit);
        (code, id)
    }

    #[test]
    fn flee_claims_settle_on_the_relays_view_only() {
        use crate::relay::Route;
        use rugen_proto::relay::{self as wire, Header};
        let kit = Kit::new();
        let api = api();
        let (aid, ka) = register(&api);
        let (bid, kb) = register(&api);
        let (_, id) = started_room(&api, &ka, &kb, &kit);
        let run = lock(&api.matchups)
            .get(&id)
            .and_then(|m| m.started.clone())
            .unwrap();
        let send = |slot: u8, kind: u8, at: Instant| {
            let p = wire::encode_client(
                Header {
                    kind,
                    from: slot,
                    to: 0,
                    session: run.session,
                },
                &run.tokens[slot as usize],
                &[],
            );
            let from = Route::Udp(
                format!("127.0.0.1:{}", 9100 + u16::from(slot))
                    .parse()
                    .unwrap(),
            );
            api.relay.on_packet(&p, &from, at);
        };
        let t0 = Instant::now();
        send(0, wire::HELLO, t0);
        send(1, wire::HELLO, t0);
        let result = |k: &str| {
            json_of(api.handle(req(
                "GET",
                &format!("/match/{id}/result?key={k}"),
                Value::Null,
            )))
        };
        // a says b fled, but the relay still hears b: nothing moves
        let ack = json_of(api.handle(req(
            "POST",
            "/result",
            json!({"key": ka, "match_id": id, "winner": aid, "ending": "flee"}),
        )));
        assert_eq!(ack["accepted"], true);
        assert!(ack["delta"].is_null(), "{ack}");
        api.store.age_reports(id, 60).unwrap();
        api.sweep_claims();
        assert!(result(&ka)["delta"].is_null(), "b is still connected");
        // b's BYE reaches the relay, a stays connected: settled for a
        send(1, wire::BYE, t0 + Duration::from_secs(1));
        send(0, wire::HELLO, t0 + Duration::from_secs(4));
        api.sweep_claims();
        let r = result(&ka);
        assert_eq!(r["delta"], 0, "casual: no rating, {r}");
        assert_eq!(r["ending"], "flee");
        assert_eq!(r["fled"], bid);
        let rb = result(&kb);
        assert_eq!(rb["fled"], bid);
        assert_eq!(rb["ending"], "flee");
        // a late report from b changes nothing
        let late = json_of(api.handle(req(
            "POST",
            "/result",
            json!({"key": kb, "match_id": id, "winner": bid}),
        )));
        assert_eq!(late["ending"], "flee");
        assert_eq!(result(&ka)["fled"], bid);
    }

    #[test]
    fn a_fresh_claim_waits_for_the_other_report() {
        use crate::relay::Route;
        use rugen_proto::relay::{self as wire, Header};
        let kit = Kit::new();
        let api = api();
        let (aid, ka) = register(&api);
        let (bid, kb) = register(&api);
        let (_, id) = started_room(&api, &ka, &kb, &kit);
        let run = lock(&api.matchups)
            .get(&id)
            .and_then(|m| m.started.clone())
            .unwrap();
        let t0 = Instant::now();
        for (slot, kind, at) in [
            (0u8, wire::HELLO, t0),
            (1, wire::HELLO, t0),
            (1, wire::BYE, t0 + Duration::from_secs(1)),
            (0, wire::HELLO, t0 + Duration::from_secs(5)),
        ] {
            let p = wire::encode_client(
                Header {
                    kind,
                    from: slot,
                    to: 0,
                    session: run.session,
                },
                &run.tokens[slot as usize],
                &[],
            );
            let from = Route::Udp(
                format!("127.0.0.1:{}", 9200 + u16::from(slot))
                    .parse()
                    .unwrap(),
            );
            api.relay.on_packet(&p, &from, at);
        }
        json_of(api.handle(req(
            "POST",
            "/result",
            json!({"key": ka, "match_id": id, "winner": aid, "ending": "disconnect"}),
        )));
        // the relay agrees, but the claim is younger than the grace period
        api.sweep_claims();
        assert_eq!(api.store.pending_claims().unwrap().len(), 1);
        // the other report says the claimant lost: a dispute, never a win
        let r = json_of(api.handle(req(
            "POST",
            "/result",
            json!({"key": kb, "match_id": id, "winner": bid}),
        )));
        assert_eq!(r["accepted"], true);
        assert_eq!(r["disputed"], true);
        assert!(api.store.pending_claims().unwrap().is_empty());
    }

    #[test]
    fn left_first_needs_the_other_slot_gone_before_the_claimant() {
        use crate::relay::Presence;
        let t = Instant::now();
        let p = |joined, heard: u64, bye| Presence {
            joined,
            heard: t + Duration::from_secs(heard),
            bye,
        };
        let now = t + Duration::from_secs(30);
        assert!(
            left_first(&p(true, 5, false), &p(true, 1, true), now),
            "bye"
        );
        assert!(
            left_first(&p(true, 20, false), &p(true, 1, false), now),
            "silent for long"
        );
        assert!(
            !left_first(&p(true, 2, false), &p(true, 1, true), now),
            "left together"
        );
        assert!(
            !left_first(&p(true, 25, false), &p(true, 24, false), now),
            "still heard"
        );
        assert!(
            !left_first(&p(true, 5, false), &p(false, 0, false), now),
            "never joined"
        );
        assert!(
            !left_first(&p(true, 1, true), &p(true, 5, true), now),
            "the claimant left first"
        );
    }

    #[test]
    fn queue_pairs_flag_high_ping_additively() {
        let api = api();
        let (_, ka) = register(&api);
        let (_, kb) = register(&api);
        // far apart: no pair inside the first windows
        json_of(api.handle(req(
            "POST",
            "/queue",
            json!({"key": ka, "ranked": false, "rtt_ms": 150}),
        )));
        let st = json_of(api.handle(req(
            "POST",
            "/queue",
            json!({"key": kb, "ranked": false, "rtt_ms": 120}),
        )));
        assert!(st["found"].is_null(), "270 ms is outside the first window");
        // after 30 s anything goes, flagged
        for e in lock(&api.queue).iter_mut() {
            e.since = Instant::now() - Duration::from_secs(31);
        }
        let st = json_of(api.handle(req("GET", &format!("/queue?key={kb}"), Value::Null)));
        assert_eq!(st["found"]["high_ping"], true, "{st}");
        assert_eq!(st["found"]["est_ping_ms"], 270);
        assert_eq!(st["found"]["matchup"]["high_ping"], true);
        assert_eq!(st["found"]["matchup"]["est_ping_ms"], 270);
        let id = st["found"]["match_id"].as_u64().unwrap();
        let st = json_of(api.handle(req("GET", &format!("/queue?key={ka}"), Value::Null)));
        assert_eq!(st["found"]["high_ping"], true);
        let v = json_of(api.handle(req("GET", &format!("/matchup/{id}?key={ka}"), Value::Null)));
        assert_eq!(
            (v["high_ping"].clone(), v["phase"].clone()),
            (json!(true), json!("pick"))
        );
        // older clients parse the typed payload unchanged
        let typed: rugen_proto::MatchupView = serde_json::from_value(v).unwrap();
        assert_eq!(typed.id, id);

        // close players: no flag
        let (_, kc) = register(&api);
        let (_, kd) = register(&api);
        json_of(api.handle(req(
            "POST",
            "/queue",
            json!({"key": kc, "ranked": false, "rtt_ms": 20}),
        )));
        let st = json_of(api.handle(req(
            "POST",
            "/queue",
            json!({"key": kd, "ranked": false, "rtt_ms": 30}),
        )));
        assert_eq!(st["found"]["high_ping"], false, "{st}");
        assert_eq!(st["found"]["matchup"]["est_ping_ms"], 50);
    }

    #[test]
    fn relay_sessions_close_with_results_and_rooms() {
        let kit = Kit::new();
        let api = api();
        let (aid, ka) = register(&api);
        let (_, kb) = register(&api);
        // a player leaving the room ends its match
        let (code, _) = started_room(&api, &ka, &kb, &kit);
        assert_eq!(api.relay.session_count(), 1);
        json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/leave"),
            json!({"key": kb}),
        )));
        assert_eq!(api.relay.session_count(), 0, "challenger left");
        // both results in: the session closes
        let (code, id) = started_room(&api, &ka, &kb, &kit);
        assert_eq!(api.relay.session_count(), 1);
        let report = |k: &str| {
            json_of(api.handle(req(
                "POST",
                "/result",
                json!({"key": k, "match_id": id, "winner": aid}),
            )))
        };
        assert_eq!(report(&ka)["accepted"], true);
        assert_eq!(
            api.relay.session_count(),
            1,
            "one report: the other may still play"
        );
        assert_eq!(report(&kb)["accepted"], true);
        assert_eq!(api.relay.session_count(), 0);
        // the host leaving closes the room and its (rematch) session
        json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/rematch"),
            json!({"key": ka}),
        )));
        let v = json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/rematch"),
            json!({"key": kb}),
        )));
        let id = v["matchup"]["id"].as_u64().unwrap();
        play_matchup(&api, id, [&ka, &kb], &kit);
        assert_eq!(api.relay.session_count(), 1);
        json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/leave"),
            json!({"key": ka}),
        )));
        assert_eq!(api.relay.session_count(), 0, "room closed");
    }

    #[test]
    fn players_of_a_live_match_do_not_time_out() {
        let kit = Kit::new();
        let api = api();
        let (_, ka) = register(&api);
        let (_, kb) = register(&api);
        let (code, _) = started_room(&api, &ka, &kb, &kit);
        let silent = || {
            for m in lock(&api.rooms).get_mut(&code).unwrap().members.iter_mut() {
                m.last_seen = Instant::now() - Duration::from_secs(MEMBER_TIMEOUT_SECS + 5);
            }
        };
        // nobody polled for longer than the timeout, but the match runs
        silent();
        json_of(api.handle(req("GET", "/rooms", Value::Null)));
        assert_eq!(lock(&api.rooms)[&code].members.len(), 2);
        // the relay session is gone (match over): they time out, the room closes
        let session = lock(&api.rooms)[&code].running.as_ref().unwrap().session;
        api.relay.close(session);
        silent();
        json_of(api.handle(req("GET", "/rooms", Value::Null)));
        assert!(!lock(&api.rooms).contains_key(&code));
    }

    /// A match longer than the member timeout (nobody polls the room while
    /// fighting) keeps both players in the room once the results settle it:
    /// REMATCH needs the challenger still there.
    #[test]
    fn players_stay_in_the_room_after_a_long_match() {
        let kit = Kit::new();
        let api = api();
        let (aid, ka) = register(&api);
        let (_, kb) = register(&api);
        let (code, id) = started_room(&api, &ka, &kb, &kit);
        // a long fight: the last poll is older than the timeout
        for m in lock(&api.rooms).get_mut(&code).unwrap().members.iter_mut() {
            m.last_seen = Instant::now() - Duration::from_secs(MEMBER_TIMEOUT_SECS + 30);
        }
        for k in [&ka, &kb] {
            json_of(api.handle(req(
                "POST",
                "/result",
                json!({"key": k, "match_id": id, "winner": aid}),
            )));
        }
        assert_eq!(api.relay.session_count(), 0, "settled, session closed");
        json_of(api.handle(req("GET", "/rooms", Value::Null)));
        assert_eq!(lock(&api.rooms)[&code].members.len(), 2, "challenger kept");
        json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/rematch"),
            json!({"key": ka}),
        )));
        let v = json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/rematch"),
            json!({"key": kb}),
        )));
        assert!(v["matchup"]["id"].as_u64().is_some_and(|n| n != id), "{v}");
    }

    #[test]
    fn health_is_cached_and_counts_running_matches_only() {
        let api = api();
        let h = json_of(api.handle(req("GET", "/health", Value::Null)));
        assert_eq!(
            (h["matches"].clone(), h["rooms"].clone()),
            (json!(0), json!(0))
        );
        let (_, ka) = register(&api);
        json_of(api.handle(req("POST", "/room", json!({"key": ka}))));
        // within the cache period: the same body
        let h = json_of(api.handle(req("GET", "/health", Value::Null)));
        assert_eq!(h["rooms"], 0);
        *lock(&api.health) = None;
        let h = json_of(api.handle(req("GET", "/health", Value::Null)));
        assert_eq!(h["rooms"], 1);
        assert_eq!(h["online"], 1, "seen in memory, no table scan");
        // a session nobody connected to is not a running match
        api.relay.create(&[1, 2]).unwrap();
        *lock(&api.health) = None;
        let h = json_of(api.handle(req("GET", "/health", Value::Null)));
        assert_eq!(
            (h["matches"].clone(), h["relay"]["sessions"].clone()),
            (json!(0), json!(1))
        );
    }

    // ---- API 4 (rugen 0.5) and API 5 (rugen 0.6) clients on one server

    fn status_err(r: Response, status: u16) -> String {
        assert_eq!(r.status, status, "{}", String::from_utf8_lossy(&r.body));
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        v["error"].as_str().unwrap().to_string()
    }

    fn create(api: &Api, key: &str, name: &str) -> String {
        let r = json_of(api.handle(req(
            "POST",
            "/room",
            json!({"key": key, "char": "kfm", "name": name}),
        )));
        r["code"].as_str().unwrap().to_string()
    }

    #[test]
    fn api4_clients_keep_their_whole_flow() {
        // what a 0.5 client sends: no API header, RGPK packages, rugen-fp-1
        client_api(4);
        let kit = Kit::legacy();
        let api = api();
        let info = json_of(api.handle(req("GET", "/health", Value::Null)));
        assert_eq!(
            (info["api"].as_u64(), info["api_min"].as_u64()),
            (Some(5), Some(4))
        );
        // still parses as the typed ServerInfo the old client decodes
        let _: ServerInfo = serde_json::from_value(info).unwrap();
        let (aid, ka) = register(&api);
        let (_, kb) = register(&api);
        // a room: create, list, join, matchup with uploads, start, download
        let code = create(&api, &ka, "OLD SCHOOL");
        let rooms = json_of(api.handle(req("GET", "/rooms", Value::Null)));
        assert_eq!(rooms[0]["name"], "OLD SCHOOL");
        let _: Vec<RoomSummary> = serde_json::from_value(rooms).unwrap();
        let joined = json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/join"),
            json!({"key": kb, "char": "kfm"}),
        )));
        let mid = joined["matchup"]["id"].as_u64().unwrap();
        let [va, _] = play_matchup(&api, mid, [&ka, &kb], &kit);
        assert!(va["ticket"]["token"].is_string());
        for (d, _) in [&kit.a, &kit.b, &kit.stage] {
            assert!(api.packages.is_legacy(&d.fingerprint), "kept as RGPK");
        }
        let fp = &kit.a.0.fingerprint;
        let r = api.handle(req("GET", &format!("/pkg/{fp}/data?key={kb}"), Value::Null));
        assert_eq!(
            r.body, kit.a.1,
            "the opponent gets the RGPK bytes unchanged"
        );
        // the same player on a 0.6 client could not read it
        client_api(5);
        let why = status_err(
            api.handle(req("GET", &format!("/pkg/{fp}/data?key={kb}"), Value::Null)),
            409,
        );
        assert!(why.contains("OLDER RUGEN (0.5)"), "{why}");
        client_api(4);
        // results settle and rate the rugen-fp-1 fingerprints
        for k in [&ka, &kb] {
            json_of(api.handle(req(
                "POST",
                "/result",
                json!({"key": k, "match_id": mid, "winner": aid, "frames": 100, "checksum": 9}),
            )));
        }
        let ca = json_of(api.handle(req("GET", &format!("/char/{fp}"), Value::Null)));
        assert_eq!(ca["games"], 1);
        // the ranked queue pairs two 0.5 clients, and known packages are reused
        let (_, kc) = register(&api);
        let (_, kd) = register(&api);
        json_of(api.handle(req("POST", "/queue", json!({"key": kc}))));
        let fd = json_of(api.handle(req("POST", "/queue", json!({"key": kd}))));
        let mid = fd["found"]["match_id"].as_u64().unwrap();
        play_matchup(&api, mid, [&kc, &kd], &kit);
        // a lying 0.5 client is still caught by its rugen-fp-1
        let (_, ke) = register(&api);
        let (_, kf) = register(&api);
        let code = create(&api, &ke, "LIARS");
        let j = json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/join"),
            json!({"key": kf, "char": "kfm"}),
        )));
        let mid = j["matchup"]["id"].as_u64().unwrap();
        let root = tmp("legacy-liar");
        let (mut d, pkg) = declare_legacy(&tiny_char(&root, "Gamma", "; g\n"), Kind::Char);
        let real = d.fingerprint.clone();
        d.fingerprint = kit
            .b
            .0
            .fingerprint
            .replace(&kit.b.0.fingerprint[..4], "0000");
        pick(&api, mid, &ke, &d, Some(&kit.stage.0));
        let why = status_err(upload(&api, &ke, &d, &pkg, 1 << 20), 422);
        assert!(why.contains("do not match"), "{why}");
        assert!(!api.packages.has(&real));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn api5_clients_use_rgc_and_each_generation_refuses_the_others_package() {
        let kit = Kit::new();
        let api = api();
        let (_, ka) = register(&api);
        let (_, kb) = register(&api);
        let code = create(&api, &ka, "NEW");
        let j = json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/join"),
            json!({"key": kb, "char": "kfm"}),
        )));
        let mid = j["matchup"]["id"].as_u64().unwrap();
        play_matchup(&api, mid, [&ka, &kb], &kit);
        let fp = &kit.a.0.fingerprint;
        assert!(!api.packages.is_legacy(fp));
        assert!(
            api.packages
                .path(fp)
                .extension()
                .is_some_and(|e| e == "rgc")
        );
        assert!(
            api.packages
                .path(&kit.stage.0.fingerprint)
                .extension()
                .is_some_and(|e| e == "rgs")
        );
        // a 0.5 client never gets an .rgc
        client_api(4);
        let why = status_err(
            api.handle(req("GET", &format!("/pkg/{fp}/data?key={kb}"), Value::Null)),
            409,
        );
        assert!(why.contains("NEWER RUGEN (0.6)"), "{why}");
        // uploads in the other generation's format are refused with a reason
        // (fresh content: nothing the server already holds)
        let old = Kit::legacy();
        let root = tmp("fresh-rgc");
        let fresh = Kit {
            a: declare(&tiny_char(&root.join("a"), "Delta", "; d\n"), Kind::Char),
            b: declare(&tiny_char(&root.join("b"), "Echo", "; e\n"), Kind::Char),
            stage: declare(&tiny_stage(&root.join("s")), Kind::Stage),
            root,
        };
        for (api_of, kit_of, code_name) in [(5, &old, "X"), (4, &fresh, "Y")] {
            client_api(api_of);
            let (_, kc) = register(&api);
            let (_, kd) = register(&api);
            let code = create(&api, &kc, code_name);
            let j = json_of(api.handle(req(
                "POST",
                &format!("/room/{code}/join"),
                json!({"key": kd, "char": "kfm"}),
            )));
            let mid = j["matchup"]["id"].as_u64().unwrap();
            pick(&api, mid, &kc, &kit_of.a.0, Some(&kit_of.stage.0));
            let why = status_err(upload(&api, &kc, &kit_of.a.0, &kit_of.a.1, 1 << 20), 400);
            if api_of == 5 {
                assert!(why.contains("older rugen (0.5)"), "{why}");
            } else {
                assert!(why.contains("did not announce API 5"), "{why}");
            }
        }
    }

    #[test]
    fn rooms_refuse_players_of_the_other_api_with_a_reason() {
        let api = api();
        client_api(4);
        let (_, old_host) = register(&api);
        let (_, old_guest) = register(&api);
        let old_room = create(&api, &old_host, "CLASSIC");
        client_api(5);
        let (_, new_host) = register(&api);
        let (_, new_guest) = register(&api);
        let new_room = create(&api, &new_host, "SHINY");
        // a 0.6 player joining a 0.5 host, as challenger or spectator
        for spectate in [false, true] {
            let why = status_err(
                api.handle(req(
                    "POST",
                    &format!("/room/{old_room}/join"),
                    json!({"key": new_guest, "char": "kfm", "spectate": spectate}),
                )),
                409,
            );
            assert_eq!(
                why,
                "THIS ROOM'S HOST RUNS AN OLDER RUGEN (0.5). BOTH PLAYERS NEED THE SAME VERSION."
            );
        }
        // the 0.6 lobby lists both, its own first, each with its api
        let rooms = json_of(api.handle(req("GET", "/rooms", Value::Null)));
        assert_eq!(rooms[0]["name"], "SHINY");
        assert_eq!(rooms[0]["api"], 5);
        assert_eq!(rooms[1]["name"], "CLASSIC");
        assert_eq!(rooms[1]["api"], 4);
        // a 0.5 player joining a 0.6 host
        client_api(4);
        let why = status_err(
            api.handle(req(
                "POST",
                &format!("/room/{new_room}/join"),
                json!({"key": old_guest, "char": "kfm"}),
            )),
            409,
        );
        assert!(
            why.contains("NEWER RUGEN (0.6)") && why.contains("UPDATE YOUR GAME"),
            "{why}"
        );
        // the 0.5 lobby marks the newer room in its name and lists it last
        let rooms = json_of(api.handle(req("GET", "/rooms", Value::Null)));
        assert_eq!(rooms[0]["name"], "CLASSIC");
        assert_eq!(rooms[1]["name"], "[0.6] SHINY");
        // same-API joins still work, and nothing was started by the refusals
        let j = json_of(api.handle(req(
            "POST",
            &format!("/room/{old_room}/join"),
            json!({"key": old_guest, "char": "kfm"}),
        )));
        assert_eq!(j["side"], 2);
        let host = json_of(api.handle(req(
            "GET",
            &format!("/room/{new_room}?key={new_host}"),
            Value::Null,
        )));
        assert!(host["matchup"].is_null());
        assert_eq!(host["members"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn the_queue_never_pairs_different_apis() {
        let api = api();
        for ranked in [true, false] {
            client_api(4);
            let (old_a, old_b) = (register(&api).1, register(&api).1);
            client_api(5);
            let (new_a, new_b) = (register(&api).1, register(&api).1);
            client_api(4);
            json_of(api.handle(req(
                "POST",
                "/queue",
                json!({"key": old_a, "ranked": ranked}),
            )));
            client_api(5);
            let st = json_of(api.handle(req(
                "POST",
                "/queue",
                json!({"key": new_a, "ranked": ranked}),
            )));
            assert!(st["found"].is_null(), "mixed APIs paired: {st}");
            assert_eq!(st["players_in_queue"], 2);
            // a partner of each API arrives: each meets its own
            let st = json_of(api.handle(req(
                "POST",
                "/queue",
                json!({"key": new_b, "ranked": ranked}),
            )));
            let new_match = st["found"]["match_id"].as_u64().unwrap();
            client_api(4);
            let st = json_of(api.handle(req(
                "POST",
                "/queue",
                json!({"key": old_b, "ranked": ranked}),
            )));
            let old_match = st["found"]["match_id"].as_u64().unwrap();
            assert_ne!(old_match, new_match);
            let id = |k: &str| api.store.by_key(k).unwrap().unwrap().id;
            let ms = lock(&api.matchups);
            for (m, keys) in [(old_match, [&old_a, &old_b]), (new_match, [&new_a, &new_b])] {
                let mut want = [id(keys[0]), id(keys[1])];
                let mut got = ms[&m].players;
                want.sort_unstable();
                got.sort_unstable();
                assert_eq!(got, want);
            }
        }
    }

    // ---- named accounts (API 5)

    fn account(api: &Api, op: &str, body: Value) -> Response {
        api.handle(req("POST", &format!("/v1/account/{op}"), body))
    }

    fn signup(api: &Api, user: &str, pw: &str) -> Value {
        json_of(account(
            api,
            "register",
            json!({"username": user, "password": pw}),
        ))
    }

    fn login(api: &Api, user: &str, pw: &str) -> Response {
        account(api, "login", json!({"username": user, "password": pw}))
    }

    fn key_works(api: &Api, key: &str) -> bool {
        api.handle(req("GET", &format!("/v1/account?key={key}"), Value::Null))
            .status
            == 200
    }

    #[test]
    fn register_login_and_username_rules() {
        let api = api();
        let info = json_of(api.handle(req("GET", "/health", Value::Null)));
        assert_eq!(info["accounts"], true);
        let s = signup(&api, "Axel_99", "simple");
        let key = s["key"].as_str().unwrap().to_string();
        assert_eq!(key.len(), 64);
        assert_eq!(s["username"], "Axel_99");
        assert_eq!(s["profile"]["name"], "Axel_99");
        assert_eq!(s["profile"]["verified"], true);
        assert_eq!(s["profile"]["rating"], 1200);
        assert!(
            !String::from_utf8_lossy(
                &account(
                    &api,
                    "register",
                    json!({"username": "zed", "password": "simple"})
                )
                .body
            )
            .contains("simple")
        );
        // the key works for the whole lobby API, like an anonymous key
        let me = json_of(api.handle(req(
            "POST",
            "/profile",
            json!({"key": key, "name": "SOMETHING ELSE", "avatar": 3}),
        )));
        assert_eq!(
            me["name"], "Axel_99",
            "a named account's name is its username"
        );
        assert_eq!(me["avatar"], 3);
        let code = create(&api, &key, "AXEL ROOM");
        let rooms = json_of(api.handle(req("GET", "/rooms", Value::Null)));
        assert_eq!(rooms[0]["code"], code.as_str());
        assert_eq!(rooms[0]["host_verified"], true);
        // case-insensitive uniqueness
        let e = status_err(
            account(
                &api,
                "register",
                json!({"username": "AXEL_99", "password": "another"}),
            ),
            409,
        );
        assert_eq!(e, "USERNAME TAKEN");
        // rules
        for (user, pw, want) in [
            ("ab", "simple", "USERNAME: 3 TO 16 LETTERS, DIGITS, _ OR -"),
            (
                "has space",
                "simple",
                "USERNAME: 3 TO 16 LETTERS, DIGITS, _ OR -",
            ),
            (
                "a2345678901234567",
                "simple",
                "USERNAME: 3 TO 16 LETTERS, DIGITS, _ OR -",
            ),
            ("Admin", "simple", "THIS USERNAME IS RESERVED"),
            ("rugen", "simple", "THIS USERNAME IS RESERVED"),
            ("Official", "simple", "THIS USERNAME IS RESERVED"),
            ("server", "simple", "THIS USERNAME IS RESERVED"),
            ("moderator", "simple", "THIS USERNAME IS RESERVED"),
            ("PLAYER1234", "simple", "THIS USERNAME IS RESERVED"),
            ("goodname", "12345", "PASSWORD: 6 TO 128 CHARACTERS"),
        ] {
            let r = account(&api, "register", json!({"username": user, "password": pw}));
            assert_eq!(status_err(r, 400), want, "{user}");
        }
        let long = "x".repeat(129);
        assert_eq!(
            status_err(
                account(
                    &api,
                    "register",
                    json!({"username": "goodname", "password": long})
                ),
                400
            ),
            "PASSWORD: 6 TO 128 CHARACTERS"
        );
        // login: any case of the name, a fresh key per device
        let l = json_of(login(&api, "axel_99", "simple"));
        assert_eq!(l["id"], s["id"]);
        assert_ne!(l["key"], s["key"]);
        assert!(key_works(&api, l["key"].as_str().unwrap()));
        assert!(key_works(&api, &key), "the first device stays logged in");
        let info = json_of(api.handle(req("GET", &format!("/v1/account?key={key}"), Value::Null)));
        assert_eq!(info["username"], "Axel_99");
        assert_eq!(info["sessions"], 2);
        // one generic answer for a wrong password and an unknown name
        assert_eq!(
            status_err(login(&api, "axel_99", "simplE"), 401),
            "WRONG USERNAME OR PASSWORD"
        );
        assert_eq!(
            status_err(login(&api, "nobody_here", "simple"), 401),
            "WRONG USERNAME OR PASSWORD"
        );
        assert_eq!(
            status_err(login(&api, "x", "simple"), 401),
            "WRONG USERNAME OR PASSWORD"
        );
        assert_eq!(
            status_err(account(&api, "login", json!({})), 401),
            "WRONG USERNAME OR PASSWORD"
        );
        // the leaderboard / profile carry the badge
        let p = json_of(api.handle(req("GET", &format!("/profile/{}", s["id"]), Value::Null)));
        assert_eq!(p["verified"], true);
    }

    #[test]
    fn failed_logins_lock_the_name_out() {
        let api = api();
        signup(&api, "victim", "right-password");
        for _ in 0..5 {
            assert_eq!(login(&api, "victim", "guess").status, 401);
        }
        // the 6th failure locks the name (even the right password waits)
        assert_eq!(login(&api, "victim", "guess").status, 401);
        let e = status_err(login(&api, "VICTIM", "right-password"), 429);
        assert!(e.starts_with("TOO MANY ATTEMPTS: TRY AGAIN IN "), "{e}");
        // other names are unaffected
        signup(&api, "bystander", "password");
        assert_eq!(login(&api, "bystander", "password").status, 200);
        // per address too: one IP guessing many names
        let from = |user: &str, pw: &str| {
            let mut r = req(
                "POST",
                "/v1/account/login",
                json!({"username": user, "password": pw}),
            );
            r.ip = Some("192.0.2.7".parse().unwrap());
            api.handle(r)
        };
        for i in 0..=20 {
            from(&format!("guess{i}"), "nope-nope");
        }
        assert_eq!(from("bystander", "password").status, 429);
    }

    #[test]
    fn claiming_an_anonymous_account_keeps_its_rating_and_history() {
        let api = api();
        let (a, ka) = register(&api);
        let (b, _) = register(&api);
        {
            let s = api.store();
            let m = s.new_match([a, b], true, "{}").unwrap();
            let w = ReportData {
                winner: a,
                ..Default::default()
            };
            s.report(a, m, &w).unwrap();
            s.report(b, m, &w).unwrap();
        }
        let before = json_of(api.handle(req("GET", &format!("/profile/{a}"), Value::Null)));
        assert_eq!(before["rating"], 1216);
        assert!(
            before.get("verified").is_none(),
            "anonymous: no flag at all"
        );
        // anonymous accounts cannot log out (the key is all they have)
        assert_eq!(account(&api, "logout", json!({"key": ka})).status, 409);
        assert_eq!(
            account(
                &api,
                "password",
                json!({"key": ka, "password": "x", "new_password": "simple"})
            )
            .status,
            409
        );
        let c = json_of(account(
            &api,
            "claim",
            json!({"key": ka, "username": "OldTimer", "password": "simple"}),
        ));
        assert_eq!(c["id"].as_u64(), Some(a));
        assert_eq!(
            c["key"].as_str(),
            Some(ka.as_str()),
            "the device keeps its key"
        );
        assert_eq!(c["profile"]["rating"], 1216);
        assert_eq!(c["profile"]["wins"], 1);
        assert_eq!(c["profile"]["verified"], true);
        // twice: refused
        let e = status_err(
            account(
                &api,
                "claim",
                json!({"key": ka, "username": "Other", "password": "simple"}),
            ),
            409,
        );
        assert_eq!(e, "THIS ACCOUNT ALREADY HAS A USERNAME");
        // a taken name cannot be claimed
        let (_, kb) = register(&api);
        let e = status_err(
            account(
                &api,
                "claim",
                json!({"key": kb, "username": "oldtimer", "password": "simple"}),
            ),
            409,
        );
        assert_eq!(e, "USERNAME TAKEN");
        // a second device logs in: same account, same rating
        let l = json_of(login(&api, "oldtimer", "simple"));
        assert_eq!(l["id"].as_u64(), Some(a));
        assert_eq!(l["profile"]["rating"], 1216);
        let board = json_of(api.handle(req("GET", "/leaderboard", Value::Null)));
        assert_eq!(board["rows"][0]["name"], "OldTimer");
        assert_eq!(board["rows"][0]["verified"], true);
        assert!(board["rows"][1].get("verified").is_none());
    }

    #[test]
    fn password_change_and_logouts_revoke_keys() {
        let api = api();
        let k1 = signup(&api, "multi", "first-pass")["key"]
            .as_str()
            .unwrap()
            .to_string();
        let k2 = json_of(login(&api, "multi", "first-pass"))["key"]
            .as_str()
            .unwrap()
            .to_string();
        let k3 = json_of(login(&api, "multi", "first-pass"))["key"]
            .as_str()
            .unwrap()
            .to_string();
        // log out one device
        json_of(account(&api, "logout", json!({"key": k3})));
        assert!(!key_works(&api, &k3));
        assert!(key_works(&api, &k1) && key_works(&api, &k2));
        // change password: needs the old one
        let wrong = account(
            &api,
            "password",
            json!({"key": k1, "password": "nope-nope", "new_password": "second-pass"}),
        );
        assert_eq!(status_err(wrong, 401), "WRONG PASSWORD");
        let short = account(
            &api,
            "password",
            json!({"key": k1, "password": "first-pass", "new_password": "123"}),
        );
        assert_eq!(short.status, 400);
        let s = json_of(account(
            &api,
            "password",
            json!({"key": k1, "password": "first-pass", "new_password": "second-pass"}),
        ));
        let k4 = s["key"].as_str().unwrap().to_string();
        assert!(
            key_works(&api, &k4),
            "this device continues with a fresh key"
        );
        assert!(
            !key_works(&api, &k1) && !key_works(&api, &k2),
            "every other key revoked"
        );
        assert_eq!(login(&api, "multi", "first-pass").status, 401);
        let k5 = json_of(login(&api, "multi", "second-pass"))["key"]
            .as_str()
            .unwrap()
            .to_string();
        // log out everywhere
        json_of(account(&api, "logout_all", json!({"key": k4})));
        assert!(!key_works(&api, &k4) && !key_works(&api, &k5));
        // a claimed account's original key is revoked the same way
        let (_, ka) = register(&api);
        json_of(account(
            &api,
            "claim",
            json!({"key": ka, "username": "claimer", "password": "simple"}),
        ));
        json_of(account(&api, "logout_all", json!({"key": ka})));
        assert!(!key_works(&api, &ka));
        assert_eq!(
            api.handle(req("POST", "/profile", json!({"key": ka})))
                .status,
            401
        );
        assert_eq!(login(&api, "claimer", "simple").status, 200);
    }

    #[test]
    fn sessions_are_capped_per_account() {
        let api = api();
        let first = signup(&api, "manydevices", "simple")["key"]
            .as_str()
            .unwrap()
            .to_string();
        for _ in 0..crate::store::MAX_SESSIONS {
            json_of(login(&api, "manydevices", "simple"));
        }
        assert!(!key_works(&api, &first), "the oldest device was dropped");
    }

    #[test]
    fn admin_backup_endpoints() {
        let fake = crate::s3_fake::FakeS3::start("bk", "AKID", "SECRET", "us-east-1");
        let url = format!("s3+http://AKID:SECRET@127.0.0.1:{}/bk/srv", fake.port);
        let api = Api::new(
            Store::open(None).unwrap(),
            ApiConfig {
                truth: TruthConfig {
                    admin_token: Some("tok".into()),
                    ..TruthConfig::default()
                },
                backup: BackupSetting::parse(Some(&url), Some("30"), None),
                ..Default::default()
            },
            Arc::new(Relay::default()),
        );
        register(&api);
        let health = json_of(api.handle(req("GET", "/health", Value::Null)));
        let b = &health["backup"];
        assert_eq!(b["configured"], true);
        assert_eq!(b["provider"], "other");
        assert_eq!(b["retention_days"], 30);
        assert!(b.get("interval_hours").is_none());
        let text = b.to_string();
        assert!(!text.contains("127.0.0.1") && !text.contains("bk") && !text.contains("AKID"));

        let post = |bearer: Option<&str>| {
            let mut r = req("POST", "/v1/admin/backup", json!({}));
            r.bearer = bearer.map(str::to_string);
            api.handle(r)
        };
        assert_eq!(post(None).status, 403);
        assert_eq!(post(Some("nope")).status, 403);
        let r = post(Some("tok"));
        assert_eq!(r.status, 202, "{}", String::from_utf8_lossy(&r.body));
        let job = serde_json::from_slice::<Value>(&r.body).unwrap()["job"].clone();
        // running → 409; done → 429 (one manual backup per 10 minutes)
        assert!(matches!(post(Some("tok")).status, 409 | 429));
        let status =
            || json_of(api.handle(req("GET", "/v1/admin/backup/status?token=tok", Value::Null)));
        let t = Instant::now();
        while status()["running"] == true && t.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(20));
        }
        let st = status();
        assert_eq!(st["job"]["id"], job);
        assert_eq!(st["job"]["state"], "done", "{st}");
        assert!(st["last_success"].is_string() && st["next_at"].is_string());
        assert!(st["last_error"].is_null());
        assert!(st["last_size_bytes"].as_u64().unwrap() > 0);
        let r = post(Some("tok"));
        assert_eq!(r.status, 429);
        assert!(
            serde_json::from_slice::<Value>(&r.body).unwrap()["retry_after"]
                .as_u64()
                .unwrap()
                > 0
        );
        let list = json_of(api.handle(req("GET", "/v1/admin/backups?token=tok", Value::Null)));
        let rows = list["backups"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0]["key"]
                .as_str()
                .unwrap()
                .starts_with("srv/backups/db/")
        );
        assert_eq!(rows[0]["complete"], true);
        assert_eq!(fake.keys().len(), 2, "database + manifest");
        assert_eq!(*fake.rejected.lock().unwrap(), 0);
        assert_eq!(
            api.handle(req("GET", "/v1/admin/backups?token=bad", Value::Null))
                .status,
            403
        );

        // without RUGEN_BACKUP_S3: 404; misconfigured: 503 with the reason
        let off = official_api();
        let mut r = req("POST", "/v1/admin/backup", json!({"token": "tok"}));
        r.bearer = None;
        assert_eq!(off.handle(r).status, 404);
        let health = json_of(off.handle(req("GET", "/health", Value::Null)));
        assert_eq!(health["backup"]["configured"], false);
        assert_eq!(health["backup"]["status"], "off");
        let bad = Api::new(
            Store::open(None).unwrap(),
            ApiConfig {
                truth: TruthConfig {
                    admin_token: Some("tok".into()),
                    ..TruthConfig::default()
                },
                backup: BackupSetting::parse(Some("s3://k:SECRET@h"), None, None),
                ..Default::default()
            },
            Arc::new(Relay::default()),
        );
        let r = bad.handle(req("POST", "/v1/admin/backup", json!({"token": "tok"})));
        assert_eq!(r.status, 503);
        assert!(!String::from_utf8_lossy(&r.body).contains("SECRET"));
    }

    /// The game asks for a link code; the website redeems it with the
    /// admin token, once; a new request replaces the old code; codes expire.
    #[test]
    fn link_codes_are_short_lived_and_used_once() {
        let api = official_api();
        let s = signup(&api, "axel", "correct horse battery");
        let key = s["key"].as_str().unwrap().to_string();
        let id = s["id"].as_u64().unwrap();
        let ask = || json_of(account(&api, "link_code", json!({"key": key})));
        let redeem = |token: &str, code: &str| {
            api.handle(req(
                "POST",
                "/v1/admin/link",
                json!({"token": token, "code": code}),
            ))
        };
        assert_eq!(
            account(&api, "link_code", json!({"key": "nope"})).status,
            401
        );
        let first = ask();
        let code = first["code"].as_str().unwrap().to_string();
        assert_eq!(code.len(), 6);
        assert!(
            code.chars()
                .all(|c| rugen_proto::room_code::ALPHABET.contains(c)),
            "{code}"
        );
        assert_eq!(first["expires_in"], 600);
        assert!(first["expires_at"].as_u64().unwrap() >= crate::store::now() + 599);
        // asking again replaces the code
        let second = ask()["code"].as_str().unwrap().to_string();
        assert_ne!(second, code);
        assert_eq!(redeem("tok", &code).status, 404, "replaced");
        assert_eq!(redeem("wrong", &second).status, 403);
        assert_eq!(redeem("tok", "").status, 404);
        // redeemed once, lower case accepted
        let got = json_of(redeem("tok", &second.to_ascii_lowercase()));
        assert_eq!(got["account_id"].as_u64(), Some(id));
        assert_eq!(got["username"], "axel");
        assert_eq!(got["profile"]["id"].as_u64(), Some(id));
        assert_eq!(got["profile"]["name"], "axel");
        assert_eq!(redeem("tok", &second).status, 404, "used");
        // expired codes are gone
        let third = ask()["code"].as_str().unwrap().to_string();
        if let Some(l) = lock(&api.links).get_mut(&third) {
            l.expires = Instant::now() - Duration::from_secs(1);
        }
        assert_eq!(redeem("tok", &third).status, 404, "expired");
        assert!(lock(&api.links).is_empty());
        // anonymous accounts link too (no username)
        let (aid, akey) = register(&api);
        let c = json_of(account(&api, "link_code", json!({"key": akey})))["code"]
            .as_str()
            .unwrap()
            .to_string();
        let got = json_of(redeem("tok", &c));
        assert_eq!(got["account_id"].as_u64(), Some(aid));
        assert_eq!(got["username"], "");
    }

    /// An operator opens a bracket for named accounts: no host, public
    /// bracket without a key, pairs called once both players are in the
    /// room, a walkover when one never comes, cancel closes it.
    #[test]
    fn admin_tournaments_run_without_a_host() {
        let api = official_api();
        let people: Vec<(u64, String)> = (0..4).map(|_| register(&api)).collect();
        let ids: Vec<u64> = people.iter().map(|p| p.0).collect();
        let key_of = |id: u64| people.iter().find(|p| p.0 == id).unwrap().1.clone();
        let create = |body: Value| api.handle(req("POST", "/v1/admin/tournament", body));
        assert_eq!(
            create(json!({"token": "tok", "size": 4, "entrants": ids})).status,
            400
        );
        assert_eq!(
            create(json!({"token": "tok", "size": 8, "entrants": [ids[0]]})).status,
            400
        );
        assert_eq!(
            create(json!({"token": "tok", "size": 8, "entrants": [ids[0], ids[0]]})).status,
            400
        );
        assert_eq!(
            create(json!({"token": "tok", "size": 8, "entrants": [ids[0], 999_999]})).status,
            404
        );
        assert_eq!(
            create(json!({"token": "nope", "size": 8, "entrants": ids})).status,
            403
        );
        let made = json_of(create(json!({
            "token": "tok", "size": 8, "name": "Site Cup", "rules": {"life": 7000},
            "entrants": ids,
        })));
        let code = made["code"].as_str().unwrap().to_string();
        assert_eq!(made["tournament"]["state"], "running");
        // the public view, no key: the bracket, seeded in the order given
        let public = || json_of(api.handle(req("GET", &format!("/room/{code}"), Value::Null)));
        let v = public();
        assert_eq!(v["name"], "Site Cup");
        assert_eq!(v["rules"]["life"], 7000);
        assert_eq!(v["server_hosted"], true);
        assert!(v.get("ticket").is_none() && v.get("matchup").is_none() && v.get("side").is_none());
        let t = &v["tournament"];
        let seeds: Vec<u64> = t["entrants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_u64().unwrap())
            .collect();
        assert_eq!(seeds, ids, "seeded in the order given");
        assert!(t["entrants"][0]["name"].is_string());
        assert!(t["live"].is_null(), "nobody here: nothing called");
        assert_eq!(t["rounds"][1][0]["state"], "next");
        // an ordinary room stays private without a key
        let (_, hk) = register(&api);
        let plain = json_of(api.handle(req("POST", "/room", json!({"key": hk}))));
        let r = api.handle(req(
            "GET",
            &format!("/room/{}", plain["code"].as_str().unwrap()),
            Value::Null,
        ));
        assert_eq!(r.status, 401);
        // seed 1 arrives alone: its semi-final waits for seed 4
        let join = |k: &str| {
            json_of(api.handle(req(
                "POST",
                &format!("/room/{code}/join"),
                json!({"key": k, "tournament": true}),
            )))
        };
        assert_eq!(
            join(&key_of(ids[0]))["side"],
            3,
            "an entrant, not a spectator"
        );
        api.sweep_tournaments();
        assert!(public()["tournament"]["live"].is_null());
        // three minutes later nobody came: a walkover
        for r in lock(&api.rooms).values_mut() {
            if let Some(t) = r.tournament.as_mut() {
                for w in t.waiting.values_mut() {
                    *w = Instant::now() - Duration::from_secs(tournament::CALL_TIMEOUT_SECS + 1);
                }
            }
        }
        api.sweep_tournaments();
        let t = public()["tournament"].clone();
        assert_eq!(t["rounds"][1][0]["winner"].as_u64(), Some(ids[0]));
        assert_eq!(t["rounds"][1][0]["score"], json!([0, 0]));
        // seeds 2 and 3 arrive: their semi-final is called at once
        join(&key_of(ids[1]));
        join(&key_of(ids[2]));
        api.sweep_tournaments();
        let t = public()["tournament"].clone();
        assert_eq!(t["live"], json!([1, 1]));
        let semi = &t["rounds"][1][1];
        assert_eq!(semi["state"], "called");
        let (p1, p2) = (semi["p1"].as_u64().unwrap(), semi["p2"].as_u64().unwrap());
        assert_eq!((p1, p2), (ids[1], ids[2]));
        let mid = semi["match_id"].as_u64().unwrap();
        let mine = json_of(api.handle(req(
            "GET",
            &format!("/room/{code}?key={}", key_of(p1)),
            Value::Null,
        )));
        assert_eq!(mine["side"], 1);
        assert_eq!(mine["matchup"]["id"].as_u64(), Some(mid));
        for k in [key_of(p1), key_of(p2)] {
            json_of(api.handle(req(
                "POST",
                "/result",
                json!({"key": k, "match_id": mid, "winner": p2, "rounds": [0, 2]}),
            )));
        }
        api.sweep_tournaments();
        let t = public()["tournament"].clone();
        assert_eq!(t["rounds"][1][1]["winner"].as_u64(), Some(p2));
        assert_eq!(t["rounds"][2][0]["p1"].as_u64(), Some(ids[0]));
        assert_eq!(t["rounds"][2][0]["p2"].as_u64(), Some(p2));
        // nobody hosts: the room survives every player leaving
        for id in [ids[0], ids[1], ids[2]] {
            json_of(api.handle(req(
                "POST",
                &format!("/room/{code}/leave"),
                json!({"key": key_of(id)}),
            )));
        }
        assert_eq!(public()["members"].as_array().unwrap().len(), 0);
        // the operator closes it
        assert_eq!(
            api.handle(req(
                "POST",
                &format!("/v1/admin/tournament/{code}/cancel"),
                json!({"token": "bad"}),
            ))
            .status,
            403
        );
        let r = json_of(api.handle(req(
            "POST",
            &format!("/v1/admin/tournament/{code}/cancel"),
            json!({"token": "tok"}),
        )));
        assert_eq!(r["cancelled"], true);
        assert_eq!(
            api.handle(req("GET", &format!("/room/{code}"), Value::Null))
                .status,
            404
        );
        // a player's own tournament room cannot be cancelled this way
        let own = json_of(api.handle(req("POST", "/room", json!({"key": hk, "tournament": 8}))));
        let r = api.handle(req(
            "POST",
            &format!(
                "/v1/admin/tournament/{}/cancel",
                own["code"].as_str().unwrap()
            ),
            json!({"token": "tok"}),
        ));
        assert_eq!(r.status, 409);
    }

    #[test]
    fn admin_resets_a_password() {
        let api = official_api();
        let key = signup(&api, "forgetful", "lost-it")["key"]
            .as_str()
            .unwrap()
            .to_string();
        let reset = |token: &str, user: &str| {
            api.handle(req(
                "POST",
                "/v1/admin/reset_password",
                json!({"token": token, "username": user}),
            ))
        };
        assert_eq!(reset("wrong", "forgetful").status, 403);
        assert_eq!(reset("tok", "nobody").status, 404);
        let r = json_of(reset("tok", "FORGETFUL"));
        assert_eq!(r["username"], "forgetful");
        let temp = r["password"].as_str().unwrap().to_string();
        assert!(!key_works(&api, &key), "logged out everywhere");
        assert_eq!(login(&api, "forgetful", "lost-it").status, 401);
        assert_eq!(login(&api, "forgetful", &temp).status, 200);
        // without RUGEN_ADMIN_TOKEN there is no admin API
        assert_eq!(
            api_with(PkgConfig::default())
                .handle(req(
                    "POST",
                    "/v1/admin/reset_password",
                    json!({"token": "", "username": "x"})
                ))
                .status,
            404
        );
    }

    #[test]
    fn api4_clients_stay_anonymous_and_cannot_wear_a_username() {
        let api = api();
        let named = signup(&api, "Champion", "simple");
        client_api(4);
        // no account routes for 0.5 clients
        assert_eq!(login(&api, "Champion", "simple").status, 404);
        assert_eq!(
            account(
                &api,
                "register",
                json!({"username": "oldie", "password": "simple"})
            )
            .status,
            404
        );
        assert_eq!(
            api.handle(req("GET", "/v1/account", Value::Null)).status,
            404
        );
        // the anonymous flow is unchanged
        let (id, key) = register(&api);
        let me = json_of(api.handle(req("POST", "/profile", json!({"key": key, "name": "Ryu"}))));
        assert_eq!(me["name"], "Ryu");
        let _: ProfileInfo = serde_json::from_value(me).unwrap();
        // a username is not available as a free-form name
        let me = json_of(api.handle(req(
            "POST",
            "/profile",
            json!({"key": key, "name": "CHAMPION"}),
        )));
        assert_eq!(me["name"], "Ryu");
        assert!(me.get("verified").is_none());
        // the named player's profile carries the additive flag 0.5 ignores
        let p = json_of(api.handle(req(
            "GET",
            &format!("/profile/{}", named["id"]),
            Value::Null,
        )));
        let old: ProfileInfo = serde_json::from_value(p).unwrap();
        assert_eq!(old.name, "Champion");
        assert!(id > 0);
        client_api(crate::compat::API);
    }
}
