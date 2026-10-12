//! JSON API routes. Mutating calls carry the account `key` in the JSON body;
//! reads that need identity take `?key=`.
//!
//! ```text
//! GET  /  (or /health)          ServerInfo: name, motd, version, players online
//! POST /register                → {id, key}
//! POST /profile                 {key, name?, avatar?}
//! GET  /profile/{id}
//! GET  /rooms                   public lobby (RoomSummary[])
//! POST /room                    {key, char, name?, public?, password?, rules?, max_spectators?}
//! POST /room/{code}/join        {key, char, password?, spectate?}
//! GET  /room/{code}?key=        RoomInfo (also a heartbeat)
//! POST /room/{code}/leave       {key}
//! POST /room/{code}/kick        {key, id}       host only
//! POST /room/{code}/rematch     {key}           both players → new match
//! POST /queue                   {key, char, ranked?, max_ping?, rtt_ms?}
//! GET  /queue?key=              QueueStatus (found match once paired)
//! DELETE /queue (or POST /queue/leave) {key}
//! POST /result                  {key, match_id, winner, frames?, checksum?, inputs?}
//! GET  /replay/{match_id}       stored ranked replay
//! GET  /leaderboard?key=
//! GET  /seasons/current
//! GET  /ws?key=                 WebSocket: presence pushes + server-side RTT
//! GET  /relay                   WebSocket: relayed match datagrams (fallback for UDP)
//!
//! bring-your-own-character matchup (rooms and queue; see crate::matchup)
//! GET  /matchup/{id}?key=       MatchupView (also pushed on /ws)
//! POST /matchup/{id}/pick       {key, fighter: FighterDecl, stage?: FighterDecl}
//! POST /matchup/{id}/accept     {key, unbalanced?}
//! POST /matchup/{id}/ready      {key, ready: ReadyReport}
//! POST /matchup/{id}/leave      {key}
//! GET  /pkg/{fp}?key=           PackageStatus ("HAS")
//! POST /pkg/{fp}/upload?key=&offset=&total=   raw chunk, resumable
//! GET  /pkg/{fp}/data?key=&offset=&len=       raw bytes, resumable
//! GET  /char/{fp}               community rating of a character fingerprint
//! POST /match/{id}/desync       {key, frame}    a client saw a desync
//! ```
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

use crate::hub::Hub;
use crate::matchmaking::{self, Candidate};
use crate::matchup::{Matchup, Running, check_decl};
use crate::packages::{Packages, PkgConfig, UploadError, Verified};
use crate::password;
use crate::relay::Relay;
use crate::resim::ResimConfig;
use crate::store::{Account, DbResult, ReportData, Store, random_code, setup_fingerprints};

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub body: Vec<u8>,
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
}

/// Matchups not started and untouched for this long fail.
const MATCHUP_IDLE: Duration = Duration::from_secs(15 * 60);
/// Started / failed matchups are forgotten after this long.
const MATCHUP_KEEP: Duration = Duration::from_secs(4 * 3600);
/// Largest chunk of an upload / download.
pub const MAX_CHUNK: u64 = 4 << 20;

pub struct Api {
    store: Mutex<Store>,
    rooms: Mutex<HashMap<String, Room>>,
    queue: Mutex<Vec<QueueEntry>>,
    /// Matches found for queued players, consumed on poll.
    found: Mutex<HashMap<u64, MatchInfo>>,
    pub hub: Mutex<Hub>,
    pub relay: Arc<Mutex<Relay>>,
    matchups: Mutex<HashMap<u64, Matchup>>,
    pub packages: Packages,
    /// Upload bytes per account in the current hour.
    upload_budget: Mutex<HashMap<u64, (Instant, u64)>>,
    me: Weak<Api>,
    cfg: ApiConfig,
}

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
        .filter(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | ' ' | '!' | '?' | '.'))
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
    r
}

fn ticket(r: &Running, slot: usize, udp: &Option<String>) -> SessionTicket {
    SessionTicket {
        session: r.session,
        slot: slot as u8,
        token: to_hex(&r.tokens[slot]),
        spectators: r.slots.len().saturating_sub(2) as u8,
        udp: udp.clone(),
    }
}

impl Api {
    pub fn new(store: Store, cfg: ApiConfig, relay: Arc<Mutex<Relay>>) -> Arc<Self> {
        let packages = Packages::open(cfg.data.as_deref(), cfg.pkg.clone())
            .or_else(|e| {
                log::error!("packages directory: {e}; using a temporary one");
                Packages::open(None, cfg.pkg.clone())
            })
            .expect("a temporary packages directory");
        Arc::new_cyclic(|me| Self {
            store: Mutex::new(store),
            rooms: Mutex::new(HashMap::new()),
            queue: Mutex::new(Vec::new()),
            found: Mutex::new(HashMap::new()),
            hub: Mutex::new(Hub::default()),
            relay,
            matchups: Mutex::new(HashMap::new()),
            packages,
            upload_budget: Mutex::new(HashMap::new()),
            me: me.clone(),
            cfg,
        })
    }

    /// Expire / evict stored packages (TTL, LRU size cap).
    pub fn sweep_packages(&self) -> Vec<String> {
        let mut s = lock(&self.store);
        self.packages.sweep(&mut s)
    }

    /// The account owning a key (WebSocket upgrade).
    pub fn account_for_key(&self, key: &str) -> Option<Account> {
        if key.len() != 64 {
            return None;
        }
        lock(&self.store).by_key(key).ok().flatten()
    }

    /// Account for the key in `v` (body) or `?key=`.
    fn auth(&self, store: &mut Store, req: &Request, v: &Value) -> Result<Account, Response> {
        let key = v
            .get("key")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| req.query.get("key").cloned())
            .ok_or_else(|| err(401, "bad key"))?;
        if key.len() != 64 {
            return Err(err(401, "bad key"));
        }
        db(store.by_key(&key))?.ok_or_else(|| err(401, "bad key"))
    }

    fn me(&self, req: &Request, v: &Value) -> Result<Account, Response> {
        let mut s = lock(&self.store);
        self.auth(&mut s, req, v)
    }

    pub fn handle(&self, req: Request) -> Response {
        self.route(req).unwrap_or_else(|e| e)
    }

    pub fn info(&self) -> DbResult<ServerInfo> {
        let accounts_online = lock(&self.store).online_count(300)?;
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
            matches: lock(&self.relay).session_count(),
            udp: self.cfg.udp_public.clone(),
        })
    }

    fn route(&self, req: Request) -> Res {
        let path: Vec<&str> = req.path.trim_matches('/').split('/').collect();
        let v = body(&req);
        match (req.method.as_str(), path.as_slice()) {
            ("GET", [""]) | ("GET", ["health"]) | ("GET", ["info"]) => ok(&db(self.info())?),
            ("POST", ["register"]) => {
                let mut s = lock(&self.store);
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
                let mut s = lock(&self.store);
                let a = self.auth(&mut s, &req, &v)?;
                let name = str_field(&v, "name", 32);
                let avatar = v.get("avatar").and_then(Value::as_u64).map(|a| a as u32);
                let a = db(s.set_profile(a.id, name, avatar))?.ok_or_else(|| err(404, "gone"))?;
                ok(&a.info())
            }
            ("GET", ["profile", id]) => {
                let id = id.parse::<u64>().map_err(|_| err(400, "bad id"))?;
                match db(lock(&self.store).by_id(id))? {
                    Some(a) => ok(&a.info()),
                    None => Err(err(404, "no such player")),
                }
            }
            ("GET", ["seasons", "current"]) => {
                let mut s = lock(&self.store);
                db(s.roll_season())?;
                ok(&db(s.season())?)
            }
            ("GET", ["leaderboard"]) => {
                let mut s = lock(&self.store);
                db(s.roll_season())?;
                let me = match self.auth(&mut s, &req, &v) {
                    Ok(a) => db(s.rank_of(a.id))?.map(|pos| (pos, a.info())),
                    Err(_) => None,
                };
                ok(&Leaderboard {
                    season: db(s.season())?,
                    rows: db(s.leaderboard(50))?,
                    me,
                })
            }
            ("GET", ["replay", id]) => self.replay(id),
            ("GET", ["rooms"]) => self.list_rooms(),
            ("POST", ["room"]) => self.create_room(&req, &v),
            ("POST", ["room", code, "join"]) => self.join_room(&req, &v, code),
            ("GET", ["room", code]) => self.poll_room(&req, &v, code),
            ("POST", ["room", code, "leave"]) => self.leave_room(&req, &v, code),
            ("POST", ["room", code, "kick"]) => self.kick(&req, &v, code),
            ("POST", ["room", code, "rematch"]) => self.rematch(&req, &v, code),
            ("POST", ["queue"]) => self.enter_queue(&req, &v),
            ("GET", ["queue"]) => self.poll_queue(&req, &v),
            ("DELETE", ["queue"]) | ("POST", ["queue", "leave"]) => self.leave_queue(&req, &v),
            ("POST", ["result"]) => self.result(&req, &v),
            ("GET", ["matchup", id]) => self.matchup_get(&req, &v, id),
            ("POST", ["matchup", id, op]) => self.matchup_op(&req, &v, id, op),
            ("GET", ["pkg", fp]) => self.pkg_status(&req, &v, fp),
            ("POST", ["pkg", fp, "upload"]) => self.pkg_upload(&req, fp),
            ("GET", ["pkg", fp, "data"]) => self.pkg_data(&req, &v, fp),
            ("GET", ["char", fp]) => {
                let r = db(lock(&self.store).char_rating(fp))?;
                ok(&r)
            }
            ("POST", ["match", id, "desync"]) => self.desync(&req, &v, id),
            _ => Err(err(404, "no such route")),
        }
    }

    // ---- rooms

    /// Drop silent members and empty / host-less / ancient rooms.
    fn expire_rooms(&self, rooms: &mut HashMap<String, Room>) {
        let hub = lock(&self.hub);
        for r in rooms.values_mut() {
            for m in &mut r.members {
                if hub.is_online(m.account) {
                    m.last_seen = Instant::now();
                }
            }
            r.members
                .retain(|m| m.last_seen.elapsed().as_secs() < MEMBER_TIMEOUT_SECS);
        }
        rooms.retain(|_, r| {
            r.player(0).is_some() && r.created.elapsed().as_secs() < ROOM_MAX_AGE_SECS
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
        let hub = lock(&self.hub);
        let my_role = r.member(me).map_or(2, |m| m.role);
        let host = r.player(0);
        let chal = r.player(1);
        let p1_char = host.map(|m| m.char_id.clone()).unwrap_or_default();
        let p2_char = match (chal, r.rules.chars.as_str()) {
            (Some(_), "mirror") => p1_char.clone(),
            (Some(c), _) => c.char_id.clone(),
            (None, _) => String::new(),
        };
        let opponent = match my_role {
            0 => chal.map(|m| Self::profile(store, m.account)),
            1 => host.map(|m| Self::profile(store, m.account)),
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
        let matchup = r.matchup.and_then(|id| {
            let ms = lock(&self.matchups);
            ms.get(&id).map(|m| self.matchup_view(store, m, me))
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
    fn start_match(&self, store: &mut Store, r: &mut Room, code: &str) -> Result<(), Response> {
        let (Some(host), Some(chal)) = (r.player(0), r.player(1)) else {
            return Ok(());
        };
        let players = [host.account, chal.account];
        let setup = json!({ "p1_char": host.char_id, "p2_char": chal.char_id, "rules": r.rules })
            .to_string();
        let match_id = db(store.new_match(players, false, &setup))?;
        if let Some(old) = r.running.take() {
            lock(&self.relay).close(old.session);
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

    fn list_rooms(&self) -> Res {
        let s = lock(&self.store);
        let mut rooms = lock(&self.rooms);
        self.expire_rooms(&mut rooms);
        let mut list: Vec<(Instant, RoomSummary)> = rooms
            .iter()
            .filter(|(_, r)| r.public)
            .map(|(code, r)| {
                (
                    r.created,
                    RoomSummary {
                        code: code.clone(),
                        name: r.name.clone(),
                        host: r
                            .player(0)
                            .map(|m| Self::profile(&s, m.account).name)
                            .unwrap_or_default(),
                        rules: r.rules.clone(),
                        players: r.members.iter().filter(|m| m.role < 2).count() as u8,
                        spectators: r.spectators(),
                        max_spectators: r.max_spectators,
                        locked: r.password.is_some(),
                        in_match: r.running.is_some(),
                    },
                )
            })
            .collect();
        list.sort_by_key(|(t, _)| std::cmp::Reverse(*t));
        let list: Vec<RoomSummary> = list.into_iter().take(100).map(|(_, r)| r).collect();
        ok(&list)
    }

    fn create_room(&self, req: &Request, v: &Value) -> Res {
        let mut s = lock(&self.store);
        let me = self.auth(&mut s, req, v)?;
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
        let room = Room {
            name,
            public: v.get("public").and_then(Value::as_bool).unwrap_or(true),
            password,
            rules,
            max_spectators: v
                .get("max_spectators")
                .and_then(Value::as_u64)
                .map_or(2, |n| n.min(MAX_SPECTATORS as u64) as u8),
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
        };
        let view = self.room_view(&s, &code, &room, me.id);
        rooms.insert(code.clone(), room);
        log::info!("room {code} created by {}", me.id);
        ok(&view)
    }

    fn join_room(&self, req: &Request, v: &Value, code: &str) -> Res {
        let mut s = lock(&self.store);
        let me = self.auth(&mut s, req, v)?;
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
            if let Some(phc) = &r.password {
                let given = str_field(v, "password", 64).unwrap_or_default();
                if !password::verify(&given, phc) {
                    return Err(err(403, "wrong password"));
                }
            }
            let role = if !spectate && r.player(1).is_none() {
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
            if role == 1 && r.running.is_none() && r.matchup.is_none() {
                self.start_match(&mut s, r, &code)?;
            }
            self.broadcast(&s, &code, r);
        }
        ok(&self.room_view(&s, &code, r, me.id))
    }

    fn poll_room(&self, req: &Request, v: &Value, code: &str) -> Res {
        let mut s = lock(&self.store);
        let me = self.auth(&mut s, req, v)?;
        let code = code.trim().to_ascii_uppercase();
        let mut rooms = lock(&self.rooms);
        if let Some(m) = rooms
            .get_mut(&code)
            .and_then(|r| r.members.iter_mut().find(|m| m.account == me.id))
        {
            m.last_seen = Instant::now();
        }
        self.expire_rooms(&mut rooms);
        let r = rooms.get(&code).ok_or_else(|| err(404, "no such room"))?;
        if r.member(me.id).is_none() {
            return Err(err(401, "not in this room"));
        }
        ok(&self.room_view(&s, &code, r, me.id))
    }

    fn leave_room(&self, req: &Request, v: &Value, code: &str) -> Res {
        let mut s = lock(&self.store);
        let me = self.auth(&mut s, req, v)?;
        let code = code.trim().to_ascii_uppercase();
        let mut rooms = lock(&self.rooms);
        if let Some(r) = rooms.get_mut(&code) {
            self.fail_matchup_of(&s, r, me.id, "your opponent left");
            r.members.retain(|m| m.account != me.id);
            if r.player(0).is_none() {
                // the host left: the room closes
                let others: Vec<u64> = r.members.iter().map(|m| m.account).collect();
                rooms.remove(&code);
                let hub = lock(&self.hub);
                for a in others {
                    hub.push(a, &ServerMsg::Kicked { code: code.clone() });
                }
            } else {
                self.broadcast(&s, &code, r);
            }
        }
        ok(&json!({ "left": true }))
    }

    fn kick(&self, req: &Request, v: &Value, code: &str) -> Res {
        let mut s = lock(&self.store);
        let me = self.auth(&mut s, req, v)?;
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
        self.fail_matchup_of(&s, r, target, "a player was removed");
        r.members.retain(|m| m.account != target);
        r.kicked.push(target);
        if r.running
            .as_ref()
            .is_some_and(|run| run.slots[..2].contains(&target))
        {
            if let Some(run) = r.running.take() {
                lock(&self.relay).close(run.session);
            }
        }
        lock(&self.hub).push(target, &ServerMsg::Kicked { code: code.clone() });
        self.broadcast(&s, &code, r);
        ok(&self.room_view(&s, &code, r, me.id))
    }

    fn rematch(&self, req: &Request, v: &Value, code: &str) -> Res {
        let mut s = lock(&self.store);
        let me = self.auth(&mut s, req, v)?;
        let code = code.trim().to_ascii_uppercase();
        let mut rooms = lock(&self.rooms);
        let r = rooms
            .get_mut(&code)
            .ok_or_else(|| err(404, "no such room"))?;
        let m = r
            .members
            .iter_mut()
            .find(|m| m.account == me.id && m.role < 2)
            .ok_or_else(|| err(403, "not a player of this room"))?;
        m.ready = true;
        m.last_seen = Instant::now();
        let both = r.members.iter().filter(|m| m.role < 2 && m.ready).count() == 2;
        if both {
            self.start_match(&mut s, r, &code)?;
            self.broadcast(&s, &code, r);
        }
        ok(&self.room_view(&s, &code, r, me.id))
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
            q.push(QueueEntry {
                id: a.id,
                rating: a.rating,
                ranked,
                max_ping,
                reported_rtt,
                char_id,
                since: Instant::now(),
                last_poll: Instant::now(),
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
        if let Some(m) = found {
            return ok(&QueueStatus {
                queued: false,
                waiting_secs: 0,
                players_in_queue: q.len(),
                found: Some(m),
            });
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
        let mut s = lock(&self.store);
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
            let m = Matchup::new(match_id, [a.id, b.id], a.ranked, Rules::default(), None);
            let views = [
                self.matchup_view(&s, &m, a.id),
                self.matchup_view(&s, &m, b.id),
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
                opponent: Self::profile(&s, opp.id),
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
                hub.push(a.id, &ServerMsg::Found { found: ma.clone() });
                hub.push(b.id, &ServerMsg::Found { found: mb.clone() });
            }
            let mut found = lock(&self.found);
            found.insert(a.id, ma);
            found.insert(b.id, mb);
            log::info!(
                "{} match {match_id}: {} vs {} (est {est} ms), matchup phase",
                if a.ranked { "ranked" } else { "quick" },
                a.id,
                b.id
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
        let mut s = lock(&self.store);
        let me = self.auth(&mut s, req, v)?.id;
        let (Some(match_id), Some(winner)) = (
            v.get("match_id").and_then(Value::as_u64),
            v.get("winner").and_then(Value::as_u64),
        ) else {
            return Err(err(400, "match_id and winner required"));
        };
        let inputs = match v.get("inputs").and_then(Value::as_str) {
            Some(h) if h.len() <= 8 * 60 * 60 * 15 => {
                rugen_proto::from_hex(h).ok_or_else(|| err(400, "inputs must be hex"))?
            }
            Some(_) => return Err(err(413, "inputs too long")),
            None => Vec::new(),
        };
        let data = ReportData {
            winner,
            frames: v.get("frames").and_then(Value::as_u64).unwrap_or(0) as u32,
            checksum: v.get("checksum").and_then(Value::as_u64),
            inputs,
        };
        let out = db(s.report(me, match_id, &data))?;
        if !out.accepted {
            return Err(err(404, "not your match"));
        }
        if out.disputed {
            self.spawn_resim(match_id);
        }
        let rating = match out.delta {
            Some(_) => db(s.by_id(me))?.map(|a| a.rating),
            None => None,
        };
        ok(&ResultAck {
            accepted: true,
            rating,
            delta: out.delta,
            disputed: out.disputed,
        })
    }

    fn replay(&self, id: &str) -> Res {
        let id = id.parse::<u64>().map_err(|_| err(400, "bad id"))?;
        let s = lock(&self.store);
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
            p1: Self::profile(&s, players[0]),
            p2: Self::profile(&s, players[1]),
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

    /// Push every player / spectator its view of the matchup.
    fn push_matchup(&self, store: &Store, m: &Matchup) {
        let mut who: Vec<u64> = m.players.to_vec();
        who.extend(&m.spectators);
        let views: Vec<(u64, rugen_proto::MatchupView)> = who
            .into_iter()
            .map(|a| (a, self.matchup_view(store, m, a)))
            .collect();
        let hub = lock(&self.hub);
        for (a, matchup) in views {
            hub.push(a, &ServerMsg::Matchup { matchup });
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
        let mut s = lock(&self.store);
        let me = self.auth(&mut s, req, v)?;
        let mut ms = lock(&self.matchups);
        Self::expire_matchups(&mut ms);
        let m = ms.get_mut(&id).ok_or_else(|| err(404, "no such matchup"))?;
        if !m.involves(me.id) {
            return Err(err(403, "not your matchup"));
        }
        if m.side_of(me.id).is_some() {
            m.touched = Instant::now();
        }
        ok(&self.matchup_view(&s, m, me.id))
    }

    fn matchup_op(&self, req: &Request, v: &Value, id: &str, op: &str) -> Res {
        let id = Self::matchup_id(id)?;
        let mut s = lock(&self.store);
        let me = self.auth(&mut s, req, v)?;
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
            return ok(&self.matchup_view(&s, m, me.id));
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
                        db(s.flag(me.id, Some(id), &why))?;
                        m.fail(why);
                        self.push_matchup(&s, m);
                        return ok(&self.matchup_view(&s, m, me.id));
                    }
                }
                if let Some(f) = fighter {
                    m.picks[side] = Some(f);
                }
                if let Some(st) = stage {
                    m.stage = Some(st);
                }
                let fps: Vec<String> = m.declared().into_iter().map(str::to_string).collect();
                let refs: Vec<&str> = fps.iter().map(String::as_str).collect();
                db(s.touch_packages(&refs))?;
                m.reset_progress();
                m.recompute_verdict(&s, &self.cfg.thresholds);
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
            "leave" => m.fail(format!("P{} left", side + 1)),
            _ => return Err(err(404, "no such matchup action")),
        }
        self.try_start(&mut s, &mut rooms, m)?;
        self.push_matchup(&s, m);
        let view = self.matchup_view(&s, m, me.id);
        if let Some(code) = m.room.clone()
            && let Some(r) = rooms.get(&code)
        {
            drop(ms);
            self.broadcast(&s, &code, r);
        }
        ok(&view)
    }

    /// Start the relay session once the matchup is confirmed, every package
    /// is on the server (verified) and both clients are ready with the same
    /// files, rules and game version.
    fn try_start(
        &self,
        store: &mut Store,
        rooms: &mut HashMap<String, Room>,
        m: &mut Matchup,
    ) -> Result<bool, Response> {
        if m.phase() != "sync" || !m.missing(&|fp| self.stored(store, fp)).is_empty() {
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
        if let Some(r) = &room {
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
        })
        .to_string();
        db(store.set_setup(m.id, &setup))?;
        db(store.touch_packages(&[&p1, &p2, &st]))?;
        let (session, tokens) = lock(&self.relay)
            .create(&slots)
            .ok_or_else(|| err(503, "relay full"))?;
        let run = Running {
            match_id: m.id,
            session,
            slots,
            tokens,
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
        let mut s = lock(&self.store);
        let me = self.auth(&mut s, req, v)?;
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
        if self.packages.has(&fp) && db(lock(&self.store).package(&fp))?.is_some() {
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
        // complete: verify outside the locks (unpack + hash + analysis)
        let verified = self.packages.finalize(&fp, me.id);
        self.after_upload(&fp, me.id, verified)?;
        let mut st = PackageStatus {
            fingerprint: fp.clone(),
            ..Default::default()
        };
        if let Some(row) = db(lock(&self.store).package(&fp))? {
            st.complete = true;
            st.size = row.size;
        }
        ok(&st)
    }

    /// Store a verified package, catch lying clients, move matchups on.
    fn after_upload(&self, fp: &str, uploader: u64, verified: Verified) -> Result<(), Response> {
        let mut s = lock(&self.store);
        let mut rooms = lock(&self.rooms);
        let mut ms = lock(&self.matchups);
        let failure = match &verified {
            Verified::Stored(row) => {
                db(s.put_package(row))?;
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
                    db(s.flag(uploader, Some(m.id), why))?;
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
                    db(s.flag(m.players[side], Some(m.id), &why))?;
                    m.fail(why);
                }
            }
            if m.failed.is_none() {
                m.recompute_verdict(&s, &self.cfg.thresholds);
                self.try_start(&mut s, &mut rooms, m)?;
            }
            touched.push(m.id);
        }
        for id in touched {
            if let Some(m) = ms.get(&id) {
                self.push_matchup(&s, m);
            }
        }
        drop(ms);
        drop(rooms);
        let _ = self.packages.sweep(&mut s);
        match verified {
            Verified::Stored(_) => Ok(()),
            Verified::Mismatch { .. } => Err(err(422, "the files do not match their fingerprint")),
            Verified::Invalid(e) => Err(err(400, &format!("invalid package: {e}"))),
        }
    }

    fn pkg_data(&self, req: &Request, v: &Value, fp: &str) -> Res {
        let fp = Self::fp_arg(fp)?;
        let mut s = lock(&self.store);
        let me = self.auth(&mut s, req, v)?;
        {
            let ms = lock(&self.matchups);
            if !ms
                .values()
                .any(|m| m.involves(me.id) && m.declared().contains(&fp.as_str()))
            {
                return Err(err(403, "not part of your matchup"));
            }
        }
        if !self.stored(&s, &fp) {
            return Err(err(404, "not on the server (yet)"));
        }
        let q = |k: &str| req.query.get(k).and_then(|x| x.parse::<u64>().ok());
        let offset = q("offset").unwrap_or(0);
        let len = q("len").unwrap_or(MAX_CHUNK).min(MAX_CHUNK);
        db(s.touch_packages(&[&fp]))?;
        drop(s);
        let bytes = self.packages.read(&fp, offset, len).map_err(|e| {
            log::error!("packages: {e}");
            err(500, "storage error")
        })?;
        Ok(Response::bytes(bytes))
    }

    fn desync(&self, req: &Request, v: &Value, id: &str) -> Res {
        let id = id.parse::<u64>().map_err(|_| err(400, "bad id"))?;
        let mut s = lock(&self.store);
        let me = self.auth(&mut s, req, v)?;
        let frame = v.get("frame").and_then(Value::as_u64).unwrap_or(0) as u32;
        if !db(s.report_desync(me.id, id, frame))? {
            return Err(err(404, "not your match"));
        }
        drop(s);
        self.spawn_resim(id);
        ok(&json!({ "recorded": true }))
    }

    /// Re-simulate a disputed match in the background when the server can
    /// (`--features resim` + `RUGEN_RESIM_DATA`), settling it with the
    /// simulated winner.
    fn spawn_resim(&self, match_id: u64) {
        let (Some(cfg), Some(api)) = (self.cfg.resim.clone(), self.me.upgrade()) else {
            return;
        };
        std::thread::spawn(move || {
            let evidence = lock(&api.store).match_evidence(match_id).ok().flatten();
            let Some((setup, _ranked, players, reports)) = evidence else {
                return;
            };
            if reports.len() < 2 || !lock(&api.store).is_disputed(match_id).unwrap_or(false) {
                return;
            }
            let Some((_, longest)) = reports.iter().max_by_key(|(_, r)| r.inputs.len()) else {
                return;
            };
            let note;
            let winner =
                match crate::resim::replay(&api.packages, &cfg, &setup, &longest.inputs, None) {
                    Ok(o) => {
                        // which report's checksum the simulation reproduces
                        let honest: Vec<u64> = reports
                            .iter()
                            .filter(|(_, r)| {
                                r.checksum.is_some_and(|c| {
                                    crate::resim::replay(
                                        &api.packages,
                                        &cfg,
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
            if let Err(e) = lock(&api.store).resolve_dispute(match_id, winner, &note) {
                log::error!("match {match_id}: {e}");
            }
        });
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testkit::{declare, tiny_char, tiny_stage, tmp};
    use rugen_fair::Kind;

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
            Arc::new(Mutex::new(Relay::default())),
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
        assert_eq!(v["missing"].as_array().unwrap().len(), 3);
        // ready before the files are on the server: waits
        json_of(ready(api, id, keys[0], &v, "rugen 9"));
        json_of(ready(api, id, keys[1], &v, "rugen 9"));
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
        let row = lock(&api.store).package(fp).unwrap().unwrap();
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
        assert_eq!(lock(&api.store).flags_of(bid).unwrap().len(), 1);
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
        assert_eq!(lock(&api.store).flags_of(aid).unwrap().len(), 1);
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
        let (_, ka) = register(&api);
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
        let mut s = lock(&api.store);
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
        let gone = pkgs.sweep(&mut s);
        assert_eq!(gone, vec![kit.a.0.fingerprint.clone()]);
        assert!(!pkgs.has(&kit.a.0.fingerprint) && pkgs.has(&kit.b.0.fingerprint));
        assert!(!pkgs.path(&"cd".repeat(32)).exists(), "orphan removed");
        assert!(young.exists(), "a fresh upload is not an orphan");
        // size cap 0: LRU eviction, replay-kept last
        pk.max_total = kit.stage.1.len() as u64;
        let pkgs = Packages::at(api.packages.dir(), pk);
        let gone = pkgs.sweep(&mut s);
        assert_eq!(gone, vec![kit.b.0.fingerprint.clone()]);
        assert!(pkgs.has(&kit.stage.0.fingerprint));
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
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../reference/mugen-1.1b1");
        if !root.join("chars/kfm/kfm.def").exists() {
            eprintln!("reference tree missing; skipping");
            return;
        }
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
            Arc::new(Mutex::new(Relay::default())),
        );
        // packages of KFM and stage0, stored as if uploaded
        let mut fps = Vec::new();
        for (kind, def) in [
            (Kind::Char, root.join("chars/kfm/kfm.def")),
            (Kind::Stage, root.join("stages/stage0.def")),
        ] {
            let files = rugen_fair::files::content_files(kind, &def, Some(&data)).unwrap();
            let fp = rugen_fair::fingerprint(&files).unwrap();
            rugen_fair::package::write_file(&files, &fp, &api.packages.path(&fp)).unwrap();
            lock(&api.store)
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
        let (aid, ka) = register(&api);
        let (bid, kb) = register(&api);
        let setup = json!({"p1_fp": fps[0], "p2_fp": fps[0], "stage_fp": fps[1], "rules": Rules::default()});
        let mid = lock(&api.store)
            .new_match([aid, bid], true, &setup.to_string())
            .unwrap();
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
        while lock(&api.store).is_disputed(mid).unwrap() && t.elapsed() < Duration::from_secs(120) {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            !lock(&api.store).is_disputed(mid).unwrap(),
            "settled by re-simulation"
        );
        let a = lock(&api.store).by_id(aid).unwrap().unwrap();
        assert_eq!(a.wins, 1);
        assert!(a.rating > 1200);
    }
}
