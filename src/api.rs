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
//! ```
//!
//! Privacy: requests carry no client address at all (the HTTP layer keeps
//! it for rate limiting only), so no response can leak one. Match traffic is
//! relayed by the server ([`crate::relay`]); players never learn each
//! other's endpoints.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use rugen_proto::{
    API_VERSION, Leaderboard, MatchInfo, ProfileInfo, QueueStatus, Replay, ResultAck, RoomInfo,
    RoomMember, RoomSummary, Rules, ServerInfo, ServerMsg, SessionTicket, to_hex,
};
use serde_json::{Value, json};

use crate::hub::Hub;
use crate::matchmaking::{self, Candidate};
use crate::password;
use crate::relay::Relay;
use crate::store::{Account, DbResult, ReportData, Store, random_code};

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub body: Vec<u8>,
}

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(status: u16, v: &Value) -> Self {
        Self {
            status,
            body: serde_json::to_vec(v).unwrap_or_default(),
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

struct Running {
    match_id: u64,
    session: u32,
    /// Accounts by relay slot (P1, P2, spectators).
    slots: Vec<u64>,
    tokens: Vec<[u8; 16]>,
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
}

pub struct Api {
    store: Mutex<Store>,
    rooms: Mutex<HashMap<String, Room>>,
    queue: Mutex<Vec<QueueEntry>>,
    /// Matches found for queued players, consumed on poll.
    found: Mutex<HashMap<u64, MatchInfo>>,
    pub hub: Mutex<Hub>,
    pub relay: Arc<Mutex<Relay>>,
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
        Arc::new(Self {
            store: Mutex::new(store),
            rooms: Mutex::new(HashMap::new()),
            queue: Mutex::new(Vec::new()),
            found: Mutex::new(HashMap::new()),
            hub: Mutex::new(Hub::default()),
            relay,
            cfg,
        })
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

    /// Start a match between host and challenger (spectators get slots 2..).
    fn start_match(&self, store: &mut Store, r: &mut Room) -> Result<(), Response> {
        let (Some(host), Some(chal)) = (r.player(0), r.player(1)) else {
            return Ok(());
        };
        let mut slots = vec![host.account, chal.account];
        slots.extend(r.members.iter().filter(|m| m.role == 2).map(|m| m.account));
        let p1 = host.char_id.clone();
        let p2 = if r.rules.chars == "mirror" {
            p1.clone()
        } else {
            chal.char_id.clone()
        };
        let setup =
            json!({ "p1_char": p1, "p2_char": p2, "stage": r.rules.stage, "rules": r.rules })
                .to_string();
        let match_id = db(store.new_match([slots[0], slots[1]], false, &setup))?;
        let (session, tokens) = lock(&self.relay)
            .create(&slots)
            .ok_or_else(|| err(503, "relay full"))?;
        r.running = Some(Running {
            match_id,
            session,
            slots,
            tokens,
        });
        for m in &mut r.members {
            m.ready = false;
        }
        log::info!("room match {match_id} started on relay session {session:08x}");
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
        if char_id.is_empty() {
            return Err(err(400, "char required"));
        }
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
        if char_id.is_empty() && !spectate {
            return Err(err(400, "char required"));
        }
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
            if role == 1 && r.running.is_none() {
                self.start_match(&mut s, r)?;
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
            if let Some(old) = r.running.take() {
                lock(&self.relay).close(old.session);
            }
            self.start_match(&mut s, r)?;
            self.broadcast(&s, &code, r);
        }
        ok(&self.room_view(&s, &code, r, me.id))
    }

    // ---- queue (quick match and ranked)

    fn enter_queue(&self, req: &Request, v: &Value) -> Res {
        let a = self.me(req, v)?;
        let char_id = clean_id(&str_field(v, "char", 64).unwrap_or_default());
        if char_id.is_empty() {
            return Err(err(400, "char required"));
        }
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
            let setup =
                json!({ "p1_char": a.char_id, "p2_char": b.char_id, "stage": "" }).to_string();
            let match_id = db(s.new_match([a.id, b.id], a.ranked, &setup))?;
            let Some((session, tokens)) = lock(&self.relay).create(&[a.id, b.id]) else {
                return Err(err(503, "relay full"));
            };
            let run = Running {
                match_id,
                session,
                slots: vec![a.id, b.id],
                tokens,
            };
            let code = random_code();
            let info = |side: u8, me: &QueueEntry, opp: &QueueEntry| MatchInfo {
                match_id,
                code: code.clone(),
                side,
                my_char: me.char_id.clone(),
                opponent: Self::profile(&s, opp.id),
                opponent_char: opp.char_id.clone(),
                stage: String::new(),
                ranked: me.ranked,
                est_ping_ms: Some(est),
                ticket: Some(ticket(&run, side as usize - 1, &self.cfg.udp_public)),
            };
            let (ma, mb) = (info(1, a, b), info(2, b, a));
            {
                let hub = lock(&self.hub);
                hub.push(a.id, &ServerMsg::Found { found: ma.clone() });
                hub.push(b.id, &ServerMsg::Found { found: mb.clone() });
            }
            let mut found = lock(&self.found);
            found.insert(a.id, ma);
            found.insert(b.id, mb);
            log::info!(
                "{} match {match_id}: {} vs {} (est {est} ms) on relay session {session:08x}",
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
        let (players, setup, winner, created, inputs) =
            db(s.replay(id))?.ok_or_else(|| err(404, "no replay"))?;
        let setup: Value = serde_json::from_str(&setup).unwrap_or(Value::Null);
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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn req(method: &str, path: &str, body: Value) -> Request {
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
            body: serde_json::to_vec(&body).unwrap(),
        }
    }

    fn json_of(r: Response) -> Value {
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        serde_json::from_slice(&r.body).unwrap()
    }

    fn api() -> Arc<Api> {
        Api::new(
            Store::open(None).unwrap(),
            ApiConfig {
                name: "test".into(),
                motd: "hello".into(),
                udp_public: Some("relay.example.com:7001".into()),
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

    #[test]
    fn ranked_queue_pairs_reports_and_stores_replays() {
        let api = api();
        let (aid, ka) = register(&api);
        let (_, kb) = register(&api);
        let st = json_of(api.handle(req("POST", "/queue", json!({"key": ka, "char": "kfm"}))));
        assert_eq!(st["queued"], true);
        let fb = json_of(api.handle(req(
            "POST",
            "/queue",
            json!({"key": kb, "char": "G6_Naruto"}),
        )));
        let fa = json_of(api.handle(req("GET", &format!("/queue?key={ka}"), Value::Null)));
        assert_eq!(fa["found"]["side"], 1);
        assert_eq!(fb["found"]["side"], 2);
        assert_eq!(fa["found"]["opponent_char"], "G6_Naruto");
        // both get a ticket for the same relay session, different slots and tokens
        let (ta, tb) = (&fa["found"]["ticket"], &fb["found"]["ticket"]);
        assert_eq!(ta["session"], tb["session"]);
        assert_eq!(
            (ta["slot"].as_u64(), tb["slot"].as_u64()),
            (Some(0), Some(1))
        );
        assert_ne!(ta["token"], tb["token"]);
        assert_eq!(ta["udp"], "relay.example.com:7001");
        let mid = fa["found"]["match_id"].as_u64().unwrap();
        let inputs = "01000200".repeat(100);
        let r1 = json_of(api.handle(req(
            "POST",
            "/result",
            json!({"key": ka, "match_id": mid, "winner": aid, "inputs": inputs, "frames": 100, "checksum": 9}),
        )));
        assert!(r1["delta"].is_null());
        let r2 = json_of(api.handle(req(
            "POST",
            "/result",
            json!({"key": kb, "match_id": mid, "winner": aid, "inputs": inputs, "frames": 100, "checksum": 9}),
        )));
        assert_eq!(r2["delta"], -16);
        assert_eq!(r2["disputed"], false);
        let lb = json_of(api.handle(req("GET", "/leaderboard", Value::Null)));
        assert_eq!(lb["rows"][0]["id"], aid);
        let rp = json_of(api.handle(req("GET", &format!("/replay/{mid}"), Value::Null)));
        assert_eq!(rp["inputs"], inputs);
        assert_eq!(rp["p1_char"], "kfm");
    }

    #[test]
    fn quick_match_ignores_rating_and_never_meets_ranked() {
        let api = api();
        let (_, ka) = register(&api);
        let (_, kb) = register(&api);
        let (_, kc) = register(&api);
        json_of(api.handle(req(
            "POST",
            "/queue",
            json!({"key": ka, "char": "kfm", "ranked": false}),
        )));
        let st = json_of(api.handle(req(
            "POST",
            "/queue",
            json!({"key": kb, "char": "kfm", "ranked": true}),
        )));
        assert!(st["found"].is_null());
        let st = json_of(api.handle(req(
            "POST",
            "/queue",
            json!({"key": kc, "char": "kfm", "ranked": false}),
        )));
        assert_eq!(st["found"]["ranked"], false);
    }

    #[test]
    fn room_lifecycle_password_spectators_kick() {
        let api = api();
        let (aid, ka) = register(&api);
        let (bid, kb) = register(&api);
        let (cid, kc) = register(&api);
        let (_, kd) = register(&api);
        let room = json_of(api.handle(req(
            "POST",
            "/room",
            json!({"key": ka, "char": "kfm", "name": "Friday <b>Night</b>", "password": "s3cret",
                   "rules": {"rounds": 9, "mode": "arena", "chars": "mirror"}, "max_spectators": 1}),
        )));
        let code = room["code"].as_str().unwrap().to_string();
        assert_eq!(room["name"], "Friday bNightb");
        assert_eq!(room["locked"], true);
        assert_eq!(room["rules"]["rounds"], 5);
        assert_eq!(room["rules"]["mode"], "arena");
        // listed publicly, without the password
        let list = json_of(api.handle(req("GET", "/rooms", Value::Null)));
        assert_eq!(list[0]["code"], code.as_str());
        assert!(!list.to_string().contains("argon2"));
        // wrong password, then right
        let r = api.handle(req(
            "POST",
            &format!("/room/{code}/join"),
            json!({"key": kb, "char": "x", "password": "nope"}),
        ));
        assert_eq!(r.status, 403);
        let joined = json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/join"),
            json!({"key": kb, "char": "G6_Naruto", "password": "s3cret"}),
        )));
        assert_eq!(joined["side"], 2);
        assert_eq!(joined["ready"], true);
        assert_eq!(joined["p2_char"], "kfm", "mirror rule");
        assert_eq!(joined["ticket"]["slot"], 1);
        // spectator gets slot 2 of the next match; the seat limit holds
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
        // rematch: both players ready → new match with the spectator slot
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
        assert_ne!(again["match_id"], joined["match_id"]);
        assert_eq!(again["ticket"]["spectators"], 1);
        let spec = json_of(api.handle(req("GET", &format!("/room/{code}?key={kc}"), Value::Null)));
        assert_eq!(spec["ticket"]["slot"], 2);
        // only the host kicks; kicked players cannot come back
        let r = api.handle(req(
            "POST",
            &format!("/room/{code}/kick"),
            json!({"key": kb, "id": cid}),
        ));
        assert_eq!(r.status, 403);
        let after = json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/kick"),
            json!({"key": ka, "id": bid}),
        )));
        assert_eq!(after["ready"], false);
        let r = api.handle(req(
            "POST",
            &format!("/room/{code}/join"),
            json!({"key": kb, "char": "kfm", "password": "s3cret"}),
        ));
        assert_eq!(r.status, 403);
        // the host leaving closes the room
        json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/leave"),
            json!({"key": ka}),
        )));
        let r = api.handle(req("GET", &format!("/room/{code}?key={kc}"), Value::Null));
        assert_eq!(r.status, 404);
        let _ = aid;
    }

    #[test]
    fn private_rooms_are_unlisted() {
        let api = api();
        let (_, ka) = register(&api);
        json_of(api.handle(req(
            "POST",
            "/room",
            json!({"key": ka, "char": "kfm", "public": false}),
        )));
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
}
