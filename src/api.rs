//! JSON API routes. All mutating calls carry the account `key` in the JSON
//! body; reads that need identity take `?key=`.
//!
//! ```text
//! GET  /                        server info
//! GET  /health                  liveness (also checks the database)
//! POST /register                → {id, key}
//! POST /profile                 {key, name?, avatar?, region?}
//! GET  /profile/{id}
//! POST /room                    {key, char, stage?} → RoomInfo (side 1)
//! POST /room/{code}/join        {key, char}        → RoomInfo (side 2)
//! GET  /room/{code}?key=        poll until ready
//! POST /queue                   {key, char, region?, max_ping?} enter ranked queue
//! GET  /queue?key=              QueueStatus (found match once paired)
//! DELETE /queue (or POST /queue/leave) {key}
//! POST /result                  {key, match_id, winner, ping_ms?}
//! GET  /leaderboard?key=
//! GET  /seasons/current
//! GET  /turn?key=               short-lived TURN credentials (when configured)
//! GET  /ws?key=                 WebSocket: presence + signaling (see `signal.rs`)
//! ```
//!
//! The handlers are synchronous (SQLite under a mutex); the HTTP layer runs
//! them on the blocking pool.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rugen_proto::{
    API_VERSION, Leaderboard, MatchInfo, QueueStatus, ResultAck, RoomInfo, ServerInfo, ServerMsg,
};
use serde_json::{Value, json};

use crate::cfturn::CfTurn;
use crate::matchmaking::{self, Candidate};
use crate::signal::Hub;
use crate::store::{Account, DbResult, Store, random_code};

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub body: Vec<u8>,
    /// Region hint from the edge (`CF-IPCountry`), empty when not behind Cloudflare.
    pub country: String,
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

struct Room {
    creator: u64,
    joiner: Option<u64>,
    p1_char: String,
    p2_char: String,
    stage: String,
    match_id: u64,
    created: Instant,
}

struct QueueEntry {
    id: u64,
    rating: i32,
    region: String,
    max_ping: Option<u32>,
    char_id: String,
    since: Instant,
    last_poll: Instant,
}

#[derive(Default)]
pub struct ApiConfig {
    pub name: String,
    /// Legacy UDP rendezvous / relay port (0 = disabled).
    pub udp_port: u16,
    /// Public `host:port` of the UDP relay, sent to clients.
    pub udp_relay: Option<String>,
    pub turn: Option<CfTurn>,
}

pub struct Api {
    store: Mutex<Store>,
    rooms: Mutex<HashMap<String, Room>>,
    queue: Mutex<Vec<QueueEntry>>,
    /// Matches found for queued players, consumed on poll.
    found: Mutex<HashMap<u64, MatchInfo>>,
    pub hub: Mutex<Hub>,
    cfg: ApiConfig,
}

const ROOM_TTL_SECS: u64 = 15 * 60;

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

fn body(req: &Request) -> Value {
    serde_json::from_slice(&req.body).unwrap_or(Value::Null)
}

fn str_field(v: &Value, k: &str, max: usize) -> Option<String> {
    v.get(k)
        .and_then(Value::as_str)
        .map(|s| s.chars().take(max).collect::<String>())
        .filter(|s| !s.is_empty())
}

/// Character ids are file stems: letters, digits, `_`, `-`, `.` and spaces.
fn clean_char(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | ' '))
        .take(64)
        .collect()
}

impl Api {
    pub fn new(store: Store, cfg: ApiConfig) -> Arc<Self> {
        let mut hub = Hub::default();
        hub.turn = cfg.turn.is_some();
        hub.udp_relay = cfg.udp_relay.clone();
        Arc::new(Self {
            store: Mutex::new(store),
            rooms: Mutex::new(HashMap::new()),
            queue: Mutex::new(Vec::new()),
            found: Mutex::new(HashMap::new()),
            hub: Mutex::new(hub),
            cfg,
        })
    }

    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The account owning a key (WebSocket upgrade).
    pub fn account_for_key(&self, key: &str) -> Option<Account> {
        if key.len() != 64 {
            return None;
        }
        self.store().by_key(key).ok().flatten()
    }

    /// Account for the key in `v` (body) or `?key=`; remembers the edge region.
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
        let a = db(store.by_key(&key))?.ok_or_else(|| err(401, "bad key"))?;
        if !req.country.is_empty() {
            db(store.set_region(a.id, &req.country))?;
        }
        Ok(a)
    }

    pub fn handle(&self, req: Request) -> Response {
        self.route(req).unwrap_or_else(|e| e)
    }

    fn route(&self, req: Request) -> Res {
        let path: Vec<&str> = req.path.trim_matches('/').split('/').collect();
        let v = body(&req);
        match (req.method.as_str(), path.as_slice()) {
            ("GET", [""]) => {
                let queued = self.queue.lock().map(|q| q.len()).unwrap_or(0);
                let ws = self.hub.lock().map(|h| h.online()).unwrap_or(0);
                let online = db(self.store().online_count(300))?.max(ws);
                ok(&ServerInfo {
                    api: API_VERSION,
                    name: self.cfg.name.clone(),
                    udp_port: self.cfg.udp_port,
                    online,
                    queued,
                    udp_relay: self.cfg.udp_relay.clone(),
                    turn: self.cfg.turn.is_some(),
                    region: crate::store::clean_region(&req.country),
                })
            }
            ("GET", ["health"]) => {
                db(self.store().account_count())?;
                ok(&json!({ "ok": true }))
            }
            ("POST", ["register"]) => {
                let mut s = self.store();
                if db(s.account_count())? >= 1_000_000 {
                    return Err(err(409, "server full"));
                }
                let a = db(s.register())?;
                if !req.country.is_empty() {
                    db(s.set_region(a.id, &req.country))?;
                }
                ok(&rugen_proto::Registered {
                    id: a.id,
                    key: a.key,
                })
            }
            ("POST", ["profile"]) => {
                let mut s = self.store();
                let a = self.auth(&mut s, &req, &v)?;
                let name = str_field(&v, "name", 32);
                let avatar = v.get("avatar").and_then(Value::as_u64).map(|a| a as u32);
                if req.country.is_empty()
                    && let Some(r) = str_field(&v, "region", 8)
                {
                    db(s.set_region(a.id, &r))?;
                }
                let a = db(s.set_profile(a.id, name, avatar))?.ok_or_else(|| err(404, "gone"))?;
                ok(&a.info())
            }
            ("GET", ["profile", id]) => {
                let id = id.parse::<u64>().map_err(|_| err(400, "bad id"))?;
                match db(self.store().by_id(id))? {
                    Some(a) => ok(&a.info()),
                    None => Err(err(404, "no such player")),
                }
            }
            ("GET", ["seasons", "current"]) => {
                let mut s = self.store();
                db(s.roll_season())?;
                ok(&db(s.season())?)
            }
            ("GET", ["leaderboard"]) => {
                let mut s = self.store();
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
            ("GET", ["turn"]) => {
                {
                    let mut s = self.store();
                    self.auth(&mut s, &req, &v)?;
                }
                let turn = self
                    .cfg
                    .turn
                    .as_ref()
                    .ok_or_else(|| err(404, "no TURN on this server"))?;
                match turn.credentials() {
                    Ok(c) => ok(&c),
                    Err(e) => {
                        log::warn!("turn: {e}");
                        Err(err(502, "TURN credentials unavailable"))
                    }
                }
            }
            ("POST", ["room"]) => self.create_room(&req, &v),
            ("POST", ["room", code, "join"]) => self.join_room(&req, &v, code),
            ("GET", ["room", code]) => self.poll_room(&req, &v, code),
            ("POST", ["queue"]) => self.enter_queue(&req, &v),
            ("GET", ["queue"]) => self.poll_queue(&req, &v),
            ("DELETE", ["queue"]) | ("POST", ["queue", "leave"]) => self.leave_queue(&req, &v),
            ("POST", ["result"]) => self.result(&req, &v),
            _ => Err(err(404, "no such route")),
        }
    }

    fn expire_rooms(rooms: &mut HashMap<String, Room>) {
        rooms.retain(|_, r| r.created.elapsed().as_secs() < ROOM_TTL_SECS);
    }

    /// Estimated round trip between two players from their regions.
    fn estimate(store: &Store, a: u64, b: u64) -> DbResult<Option<u32>> {
        let (ra, rb) = (store.region_of(a)?, store.region_of(b)?);
        if ra.is_empty() || rb.is_empty() {
            return Ok(None);
        }
        let measured = store.region_ping(&ra, &rb)?;
        Ok(Some(matchmaking::estimate(&ra, &rb, measured)))
    }

    fn room_info(&self, store: &Store, code: &str, r: &Room, side: u8) -> DbResult<RoomInfo> {
        let other = if side == 1 { r.joiner } else { Some(r.creator) };
        let opponent = match other {
            Some(id) => store.by_id(id)?.map(|a| a.info()),
            None => None,
        };
        let est_ping_ms = match r.joiner {
            Some(j) => Self::estimate(store, r.creator, j)?,
            None => None,
        };
        Ok(RoomInfo {
            code: code.to_string(),
            side,
            ready: r.joiner.is_some(),
            p1_char: r.p1_char.clone(),
            p2_char: r.p2_char.clone(),
            stage: r.stage.clone(),
            opponent,
            match_id: r.match_id,
            est_ping_ms,
        })
    }

    fn create_room(&self, req: &Request, v: &Value) -> Res {
        let mut s = self.store();
        let me = self.auth(&mut s, req, v)?.id;
        let char_id = clean_char(&str_field(v, "char", 64).unwrap_or_default());
        if char_id.is_empty() {
            return Err(err(400, "char required"));
        }
        let stage = clean_char(&str_field(v, "stage", 64).unwrap_or_default());
        let mut rooms = self.rooms.lock().unwrap_or_else(|p| p.into_inner());
        Self::expire_rooms(&mut rooms);
        if rooms.len() > 10_000 {
            return Err(err(409, "too many rooms"));
        }
        // one open room per player
        rooms.retain(|_, r| r.creator != me || r.joiner.is_some());
        let mut code = random_code();
        while rooms.contains_key(&code) {
            code = random_code();
        }
        let room = Room {
            creator: me,
            joiner: None,
            p1_char: char_id,
            p2_char: String::new(),
            stage,
            match_id: 0,
            created: Instant::now(),
        };
        let info = db(self.room_info(&s, &code, &room, 1))?;
        rooms.insert(code, room);
        log::info!("room created by {me}");
        ok(&info)
    }

    fn join_room(&self, req: &Request, v: &Value, code: &str) -> Res {
        let mut s = self.store();
        let me = self.auth(&mut s, req, v)?.id;
        let char_id = clean_char(&str_field(v, "char", 64).unwrap_or_default());
        if char_id.is_empty() {
            return Err(err(400, "char required"));
        }
        let code = code.to_ascii_uppercase();
        let mut rooms = self.rooms.lock().unwrap_or_else(|p| p.into_inner());
        Self::expire_rooms(&mut rooms);
        let r = rooms
            .get_mut(&code)
            .ok_or_else(|| err(404, "no such room"))?;
        if r.creator == me {
            return Err(err(409, "that is your own room"));
        }
        if r.joiner.is_some() && r.joiner != Some(me) {
            return Err(err(409, "room is full"));
        }
        if r.joiner.is_none() {
            r.joiner = Some(me);
            r.p2_char = char_id;
            r.match_id = db(s.new_match([r.creator, me], false))?;
            log::info!("room {code}: {me} joined");
            let creator_view = db(self.room_info(&s, &code, r, 1))?;
            let mut hub = self.hub.lock().unwrap_or_else(|p| p.into_inner());
            hub.register_session(&code, [r.creator, me]);
            hub.push(r.creator, &ServerMsg::Room { room: creator_view });
        }
        ok(&db(self.room_info(&s, &code, r, 2))?)
    }

    fn poll_room(&self, req: &Request, v: &Value, code: &str) -> Res {
        let mut s = self.store();
        let me = self.auth(&mut s, req, v)?.id;
        let code = code.to_ascii_uppercase();
        let rooms = self.rooms.lock().unwrap_or_else(|p| p.into_inner());
        let r = rooms.get(&code).ok_or_else(|| err(404, "no such room"))?;
        let side = if r.creator == me {
            1
        } else if r.joiner == Some(me) {
            2
        } else {
            return Err(err(401, "not in this room"));
        };
        ok(&db(self.room_info(&s, &code, r, side))?)
    }

    fn enter_queue(&self, req: &Request, v: &Value) -> Res {
        let mut s = self.store();
        let a = self.auth(&mut s, req, v)?;
        let char_id = clean_char(&str_field(v, "char", 64).unwrap_or_default());
        if char_id.is_empty() {
            return Err(err(400, "char required"));
        }
        if req.country.is_empty()
            && let Some(r) = str_field(v, "region", 8)
        {
            db(s.set_region(a.id, &r))?;
        }
        let region = db(s.region_of(a.id))?;
        let max_ping = v
            .get("max_ping")
            .and_then(Value::as_u64)
            .filter(|&p| p > 0)
            .map(|p| p.min(10_000) as u32);
        let mut q = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        if q.len() > 10_000 {
            return Err(err(409, "queue full"));
        }
        if !q.iter().any(|e| e.id == a.id) {
            q.push(QueueEntry {
                id: a.id,
                rating: a.rating,
                region,
                max_ping,
                char_id,
                since: Instant::now(),
                last_poll: Instant::now(),
            });
            log::info!("{} queued ({})", a.id, a.rating);
        }
        drop(q);
        drop(s);
        self.pair()?;
        self.status_for(a.id)
    }

    fn leave_queue(&self, req: &Request, v: &Value) -> Res {
        let me = {
            let mut s = self.store();
            self.auth(&mut s, req, v)?.id
        };
        self.queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|e| e.id != me);
        self.found
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&me);
        ok(&json!({ "queued": false }))
    }

    fn poll_queue(&self, req: &Request, v: &Value) -> Res {
        let me = {
            let mut s = self.store();
            self.auth(&mut s, req, v)?.id
        };
        if let Some(e) = self
            .queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter_mut()
            .find(|e| e.id == me)
        {
            e.last_poll = Instant::now();
        }
        self.pair()?;
        self.status_for(me)
    }

    fn status_for(&self, me: u64) -> Res {
        let found = self
            .found
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&me);
        let q = self.queue.lock().unwrap_or_else(|p| p.into_inner());
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

    /// Pair queued players: rating and ping windows widen with waiting time;
    /// among acceptable partners the lowest estimated ping wins.
    pub fn pair(&self) -> Result<(), Response> {
        let mut q = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        // drop entries nobody polled for a while (client gone)
        q.retain(|e| e.last_poll.elapsed().as_secs() < 60);
        if q.len() < 2 {
            return Ok(());
        }
        let mut s = self.store();
        let cands: Vec<Candidate> = q
            .iter()
            .map(|e| Candidate {
                id: e.id,
                rating: e.rating,
                region: e.region.clone(),
                waited_secs: e.since.elapsed().as_secs(),
                max_ping: e.max_ping,
            })
            .collect();
        let mut measured: HashMap<(String, String), Option<u32>> = HashMap::new();
        for a in &cands {
            for b in &cands {
                if a.id < b.id && !a.region.is_empty() && !b.region.is_empty() {
                    let m = db(s.region_ping(&a.region, &b.region))?;
                    measured.insert((a.region.clone(), b.region.clone()), m);
                }
            }
        }
        let pairs = matchmaking::pairs(&cands, |a, b| {
            let m = measured
                .get(&(a.region.clone(), b.region.clone()))
                .or_else(|| measured.get(&(b.region.clone(), a.region.clone())))
                .copied()
                .flatten();
            matchmaking::estimate(&a.region, &b.region, m)
        });
        let mut remove = Vec::new();
        for (i, j) in pairs {
            let (a, b) = (&q[i], &q[j]);
            let est = matchmaking::estimate(
                &a.region,
                &b.region,
                db(s.region_ping(&a.region, &b.region))?,
            );
            let match_id = db(s.new_match([a.id, b.id], true))?;
            let code = random_code();
            let pa = db(s.by_id(a.id))?.map(|x| x.info()).unwrap_or_default();
            let pb = db(s.by_id(b.id))?.map(|x| x.info()).unwrap_or_default();
            let known = !a.region.is_empty() && !b.region.is_empty();
            let ma = MatchInfo {
                match_id,
                code: code.clone(),
                side: 1,
                my_char: a.char_id.clone(),
                opponent: pb,
                opponent_char: b.char_id.clone(),
                stage: String::new(),
                est_ping_ms: known.then_some(est),
            };
            let mb = MatchInfo {
                match_id,
                code: code.clone(),
                side: 2,
                my_char: b.char_id.clone(),
                opponent: pa,
                opponent_char: a.char_id.clone(),
                stage: String::new(),
                est_ping_ms: known.then_some(est),
            };
            {
                let mut hub = self.hub.lock().unwrap_or_else(|p| p.into_inner());
                hub.register_session(&code, [a.id, b.id]);
                hub.push(a.id, &ServerMsg::Found { found: ma.clone() });
                hub.push(b.id, &ServerMsg::Found { found: mb.clone() });
            }
            let mut found = self.found.lock().unwrap_or_else(|p| p.into_inner());
            found.insert(a.id, ma);
            found.insert(b.id, mb);
            log::info!(
                "ranked match {match_id}: {} vs {} in {code} (est {est} ms)",
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

    fn result(&self, req: &Request, v: &Value) -> Res {
        let mut s = self.store();
        let me = self.auth(&mut s, req, v)?.id;
        let (Some(match_id), Some(winner)) = (
            v.get("match_id").and_then(Value::as_u64),
            v.get("winner").and_then(Value::as_u64),
        ) else {
            return Err(err(400, "match_id and winner required"));
        };
        let (accepted, delta) = db(s.report(me, match_id, winner))?;
        if !accepted {
            return Err(err(404, "not your match"));
        }
        // measured round trip feeds the region-pair latency table
        if let Some(ping) = v.get("ping_ms").and_then(Value::as_u64)
            && ping > 0
            && let Some(opp) = db(s.opponent_of(match_id, me))?
        {
            let (ra, rb) = (db(s.region_of(me))?, db(s.region_of(opp))?);
            db(s.record_ping(&ra, &rb, ping as u32))?;
        }
        let rating = match delta {
            Some(_) => db(s.by_id(me))?.map(|a| a.rating),
            None => None,
        };
        ok(&ResultAck {
            accepted,
            rating,
            delta,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, path: &str, body: Value) -> Request {
        req_from(method, path, body, "")
    }

    fn req_from(method: &str, path: &str, body: Value, country: &str) -> Request {
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
            country: country.into(),
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
                ..Default::default()
            },
        )
    }

    #[test]
    fn ranked_queue_pairs_and_reports() {
        let api = api();
        let a = json_of(api.handle(req("POST", "/register", Value::Null)));
        let b = json_of(api.handle(req("POST", "/register", Value::Null)));
        let (ka, kb) = (a["key"].as_str().unwrap(), b["key"].as_str().unwrap());
        let st = json_of(api.handle(req("POST", "/queue", json!({"key": ka, "char": "kfm"}))));
        assert_eq!(st["queued"], true);
        // the second entry pairs straight away
        let fb = json_of(api.handle(req(
            "POST",
            "/queue",
            json!({"key": kb, "char": "G6_Naruto"}),
        )));
        let fa = json_of(api.handle(req("GET", &format!("/queue?key={ka}"), Value::Null)));
        assert_eq!(fa["found"]["side"], 1);
        assert_eq!(fb["found"]["side"], 2);
        assert_eq!(fa["found"]["code"], fb["found"]["code"]);
        assert_eq!(fa["found"]["opponent_char"], "G6_Naruto");
        let mid = fa["found"]["match_id"].as_u64().unwrap();
        let aid = a["id"].as_u64().unwrap();
        let r1 = json_of(api.handle(req(
            "POST",
            "/result",
            json!({"key": ka, "match_id": mid, "winner": aid, "ping_ms": 42}),
        )));
        assert!(r1["delta"].is_null());
        let r2 = json_of(api.handle(req(
            "POST",
            "/result",
            json!({"key": kb, "match_id": mid, "winner": aid}),
        )));
        assert_eq!(r2["delta"], -16);
        assert_eq!(r2["rating"], 1184);
        let lb = json_of(api.handle(req("GET", "/leaderboard", Value::Null)));
        assert_eq!(lb["rows"][0]["id"], aid);
        assert_eq!(lb["rows"][0]["rank"], "SILVER");
        let lb = json_of(api.handle(req("GET", &format!("/leaderboard?key={kb}"), Value::Null)));
        assert_eq!(lb["me"][0], 2);
    }

    #[test]
    fn queue_prefers_low_ping_regions_and_learns_pings() {
        let api = api();
        let reg = |c: &str| json_of(api.handle(req_from("POST", "/register", Value::Null, c)));
        let (fr1, us, fr2) = (reg("FR"), reg("US"), reg("FR"));
        let key = |v: &Value| v["key"].as_str().unwrap().to_string();
        for (p, c) in [(&fr1, "kfm"), (&us, "kfm")] {
            let st = json_of(api.handle(req("POST", "/queue", json!({"key": key(p), "char": c}))));
            assert!(st["found"].is_null(), "FR and US must not pair at once");
        }
        let st = json_of(api.handle(req(
            "POST",
            "/queue",
            json!({"key": key(&fr2), "char": "kfm"}),
        )));
        assert_eq!(st["found"]["opponent"]["id"], fr1["id"]);
        assert_eq!(st["found"]["est_ping_ms"], matchmaking::SAME_REGION_MS);
        let info = json_of(api.handle(req_from("GET", "/", Value::Null, "DE")));
        assert_eq!(info["region"], "DE");
        assert_eq!(info["turn"], false);
    }

    #[test]
    fn rooms_pair_creator_and_joiner() {
        let api = api();
        let a = json_of(api.handle(req("POST", "/register", Value::Null)));
        let b = json_of(api.handle(req("POST", "/register", Value::Null)));
        let (ka, kb) = (a["key"].as_str().unwrap(), b["key"].as_str().unwrap());
        let room = json_of(api.handle(req("POST", "/room", json!({"key": ka, "char": "kfm"}))));
        let code = room["code"].as_str().unwrap().to_string();
        assert_eq!(room["ready"], false);
        assert_eq!(code.len(), 5);
        let bad = api.handle(req(
            "POST",
            "/room/ZZZZZ/join",
            json!({"key": kb, "char": "kfm"}),
        ));
        assert_eq!(bad.status, 404);
        let joined = json_of(api.handle(req(
            "POST",
            &format!("/room/{code}/join"),
            json!({"key": kb, "char": "kfm"}),
        )));
        assert_eq!(joined["side"], 2);
        assert_eq!(joined["ready"], true);
        let polled =
            json_of(api.handle(req("GET", &format!("/room/{code}?key={ka}"), Value::Null)));
        assert_eq!(polled["ready"], true);
        assert_eq!(polled["opponent"]["id"], b["id"]);
    }

    #[test]
    fn bad_keys_are_rejected() {
        let api = api();
        let r = api.handle(req("POST", "/queue", json!({"key": "nope", "char": "kfm"})));
        assert_eq!(r.status, 401);
        let r = api.handle(req("GET", "/nothing", Value::Null));
        assert_eq!(r.status, 404);
        let a = json_of(api.handle(req("POST", "/register", Value::Null)));
        let r = api.handle(req(
            "GET",
            &format!("/turn?key={}", a["key"].as_str().unwrap()),
            Value::Null,
        ));
        assert_eq!(r.status, 404);
        assert_eq!(
            json_of(api.handle(req("GET", "/health", Value::Null)))["ok"],
            true
        );
    }
}
