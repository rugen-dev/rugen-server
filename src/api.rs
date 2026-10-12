//! JSON API routes. All mutating calls carry the account `key` in the JSON
//! body; reads that need identity take `?key=`.
//!
//! ```text
//! GET  /                        server info
//! POST /register                → {id, key}
//! POST /profile                 {key, name?, avatar?}
//! GET  /profile/{id}
//! POST /room                    {key, char, stage?} → RoomInfo (side 1)
//! POST /room/{code}/join        {key, char}        → RoomInfo (side 2)
//! GET  /room/{code}?key=        poll until ready
//! POST /queue                   {key, char} enter ranked queue
//! GET  /queue?key=              QueueStatus (found match once paired)
//! DELETE /queue (or POST /queue/leave) {key}
//! POST /result                  {key, match_id, winner}
//! GET  /leaderboard?key=
//! GET  /seasons/current
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rugen_proto::{
    API_VERSION, Leaderboard, MatchInfo, QueueStatus, ResultAck, RoomInfo, ServerInfo,
};
use serde_json::{Value, json};

use crate::elo;
use crate::http::{Request, Response};
use crate::store::{Store, random_code};

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
    char_id: String,
    since: Instant,
}

pub struct Api {
    store: Mutex<Store>,
    rooms: Mutex<HashMap<String, Room>>,
    queue: Mutex<Vec<QueueEntry>>,
    /// Matches found for queued players, consumed on poll.
    found: Mutex<HashMap<u64, MatchInfo>>,
    udp_port: u16,
    name: String,
}

const ROOM_TTL_SECS: u64 = 15 * 60;

fn err(status: u16, msg: &str) -> Response {
    Response::json(status, &json!({ "error": msg }))
}

fn ok<T: serde::Serialize>(v: &T) -> Response {
    Response::json(200, &serde_json::to_value(v).unwrap_or(Value::Null))
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
    pub fn new(store: Store, udp_port: u16, name: String) -> Arc<Self> {
        Arc::new(Self {
            store: Mutex::new(store),
            rooms: Mutex::new(HashMap::new()),
            queue: Mutex::new(Vec::new()),
            found: Mutex::new(HashMap::new()),
            udp_port,
            name,
        })
    }

    /// Account index for the key in `v` (body) or `?key=`.
    fn auth(&self, store: &mut Store, req: &Request, v: &Value) -> Option<usize> {
        let key = v
            .get("key")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| req.query.get("key").cloned())?;
        if key.len() != 64 {
            return None;
        }
        store.by_key(&key)
    }

    pub fn handle(&self, req: Request) -> Response {
        let path: Vec<&str> = req.path.trim_matches('/').split('/').collect();
        let v = body(&req);
        match (req.method.as_str(), path.as_slice()) {
            ("GET", [""]) => {
                let queued = self.queue.lock().map(|q| q.len()).unwrap_or(0);
                let online = self.store.lock().map_or(0, |s| {
                    let t = crate::store::now();
                    s.state
                        .accounts
                        .iter()
                        .filter(|a| t.saturating_sub(a.last_seen) < 300)
                        .count()
                });
                ok(&ServerInfo {
                    api: API_VERSION,
                    name: self.name.clone(),
                    udp_port: self.udp_port,
                    online,
                    queued,
                })
            }
            ("POST", ["register"]) => {
                let mut s = self.store.lock().unwrap();
                if s.state.accounts.len() >= 1_000_000 {
                    return err(409, "server full");
                }
                let a = s.register();
                ok(&rugen_proto::Registered {
                    id: a.id,
                    key: a.key.clone(),
                })
            }
            ("POST", ["profile"]) => {
                let mut s = self.store.lock().unwrap();
                let Some(idx) = self.auth(&mut s, &req, &v) else {
                    return err(401, "bad key");
                };
                let name = str_field(&v, "name", 32);
                let avatar = v.get("avatar").and_then(Value::as_u64).map(|a| a as u32);
                s.set_profile(idx, name, avatar);
                ok(&s.state.accounts[idx].info())
            }
            ("GET", ["profile", id]) => {
                let Ok(id) = id.parse::<u64>() else {
                    return err(400, "bad id");
                };
                let s = self.store.lock().unwrap();
                match s.by_id(id) {
                    Some(a) => ok(&a.info()),
                    None => err(404, "no such player"),
                }
            }
            ("GET", ["seasons", "current"]) => ok(&self.store.lock().unwrap().season()),
            ("GET", ["leaderboard"]) => {
                let mut s = self.store.lock().unwrap();
                let me = self
                    .auth(&mut s, &req, &v)
                    .map(|idx| s.state.accounts[idx].id)
                    .and_then(|id| Some((s.rank_of(id)?, s.by_id(id)?.info())));
                ok(&Leaderboard {
                    season: s.season(),
                    rows: s.leaderboard(50),
                    me,
                })
            }
            ("POST", ["room"]) => self.create_room(&req, &v),
            ("POST", ["room", code, "join"]) => self.join_room(&req, &v, code),
            ("GET", ["room", code]) => self.poll_room(&req, &v, code),
            ("POST", ["queue"]) => self.enter_queue(&req, &v),
            ("GET", ["queue"]) => self.poll_queue(&req, &v),
            ("DELETE", ["queue"]) | ("POST", ["queue", "leave"]) => self.leave_queue(&req, &v),
            ("POST", ["result"]) => self.result(&req, &v),
            _ => err(404, "no such route"),
        }
    }

    fn expire_rooms(rooms: &mut HashMap<String, Room>) {
        rooms.retain(|_, r| r.created.elapsed().as_secs() < ROOM_TTL_SECS);
    }

    fn room_info(&self, store: &Store, code: &str, r: &Room, side: u8) -> RoomInfo {
        let other = if side == 1 { r.joiner } else { Some(r.creator) };
        RoomInfo {
            code: code.to_string(),
            side,
            ready: r.joiner.is_some(),
            p1_char: r.p1_char.clone(),
            p2_char: r.p2_char.clone(),
            stage: r.stage.clone(),
            opponent: other.and_then(|id| store.by_id(id)).map(|a| a.info()),
            match_id: r.match_id,
        }
    }

    fn create_room(&self, req: &Request, v: &Value) -> Response {
        let mut s = self.store.lock().unwrap();
        let Some(idx) = self.auth(&mut s, req, v) else {
            return err(401, "bad key");
        };
        let me = s.state.accounts[idx].id;
        let char_id = clean_char(&str_field(v, "char", 64).unwrap_or_default());
        if char_id.is_empty() {
            return err(400, "char required");
        }
        let stage = clean_char(&str_field(v, "stage", 64).unwrap_or_default());
        let mut rooms = self.rooms.lock().unwrap();
        Self::expire_rooms(&mut rooms);
        if rooms.len() > 10_000 {
            return err(409, "too many rooms");
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
        let info = self.room_info(&s, &code, &room, 1);
        rooms.insert(code, room);
        log::info!("room created by {me}");
        ok(&info)
    }

    fn join_room(&self, req: &Request, v: &Value, code: &str) -> Response {
        let mut s = self.store.lock().unwrap();
        let Some(idx) = self.auth(&mut s, req, v) else {
            return err(401, "bad key");
        };
        let me = s.state.accounts[idx].id;
        let char_id = clean_char(&str_field(v, "char", 64).unwrap_or_default());
        if char_id.is_empty() {
            return err(400, "char required");
        }
        let code = code.to_ascii_uppercase();
        let mut rooms = self.rooms.lock().unwrap();
        Self::expire_rooms(&mut rooms);
        let Some(r) = rooms.get_mut(&code) else {
            return err(404, "no such room");
        };
        if r.creator == me {
            return err(409, "that is your own room");
        }
        if r.joiner.is_some() && r.joiner != Some(me) {
            return err(409, "room is full");
        }
        if r.joiner.is_none() {
            r.joiner = Some(me);
            r.p2_char = char_id;
            r.match_id = s.new_match([r.creator, me], false);
            log::info!("room {code}: {me} joined");
        }
        let info = self.room_info(&s, &code, r, 2);
        ok(&info)
    }

    fn poll_room(&self, req: &Request, v: &Value, code: &str) -> Response {
        let mut s = self.store.lock().unwrap();
        let Some(idx) = self.auth(&mut s, req, v) else {
            return err(401, "bad key");
        };
        let me = s.state.accounts[idx].id;
        let code = code.to_ascii_uppercase();
        let rooms = self.rooms.lock().unwrap();
        let Some(r) = rooms.get(&code) else {
            return err(404, "no such room");
        };
        let side = if r.creator == me {
            1
        } else if r.joiner == Some(me) {
            2
        } else {
            return err(401, "not in this room");
        };
        ok(&self.room_info(&s, &code, r, side))
    }

    fn enter_queue(&self, req: &Request, v: &Value) -> Response {
        let mut s = self.store.lock().unwrap();
        let Some(idx) = self.auth(&mut s, req, v) else {
            return err(401, "bad key");
        };
        let (me, rating) = (s.state.accounts[idx].id, s.state.accounts[idx].rating);
        let char_id = clean_char(&str_field(v, "char", 64).unwrap_or_default());
        if char_id.is_empty() {
            return err(400, "char required");
        }
        let mut q = self.queue.lock().unwrap();
        if q.len() > 10_000 {
            return err(409, "queue full");
        }
        if !q.iter().any(|e| e.id == me) {
            q.push(QueueEntry {
                id: me,
                rating,
                char_id,
                since: Instant::now(),
            });
            log::info!("{me} queued ({rating})");
        }
        drop(q);
        drop(s);
        self.status_for(me)
    }

    fn leave_queue(&self, req: &Request, v: &Value) -> Response {
        let mut s = self.store.lock().unwrap();
        let Some(idx) = self.auth(&mut s, req, v) else {
            return err(401, "bad key");
        };
        let me = s.state.accounts[idx].id;
        self.queue.lock().unwrap().retain(|e| e.id != me);
        self.found.lock().unwrap().remove(&me);
        ok(&json!({ "queued": false }))
    }

    fn poll_queue(&self, req: &Request, v: &Value) -> Response {
        let me = {
            let mut s = self.store.lock().unwrap();
            let Some(idx) = self.auth(&mut s, req, v) else {
                return err(401, "bad key");
            };
            s.state.accounts[idx].id
        };
        self.pair();
        self.status_for(me)
    }

    fn status_for(&self, me: u64) -> Response {
        if let Some(m) = self.found.lock().unwrap().remove(&me) {
            return ok(&QueueStatus {
                queued: false,
                waiting_secs: 0,
                players_in_queue: self.queue.lock().unwrap().len(),
                found: Some(m),
            });
        }
        let q = self.queue.lock().unwrap();
        let mine = q.iter().find(|e| e.id == me);
        ok(&QueueStatus {
            queued: mine.is_some(),
            waiting_secs: mine.map_or(0, |e| e.since.elapsed().as_secs()),
            players_in_queue: q.len(),
            found: None,
        })
    }

    /// Pair queued players whose ratings fit inside each other's widening window.
    fn pair(&self) {
        let mut q = self.queue.lock().unwrap();
        // drop entries nobody polled for a while (client gone)
        q.retain(|e| e.since.elapsed().as_secs() < 600);
        let mut i = 0;
        while i < q.len() {
            let mut partner = None;
            for j in (i + 1)..q.len() {
                let gap = (q[i].rating - q[j].rating).abs();
                let allowed = elo::window(q[i].since.elapsed().as_secs())
                    .max(elo::window(q[j].since.elapsed().as_secs()));
                if gap <= allowed {
                    partner = Some(j);
                    break;
                }
            }
            let Some(j) = partner else {
                i += 1;
                continue;
            };
            let b = q.remove(j);
            let a = q.remove(i);
            let mut s = self.store.lock().unwrap();
            let match_id = s.new_match([a.id, b.id], true);
            let code = random_code();
            let (pa, pb) = (
                s.by_id(a.id).map(|x| x.info()).unwrap_or_default(),
                s.by_id(b.id).map(|x| x.info()).unwrap_or_default(),
            );
            drop(s);
            let mut found = self.found.lock().unwrap();
            found.insert(
                a.id,
                MatchInfo {
                    match_id,
                    code: code.clone(),
                    side: 1,
                    my_char: a.char_id.clone(),
                    opponent: pb,
                    opponent_char: b.char_id.clone(),
                    stage: String::new(),
                },
            );
            found.insert(
                b.id,
                MatchInfo {
                    match_id,
                    code: code.clone(),
                    side: 2,
                    my_char: b.char_id,
                    opponent: pa,
                    opponent_char: a.char_id,
                    stage: String::new(),
                },
            );
            log::info!(
                "ranked match {match_id}: {} vs {} in room {code}",
                a.id,
                b.id
            );
        }
    }

    fn result(&self, req: &Request, v: &Value) -> Response {
        let mut s = self.store.lock().unwrap();
        let Some(idx) = self.auth(&mut s, req, v) else {
            return err(401, "bad key");
        };
        let me = s.state.accounts[idx].id;
        let (Some(match_id), Some(winner)) = (
            v.get("match_id").and_then(Value::as_u64),
            v.get("winner").and_then(Value::as_u64),
        ) else {
            return err(400, "match_id and winner required");
        };
        let (accepted, delta) = s.report(me, match_id, winner);
        if !accepted {
            return err(404, "not your match");
        }
        let rating = delta.map(|_| s.state.accounts[idx].rating);
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
    use std::net::{IpAddr, Ipv4Addr};

    fn req(method: &str, path: &str, body: Value) -> Request {
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
            peer: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }

    fn json_of(r: Response) -> Value {
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        serde_json::from_slice(&r.body).unwrap()
    }

    #[test]
    fn ranked_queue_pairs_and_reports() {
        let api = Api::new(Store::open(None).unwrap(), 7777, "test".into());
        let a = json_of(api.handle(req("POST", "/register", Value::Null)));
        let b = json_of(api.handle(req("POST", "/register", Value::Null)));
        let (ka, kb) = (a["key"].as_str().unwrap(), b["key"].as_str().unwrap());
        let st = json_of(api.handle(req("POST", "/queue", json!({"key": ka, "char": "kfm"}))));
        assert_eq!(st["queued"], true);
        let st = json_of(api.handle(req(
            "POST",
            "/queue",
            json!({"key": kb, "char": "G6_Naruto"}),
        )));
        assert_eq!(st["queued"], true);
        let fa = json_of(api.handle(req("GET", &format!("/queue?key={ka}"), Value::Null)));
        let fb = json_of(api.handle(req("GET", &format!("/queue?key={kb}"), Value::Null)));
        assert_eq!(fa["found"]["side"], 1);
        assert_eq!(fb["found"]["side"], 2);
        assert_eq!(fa["found"]["code"], fb["found"]["code"]);
        assert_eq!(fa["found"]["opponent_char"], "G6_Naruto");
        let mid = fa["found"]["match_id"].as_u64().unwrap();
        let aid = a["id"].as_u64().unwrap();
        let r1 = json_of(api.handle(req(
            "POST",
            "/result",
            json!({"key": ka, "match_id": mid, "winner": aid}),
        )));
        assert!(r1["delta"].is_null());
        let r2 = json_of(api.handle(req(
            "POST",
            "/result",
            json!({"key": kb, "match_id": mid, "winner": aid}),
        )));
        assert_eq!(r2["delta"], -16);
        let lb = json_of(api.handle(req("GET", "/leaderboard", Value::Null)));
        assert_eq!(lb["rows"][0]["id"], aid);
        assert_eq!(lb["rows"][0]["rank"], "SILVER");
    }

    #[test]
    fn rooms_pair_creator_and_joiner() {
        let api = Api::new(Store::open(None).unwrap(), 7777, "test".into());
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
        let api = Api::new(Store::open(None).unwrap(), 7777, "test".into());
        let r = api.handle(req("POST", "/queue", json!({"key": "nope", "char": "kfm"})));
        assert_eq!(r.status, 401);
        let r = api.handle(req("GET", "/nothing", Value::Null));
        assert_eq!(r.status, 404);
    }
}
