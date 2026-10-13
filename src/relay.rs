//! The match relay: every datagram of a match goes player → server → player
//! (and host → spectators). Sessions are created by the lobby (room match,
//! quick match, ranked) with one secret token per slot; the token
//! authenticates each datagram ([`rugen_proto::relay`] framing), so a slot's
//! transport may change (UDP ↔ WebSocket, NAT rebinding) without trust in
//! source addresses. The server never inspects payloads (ggrs messages) and
//! never tells anyone where another slot connects from.
//!
//! Concurrency: there is no relay-wide lock on the datagram path. The
//! session map is behind a read-mostly `RwLock` (writes only on create /
//! close / expiry) and each session has its own mutex, so frames of
//! different matches never contend. A `/relay` WebSocket connection
//! ([`WsConn`]) remembers the (session, slot) pairs it routes for, so a
//! disconnect touches only those sessions. Outbound WebSocket queues are
//! bounded: when a slow client's queue is full, new frames for it are
//! dropped (and counted) like lost UDP datagrams; ggrs resends.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};
use std::time::{Duration, Instant};

use rugen_proto::relay::{self as wire, Header, TOKEN_LEN};
use tokio::sync::mpsc;

/// Datagrams per slot per second (ggrs sends ~60-120).
const SLOT_PPS: u32 = 600;
/// Sessions without traffic for this long are dropped.
pub const IDLE: Duration = Duration::from_secs(120);
/// Hard cap on a session's life.
const MAX_AGE: Duration = Duration::from_secs(3 * 3600);
const MAX_SESSIONS: usize = 10_000;
/// A session counts as a running match (`/health` "matches") while a slot
/// is connected and it carried traffic this recently.
pub const ACTIVE: Duration = Duration::from_secs(10);
/// Outbound frames queued per `/relay` WebSocket (~2 s of a match).
pub const WS_QUEUE: usize = 256;
/// How long a closed session's [`Presence`] stays known (a flee claim is
/// checked against it after both players left).
const ENDED_KEEP: Duration = Duration::from_secs(3600);

/// What the relay saw of one slot: when it was last heard from and how it
/// left. The server's own view of who left a match first (a claim that the
/// other player fled is checked against it, never taken on trust).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Presence {
    /// The slot sent at least one valid datagram.
    pub joined: bool,
    /// Last valid datagram (the session's creation before the first).
    pub heard: Instant,
    /// Its last word was BYE (it left the session).
    pub bye: bool,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// One `/relay` WebSocket connection: its bounded outbound queue and the
/// (session, slot) pairs routed to it (reverse index for disconnects).
pub struct WsConn {
    pub id: u64,
    tx: mpsc::Sender<Vec<u8>>,
    bound: Mutex<Vec<(u32, u8)>>,
}

/// Where a slot's datagrams go back to.
#[derive(Clone)]
pub enum Route {
    Udp(SocketAddr),
    /// A `/relay` WebSocket connection.
    Ws(Arc<WsConn>),
}

impl PartialEq for Route {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Route::Udp(a), Route::Udp(b)) => a == b,
            (Route::Ws(a), Route::Ws(b)) => a.id == b.id,
            _ => false,
        }
    }
}

impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Route::Udp(a) => write!(f, "Udp({a})"),
            Route::Ws(c) => write!(f, "Ws({})", c.id),
        }
    }
}

struct Slot {
    token: [u8; TOKEN_LEN],
    route: Option<Route>,
    rate: (Instant, u32),
    /// TURN bytes (received, sent) this slot reported in its HELLOs.
    turn: (u64, u64),
    /// Last valid datagram from this slot.
    heard: Instant,
    /// Said BYE (and nothing since).
    bye: bool,
    /// Sent at least one valid datagram.
    joined: bool,
}

struct Session {
    slots: Vec<Slot>,
    created: Instant,
    last: Instant,
}

impl Session {
    fn mask(&self) -> u8 {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.route.is_some())
            .fold(0u8, |m, (i, _)| {
                m | (1u8.checked_shl(i as u32).unwrap_or(0))
            })
    }

    fn alive(&self, now: Instant) -> bool {
        now.duration_since(self.last) < IDLE && now.duration_since(self.created) < MAX_AGE
    }

    fn presence(&self) -> Vec<Presence> {
        self.slots
            .iter()
            .map(|s| Presence {
                joined: s.joined,
                heard: s.heard,
                bye: s.bye,
            })
            .collect()
    }
}

#[derive(Default)]
pub struct Relay {
    sessions: RwLock<HashMap<u32, Arc<Mutex<Session>>>>,
    next_ws: AtomicU64,
    udp: OnceLock<Arc<UdpSocket>>,
    /// Datagrams forwarded / dropped (bad token, unknown session, rate).
    pub forwarded: AtomicU64,
    pub dropped: AtomicU64,
    /// Frames dropped because a WebSocket client's outbound queue was full.
    pub queue_drops: AtomicU64,
    /// [`Presence`] of sessions closed or expired in the last [`ENDED_KEEP`].
    ended: Mutex<HashMap<u32, (Instant, Vec<Presence>)>>,
}

pub fn random_token() -> [u8; TOKEN_LEN] {
    let mut t = [0u8; TOKEN_LEN];
    let _ = getrandom::getrandom(&mut t);
    t
}

impl Relay {
    pub fn set_udp(&self, socket: Arc<UdpSocket>) {
        let _ = self.udp.set(socket);
    }

    fn get(&self, id: u32) -> Option<Arc<Mutex<Session>>> {
        self.sessions
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(&id)
            .cloned()
    }

    /// New session for `accounts` (slot order: P1, P2, spectators...).
    /// Returns the session id and one token per slot.
    pub fn create(&self, accounts: &[u64]) -> Option<(u32, Vec<[u8; TOKEN_LEN]>)> {
        if accounts.len() > 8 {
            return None;
        }
        let now = Instant::now();
        let mut map = self.sessions.write().unwrap_or_else(|p| p.into_inner());
        if map.len() >= MAX_SESSIONS {
            map.retain(|_, s| lock(s).alive(now));
            if map.len() >= MAX_SESSIONS {
                return None;
            }
        }
        let mut id = 0;
        while id == 0 || map.contains_key(&id) {
            let mut b = [0u8; 4];
            let _ = getrandom::getrandom(&mut b);
            id = u32::from_be_bytes(b);
        }
        let slots: Vec<Slot> = accounts
            .iter()
            .map(|_| Slot {
                token: random_token(),
                route: None,
                rate: (now, 0),
                turn: (0, 0),
                heard: now,
                bye: false,
                joined: false,
            })
            .collect();
        let tokens = slots.iter().map(|s| s.token).collect();
        map.insert(
            id,
            Arc::new(Mutex::new(Session {
                slots,
                created: now,
                last: now,
            })),
        );
        Some((id, tokens))
    }

    pub fn close(&self, id: u32) {
        let gone = self
            .sessions
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&id);
        if let Some(s) = gone {
            self.remember(id, &lock(&s));
            log::debug!("relay session {id:08x} closed");
        }
    }

    /// Keep what a session saw of its slots after it is gone.
    fn remember(&self, id: u32, s: &Session) {
        let now = Instant::now();
        let mut ended = lock(&self.ended);
        ended.retain(|_, (t, _)| now.duration_since(*t) < ENDED_KEEP);
        if ended.len() < MAX_SESSIONS {
            ended.insert(id, (now, s.presence()));
        }
    }

    /// What the relay saw of each slot of session `id`, live or (for an
    /// hour) after it closed; `None` when it never knew the session.
    pub fn presence(&self, id: u32) -> Option<Vec<Presence>> {
        if let Some(s) = self.get(id) {
            return Some(lock(&s).presence());
        }
        lock(&self.ended).get(&id).map(|(_, p)| p.clone())
    }

    /// TURN bytes (received, sent) slot `slot` of session `id` reported;
    /// `None` once the session is gone.
    pub fn turn_bytes(&self, id: u32, slot: u8) -> Option<(u64, u64)> {
        let s = self.get(id)?;
        let s = lock(&s);
        Some(s.slots.get(slot as usize).map_or((0, 0), |s| s.turn))
    }

    /// When each slot of session `id` was last heard from (its creation
    /// before the first datagram); `None` once the session is gone.
    pub fn heard(&self, id: u32) -> Option<Vec<Instant>> {
        let s = self.get(id)?;
        let s = lock(&s);
        s.alive(Instant::now())
            .then(|| s.slots.iter().map(|x| x.heard).collect())
    }

    /// Every session held (including ones not connected yet).
    pub fn session_count(&self) -> usize {
        self.sessions
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }

    /// Sessions with a connected slot and traffic within [`ACTIVE`].
    pub fn active_count(&self, now: Instant) -> usize {
        let all: Vec<Arc<Mutex<Session>>> = self
            .sessions
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .cloned()
            .collect();
        all.iter()
            .filter(|s| {
                let s = lock(s);
                now.duration_since(s.last) < ACTIVE && s.mask() != 0
            })
            .count()
    }

    /// A new `/relay` WebSocket: its connection and the receiving end of
    /// its bounded outbound queue.
    pub fn ws_connect(&self) -> (Arc<WsConn>, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(WS_QUEUE);
        let id = self.next_ws.fetch_add(1, Relaxed) + 1;
        (
            Arc::new(WsConn {
                id,
                tx,
                bound: Mutex::new(Vec::new()),
            }),
            rx,
        )
    }

    /// The connection closed: free the slots it carried and tell the others.
    pub fn ws_disconnect(&self, conn: &Arc<WsConn>) {
        let bound = std::mem::take(&mut *lock(&conn.bound));
        for (id, slot) in bound {
            let Some(s) = self.get(id) else { continue };
            let mut s = lock(&s);
            let Some(sl) = s.slots.get_mut(slot as usize) else {
                continue;
            };
            if matches!(&sl.route, Some(Route::Ws(c)) if c.id == conn.id) {
                sl.route = None;
                self.announce(id, &s, None);
            }
        }
    }

    /// Drop idle / ancient sessions; returns how many went.
    pub fn expire(&self, now: Instant) -> usize {
        let mut map = self.sessions.write().unwrap_or_else(|p| p.into_inner());
        let mut gone = Vec::new();
        map.retain(|id, s| {
            let s = lock(s);
            let keep = s.alive(now);
            if !keep {
                gone.push((*id, s.presence()));
            }
            keep
        });
        std::mem::drop(map);
        let n = gone.len();
        let mut ended = lock(&self.ended);
        ended.retain(|_, (t, _)| now.duration_since(*t) < ENDED_KEEP);
        for (id, p) in gone {
            if ended.len() < MAX_SESSIONS {
                ended.insert(id, (now, p));
            }
        }
        n
    }

    fn send(&self, route: &Route, bytes: Vec<u8>) {
        match route {
            Route::Udp(addr) => {
                if let Some(u) = self.udp.get() {
                    let _ = u.send_to(&bytes, addr);
                }
            }
            Route::Ws(c) => {
                if let Err(mpsc::error::TrySendError::Full(_)) = c.tx.try_send(bytes) {
                    self.queue_drops.fetch_add(1, Relaxed);
                }
            }
        }
    }

    /// Tell every connected slot (but `except`) which slots are connected.
    fn announce(&self, id: u32, s: &Session, except: Option<u8>) {
        let mask = s.mask();
        for (i, slot) in s.slots.iter().enumerate() {
            if let Some(r) = &slot.route
                && except != Some(i as u8)
            {
                let h = Header {
                    kind: wire::PEERS,
                    from: 0xFF,
                    to: i as u8,
                    session: id,
                };
                self.send(r, wire::encode_server(h, &[mask]));
            }
        }
    }

    /// Handle one client datagram arriving over `from`.
    pub fn on_packet(&self, buf: &[u8], from: &Route, now: Instant) {
        let reject = || {
            self.dropped.fetch_add(1, Relaxed);
        };
        let Some((h, token, payload)) = wire::decode_client(buf) else {
            return reject();
        };
        let Some(sess) = self.get(h.session) else {
            return reject();
        };
        let mut s = lock(&sess);
        let Some(slot) = s.slots.get_mut(h.from as usize) else {
            return reject();
        };
        if !wire::token_eq(&slot.token, &token) {
            return reject();
        }
        if now.duration_since(slot.rate.0) >= Duration::from_secs(1) {
            slot.rate = (now, 0);
        }
        slot.rate.1 += 1;
        if slot.rate.1 > SLOT_PPS {
            return reject();
        }
        // TURN clients put their byte counters in the hello
        if h.kind == wire::HELLO
            && let (Ok(rx), Ok(tx)) = (
                <[u8; 8]>::try_from(payload.get(..8).unwrap_or_default()),
                <[u8; 8]>::try_from(payload.get(8..16).unwrap_or_default()),
            )
        {
            slot.turn.0 = slot.turn.0.max(u64::from_be_bytes(rx));
            slot.turn.1 = slot.turn.1.max(u64::from_be_bytes(tx));
        }
        let moved = slot.route.as_ref() != Some(from);
        slot.heard = now;
        slot.joined = true;
        if h.kind == wire::BYE {
            slot.route = None;
            slot.bye = true;
        } else {
            slot.bye = false;
            if moved {
                slot.route = Some(from.clone());
                if let Route::Ws(c) = from {
                    let mut b = lock(&c.bound);
                    if !b.contains(&(h.session, h.from)) {
                        b.push((h.session, h.from));
                    }
                }
            }
        }
        s.last = now;
        let reply = |kind: u8, payload: &[u8]| {
            wire::encode_server(
                Header {
                    kind,
                    from: 0xFF,
                    to: h.from,
                    session: h.session,
                },
                payload,
            )
        };
        match h.kind {
            wire::HELLO => {
                self.send(from, reply(wire::ACK, &[s.mask()]));
                if moved {
                    self.announce(h.session, &s, Some(h.from));
                }
            }
            wire::PING => self.send(from, reply(wire::PONG, payload)),
            wire::BYE => {
                self.announce(h.session, &s, Some(h.from));
                // both players are done: the match is over
                let done = s.slots.len() >= 2 && s.slots[0].bye && s.slots[1].bye;
                std::mem::drop(s);
                if done {
                    self.close(h.session);
                }
            }
            wire::DATA => {
                let to = h.to as usize;
                // spectators only talk to the host (ggrs acks)
                let target = if to == h.from as usize || (h.from >= 2 && to != 0) {
                    None
                } else {
                    s.slots.get(to).and_then(|x| x.route.clone())
                };
                match target {
                    Some(route) => {
                        self.send(&route, wire::encode_server(h, payload));
                        self.forwarded.fetch_add(1, Relaxed);
                    }
                    None if to == h.from as usize || (h.from >= 2 && to != 0) => reject(),
                    None => {}
                }
                if moved {
                    self.announce(h.session, &s, Some(h.from));
                }
            }
            _ => reject(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(kind: u8, from: u8, to: u8, session: u32, token: &[u8; 16], p: &[u8]) -> Vec<u8> {
        wire::encode_client(
            Header {
                kind,
                from,
                to,
                session,
            },
            token,
            p,
        )
    }

    fn dropped(r: &Relay) -> u64 {
        r.dropped.load(Relaxed)
    }

    #[test]
    fn forwards_between_slots_and_rejects_bad_tokens() {
        let r = Relay::default();
        let (id, tokens) = r.create(&[10, 20, 30]).unwrap();
        let (ca, mut ra) = r.ws_connect();
        let (cb, mut rb) = r.ws_connect();
        let (cs, mut rs) = r.ws_connect();
        let (ca, cb, cs) = (Route::Ws(ca), Route::Ws(cb), Route::Ws(cs));
        let now = Instant::now();
        r.on_packet(&pkt(wire::HELLO, 0, 0, id, &tokens[0], &[]), &ca, now);
        let (h, p) = {
            let m = ra.try_recv().unwrap();
            let (h, p) = wire::decode_server(&m).unwrap();
            (h, p.to_vec())
        };
        assert_eq!((h.kind, p), (wire::ACK, vec![0b001]));
        r.on_packet(&pkt(wire::HELLO, 1, 0, id, &tokens[1], &[]), &cb, now);
        // A learns B joined (PEERS), B gets its ACK
        let peers = ra.try_recv().unwrap();
        assert_eq!(wire::decode_server(&peers).unwrap().1, &[0b011]);
        assert_eq!(
            wire::decode_server(&rb.try_recv().unwrap()).unwrap().0.kind,
            wire::ACK
        );
        while rb.try_recv().is_ok() {}
        // data A → B, tagged with the sender slot only
        r.on_packet(&pkt(wire::DATA, 0, 1, id, &tokens[0], b"in"), &ca, now);
        let m = rb.try_recv().unwrap();
        let (h, p) = wire::decode_server(&m).unwrap();
        assert_eq!((h.kind, h.from, h.to, p), (wire::DATA, 0, 1, &b"in"[..]));
        // wrong token or slot: dropped
        r.on_packet(&pkt(wire::DATA, 0, 1, id, &tokens[1], b"x"), &cb, now);
        r.on_packet(&pkt(wire::DATA, 7, 1, id, &tokens[1], b"x"), &cb, now);
        r.on_packet(&pkt(wire::DATA, 0, 1, id + 1, &tokens[0], b"x"), &ca, now);
        assert!(rb.try_recv().is_err());
        assert_eq!(dropped(&r), 3);
        // spectator may only answer the host
        r.on_packet(&pkt(wire::HELLO, 2, 0, id, &tokens[2], &[]), &cs, now);
        while ra.try_recv().is_ok() {}
        while rb.try_recv().is_ok() {}
        r.on_packet(&pkt(wire::DATA, 2, 1, id, &tokens[2], b"no"), &cs, now);
        assert!(rb.try_recv().is_err());
        r.on_packet(&pkt(wire::DATA, 2, 0, id, &tokens[2], b"ack"), &cs, now);
        assert!(ra.try_recv().is_ok());
        r.on_packet(&pkt(wire::DATA, 0, 2, id, &tokens[0], b"in"), &ca, now);
        while let Ok(m) = rs.try_recv() {
            let (h, _) = wire::decode_server(&m).unwrap();
            if h.kind == wire::DATA {
                assert_eq!(h.from, 0);
            }
        }
        // opaque payloads between the two players never reach spectators
        r.on_packet(&pkt(wire::DATA, 1, 0, id, &tokens[1], b"p2p"), &cb, now);
        assert!(rs.try_recv().is_err());
        assert_eq!(
            wire::decode_server(&ra.try_recv().unwrap()).unwrap().1,
            b"p2p"
        );
        // ping echo
        r.on_packet(&pkt(wire::PING, 1, 0, id, &tokens[1], b"t0"), &cb, now);
        let m = rb.try_recv().unwrap();
        assert_eq!(
            wire::decode_server(&m).unwrap(),
            (
                Header {
                    kind: wire::PONG,
                    from: 0xFF,
                    to: 1,
                    session: id
                },
                &b"t0"[..]
            )
        );
        // disconnecting B tells the others
        let Route::Ws(cbc) = &cb else { unreachable!() };
        r.ws_disconnect(cbc);
        let m = ra.try_recv().unwrap();
        assert_eq!(wire::decode_server(&m).unwrap().1, &[0b101]);
    }

    #[test]
    fn slots_are_rate_limited_and_sessions_expire() {
        let r = Relay::default();
        let (id, tokens) = r.create(&[1, 2]).unwrap();
        let (c, _rx) = r.ws_connect();
        let c = Route::Ws(c);
        let now = Instant::now();
        for _ in 0..SLOT_PPS + 5 {
            r.on_packet(&pkt(wire::PING, 0, 0, id, &tokens[0], &[]), &c, now);
        }
        assert_eq!(dropped(&r), 5);
        assert_eq!(r.active_count(now), 1);
        assert_eq!(
            r.active_count(now + ACTIVE),
            0,
            "quiet: not a running match"
        );
        assert_eq!(r.expire(now + IDLE + Duration::from_secs(1)), 1);
        assert_eq!(r.session_count(), 0);
    }

    #[test]
    fn full_websocket_queues_drop_frames_instead_of_growing() {
        let r = Relay::default();
        let (id, tokens) = r.create(&[1, 2]).unwrap();
        let (ca, _ra) = r.ws_connect();
        let (cb, mut rb) = r.ws_connect();
        let (ca, cb) = (Route::Ws(ca), Route::Ws(cb));
        let now = Instant::now();
        r.on_packet(&pkt(wire::HELLO, 0, 0, id, &tokens[0], &[]), &ca, now);
        r.on_packet(&pkt(wire::HELLO, 1, 0, id, &tokens[1], &[]), &cb, now);
        // B never reads: its queue fills, the rest is dropped and counted
        let n = WS_QUEUE + 100;
        for i in 0..n {
            let t = now + Duration::from_millis(i as u64 * 3);
            r.on_packet(&pkt(wire::DATA, 0, 1, id, &tokens[0], b"x"), &ca, t);
        }
        let mut got = 0;
        while rb.try_recv().is_ok() {
            got += 1;
        }
        assert_eq!(got, WS_QUEUE);
        // the ACK took one place in B's queue
        assert_eq!(r.queue_drops.load(Relaxed), (n + 1 - WS_QUEUE) as u64);
    }

    #[test]
    fn disconnect_only_touches_the_connections_sessions() {
        let r = Relay::default();
        let (c, _rx) = r.ws_connect();
        let c = Route::Ws(c);
        let now = Instant::now();
        let mut ids = Vec::new();
        for _ in 0..50 {
            let (id, t) = r.create(&[1, 2]).unwrap();
            ids.push((id, t));
        }
        let (id, t) = &ids[7];
        r.on_packet(&pkt(wire::HELLO, 0, 0, *id, &t[0], &[]), &c, now);
        r.on_packet(&pkt(wire::HELLO, 1, 0, *id, &t[1], &[]), &c, now);
        let Route::Ws(conn) = &c else { unreachable!() };
        assert_eq!(lock(&conn.bound).len(), 2);
        assert_eq!(r.active_count(now), 1);
        r.ws_disconnect(conn);
        assert!(lock(&conn.bound).is_empty());
        assert_eq!(r.active_count(now), 0, "no slot connected any more");
    }

    #[test]
    fn session_closes_when_both_players_say_bye() {
        let r = Relay::default();
        let (id, tokens) = r.create(&[1, 2, 3]).unwrap();
        let (c, _rx) = r.ws_connect();
        let c = Route::Ws(c);
        let now = Instant::now();
        r.on_packet(&pkt(wire::HELLO, 0, 0, id, &tokens[0], &[]), &c, now);
        r.on_packet(&pkt(wire::BYE, 0, 0, id, &tokens[0], &[]), &c, now);
        // P1 is back (reconnect): its BYE no longer counts
        r.on_packet(&pkt(wire::HELLO, 0, 0, id, &tokens[0], &[]), &c, now);
        r.on_packet(&pkt(wire::BYE, 1, 0, id, &tokens[1], &[]), &c, now);
        assert_eq!(r.session_count(), 1);
        r.on_packet(&pkt(wire::BYE, 0, 0, id, &tokens[0], &[]), &c, now);
        assert_eq!(r.session_count(), 0);
        assert!(r.heard(id).is_none());
    }
}
