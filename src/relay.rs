//! The match relay: every datagram of a match goes player → server → player
//! (and host → spectators). Sessions are created by the lobby (room match,
//! quick match, ranked) with one secret token per slot; the token
//! authenticates each datagram ([`rugen_proto::relay`] framing), so a slot's
//! transport may change (UDP ↔ WebSocket, NAT rebinding) without trust in
//! source addresses. The server never inspects payloads (ggrs messages) and
//! never tells anyone where another slot connects from.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rugen_proto::relay::{self as wire, Header, TOKEN_LEN};
use tokio::sync::mpsc::UnboundedSender;

/// Datagrams per slot per second (ggrs sends ~60-120).
const SLOT_PPS: u32 = 600;
/// Sessions without traffic for this long are dropped.
const IDLE: Duration = Duration::from_secs(120);
/// Hard cap on a session's life.
const MAX_AGE: Duration = Duration::from_secs(3 * 3600);
const MAX_SESSIONS: usize = 10_000;

/// Where a slot's datagrams go back to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Route {
    Udp(SocketAddr),
    /// A `/relay` WebSocket connection id.
    Ws(u64),
}

struct Slot {
    token: [u8; TOKEN_LEN],
    route: Option<Route>,
    rate: (Instant, u32),
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
}

#[derive(Default)]
pub struct Relay {
    sessions: HashMap<u32, Session>,
    ws: HashMap<u64, UnboundedSender<Vec<u8>>>,
    next_ws: u64,
    udp: Option<Arc<UdpSocket>>,
    /// Datagrams forwarded / dropped (bad token, unknown session, rate).
    pub forwarded: u64,
    pub dropped: u64,
}

pub fn random_token() -> [u8; TOKEN_LEN] {
    let mut t = [0u8; TOKEN_LEN];
    let _ = getrandom::getrandom(&mut t);
    t
}

impl Relay {
    pub fn set_udp(&mut self, socket: Arc<UdpSocket>) {
        self.udp = Some(socket);
    }

    /// New session for `accounts` (slot order: P1, P2, spectators...).
    /// Returns the session id and one token per slot.
    pub fn create(&mut self, accounts: &[u64]) -> Option<(u32, Vec<[u8; TOKEN_LEN]>)> {
        self.expire(Instant::now());
        if self.sessions.len() >= MAX_SESSIONS || accounts.len() > 8 {
            return None;
        }
        let mut id = 0;
        while id == 0 || self.sessions.contains_key(&id) {
            let mut b = [0u8; 4];
            let _ = getrandom::getrandom(&mut b);
            id = u32::from_be_bytes(b);
        }
        let now = Instant::now();
        let slots: Vec<Slot> = accounts
            .iter()
            .map(|_| Slot {
                token: random_token(),
                route: None,
                rate: (now, 0),
            })
            .collect();
        let tokens = slots.iter().map(|s| s.token).collect();
        self.sessions.insert(
            id,
            Session {
                slots,
                created: now,
                last: now,
            },
        );
        Some((id, tokens))
    }

    pub fn close(&mut self, id: u32) {
        self.sessions.remove(&id);
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn ws_connect(&mut self, tx: UnboundedSender<Vec<u8>>) -> u64 {
        self.next_ws += 1;
        self.ws.insert(self.next_ws, tx);
        self.next_ws
    }

    pub fn ws_disconnect(&mut self, conn: u64) {
        self.ws.remove(&conn);
        let mut changed = Vec::new();
        for (id, s) in &mut self.sessions {
            for slot in &mut s.slots {
                if slot.route == Some(Route::Ws(conn)) {
                    slot.route = None;
                    changed.push(*id);
                }
            }
        }
        for id in changed {
            self.announce(id, None);
        }
    }

    pub fn expire(&mut self, now: Instant) {
        self.sessions.retain(|_, s| {
            now.duration_since(s.last) < IDLE && now.duration_since(s.created) < MAX_AGE
        });
    }

    fn send(&self, route: Route, bytes: &[u8]) {
        match route {
            Route::Udp(addr) => {
                if let Some(u) = &self.udp {
                    let _ = u.send_to(bytes, addr);
                }
            }
            Route::Ws(c) => {
                if let Some(tx) = self.ws.get(&c) {
                    let _ = tx.send(bytes.to_vec());
                }
            }
        }
    }

    /// Tell every connected slot (but `except`) which slots are connected.
    fn announce(&self, id: u32, except: Option<u8>) {
        let Some(s) = self.sessions.get(&id) else {
            return;
        };
        let mask = s.mask();
        for (i, slot) in s.slots.iter().enumerate() {
            if let Some(r) = slot.route
                && except != Some(i as u8)
            {
                let h = Header {
                    kind: wire::PEERS,
                    from: 0xFF,
                    to: i as u8,
                    session: id,
                };
                self.send(r, &wire::encode_server(h, &[mask]));
            }
        }
    }

    /// Handle one client datagram arriving over `from`.
    pub fn on_packet(&mut self, buf: &[u8], from: Route, now: Instant) {
        let Some((h, token, payload)) = wire::decode_client(buf) else {
            self.dropped += 1;
            return;
        };
        // validate and update the slot; decide what to send afterwards
        let decided = (|| {
            let s = self.sessions.get_mut(&h.session)?;
            let slot = s.slots.get_mut(h.from as usize)?;
            if !wire::token_eq(&slot.token, &token) {
                return None;
            }
            if now.duration_since(slot.rate.0) >= Duration::from_secs(1) {
                slot.rate = (now, 0);
            }
            slot.rate.1 += 1;
            if slot.rate.1 > SLOT_PPS {
                return None;
            }
            let moved = slot.route != Some(from);
            slot.route = if h.kind == wire::BYE {
                None
            } else {
                Some(from)
            };
            s.last = now;
            let target = match h.kind {
                wire::DATA => {
                    let to = h.to as usize;
                    // spectators only talk to the host (ggrs acks)
                    if to == h.from as usize || (h.from >= 2 && to != 0) {
                        return None;
                    }
                    Some(s.slots.get(to)?.route?)
                }
                _ => None,
            };
            Some((s.mask(), moved, target))
        })();
        let Some((mask, moved, target)) = decided else {
            self.dropped += 1;
            return;
        };
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
                self.send(from, &reply(wire::ACK, &[mask]));
                if moved {
                    self.announce(h.session, Some(h.from));
                }
            }
            wire::PING => self.send(from, &reply(wire::PONG, payload)),
            wire::BYE => self.announce(h.session, Some(h.from)),
            wire::DATA => {
                if let Some(route) = target {
                    self.send(route, &wire::encode_server(h, payload));
                    self.forwarded += 1;
                }
                if moved {
                    self.announce(h.session, Some(h.from));
                }
            }
            _ => self.dropped += 1,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc::unbounded_channel;

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

    #[test]
    fn forwards_between_slots_and_rejects_bad_tokens() {
        let mut r = Relay::default();
        let (id, tokens) = r.create(&[10, 20, 30]).unwrap();
        let (ta, mut ra) = unbounded_channel();
        let (tb, mut rb) = unbounded_channel();
        let (ts, mut rs) = unbounded_channel();
        let (ca, cb, cs) = (r.ws_connect(ta), r.ws_connect(tb), r.ws_connect(ts));
        let now = Instant::now();
        r.on_packet(
            &pkt(wire::HELLO, 0, 0, id, &tokens[0], &[]),
            Route::Ws(ca),
            now,
        );
        let (h, p) = {
            let m = ra.try_recv().unwrap();
            let (h, p) = wire::decode_server(&m).unwrap();
            (h, p.to_vec())
        };
        assert_eq!((h.kind, p), (wire::ACK, vec![0b001]));
        r.on_packet(
            &pkt(wire::HELLO, 1, 0, id, &tokens[1], &[]),
            Route::Ws(cb),
            now,
        );
        // A learns B joined (PEERS), B gets its ACK
        let peers = ra.try_recv().unwrap();
        assert_eq!(wire::decode_server(&peers).unwrap().1, &[0b011]);
        assert_eq!(
            wire::decode_server(&rb.try_recv().unwrap()).unwrap().0.kind,
            wire::ACK
        );
        while rb.try_recv().is_ok() {}
        // data A → B, tagged with the sender slot only
        r.on_packet(
            &pkt(wire::DATA, 0, 1, id, &tokens[0], b"in"),
            Route::Ws(ca),
            now,
        );
        let m = rb.try_recv().unwrap();
        let (h, p) = wire::decode_server(&m).unwrap();
        assert_eq!((h.kind, h.from, h.to, p), (wire::DATA, 0, 1, &b"in"[..]));
        // wrong token or slot: dropped
        r.on_packet(
            &pkt(wire::DATA, 0, 1, id, &tokens[1], b"x"),
            Route::Ws(cb),
            now,
        );
        r.on_packet(
            &pkt(wire::DATA, 7, 1, id, &tokens[1], b"x"),
            Route::Ws(cb),
            now,
        );
        r.on_packet(
            &pkt(wire::DATA, 0, 1, id + 1, &tokens[0], b"x"),
            Route::Ws(ca),
            now,
        );
        assert!(rb.try_recv().is_err());
        assert_eq!(r.dropped, 3);
        // spectator may only answer the host
        r.on_packet(
            &pkt(wire::HELLO, 2, 0, id, &tokens[2], &[]),
            Route::Ws(cs),
            now,
        );
        while ra.try_recv().is_ok() {}
        while rb.try_recv().is_ok() {}
        r.on_packet(
            &pkt(wire::DATA, 2, 1, id, &tokens[2], b"no"),
            Route::Ws(cs),
            now,
        );
        assert!(rb.try_recv().is_err());
        r.on_packet(
            &pkt(wire::DATA, 2, 0, id, &tokens[2], b"ack"),
            Route::Ws(cs),
            now,
        );
        assert!(ra.try_recv().is_ok());
        r.on_packet(
            &pkt(wire::DATA, 0, 2, id, &tokens[0], b"in"),
            Route::Ws(ca),
            now,
        );
        while let Ok(m) = rs.try_recv() {
            let (h, _) = wire::decode_server(&m).unwrap();
            if h.kind == wire::DATA {
                assert_eq!(h.from, 0);
            }
        }
        // ping echo
        r.on_packet(
            &pkt(wire::PING, 1, 0, id, &tokens[1], b"t0"),
            Route::Ws(cb),
            now,
        );
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
        r.ws_disconnect(cb);
        let m = ra.try_recv().unwrap();
        assert_eq!(wire::decode_server(&m).unwrap().1, &[0b101]);
    }

    #[test]
    fn slots_are_rate_limited_and_sessions_expire() {
        let mut r = Relay::default();
        let (id, tokens) = r.create(&[1, 2]).unwrap();
        let (ta, _ra) = unbounded_channel();
        let c = r.ws_connect(ta);
        let now = Instant::now();
        for _ in 0..SLOT_PPS + 5 {
            r.on_packet(
                &pkt(wire::PING, 0, 0, id, &tokens[0], &[]),
                Route::Ws(c),
                now,
            );
        }
        assert_eq!(r.dropped, 5);
        r.expire(now + IDLE + Duration::from_secs(1));
        assert_eq!(r.session_count(), 0);
    }
}
