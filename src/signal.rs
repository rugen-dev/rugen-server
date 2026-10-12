//! Signaling hub behind `GET /ws`: tracks each account's live WebSocket
//! connections, pushes presence events (room joined, ranked match found) and
//! exchanges UDP endpoints between the two players of a code so they can
//! hole-punch a direct path. No game traffic ever goes through here.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rugen_proto::ServerMsg;
use tokio::sync::mpsc::UnboundedSender;

/// Signal slots and known sessions expire after this long.
const SLOT_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_SLOTS: usize = 20_000;
const MAX_CANDIDATES: usize = 8;

struct Side {
    account: u64,
    conn: u64,
    candidates: Vec<String>,
}

struct Slot {
    sides: [Option<Side>; 2],
    created: Instant,
}

#[derive(Default)]
pub struct Hub {
    conns: HashMap<u64, (u64, UnboundedSender<ServerMsg>)>,
    next_conn: u64,
    slots: HashMap<String, Slot>,
    /// Codes the API created (rooms, ranked matches) and their players by side.
    sessions: HashMap<String, ([u64; 2], Instant)>,
    pub turn: bool,
    pub udp_relay: Option<String>,
}

/// Keep only `ip:port` strings that parse, at most [`MAX_CANDIDATES`].
fn clean_candidates(c: &[String]) -> Vec<String> {
    c.iter()
        .filter(|s| s.len() <= 64 && s.parse::<std::net::SocketAddr>().is_ok())
        .take(MAX_CANDIDATES)
        .cloned()
        .collect()
}

impl Hub {
    pub fn connect(&mut self, account: u64, tx: UnboundedSender<ServerMsg>) -> u64 {
        self.next_conn += 1;
        self.conns.insert(self.next_conn, (account, tx));
        self.next_conn
    }

    pub fn disconnect(&mut self, conn: u64) {
        self.conns.remove(&conn);
    }

    /// Accounts with at least one open WebSocket.
    pub fn online(&self) -> usize {
        let mut ids: Vec<u64> = self.conns.values().map(|(a, _)| *a).collect();
        ids.sort_unstable();
        ids.dedup();
        ids.len()
    }

    /// Send to every connection of an account. Returns false when none is open.
    pub fn push(&self, account: u64, msg: &ServerMsg) -> bool {
        let mut any = false;
        for (a, tx) in self.conns.values() {
            if *a == account && tx.send(msg.clone()).is_ok() {
                any = true;
            }
        }
        any
    }

    fn send(&self, conn: u64, msg: ServerMsg) {
        if let Some((_, tx)) = self.conns.get(&conn) {
            let _ = tx.send(msg);
        }
    }

    pub fn register_session(&mut self, code: &str, players: [u64; 2]) {
        let now = Instant::now();
        self.sessions
            .retain(|_, (_, t)| now.duration_since(*t) < SLOT_TTL);
        self.sessions.insert(code.to_string(), (players, now));
    }

    fn expire(&mut self) {
        let now = Instant::now();
        self.slots
            .retain(|_, s| now.duration_since(s.created) < SLOT_TTL);
    }

    /// One side announces its endpoints for `code`. Once both sides did,
    /// each receives the other's candidates.
    pub fn signal(
        &mut self,
        account: u64,
        conn: u64,
        code: &str,
        side_hint: u8,
        candidates: &[String],
    ) -> Result<(), String> {
        let code = code.trim().to_ascii_uppercase();
        if code.is_empty() || code.len() > 32 || !code.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err("bad code".into());
        }
        let side = match self.sessions.get(&code) {
            // known room / ranked match: membership decides the side
            Some((players, _)) => {
                if players[0] == account && players[1] == account {
                    usize::from(side_hint == 2)
                } else if players[0] == account {
                    0
                } else if players[1] == account {
                    1
                } else {
                    return Err("not a player of this match".into());
                }
            }
            // free code (CLI / LAN parties): the client says which side it plays
            None if matches!(side_hint, 1 | 2) => usize::from(side_hint == 2),
            None => return Err("side must be 1 or 2".into()),
        };
        self.expire();
        if self.slots.len() >= MAX_SLOTS && !self.slots.contains_key(&code) {
            return Err("server busy".into());
        }
        let slot = self.slots.entry(code.clone()).or_insert_with(|| Slot {
            sides: [None, None],
            created: Instant::now(),
        });
        if let Some(other) = &slot.sides[side]
            && other.account != account
            && self.conns.contains_key(&other.conn)
        {
            return Err(format!("side {} is taken", side + 1));
        }
        slot.sides[side] = Some(Side {
            account,
            conn,
            candidates: clean_candidates(candidates),
        });
        log::info!("signal {code}: side {} ready", side + 1);
        let (Some(a), Some(b)) = (&slot.sides[0], &slot.sides[1]) else {
            return Ok(());
        };
        let peer = |me: usize, other: &Side| ServerMsg::Peer {
            code: code.clone(),
            side: me as u8 + 1,
            candidates: other.candidates.clone(),
            turn: self.turn,
            udp_relay: self.udp_relay.clone(),
        };
        let (ma, mb) = (peer(0, b), peer(1, a));
        let (ca, cb) = (a.conn, b.conn);
        self.send(ca, ma);
        self.send(cb, mb);
        log::info!("signal {code}: endpoints exchanged");
        Ok(())
    }

    /// Forward a TURN relayed address (or its absence) to the other side.
    pub fn relay(&mut self, conn: u64, code: &str, addr: Option<String>) -> Result<(), String> {
        let code = code.trim().to_ascii_uppercase();
        let slot = self.slots.get(&code).ok_or("unknown code")?;
        let me = slot
            .sides
            .iter()
            .position(|s| s.as_ref().is_some_and(|s| s.conn == conn))
            .ok_or("not signalled on this code")?;
        let addr = addr.filter(|a| a.parse::<std::net::SocketAddr>().is_ok());
        if let Some(other) = &slot.sides[1 - me] {
            let c = other.conn;
            self.send(c, ServerMsg::PeerRelay { code, addr });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc::unbounded_channel;

    #[test]
    fn exchanges_candidates_once_both_sides_signal() {
        let mut hub = Hub::default();
        let (ta, mut ra) = unbounded_channel();
        let (tb, mut rb) = unbounded_channel();
        let ca = hub.connect(1, ta);
        let cb = hub.connect(2, tb);
        hub.register_session("ROOM1", [1, 2]);
        hub.signal(2, cb, "room1", 1, &["5.6.7.8:9".into(), "junk".into()])
            .unwrap();
        assert!(ra.try_recv().is_err());
        hub.signal(1, ca, "ROOM1", 2, &["1.2.3.4:5".into()])
            .unwrap();
        match ra.try_recv().unwrap() {
            ServerMsg::Peer {
                side, candidates, ..
            } => {
                assert_eq!(side, 1);
                assert_eq!(candidates, vec!["5.6.7.8:9".to_string()]);
            }
            m => panic!("{m:?}"),
        }
        match rb.try_recv().unwrap() {
            ServerMsg::Peer { side, .. } => assert_eq!(side, 2),
            m => panic!("{m:?}"),
        }
        // outsiders cannot join a known session
        let (tc, _rc) = unbounded_channel();
        let cc = hub.connect(3, tc);
        assert!(hub.signal(3, cc, "ROOM1", 1, &[]).is_err());
        // relay addresses are forwarded to the other side
        hub.relay(ca, "ROOM1", Some("9.9.9.9:3478".into())).unwrap();
        assert_eq!(
            rb.try_recv().unwrap(),
            ServerMsg::PeerRelay {
                code: "ROOM1".into(),
                addr: Some("9.9.9.9:3478".into())
            }
        );
    }

    #[test]
    fn free_codes_use_the_side_hint() {
        let mut hub = Hub::default();
        let (ta, _ra) = unbounded_channel();
        let c = hub.connect(1, ta);
        assert!(hub.signal(1, c, "LAN", 0, &[]).is_err());
        hub.signal(1, c, "LAN", 1, &[]).unwrap();
        let (tb, _rb) = unbounded_channel();
        let c2 = hub.connect(2, tb);
        assert!(hub.signal(2, c2, "LAN", 1, &[]).is_err());
        assert_eq!(hub.online(), 2);
        hub.disconnect(c);
        assert_eq!(hub.online(), 1);
    }
}
