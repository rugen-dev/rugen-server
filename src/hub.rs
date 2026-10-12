//! Lobby presence behind `GET /ws`: each account's live WebSocket
//! connections (for pushes: room changes, queue matches, kicks) and the
//! server-measured round trip of each account (WebSocket ping/pong), used by
//! matchmaking and shown in rooms.

use std::collections::HashMap;
use std::time::Instant;

use rugen_proto::ServerMsg;
use serde_json::Value;
use tokio::sync::mpsc::UnboundedSender;

/// Lobby pushes travel as serialized JSON text (serialized once per push,
/// and the server may add fields older clients ignore).
pub type Outbox = UnboundedSender<String>;

#[derive(Default)]
pub struct Hub {
    /// Connection → account.
    conns: HashMap<u64, u64>,
    /// Account → its open connections.
    by_account: HashMap<u64, Vec<(u64, Outbox)>>,
    next_conn: u64,
    /// Smoothed round trip per account and when it was measured.
    rtt: HashMap<u64, (u32, Instant)>,
}

impl Hub {
    pub fn connect(&mut self, account: u64, tx: Outbox) -> u64 {
        self.next_conn += 1;
        self.conns.insert(self.next_conn, account);
        self.by_account
            .entry(account)
            .or_default()
            .push((self.next_conn, tx));
        self.next_conn
    }

    pub fn disconnect(&mut self, conn: u64) {
        let Some(account) = self.conns.remove(&conn) else {
            return;
        };
        if let Some(v) = self.by_account.get_mut(&account) {
            v.retain(|(c, _)| *c != conn);
            if v.is_empty() {
                self.by_account.remove(&account);
            }
        }
    }

    /// Accounts with at least one open WebSocket.
    pub fn online(&self) -> usize {
        self.by_account.len()
    }

    pub fn is_online(&self, account: u64) -> bool {
        self.by_account.contains_key(&account)
    }

    /// Send to every connection of an account. Returns false when none is open.
    pub fn push(&self, account: u64, msg: &ServerMsg) -> bool {
        match serde_json::to_string(msg) {
            Ok(text) => self.push_text(account, text),
            Err(_) => false,
        }
    }

    /// [`Self::push`] of a message the server extended with additive fields.
    pub fn push_json(&self, account: u64, msg: &Value) -> bool {
        self.push_text(account, msg.to_string())
    }

    fn push_text(&self, account: u64, text: String) -> bool {
        let mut any = false;
        for (_, tx) in self.by_account.get(&account).into_iter().flatten() {
            if tx.send(text.clone()).is_ok() {
                any = true;
            }
        }
        any
    }

    /// Fold a new round-trip sample in (exponential moving average).
    pub fn record_rtt(&mut self, account: u64, ms: u32) {
        let ms = ms.min(5000);
        let v = match self.rtt.get(&account) {
            Some((old, _)) => (old * 3 + ms) / 4,
            None => ms,
        };
        self.rtt.insert(account, (v, Instant::now()));
        if self.rtt.len() > 100_000 {
            self.rtt.retain(|_, (_, t)| t.elapsed().as_secs() < 3600);
        }
    }

    /// Server-measured round trip of an account (fresh within ten minutes).
    pub fn rtt(&self, account: u64) -> Option<u32> {
        self.rtt
            .get(&account)
            .filter(|(_, t)| t.elapsed().as_secs() < 600)
            .map(|(v, _)| *v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc::unbounded_channel;

    #[test]
    fn presence_and_rtt() {
        let mut hub = Hub::default();
        let (ta, mut ra) = unbounded_channel();
        let c = hub.connect(1, ta);
        assert!(hub.push(1, &ServerMsg::Pong));
        let got: ServerMsg = serde_json::from_str(&ra.try_recv().unwrap()).unwrap();
        assert_eq!(got, ServerMsg::Pong);
        assert!(!hub.push(2, &ServerMsg::Pong));
        assert_eq!(hub.online(), 1);
        hub.record_rtt(1, 40);
        hub.record_rtt(1, 80);
        assert_eq!(hub.rtt(1), Some(50));
        assert_eq!(hub.rtt(2), None);
        let (tb, _rb) = unbounded_channel();
        let c2 = hub.connect(1, tb);
        hub.disconnect(c);
        assert!(hub.is_online(1), "a second connection is still open");
        hub.disconnect(c2);
        assert!(!hub.is_online(1));
        assert_eq!(hub.online(), 0);
    }
}
