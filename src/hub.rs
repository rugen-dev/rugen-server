//! Lobby presence behind `GET /ws`: each account's live WebSocket
//! connections (for pushes: room changes, queue matches, kicks) and the
//! server-measured round trip of each account (WebSocket ping/pong), used by
//! matchmaking and shown in rooms.

use std::collections::HashMap;
use std::time::Instant;

use rugen_proto::ServerMsg;
use tokio::sync::mpsc::UnboundedSender;

#[derive(Default)]
pub struct Hub {
    conns: HashMap<u64, (u64, UnboundedSender<ServerMsg>)>,
    next_conn: u64,
    /// Smoothed round trip per account and when it was measured.
    rtt: HashMap<u64, (u32, Instant)>,
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

    pub fn is_online(&self, account: u64) -> bool {
        self.conns.values().any(|(a, _)| *a == account)
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
        assert_eq!(ra.try_recv().unwrap(), ServerMsg::Pong);
        assert!(!hub.push(2, &ServerMsg::Pong));
        assert_eq!(hub.online(), 1);
        hub.record_rtt(1, 40);
        hub.record_rtt(1, 80);
        assert_eq!(hub.rtt(1), Some(50));
        assert_eq!(hub.rtt(2), None);
        hub.disconnect(c);
        assert!(!hub.is_online(1));
    }
}
