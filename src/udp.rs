//! Optional UDP service (`RUGEN_UDP_RELAY`): legacy rendezvous plus a dumb
//! packet relay, the last resort when hole punching fails and no TURN is
//! configured. Needs a public UDP port, so it cannot run through a
//! Cloudflare Tunnel. Protocol (text control datagrams):
//!
//! * `rugen1 hello <room> <side>` → `rugen1 peer <ip:port>` once both sides
//!   are known (rendezvous: only addresses are exchanged)
//! * `rugen1 relay <code> <side>` → `rugen1 relayok`; afterwards every other
//!   datagram from one side is forwarded to the other side of the code
//!
//! Rooms expire after two minutes of silence; each source is rate limited.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

const IDLE: Duration = Duration::from_secs(120);
/// Datagrams per source per second (ggrs sends ~60-120).
const PPS: u32 = 400;
const MAX_ROOMS: usize = 10_000;

#[derive(Default)]
pub struct Udp {
    rooms: HashMap<String, [Option<(SocketAddr, Instant)>; 2]>,
    relays: HashMap<String, [Option<(SocketAddr, Instant)>; 2]>,
    /// Relay source → (code, side).
    route: HashMap<SocketAddr, (String, usize)>,
    rate: HashMap<SocketAddr, (Instant, u32)>,
}

/// What to send in answer to one datagram.
pub type Out = Vec<(Vec<u8>, SocketAddr)>;

impl Udp {
    fn expire(&mut self, now: Instant) {
        let alive = |sides: &[Option<(SocketAddr, Instant)>; 2]| {
            sides
                .iter()
                .flatten()
                .any(|(_, t)| now.duration_since(*t) < IDLE)
        };
        self.rooms.retain(|_, s| alive(s));
        self.relays.retain(|_, s| alive(s));
        let relays = &self.relays;
        self.route.retain(|_, (code, _)| relays.contains_key(code));
        self.rate
            .retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(2));
    }

    fn limited(&mut self, from: SocketAddr, now: Instant) -> bool {
        let e = self.rate.entry(from).or_insert((now, 0));
        if now.duration_since(e.0) >= Duration::from_secs(1) {
            *e = (now, 0);
        }
        e.1 += 1;
        e.1 > PPS
    }

    pub fn handle(&mut self, data: &[u8], from: SocketAddr, now: Instant) -> Out {
        if self.limited(from, now) {
            return vec![];
        }
        if !data.starts_with(b"rugen1 ") {
            // relayed game traffic
            let Some((code, side)) = self.route.get(&from) else {
                return vec![];
            };
            let Some(sides) = self.relays.get_mut(code) else {
                return vec![];
            };
            if let Some((_, t)) = &mut sides[*side] {
                *t = now;
            }
            return match sides[1 - side] {
                Some((to, _)) => vec![(data.to_vec(), to)],
                None => vec![],
            };
        }
        let text = String::from_utf8_lossy(data);
        let mut it = text.split_whitespace().skip(1);
        let (Some(cmd), Some(code), Some(side)) = (
            it.next(),
            it.next(),
            it.next().and_then(|s| s.parse::<usize>().ok()),
        ) else {
            return vec![];
        };
        if !(1..=2).contains(&side) || code.len() > 64 {
            return vec![];
        }
        let side = side - 1;
        let table = match cmd {
            "hello" => &mut self.rooms,
            "relay" => &mut self.relays,
            _ => return vec![],
        };
        if table.len() >= MAX_ROOMS && !table.contains_key(code) {
            return vec![];
        }
        let entry = table.entry(code.to_string()).or_default();
        // a different address may take a side only once the old one went quiet
        if let Some((addr, t)) = entry[side]
            && addr != from
            && now.duration_since(t) < Duration::from_secs(10)
        {
            return vec![];
        }
        if entry[side].map(|(a, _)| a) != Some(from) {
            log::info!("udp {cmd} {code}: side {} is {from}", side + 1);
        }
        entry[side] = Some((from, now));
        match cmd {
            "hello" => match *entry {
                [Some((a, _)), Some((b, _))] => vec![
                    (format!("rugen1 peer {b}").into_bytes(), a),
                    (format!("rugen1 peer {a}").into_bytes(), b),
                ],
                _ => vec![],
            },
            _ => {
                self.route.insert(from, (code.to_string(), side));
                vec![(b"rugen1 relayok".to_vec(), from)]
            }
        }
    }
}

pub fn serve(socket: UdpSocket) -> std::io::Result<()> {
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    log::info!("udp rendezvous/relay listening on {}", socket.local_addr()?);
    let mut udp = Udp::default();
    let mut buf = [0u8; 2048];
    let mut last_expire = Instant::now();
    loop {
        let now = Instant::now();
        if now.duration_since(last_expire) > Duration::from_secs(5) {
            udp.expire(now);
            last_expire = now;
        }
        let (n, from) = match socket.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                continue;
            }
            Err(e) => {
                log::warn!("udp recv: {e}");
                continue;
            }
        };
        for (data, to) in udp.handle(&buf[..n], from, now) {
            let _ = socket.send_to(&data, to);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendezvous_and_relay() {
        let mut u = Udp::default();
        let t = Instant::now();
        let a: SocketAddr = "1.1.1.1:1000".parse().unwrap();
        let b: SocketAddr = "2.2.2.2:2000".parse().unwrap();
        assert!(u.handle(b"rugen1 hello R 1", a, t).is_empty());
        let out = u.handle(b"rugen1 hello R 2", b, t);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], (b"rugen1 peer 2.2.2.2:2000".to_vec(), a));

        assert_eq!(
            u.handle(b"rugen1 relay X 1", a, t),
            vec![(b"rugen1 relayok".to_vec(), a)]
        );
        // nobody on the other side yet: dropped
        assert!(u.handle(b"\x01game", a, t).is_empty());
        u.handle(b"rugen1 relay X 2", b, t);
        assert_eq!(u.handle(b"\x01game", a, t), vec![(b"\x01game".to_vec(), b)]);
        assert_eq!(u.handle(b"\x02back", b, t), vec![(b"\x02back".to_vec(), a)]);
        // a hijacker cannot steal an active side
        let c: SocketAddr = "3.3.3.3:3000".parse().unwrap();
        assert!(u.handle(b"rugen1 relay X 2", c, t).is_empty());
        assert!(u.handle(b"\x03evil", c, t).is_empty());
    }

    #[test]
    fn sources_are_rate_limited() {
        let mut u = Udp::default();
        let t = Instant::now();
        let a: SocketAddr = "1.1.1.1:1000".parse().unwrap();
        for _ in 0..PPS {
            u.handle(b"rugen1 relay Y 1", a, t);
        }
        assert!(u.handle(b"rugen1 relay Y 1", a, t).is_empty());
    }
}
