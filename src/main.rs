//! `rugen-relay [port]` (default 7777): UDP rendezvous for netplay.
//!
//! Protocol (plain text datagrams):
//! * client → server: `rugen1 hello <room> <side>` (side 1 or 2), repeated
//! * server → client: `rugen1 peer <ip:port>` once both sides of a room are known
//!
//! Only public addresses are exchanged; the match itself runs peer to peer.
//! Rooms expire after two minutes without a hello.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(7777);
    let socket = UdpSocket::bind(("0.0.0.0", port))?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    log::info!("rugen-relay listening on udp/{port}");
    let mut rooms: HashMap<String, [Option<(SocketAddr, Instant)>; 2]> = HashMap::new();
    let mut buf = [0u8; 512];
    loop {
        let now = Instant::now();
        rooms.retain(|_, sides| {
            sides
                .iter()
                .flatten()
                .any(|(_, t)| now.duration_since(*t) < Duration::from_secs(120))
        });
        let (n, from) = match socket.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => {
                log::warn!("recv: {e}");
                continue;
            }
        };
        let text = String::from_utf8_lossy(&buf[..n]);
        let mut it = text.split_whitespace();
        if it.next() != Some("rugen1") || it.next() != Some("hello") {
            continue;
        }
        let (Some(room), Some(side)) = (it.next(), it.next().and_then(|s| s.parse::<usize>().ok()))
        else {
            continue;
        };
        if !(1..=2).contains(&side) || room.len() > 64 {
            continue;
        }
        let entry = rooms.entry(room.to_string()).or_default();
        if entry[side - 1].map(|(a, _)| a) != Some(from) {
            log::info!("room {room}: side {side} is {from}");
        }
        entry[side - 1] = Some((from, now));
        if let [Some((a, _)), Some((b, _))] = *entry {
            let _ = socket.send_to(format!("rugen1 peer {b}").as_bytes(), a);
            let _ = socket.send_to(format!("rugen1 peer {a}").as_bytes(), b);
        }
    }
}
