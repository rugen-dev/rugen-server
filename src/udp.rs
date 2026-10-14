//! UDP front of the match relay (`RUGEN_UDP_BIND`, default 0.0.0.0:7001):
//! the fast path. Needs a published UDP port — a Cloudflare Tunnel cannot
//! carry it; clients fall back to the `/relay` WebSocket when UDP is blocked.

use std::collections::HashMap;
use std::net::{IpAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::relay::{Relay, Route};

/// Datagrams per source IP per second before anything is parsed.
const IP_PPS: u32 = 2000;

pub fn serve(socket: Arc<UdpSocket>, relay: Arc<Relay>) -> std::io::Result<()> {
    log::info!("udp relay listening on {}", socket.local_addr()?);
    serve_until(socket, relay, None)
}

/// [`serve`] until `stop` is set (checked at least every 2 s).
pub fn serve_until(
    socket: Arc<UdpSocket>,
    relay: Arc<Relay>,
    stop: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> std::io::Result<()> {
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut buf = [0u8; 2048];
    let mut per_ip: HashMap<IpAddr, (Instant, u32)> = HashMap::new();
    let mut last_expire = Instant::now();
    loop {
        if stop
            .as_ref()
            .is_some_and(|s| s.load(std::sync::atomic::Ordering::Relaxed))
        {
            return Ok(());
        }
        let now = Instant::now();
        if now.duration_since(last_expire) > Duration::from_secs(5) {
            // (relay sessions expire on the server's own timer, UDP or not)
            per_ip.retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(2));
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
        let e = per_ip.entry(from.ip()).or_insert((now, 0));
        if now.duration_since(e.0) >= Duration::from_secs(1) {
            *e = (now, 0);
        }
        e.1 += 1;
        if e.1 > IP_PPS {
            continue;
        }
        relay.on_packet(&buf[..n], &Route::Udp(from), now);
    }
}

#[cfg(test)]
mod tests {
    //! Two fake clients and the relay on loopback over real UDP.

    use super::*;
    use rugen_proto::relay::{self as wire, Header};

    #[test]
    fn udp_clients_exchange_through_the_relay() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let server = socket.local_addr().unwrap();
        let relay = Arc::new(Relay::default());
        relay.set_udp(socket.clone());
        let (id, tokens) = relay.create(&[1, 2]).unwrap();
        let r = relay.clone();
        std::thread::spawn(move || serve(socket, r));

        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        for s in [&a, &b] {
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        }
        let send = |s: &UdpSocket, kind, from: u8, to, p: &[u8]| {
            let h = Header {
                kind,
                from,
                to,
                session: id,
            };
            s.send_to(&wire::encode_client(h, &tokens[from as usize], p), server)
                .unwrap();
        };
        let mut buf = [0u8; 1500];
        let mut recv = |s: &UdpSocket, want: u8| -> Vec<u8> {
            loop {
                let (n, from) = s.recv_from(&mut buf).unwrap();
                assert_eq!(from, server, "only the server ever talks to a client");
                let (h, p) = wire::decode_server(&buf[..n]).unwrap();
                if h.kind == want {
                    return p.to_vec();
                }
            }
        };
        send(&a, wire::HELLO, 0, 0, &[]);
        assert_eq!(recv(&a, wire::ACK), vec![0b01]);
        send(&b, wire::HELLO, 1, 0, &[]);
        assert_eq!(recv(&b, wire::ACK), vec![0b11]);
        assert_eq!(recv(&a, wire::PEERS), vec![0b11]);
        send(&a, wire::DATA, 0, 1, b"input-a");
        assert_eq!(recv(&b, wire::DATA), b"input-a");
        send(&b, wire::DATA, 1, 0, b"input-b");
        assert_eq!(recv(&a, wire::DATA), b"input-b");
        send(&a, wire::PING, 0, 0, b"123");
        assert_eq!(recv(&a, wire::PONG), b"123");
        assert_eq!(
            relay.forwarded.load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }
}
