//! HTTP + WebSocket front end on axum. Plain HTTP/1.1, so it runs behind a
//! Cloudflare Tunnel (which terminates TLS and carries HTTP / WebSocket):
//!
//! * JSON API → [`Api::handle`] on the blocking pool
//! * `/ws` lobby WebSocket: presence pushes, server-side round-trip pings
//! * `/relay` binary WebSocket: relayed match datagrams for clients whose UDP
//!   is blocked (same framing as the UDP relay)
//!
//! Client addresses are used for rate limiting only: never logged at info
//! level, never passed to the API, never sent to anyone.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response as HttpResponse};
use axum::routing::get;
use rugen_proto::{ClientMsg, ServerMsg};

use crate::api::{Api, Request, Response};
use crate::relay::Route;

/// Package upload chunks (4 MB) are the largest bodies; results carry input
/// streams; everything else is tiny.
const MAX_BODY: usize = 4 * 1024 * 1024 + 64 * 1024;
/// Requests allowed per IP per window.
const RATE_LIMIT: u32 = 120;
const RATE_WINDOW: Duration = Duration::from_secs(10);
/// Lobby WebSocket keepalive + RTT probe (Cloudflare closes idle sockets after ~100 s).
const WS_PING: Duration = Duration::from_secs(15);

#[derive(Default)]
struct RateLimiter {
    hits: HashMap<IpAddr, (Instant, u32)>,
}

impl RateLimiter {
    fn allow(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        if self.hits.len() > 50_000 {
            self.hits
                .retain(|_, (t, _)| now.duration_since(*t) < RATE_WINDOW);
        }
        let e = self.hits.entry(ip).or_insert((now, 0));
        if now.duration_since(e.0) >= RATE_WINDOW {
            *e = (now, 0);
        }
        e.1 += 1;
        e.1 <= RATE_LIMIT
    }
}

/// Package upload bytes per client IP per hour.
#[derive(Default)]
struct UploadLimiter {
    bytes: HashMap<IpAddr, (Instant, u64)>,
}

impl UploadLimiter {
    fn allow(&mut self, ip: IpAddr, n: u64, cap: u64) -> bool {
        let now = Instant::now();
        if self.bytes.len() > 50_000 {
            self.bytes
                .retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(3600));
        }
        let e = self.bytes.entry(ip).or_insert((now, 0));
        if now.duration_since(e.0) >= Duration::from_secs(3600) {
            *e = (now, 0);
        }
        e.1 += n;
        e.1 <= cap
    }
}

#[derive(Clone)]
struct AppState {
    api: Arc<Api>,
    limiter: Arc<Mutex<RateLimiter>>,
    uploads: Arc<Mutex<UploadLimiter>>,
    started: Instant,
}

/// The client address: the tunnel / proxy header when present, else the socket peer.
fn client_ip(headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    let h = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    h("cf-connecting-ip")
        .or_else(|| h("x-forwarded-for").and_then(|v| v.split(',').next()))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(peer.ip())
}

fn to_http(r: Response) -> HttpResponse {
    (
        StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        [(header::CONTENT_TYPE, r.content_type)],
        Body::from(r.body),
    )
        .into_response()
}

fn json_error(status: u16, msg: &str) -> HttpResponse {
    to_http(Response::json(status, &serde_json::json!({ "error": msg })))
}

fn allowed(st: &AppState, headers: &HeaderMap, peer: SocketAddr) -> bool {
    let ip = client_ip(headers, peer);
    st.limiter.lock().map(|mut l| l.allow(ip)).unwrap_or(false)
}

pub fn router(api: Arc<Api>) -> Router {
    let state = AppState {
        api,
        limiter: Arc::new(Mutex::new(RateLimiter::default())),
        uploads: Arc::new(Mutex::new(UploadLimiter::default())),
        started: Instant::now(),
    };
    Router::new()
        .route("/ws", get(lobby_ws))
        .route("/relay", get(relay_ws))
        .fallback(any)
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

pub async fn serve(
    listener: tokio::net::TcpListener,
    api: Arc<Api>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        router(api).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

/// Every JSON route goes through [`Api::handle`] on the blocking pool.
async fn any(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> HttpResponse {
    // health checks (docker, tunnel, server lists) are not rate limited
    // package transfers have their own byte budget (below / per account)
    let transfer = uri.path().starts_with("/pkg/")
        && (uri.path().ends_with("/upload") || uri.path().ends_with("/data"));
    if uri.path() != "/health" && !transfer && !allowed(&st, &headers, peer) {
        return json_error(429, "rate limited");
    }
    if method == Method::POST && uri.path().starts_with("/pkg/") && uri.path().ends_with("/upload")
    {
        let ip = client_ip(&headers, peer);
        let cap = st.api.packages.cfg.ip_rate;
        let ok = st
            .uploads
            .lock()
            .map(|mut u| u.allow(ip, body.len() as u64, cap))
            .unwrap_or(false);
        if !ok {
            return json_error(429, "upload limit reached, try again later");
        }
    }
    let query = uri
        .query()
        .map(|q| {
            q.split('&')
                .filter_map(|kv| kv.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let req = Request {
        method: method.as_str().to_string(),
        path: uri.path().to_string(),
        query,
        body: body.to_vec(),
    };
    let api = st.api.clone();
    match tokio::task::spawn_blocking(move || api.handle(req)).await {
        Ok(r) => to_http(r),
        Err(e) => {
            log::error!("handler panicked: {e}");
            json_error(500, "internal error")
        }
    }
}

async fn lobby_ws(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    upgrade: WebSocketUpgrade,
) -> HttpResponse {
    if !allowed(&st, &headers, peer) {
        return json_error(429, "rate limited");
    }
    let key = q.get("key").cloned().unwrap_or_default();
    let api = st.api.clone();
    let account = tokio::task::spawn_blocking(move || api.account_for_key(&key))
        .await
        .ok()
        .flatten();
    let Some(account) = account else {
        return json_error(401, "bad key");
    };
    let (api, started) = (st.api.clone(), st.started);
    upgrade
        .max_message_size(16 * 1024)
        .on_upgrade(move |socket| lobby_session(api, started, account.id, account.name, socket))
}

async fn lobby_session(
    api: Arc<Api>,
    started: Instant,
    account: u64,
    name: String,
    mut socket: WebSocket,
) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ServerMsg>();
    let conn = api
        .hub
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .connect(account, tx.clone());
    log::debug!("ws: account {account} connected");
    let _ = tx.send(ServerMsg::Welcome { id: account, name });
    let mut ping = tokio::time::interval(WS_PING);
    let mut budget = (Instant::now(), 0u32);
    loop {
        tokio::select! {
            out = rx.recv() => {
                let Some(m) = out else { break };
                let Ok(text) = serde_json::to_string(&m) else { continue };
                if socket.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
            _ = ping.tick() => {
                // the payload is our clock: the pong tells the round trip
                let t = started.elapsed().as_millis() as u64;
                if socket.send(Message::Ping(Bytes::copy_from_slice(&t.to_be_bytes()))).await.is_err() {
                    break;
                }
            }
            incoming = socket.recv() => {
                let text = match incoming {
                    Some(Ok(Message::Text(t))) => t,
                    Some(Ok(Message::Pong(p))) => {
                        if let Ok(b) = <[u8; 8]>::try_from(p.as_ref()) {
                            let sent = u64::from_be_bytes(b);
                            let now = started.elapsed().as_millis() as u64;
                            if now >= sent {
                                api.hub.lock().unwrap_or_else(|p| p.into_inner())
                                    .record_rtt(account, (now - sent) as u32);
                            }
                        }
                        continue;
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(_)) => continue,
                };
                if budget.0.elapsed() > Duration::from_secs(10) {
                    budget = (Instant::now(), 0);
                }
                budget.1 += 1;
                if budget.1 > 60 {
                    continue;
                }
                let reply = match serde_json::from_str::<ClientMsg>(&text) {
                    Ok(ClientMsg::Ping) => ServerMsg::Pong,
                    Err(e) => ServerMsg::Error { error: format!("bad message: {e}") },
                };
                let _ = tx.send(reply);
            }
        }
    }
    api.hub
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .disconnect(conn);
    log::debug!("ws: account {account} disconnected");
}

/// Relayed match datagrams over a WebSocket (binary frames, same framing as
/// UDP; every frame carries its slot token).
async fn relay_ws(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> HttpResponse {
    if !allowed(&st, &headers, peer) {
        return json_error(429, "rate limited");
    }
    let api = st.api.clone();
    upgrade
        .max_message_size(4 * 1024)
        .on_upgrade(move |socket| relay_session(api, socket))
}

async fn relay_session(api: Arc<Api>, mut socket: WebSocket) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let conn = api
        .relay
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .ws_connect(tx);
    loop {
        tokio::select! {
            out = rx.recv() => {
                let Some(bytes) = out else { break };
                if socket.send(Message::Binary(bytes.into())).await.is_err() {
                    break;
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Binary(b))) => {
                        api.relay.lock().unwrap_or_else(|p| p.into_inner())
                            .on_packet(&b, Route::Ws(conn), Instant::now());
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(_)) => {}
                }
            }
        }
    }
    api.relay
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .ws_disconnect(conn);
}

#[cfg(test)]
mod tests {
    //! The real server on 127.0.0.1 with WebSocket clients.

    use super::*;
    use crate::api::ApiConfig;
    use crate::relay::Relay;
    use crate::store::Store;
    use futures_util::{SinkExt, StreamExt};
    use rugen_proto::relay::{self as wire, Header};
    use tokio_tungstenite::tungstenite::Message as WsMsg;

    async fn start() -> (SocketAddr, Arc<Api>) {
        let api = Api::new(
            Store::open(None).unwrap(),
            ApiConfig {
                name: "test".into(),
                ..Default::default()
            },
            Arc::new(Mutex::new(Relay::default())),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let a = api.clone();
        tokio::spawn(async move { serve(listener, a, std::future::pending()).await });
        (addr, api)
    }

    /// Raw HTTP so the test can set proxy headers.
    async fn http(addr: SocketAddr, method: &str, path: &str, body: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nCF-Connecting-IP: 203.0.113.77\r\nX-Forwarded-For: 198.51.100.9\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out.split_once("\r\n\r\n").unwrap().1.to_string()
    }

    async fn json(addr: SocketAddr, method: &str, path: &str, body: &str) -> serde_json::Value {
        serde_json::from_str(&http(addr, method, path, body).await).unwrap_or_default()
    }

    type Ws = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    async fn next_text(ws: &mut Ws) -> String {
        loop {
            let m = tokio::time::timeout(Duration::from_secs(5), ws.next())
                .await
                .expect("timed out")
                .unwrap()
                .unwrap();
            if let WsMsg::Text(t) = m {
                return t.to_string();
            }
        }
    }

    async fn next_bin(ws: &mut Ws, kind: u8) -> Vec<u8> {
        loop {
            let m = tokio::time::timeout(Duration::from_secs(5), ws.next())
                .await
                .expect("timed out")
                .unwrap()
                .unwrap();
            if let WsMsg::Binary(b) = m {
                let (h, p) = wire::decode_server(&b).unwrap();
                if h.kind == kind {
                    return p.to_vec();
                }
            }
        }
    }

    #[tokio::test]
    async fn room_match_over_websocket_relay_without_leaking_ips() {
        let (addr, _api) = start().await;
        let mut seen = String::new();
        let a = json(addr, "POST", "/register", "{}").await;
        let b = json(addr, "POST", "/register", "{}").await;
        let (ka, kb) = (a["key"].as_str().unwrap(), b["key"].as_str().unwrap());

        // lobby presence: A hears about B joining, with its ticket
        let (mut la, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws?key={ka}"))
            .await
            .unwrap();
        seen += &next_text(&mut la).await;
        assert!(
            tokio_tungstenite::connect_async(format!("ws://{addr}/ws?key=nope"))
                .await
                .is_err()
        );
        let room = http(
            addr,
            "POST",
            "/room",
            &format!(r#"{{"key":"{ka}","char":"kfm"}}"#),
        )
        .await;
        seen += &room;
        let code = serde_json::from_str::<serde_json::Value>(&room).unwrap()["code"]
            .as_str()
            .unwrap()
            .to_string();
        seen += &http(addr, "GET", "/rooms", "").await;
        let joined = http(
            addr,
            "POST",
            &format!("/room/{code}/join"),
            &format!(r#"{{"key":"{kb}","char":"kfm"}}"#),
        )
        .await;
        seen += &joined;
        let pushed = next_text(&mut la).await;
        seen += &pushed;
        let pushed: ServerMsg = serde_json::from_str(&pushed).unwrap();
        let ServerMsg::Room { room: ra } = pushed else {
            panic!("{pushed:?}")
        };
        let rb: rugen_proto::RoomInfo = serde_json::from_str(&joined).unwrap();
        assert!(ra.ticket.is_none() && rb.ticket.is_none(), "matchup first");
        let id = rb.matchup.as_ref().unwrap().id;
        // pick / verdict / confirm / upload / ready (see api tests)
        let kit = crate::api::tests::Kit::new();
        let api2 = _api.clone();
        let (ka2, kb2) = (ka.to_string(), kb.to_string());
        tokio::task::spawn_blocking(move || {
            crate::api::tests::play_matchup(&api2, id, [&ka2, &kb2], &kit);
        })
        .await
        .unwrap();
        let ra = http(addr, "GET", &format!("/room/{code}?key={ka}"), "").await;
        let rb = http(addr, "GET", &format!("/room/{code}?key={kb}"), "").await;
        seen += &ra;
        seen += &rb;
        let ra: rugen_proto::RoomInfo = serde_json::from_str(&ra).unwrap();
        let rb: rugen_proto::RoomInfo = serde_json::from_str(&rb).unwrap();
        let (ta, tb) = (ra.ticket.unwrap(), rb.ticket.unwrap());
        assert_eq!(ta.session, tb.session);

        // both players relay over /relay WebSockets
        let tok = |t: &rugen_proto::SessionTicket| -> [u8; 16] {
            rugen_proto::from_hex(&t.token).unwrap().try_into().unwrap()
        };
        let (mut wa, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/relay"))
            .await
            .unwrap();
        let (mut wb, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/relay"))
            .await
            .unwrap();
        let frame = |kind, from: u8, to, t: &[u8; 16], p: &[u8]| {
            WsMsg::Binary(
                wire::encode_client(
                    Header {
                        kind,
                        from,
                        to,
                        session: ta.session,
                    },
                    t,
                    p,
                )
                .into(),
            )
        };
        wa.send(frame(wire::HELLO, 0, 0, &tok(&ta), &[]))
            .await
            .unwrap();
        assert_eq!(next_bin(&mut wa, wire::ACK).await, vec![0b01]);
        wb.send(frame(wire::HELLO, 1, 0, &tok(&tb), &[]))
            .await
            .unwrap();
        assert_eq!(next_bin(&mut wa, wire::PEERS).await, vec![0b11]);
        wa.send(frame(wire::DATA, 0, 1, &tok(&ta), b"ggrs-a"))
            .await
            .unwrap();
        assert_eq!(next_bin(&mut wb, wire::DATA).await, b"ggrs-a");
        wb.send(frame(wire::DATA, 1, 0, &tok(&tb), b"ggrs-b"))
            .await
            .unwrap();
        assert_eq!(next_bin(&mut wa, wire::DATA).await, b"ggrs-b");
        // forged token: nothing arrives
        wb.send(frame(wire::DATA, 1, 0, &[0u8; 16], b"evil"))
            .await
            .unwrap();
        wb.send(frame(wire::DATA, 1, 0, &tok(&tb), b"ok"))
            .await
            .unwrap();
        assert_eq!(next_bin(&mut wa, wire::DATA).await, b"ok");

        let poll = http(addr, "GET", &format!("/room/{code}?key={ka}"), "").await;
        seen += &poll;
        seen += &http(addr, "GET", "/", "").await;
        for ip in ["203.0.113.77", "198.51.100.9", "127.0.0.1"] {
            assert!(!seen.contains(ip), "payload leaked {ip}: {seen}");
        }
    }

    #[tokio::test]
    async fn lobby_websocket_measures_rtt() {
        let (addr, api) = start().await;
        let a = json(addr, "POST", "/register", "{}").await;
        let ka = a["key"].as_str().unwrap();
        let id = a["id"].as_u64().unwrap();
        let (mut la, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws?key={ka}"))
            .await
            .unwrap();
        // tungstenite answers pings automatically while we read
        let t = Instant::now();
        while api.hub.lock().unwrap().rtt(id).is_none() && t.elapsed() < Duration::from_secs(5) {
            let _ = tokio::time::timeout(Duration::from_millis(100), la.next()).await;
        }
        assert!(api.hub.lock().unwrap().rtt(id).is_some());
        la.send(WsMsg::Text(r#"{"t":"ping"}"#.into()))
            .await
            .unwrap();
        let mut got_pong = false;
        for _ in 0..5 {
            if next_text(&mut la).await.contains("pong") {
                got_pong = true;
                break;
            }
        }
        assert!(got_pong);
    }

    #[tokio::test]
    async fn queue_match_is_pushed() {
        let (addr, _api) = start().await;
        let a = json(addr, "POST", "/register", "{}").await;
        let b = json(addr, "POST", "/register", "{}").await;
        let (ka, kb) = (a["key"].as_str().unwrap(), b["key"].as_str().unwrap());
        let (mut wa, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws?key={ka}"))
            .await
            .unwrap();
        next_text(&mut wa).await;
        json(
            addr,
            "POST",
            "/queue",
            &format!(r#"{{"key":"{ka}","char":"kfm"}}"#),
        )
        .await;
        json(
            addr,
            "POST",
            "/queue",
            &format!(r#"{{"key":"{kb}","char":"kfm"}}"#),
        )
        .await;
        let id = loop {
            let m: ServerMsg = serde_json::from_str(&next_text(&mut wa).await).unwrap();
            if let ServerMsg::Found { found } = m {
                assert_eq!(found.side, 1);
                assert!(found.ticket.is_none());
                break found.matchup.unwrap().id;
            }
        };
        let kit = crate::api::tests::Kit::new();
        let (ka2, kb2) = (ka.to_string(), kb.to_string());
        tokio::task::spawn_blocking(move || {
            crate::api::tests::play_matchup(&_api, id, [&ka2, &kb2], &kit);
        })
        .await
        .unwrap();
        // the start is pushed with this player's ticket
        loop {
            let m: ServerMsg = serde_json::from_str(&next_text(&mut wa).await).unwrap();
            if let ServerMsg::Matchup { matchup } = m
                && let Some(t) = matchup.ticket
            {
                assert_eq!(matchup.phase, "started");
                assert_eq!(t.slot, 0);
                break;
            }
        }
    }
}
