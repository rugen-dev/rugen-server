//! HTTP + WebSocket front end on axum. Everything speaks plain HTTP/1.1 so it
//! runs behind a Cloudflare Tunnel (which carries HTTP and WebSocket only):
//! the tunnel terminates TLS, `CF-Connecting-IP` / `CF-IPCountry` carry the
//! client address and region.

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

const MAX_BODY: usize = 64 * 1024;
/// Requests allowed per IP per window.
const RATE_LIMIT: u32 = 120;
const RATE_WINDOW: Duration = Duration::from_secs(10);
/// WebSocket keepalive (Cloudflare closes idle connections after ~100 s).
const WS_PING: Duration = Duration::from_secs(30);

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

#[derive(Clone)]
struct AppState {
    api: Arc<Api>,
    limiter: Arc<Mutex<RateLimiter>>,
}

/// The client address: the tunnel / proxy header when present, else the socket peer.
fn client_ip(headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    let h = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    h("cf-connecting-ip")
        .or_else(|| h("x-forwarded-for").and_then(|v| v.split(',').next()))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(peer.ip())
}

fn country(headers: &HeaderMap) -> String {
    headers
        .get("cf-ipcountry")
        .and_then(|v| v.to_str().ok())
        .map(crate::store::clean_region)
        .unwrap_or_default()
}

fn to_http(r: Response) -> HttpResponse {
    (
        StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        [(header::CONTENT_TYPE, "application/json")],
        Body::from(r.body),
    )
        .into_response()
}

fn json_error(status: u16, msg: &str) -> HttpResponse {
    to_http(Response::json(status, &serde_json::json!({ "error": msg })))
}

pub fn router(api: Arc<Api>) -> Router {
    let state = AppState {
        api,
        limiter: Arc::new(Mutex::new(RateLimiter::default())),
    };
    Router::new()
        .route("/ws", get(ws))
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
    let ip = client_ip(&headers, peer);
    // health checks (docker, tunnel) are not rate limited
    if uri.path() != "/health" {
        let allowed = st.limiter.lock().map(|mut l| l.allow(ip)).unwrap_or(false);
        if !allowed {
            return json_error(429, "rate limited");
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
        country: country(&headers),
    };
    log::debug!("{ip} {} {}", req.method, req.path);
    let api = st.api.clone();
    match tokio::task::spawn_blocking(move || api.handle(req)).await {
        Ok(r) => to_http(r),
        Err(e) => {
            log::error!("handler panicked: {e}");
            json_error(500, "internal error")
        }
    }
}

async fn ws(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    upgrade: WebSocketUpgrade,
) -> HttpResponse {
    let ip = client_ip(&headers, peer);
    let allowed = st.limiter.lock().map(|mut l| l.allow(ip)).unwrap_or(false);
    if !allowed {
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
    let api = st.api.clone();
    upgrade
        .max_message_size(16 * 1024)
        .on_upgrade(move |socket| session(api, account.id, account.name, socket))
}

async fn session(api: Arc<Api>, account: u64, name: String, mut socket: WebSocket) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ServerMsg>();
    let conn = api
        .hub
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .connect(account, tx.clone());
    log::info!("ws: {account} connected");
    let _ = tx.send(ServerMsg::Welcome { id: account, name });
    let mut ping = tokio::time::interval(WS_PING);
    ping.tick().await;
    // a burst limit per connection: signaling is a handful of messages
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
                if socket.send(Message::Ping(Bytes::new())).await.is_err() {
                    break;
                }
            }
            incoming = socket.recv() => {
                let text = match incoming {
                    Some(Ok(Message::Text(t))) => t,
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(_)) => continue,
                };
                if budget.0.elapsed() > Duration::from_secs(10) {
                    budget = (Instant::now(), 0);
                }
                budget.1 += 1;
                if budget.1 > 60 {
                    let _ = tx.send(ServerMsg::Error { error: "slow down".into() });
                    continue;
                }
                let reply = match serde_json::from_str::<ClientMsg>(&text) {
                    Ok(ClientMsg::Ping) => Some(ServerMsg::Pong),
                    Ok(ClientMsg::Signal { code, side, candidates }) => {
                        let r = api.hub.lock().unwrap_or_else(|p| p.into_inner())
                            .signal(account, conn, &code, side, &candidates);
                        r.err().map(|error| ServerMsg::Error { error })
                    }
                    Ok(ClientMsg::Relay { code, addr }) => {
                        let r = api.hub.lock().unwrap_or_else(|p| p.into_inner())
                            .relay(conn, &code, addr);
                        r.err().map(|error| ServerMsg::Error { error })
                    }
                    Err(e) => Some(ServerMsg::Error { error: format!("bad message: {e}") }),
                };
                if let Some(r) = reply {
                    let _ = tx.send(r);
                }
            }
        }
    }
    api.hub
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .disconnect(conn);
    log::info!("ws: {account} disconnected");
}

#[cfg(test)]
mod tests {
    //! The real server on 127.0.0.1 with two WebSocket clients.

    use super::*;
    use crate::api::ApiConfig;
    use crate::store::Store;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message as WsMsg;

    async fn start() -> (SocketAddr, Arc<Api>) {
        let api = Api::new(
            Store::open(None).unwrap(),
            ApiConfig {
                name: "test".into(),
                ..Default::default()
            },
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let a = api.clone();
        tokio::spawn(async move { serve(listener, a, std::future::pending()).await });
        (addr, api)
    }

    async fn http(addr: SocketAddr, method: &str, path: &str, body: &str) -> serde_json::Value {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        let body = out.split_once("\r\n\r\n").unwrap().1;
        serde_json::from_str(body).unwrap_or(serde_json::Value::Null)
    }

    type Ws = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    async fn next_msg(ws: &mut Ws) -> ServerMsg {
        loop {
            let m = tokio::time::timeout(Duration::from_secs(5), ws.next())
                .await
                .expect("timed out")
                .unwrap()
                .unwrap();
            if let WsMsg::Text(t) = m {
                return serde_json::from_str(&t).unwrap();
            }
        }
    }

    async fn send(ws: &mut Ws, m: &ClientMsg) {
        ws.send(WsMsg::Text(serde_json::to_string(m).unwrap().into()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn room_presence_and_signaling_over_websocket() {
        let (addr, _api) = start().await;
        assert_eq!(http(addr, "GET", "/health", "").await["ok"], true);
        let a = http(addr, "POST", "/register", "{}").await;
        let b = http(addr, "POST", "/register", "{}").await;
        let (ka, kb) = (a["key"].as_str().unwrap(), b["key"].as_str().unwrap());

        // bad keys never upgrade
        assert!(
            tokio_tungstenite::connect_async(format!("ws://{addr}/ws?key=nope"))
                .await
                .is_err()
        );
        let (mut wa, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws?key={ka}"))
            .await
            .unwrap();
        let (mut wb, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws?key={kb}"))
            .await
            .unwrap();
        assert!(matches!(next_msg(&mut wa).await, ServerMsg::Welcome { .. }));
        assert!(matches!(next_msg(&mut wb).await, ServerMsg::Welcome { .. }));
        send(&mut wa, &ClientMsg::Ping).await;
        assert_eq!(next_msg(&mut wa).await, ServerMsg::Pong);

        // A creates a room, B joins over HTTP: A is told over the WebSocket
        let room = http(
            addr,
            "POST",
            "/room",
            &format!(r#"{{"key":"{ka}","char":"kfm"}}"#),
        )
        .await;
        let code = room["code"].as_str().unwrap().to_string();
        http(
            addr,
            "POST",
            &format!("/room/{code}/join"),
            &format!(r#"{{"key":"{kb}","char":"kfm"}}"#),
        )
        .await;
        match next_msg(&mut wa).await {
            ServerMsg::Room { room } => {
                assert!(room.ready);
                assert_eq!(room.code, code);
            }
            m => panic!("{m:?}"),
        }

        // both signal their endpoints; each receives the other's
        send(
            &mut wb,
            &ClientMsg::Signal {
                code: code.clone(),
                side: 0,
                candidates: vec!["127.0.0.1:7002".into()],
            },
        )
        .await;
        send(
            &mut wa,
            &ClientMsg::Signal {
                code: code.clone(),
                side: 0,
                candidates: vec!["127.0.0.1:7001".into()],
            },
        )
        .await;
        match next_msg(&mut wa).await {
            ServerMsg::Peer {
                side, candidates, ..
            } => {
                assert_eq!(side, 1);
                assert_eq!(candidates, vec!["127.0.0.1:7002".to_string()]);
            }
            m => panic!("{m:?}"),
        }
        match next_msg(&mut wb).await {
            ServerMsg::Peer {
                side, candidates, ..
            } => {
                assert_eq!(side, 2);
                assert_eq!(candidates, vec!["127.0.0.1:7001".to_string()]);
            }
            m => panic!("{m:?}"),
        }
        let info = http(addr, "GET", "/", "").await;
        assert_eq!(info["online"], 2);
    }

    #[tokio::test]
    async fn queue_match_is_pushed() {
        let (addr, _api) = start().await;
        let a = http(addr, "POST", "/register", "{}").await;
        let b = http(addr, "POST", "/register", "{}").await;
        let (ka, kb) = (a["key"].as_str().unwrap(), b["key"].as_str().unwrap());
        let (mut wa, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws?key={ka}"))
            .await
            .unwrap();
        next_msg(&mut wa).await;
        http(
            addr,
            "POST",
            "/queue",
            &format!(r#"{{"key":"{ka}","char":"kfm"}}"#),
        )
        .await;
        http(
            addr,
            "POST",
            "/queue",
            &format!(r#"{{"key":"{kb}","char":"kfm"}}"#),
        )
        .await;
        match next_msg(&mut wa).await {
            ServerMsg::Found { found } => {
                assert_eq!(found.side, 1);
                assert_eq!(found.opponent.id, b["id"].as_u64().unwrap());
            }
            m => panic!("{m:?}"),
        }
    }
}
