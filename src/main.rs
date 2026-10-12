//! `rugen-server`: accounts, rooms, ranked matchmaking with Elo and seasons,
//! leaderboard, and WebSocket signaling for UDP hole punching. Match traffic
//! itself is peer to peer (ggrs rollback); the server never sees it unless the
//! optional UDP relay is enabled.
//!
//! Configuration (environment, flags override):
//!
//! ```text
//! RUGEN_BIND          --bind        HTTP/WebSocket listener      0.0.0.0:8080
//! RUGEN_DATA          --data        directory of rugen.db        /data
//! RUGEN_NAME          --name        server name shown in game    rugen server
//! RUGEN_PUBLIC_URL                  public https URL (logged, UDP host fallback)
//! RUGEN_UDP_RELAY     --udp-relay   bind addr of the UDP rendezvous/relay (off)
//! RUGEN_UDP_PUBLIC                  public host:port of that relay for clients
//! CF_TURN_KEY_ID + CF_TURN_API_TOKEN   Cloudflare Realtime TURN key (optional)
//! RUST_LOG                          log filter                   info
//! ```
//!
//! `rugen-server --backup out.db` writes a consistent copy of the database.
//! `rugen-server --healthcheck` probes `GET /health` on the bind port and
//! exits 0 / 1 (for container health checks without curl).
//! Legacy: `rugen-server --port 7777` binds HTTP and the UDP relay on 7777.

#![forbid(unsafe_code)]

mod api;
mod cfturn;
mod elo;
mod http;
mod matchmaking;
mod signal;
mod store;
mod udp;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

struct Settings {
    bind: String,
    data: PathBuf,
    name: String,
    public_url: Option<String>,
    udp_relay: Option<String>,
    udp_public: Option<String>,
    turn: Option<(String, String)>,
}

fn settings() -> Settings {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opt = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1).cloned())
    };
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
    // legacy: `--port n` or a bare number = HTTP and UDP on that port
    let legacy_port = opt("--port")
        .or_else(|| args.first().filter(|a| !a.starts_with("--")).cloned())
        .and_then(|p| p.parse::<u16>().ok());
    let bind = opt("--bind")
        .or(legacy_port.map(|p| format!("0.0.0.0:{p}")))
        .or_else(|| env("RUGEN_BIND"))
        .unwrap_or_else(|| "0.0.0.0:8080".into());
    let udp_relay = opt("--udp-relay")
        .or(legacy_port.map(|p| format!("0.0.0.0:{p}")))
        .or_else(|| env("RUGEN_UDP_RELAY"));
    let turn = match (env("CF_TURN_KEY_ID"), env("CF_TURN_API_TOKEN")) {
        (Some(k), Some(t)) => Some((k, t)),
        _ => None,
    };
    Settings {
        bind,
        data: opt("--data")
            .or_else(|| env("RUGEN_DATA"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/data")),
        name: opt("--name")
            .or_else(|| env("RUGEN_NAME"))
            .unwrap_or_else(|| "rugen server".into()),
        public_url: env("RUGEN_PUBLIC_URL"),
        udp_relay,
        udp_public: env("RUGEN_UDP_PUBLIC"),
        turn,
    }
}

/// Public `host:port` clients should send relay traffic to.
fn udp_public(s: &Settings, bound: SocketAddr) -> String {
    if let Some(p) = &s.udp_public {
        return p.clone();
    }
    let host = s
        .public_url
        .as_deref()
        .map(|u| u.split("://").last().unwrap_or(u))
        .and_then(|u| u.split(['/', ':']).next())
        .filter(|h| !h.is_empty());
    match host {
        Some(h) => format!("{h}:{}", bound.port()),
        None => bound.to_string(),
    }
}

fn healthcheck(bind: &str) -> i32 {
    let port = bind
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);
    let probe = || -> std::io::Result<bool> {
        let addr = ("127.0.0.1", port).to_socket_addrs()?.next().unwrap();
        let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
        s.set_read_timeout(Some(Duration::from_secs(3)))?;
        s.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
        let mut out = String::new();
        s.take(4096).read_to_string(&mut out)?;
        Ok(out.starts_with("HTTP/1.1 200"))
    };
    match probe() {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(e) => {
            eprintln!("healthcheck: {e}");
            1
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
    log::info!("shutting down");
}

fn main() {
    let s = settings();
    if std::env::args().any(|a| a == "--healthcheck") {
        std::process::exit(healthcheck(&s.bind));
    }
    if std::env::args().any(|a| a == "--help" || a == "-h") {
        println!(
            "rugen-server [--bind 0.0.0.0:8080] [--data /data] [--name NAME] [--udp-relay 0.0.0.0:7777] [--healthcheck] [--backup out.db]\n\
             env: RUGEN_BIND RUGEN_DATA RUGEN_NAME RUGEN_PUBLIC_URL RUGEN_UDP_RELAY RUGEN_UDP_PUBLIC CF_TURN_KEY_ID CF_TURN_API_TOKEN RUST_LOG"
        );
        return;
    }
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    if let Err(e) = run(s) {
        log::error!("{e}");
        std::process::exit(1);
    }
}

fn run(s: Settings) -> Result<(), Box<dyn std::error::Error>> {
    let store = store::Store::open(Some(&s.data))
        .map_err(|e| format!("database in {}: {e}", s.data.display()))?;
    if let Some(i) = std::env::args().position(|a| a == "--backup") {
        let out = std::env::args()
            .nth(i + 1)
            .ok_or("--backup needs an output file")?;
        store.backup_to(std::path::Path::new(&out))?;
        log::info!("backup written to {out}");
        return Ok(());
    }
    log::info!(
        "schema v{}, {} accounts, {}, data in {}",
        store.schema_version()?,
        store.account_count()?,
        store.season()?.name.to_lowercase(),
        s.data.display()
    );
    let mut cfg = api::ApiConfig {
        name: s.name.clone(),
        ..Default::default()
    };
    if let Some(bind) = &s.udp_relay {
        let socket = std::net::UdpSocket::bind(bind.as_str())
            .map_err(|e| format!("udp relay on {bind}: {e}"))?;
        let bound = socket.local_addr()?;
        cfg.udp_port = bound.port();
        cfg.udp_relay = Some(udp_public(&s, bound));
        log::info!(
            "udp relay advertised as {}",
            cfg.udp_relay.as_deref().unwrap_or("")
        );
        std::thread::spawn(move || {
            if let Err(e) = udp::serve(socket) {
                log::error!("udp: {e}");
            }
        });
    }
    if let Some((key, token)) = s.turn.clone() {
        log::info!("cloudflare TURN credentials enabled");
        cfg.turn = Some(cfturn::CfTurn::new(key, token));
    }
    if let Some(u) = &s.public_url {
        log::info!("public url {u}");
    }
    let api = api::Api::new(store, cfg);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(32)
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(s.bind.as_str())
            .await
            .map_err(|e| format!("bind {}: {e}", s.bind))?;
        log::info!("http + websocket on {}", listener.local_addr()?);
        http::serve(listener, api, shutdown_signal()).await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_public_address_falls_back_to_the_public_url_host() {
        let mut s = Settings {
            bind: String::new(),
            data: PathBuf::new(),
            name: String::new(),
            public_url: Some("https://rugen.example.com/".into()),
            udp_relay: None,
            udp_public: None,
            turn: None,
        };
        let bound: SocketAddr = "0.0.0.0:7777".parse().unwrap();
        assert_eq!(udp_public(&s, bound), "rugen.example.com:7777");
        s.udp_public = Some("1.2.3.4:9999".into());
        assert_eq!(udp_public(&s, bound), "1.2.3.4:9999");
    }
}
