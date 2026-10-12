//! `rugen-server`: a self-hostable hub for rugen online play — accounts,
//! lobby with public / private rooms and spectators, quick match and ranked
//! (Elo, seasons, leaderboard), and the **match relay**: players only ever
//! connect to this server, which forwards their rollback (ggrs) datagrams to
//! each other. Nobody learns anybody else's IP address.
//!
//! Configuration (environment, flags override):
//!
//! ```text
//! RUGEN_BIND        --bind      HTTP / WebSocket listener          0.0.0.0:8080
//! RUGEN_UDP_BIND    --udp-bind  UDP relay (fast path), "off"       0.0.0.0:7001
//! RUGEN_UDP_PUBLIC              host:port clients send UDP to      <public url host>:<udp port>
//! RUGEN_PUBLIC_URL              public https URL (logged, UDP host fallback)
//! RUGEN_DATA        --data      directory of rugen.db              /data
//! RUGEN_NAME        --name      server name in server lists        rugen server
//! RUGEN_MOTD                    message of the day
//! RUST_LOG                      log filter                         info
//! RUGEN_PKG_TTL                 package expiry after last use      24h
//! RUGEN_PKG_MAX_TOTAL           all packages (LRU eviction)        5GB
//! RUGEN_PKG_MAX                 one package                        150MB
//! RUGEN_PKG_RATE_ACCOUNT        uploads per account per hour       1GB
//! RUGEN_PKG_RATE_IP             uploads per client IP per hour     2GB
//! RUGEN_PKG_REPLAY_TTL          hours packages of ranked replays stay  720
//! RUGEN_FAIR_RATIO              power ratio that is UNBALANCED     1.6
//! RUGEN_FAIR_COMMUNITY_GAP      community rating gap, UNBALANCED   200
//! RUGEN_FAIR_MIN_GAMES          games before a rating counts       10
//! RUGEN_RESIM_DATA              engine data/ for re-simulation (--features resim)
//! RUGEN_RESIM_MOTIF             motif for re-simulation            RUGEN_RESIM_DATA
//! ```
//!
//! `rugen-server --backup out.db` writes a consistent copy of the database.
//! `rugen-server --healthcheck` probes `GET /health` on the bind port and
//! exits 0 / 1 (container health checks without curl).

#![forbid(unsafe_code)]

mod api;
#[cfg(test)]
mod e2e;
mod elo;
mod http;
mod hub;
mod matchmaking;
mod matchup;
mod packages;
mod password;
mod relay;
mod resim;
mod store;
#[cfg(test)]
mod testkit;
mod udp;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct Settings {
    bind: String,
    udp_bind: Option<String>,
    udp_public: Option<String>,
    public_url: Option<String>,
    data: PathBuf,
    name: String,
    motd: String,
}

fn settings() -> Settings {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opt = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1).cloned())
    };
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
    let udp_bind = opt("--udp-bind")
        .or_else(|| env("RUGEN_UDP_BIND"))
        .unwrap_or_else(|| "0.0.0.0:7001".into());
    Settings {
        bind: opt("--bind")
            .or_else(|| env("RUGEN_BIND"))
            .unwrap_or_else(|| "0.0.0.0:8080".into()),
        udp_bind: (!matches!(udp_bind.as_str(), "off" | "0" | "false" | "none"))
            .then_some(udp_bind),
        udp_public: env("RUGEN_UDP_PUBLIC"),
        public_url: env("RUGEN_PUBLIC_URL"),
        data: opt("--data")
            .or_else(|| env("RUGEN_DATA"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/data")),
        name: opt("--name")
            .or_else(|| env("RUGEN_NAME"))
            .unwrap_or_else(|| "rugen server".into()),
        motd: env("RUGEN_MOTD").unwrap_or_default(),
    }
}

/// Public `host:port` clients send UDP relay traffic to (the server's own address).
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
        let addr = ("127.0.0.1", port)
            .to_socket_addrs()?
            .next()
            .ok_or(std::io::ErrorKind::AddrNotAvailable)?;
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
            "rugen-server [--bind 0.0.0.0:8080] [--udp-bind 0.0.0.0:7001|off] [--data /data] [--name NAME] [--healthcheck] [--backup out.db]\n\
             env: RUGEN_BIND RUGEN_UDP_BIND RUGEN_UDP_PUBLIC RUGEN_PUBLIC_URL RUGEN_DATA RUGEN_NAME RUGEN_MOTD RUST_LOG"
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
    let relay = Arc::new(Mutex::new(relay::Relay::default()));
    let env_f = |k: &str| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.trim().parse::<f64>().ok())
    };
    let dt = rugen_fair::verdict::Thresholds::default();
    let thresholds = rugen_fair::verdict::Thresholds {
        ratio: env_f("RUGEN_FAIR_RATIO").map_or(dt.ratio, |v| v.max(1.0) as f32),
        community_gap: env_f("RUGEN_FAIR_COMMUNITY_GAP").map_or(dt.community_gap, |v| v as i32),
        min_games: env_f("RUGEN_FAIR_MIN_GAMES").map_or(dt.min_games, |v| v as u32),
    };
    let pkg = packages::PkgConfig::from_env();
    log::info!(
        "packages: ttl {} h, max {} MB each, {} MB total; fair ratio {}",
        pkg.ttl_secs / 3600,
        pkg.max_pkg >> 20,
        pkg.max_total >> 20,
        thresholds.ratio
    );
    let resim = resim::ResimConfig::from_env();
    if let Some(r) = &resim {
        log::info!(
            "disputed matches are re-simulated with {}",
            r.data.display()
        );
    }
    let mut cfg = api::ApiConfig {
        name: s.name.clone(),
        motd: s.motd.clone(),
        udp_public: None,
        data: Some(s.data.clone()),
        pkg,
        thresholds,
        resim,
    };
    if let Some(bind) = &s.udp_bind {
        let socket = Arc::new(
            std::net::UdpSocket::bind(bind.as_str())
                .map_err(|e| format!("udp relay on {bind}: {e}"))?,
        );
        let bound = socket.local_addr()?;
        let public = udp_public(&s, bound);
        log::info!("udp relay advertised as {public}");
        cfg.udp_public = Some(public);
        relay
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .set_udp(socket.clone());
        let r = relay.clone();
        std::thread::spawn(move || {
            if let Err(e) = udp::serve(socket, r) {
                log::error!("udp: {e}");
            }
        });
    } else {
        log::info!("udp relay off: matches relay over the /relay WebSocket only");
    }
    if let Some(u) = &s.public_url {
        log::info!("public url {u}");
    }
    let api = api::Api::new(store, cfg, relay);
    api.sweep_packages();
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
        // package retention: TTL + LRU size cap
        let sweeper = api.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(Duration::from_secs(600));
            loop {
                every.tick().await;
                let a = sweeper.clone();
                let _ = tokio::task::spawn_blocking(move || a.sweep_packages()).await;
            }
        });
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
            udp_bind: None,
            udp_public: None,
            public_url: Some("https://rugen.example.com/".into()),
            data: PathBuf::new(),
            name: String::new(),
            motd: String::new(),
        };
        let bound: SocketAddr = "0.0.0.0:7001".parse().unwrap();
        assert_eq!(udp_public(&s, bound), "rugen.example.com:7001");
        s.udp_public = Some("udp.example.com:7001".into());
        assert_eq!(udp_public(&s, bound), "udp.example.com:7001");
    }
}
