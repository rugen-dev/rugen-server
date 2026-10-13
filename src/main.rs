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
//! RUGEN_UDP_PUBLIC              host:port clients send UDP to,     <public url host>:<udp port>
//!                               "off" = no UDP relay at all (tunnel-only: nothing bound,
//!                               nothing advertised, clients use the /relay WebSocket at once)
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
//!
//! official server / truth feed (see `truth`)
//! RUGEN_SIGNING_KEY             this server's Ed25519 seed (hex)   <data>/signing.key (generated)
//! RUGEN_SIGNING_KEY_FILE        file holding the seed instead
//! RUGEN_OFFICIAL_KEY            public key that is official        baked into the build
//! RUGEN_OFFICIAL_URL            official feed source, "off"        baked official address
//! RUGEN_OFFICIAL_PULL           seconds between feed pulls         900
//! RUGEN_ADMIN_TOKEN             enables POST /v1/admin/*           (off)
//! RUGEN_AUTO_BLOCK_LIARS        players lying about a fingerprint  3 (0 = off)
//! RUGEN_AUTO_BLOCK_DESYNCS      desynced matches of a fingerprint  10 (0 = off)
//! RUGEN_AUTO_BLOCK_ANALYSIS     block on server-side cheat flags   on
//! RUGEN_CF_TURN_KEY_ID          Cloudflare Realtime TURN key id (TURN off without)
//! RUGEN_CF_TURN_TOKEN           its API token (secret)
//! RUGEN_TURN_BUDGET_GB          hard monthly TURN cap, decimal GB   500 (half the free 1000)
//! RUGEN_TURN_SOFT_PERCENT       above this: TURN for ranked only    80
//! RUGEN_TURN_MAX_MATCHES_PER_HOUR / _PER_DAY        per account     12 / 60
//! RUGEN_TURN_MAX_MATCHES_PER_HOUR_IP / _PER_DAY_IP  per client IP   24 / 120
//! RUGEN_TURN_RATE_ESTIMATE      bytes/s per player per direction    8000
//! RUGEN_TURN_SAFETY             factor on estimates and reports     2.0
//! RUGEN_TURN_TTL_MAX            longest credential, seconds         1800
//! RUGEN_CF_ACCOUNT_ID + RUGEN_CF_ANALYTICS_TOKEN  cross-check usage with Cloudflare analytics
//!
//! capacity and abuse limits
//! RUGEN_WORKERS                 async worker threads               CPU quota (cgroup cpu.max) or cores, min 2
//! RUGEN_RATE_ACCOUNT            API calls per account per 10 s     120
//! RUGEN_RATE_IP                 API calls per client IP per 10 s   2000 (ceiling; CGNAT shares IPs)
//! RUGEN_RATE_ANON               calls without a key per IP / 10 s  300
//! RUGEN_RATE_REGISTER           registrations per IP per minute    30
//! RUGEN_RATE_RELAY              /relay upgrades per IP per 10 s    300 (never charged to the API)
//! RUGEN_HIGH_PING_MS            queue pairs above this: high_ping  200
//! ```
//!
//! A server is **official** when its signing key is the official key;
//! otherwise it is a community server that enforces the official feed.
//!
//! `rugen-server --backup out.db` writes a consistent copy of the database.
//! `rugen-server --healthcheck` probes `GET /health` on the bind port and
//! exits 0 / 1 (container health checks without curl).
//! `rugen-server --gen-key` prints a new signing key pair.
//! `rugen-server --block <fp> [--reason text] | --unblock <fp> | --blocklist`
//! edit / show this server's blocklist (works while the server runs).
//! `rugen-server --delete-accounts <name prefix> [--yes]` deletes the
//! accounts whose name starts with the prefix (e.g. `loadtest-`) and their
//! unranked matches; without `--yes` it only counts them.

#![forbid(unsafe_code)]

mod api;
mod compat;
#[cfg(test)]
mod e2e;
mod elo;
mod http;
mod hub;
mod legacy;
mod matchmaking;
mod matchup;
mod packages;
mod password;
mod relay;
mod resim;
mod store;
#[cfg(test)]
mod testkit;
mod truth;
mod turn;
mod udp;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
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
    let off = |v: &str| matches!(v, "off" | "0" | "false" | "none");
    let udp_public = env("RUGEN_UDP_PUBLIC");
    // RUGEN_UDP_PUBLIC=off: tunnel-only server, no UDP socket at all
    let udp_off = off(&udp_bind) || udp_public.as_deref().is_some_and(off);
    Settings {
        bind: opt("--bind")
            .or_else(|| env("RUGEN_BIND"))
            .unwrap_or_else(|| "0.0.0.0:8080".into()),
        udp_bind: (!udp_off).then_some(udp_bind),
        udp_public: udp_public.filter(|v| !off(v)),
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
             rugen-server --gen-key | --block <fingerprint> [--reason text] | --unblock <fingerprint> | --blocklist\n\
             rugen-server --delete-accounts <name prefix> [--yes]\n\
             env: RUGEN_BIND RUGEN_UDP_BIND RUGEN_UDP_PUBLIC RUGEN_PUBLIC_URL RUGEN_DATA RUGEN_NAME RUGEN_MOTD RUST_LOG\n\
             \x20    RUGEN_SIGNING_KEY RUGEN_SIGNING_KEY_FILE RUGEN_OFFICIAL_KEY RUGEN_OFFICIAL_URL RUGEN_OFFICIAL_PULL\n\
             \x20    RUGEN_ADMIN_TOKEN RUGEN_AUTO_BLOCK_LIARS RUGEN_AUTO_BLOCK_DESYNCS RUGEN_AUTO_BLOCK_ANALYSIS\n\
             \x20    RUGEN_WORKERS RUGEN_RATE_ACCOUNT RUGEN_RATE_IP RUGEN_RATE_ANON RUGEN_RATE_REGISTER RUGEN_RATE_RELAY RUGEN_HIGH_PING_MS"
        );
        return;
    }
    if std::env::args().any(|a| a == "--gen-key") {
        gen_key();
        return;
    }
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    if let Err(e) = run(s) {
        log::error!("{e}");
        std::process::exit(1);
    }
}

/// `--gen-key`: a fresh key pair and where each half goes.
fn gen_key() {
    match rugen_fair::trust::SigningKey::generate() {
        Ok(k) => println!(
            "# private: the official server only (secret env / file, never commit)\n\
             RUGEN_SIGNING_KEY={}\n\
             # public: bake into game builds and pass to community servers if needed\n\
             RUGEN_OFFICIAL_KEY={}\n\
             # key fingerprint shown in game: {}",
            k.seed_hex(),
            k.public().hex(),
            k.public().fingerprint()
        ),
        Err(e) => {
            eprintln!("--gen-key: {e}");
            std::process::exit(1);
        }
    }
}

/// `--block` / `--unblock` / `--blocklist`: edit the blocklist and exit.
/// True when one of them ran.
fn blocklist_cli(store: &mut store::Store) -> Result<bool, Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1).cloned())
    };
    let fp_of = |v: Option<String>, flag: &str| -> Result<String, String> {
        let fp = v
            .ok_or(format!("{flag} needs a fingerprint"))?
            .to_ascii_lowercase();
        if rugen_proto::is_fingerprint(&fp) {
            Ok(fp)
        } else {
            Err(format!("{flag}: a fingerprint is 64 hex digits"))
        }
    };
    if args.iter().any(|a| a == "--block") {
        let fp = fp_of(arg("--block"), "--block")?;
        let reason = arg("--reason").unwrap_or_else(|| "blocked by the operator".into());
        store.block(&fp, &reason, "admin")?;
        println!("blocked {fp} ({reason})");
    } else if args.iter().any(|a| a == "--unblock") {
        let fp = fp_of(arg("--unblock"), "--unblock")?;
        let was = store.unblock(&fp)?;
        println!(
            "{} {fp}",
            if was { "unblocked" } else { "was not blocked:" }
        );
    } else if !args.iter().any(|a| a == "--blocklist") {
        return Ok(false);
    }
    let list = store.blocklist()?;
    println!("blocklist #{}: {} entries", store.truth_seq()?, list.len());
    for b in list {
        println!("  {}  {:<5}  {}", b.fingerprint, b.source, b.reason);
    }
    Ok(true)
}

/// `--delete-accounts <prefix> [--yes]`: remove accounts by name prefix
/// (load-test leftovers) and exit. True when it ran.
fn delete_accounts_cli(store: &mut store::Store) -> Result<bool, Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let Some(i) = args.iter().position(|a| a == "--delete-accounts") else {
        return Ok(false);
    };
    let prefix = args
        .get(i + 1)
        .filter(|p| !p.starts_with("--"))
        .ok_or("--delete-accounts needs a name prefix")?;
    // a short prefix would sweep real players
    if prefix.chars().count() < 4 {
        return Err("--delete-accounts: the prefix needs at least 4 characters".into());
    }
    let yes = args.iter().any(|a| a == "--yes");
    let (accounts, matches) = store.delete_accounts_by_prefix(prefix, !yes)?;
    if yes {
        println!("deleted {accounts} accounts named {prefix}* and {matches} of their matches");
    } else {
        println!(
            "{accounts} accounts named {prefix}* ({matches} unranked matches); run again with --yes to delete them"
        );
    }
    Ok(true)
}

/// Async worker threads: `RUGEN_WORKERS`, else the CPU quota of this
/// process's cgroup (containers: `--cpus`), else the cores available; at
/// least two.
fn worker_threads() -> usize {
    if let Some(n) = std::env::var("RUGEN_WORKERS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
    {
        return n;
    }
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    // at least two: with a single worker, socket readiness is only picked up
    // between task batches and relay latency climbs long before the CPU
    // quota is used up (measured under `--cpus 1`)
    cgroup_cpus().map_or(cores, |q| q.min(cores)).max(2)
}

/// CPUs allowed by the cgroup v2 `cpu.max` of this process (the tightest
/// along its path, rounded up), or v1 `cpu.cfs_quota_us`; `None` = no quota.
fn cgroup_cpus() -> Option<usize> {
    let read = |p: &std::path::Path| std::fs::read_to_string(p).ok();
    let quota = |text: &str| -> Option<f64> {
        let mut it = text.split_whitespace();
        let (q, p) = (it.next()?, it.next().unwrap_or("100000"));
        let (q, p) = (q.parse::<f64>().ok()?, p.parse::<f64>().ok()?);
        (q > 0.0 && p > 0.0).then_some(q / p)
    };
    let mut best: Option<f64> = None;
    let mut take = |v: Option<f64>| {
        if let Some(v) = v {
            best = Some(best.map_or(v, |b| b.min(v)));
        }
    };
    let root = std::path::Path::new("/sys/fs/cgroup");
    let own = read(std::path::Path::new("/proc/self/cgroup")).and_then(|c| {
        c.lines()
            .find_map(|l| l.strip_prefix("0::").map(|p| p.trim().to_string()))
    });
    if let Some(path) = own {
        let mut dir = root.join(path.trim_start_matches('/'));
        loop {
            take(read(&dir.join("cpu.max")).and_then(|t| quota(&t)));
            if dir == root || !dir.pop() {
                break;
            }
        }
    }
    // cgroup v1
    if let (Some(q), Some(p)) = (
        read(&root.join("cpu/cpu.cfs_quota_us")),
        read(&root.join("cpu/cpu.cfs_period_us")),
    ) {
        take(quota(&format!("{} {}", q.trim(), p.trim())));
    }
    best.map(|c| c.ceil() as usize)
}

fn run(s: Settings) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = store::Store::open(Some(&s.data))
        .map_err(|e| format!("database in {}: {e}", s.data.display()))?;
    if let Some(i) = std::env::args().position(|a| a == "--backup") {
        let out = std::env::args()
            .nth(i + 1)
            .ok_or("--backup needs an output file")?;
        store.backup_to(std::path::Path::new(&out))?;
        log::info!("backup written to {out}");
        return Ok(());
    }
    if blocklist_cli(&mut store)? || delete_accounts_cli(&mut store)? {
        return Ok(());
    }
    let (key, key_from) = truth::load_key(&s.data)?;
    let truth_cfg = truth::TruthConfig::from_env(Some(key))?;
    let public = truth_cfg.key.as_ref().map(|k| k.public());
    if truth_cfg.is_official() {
        log::info!(
            "OFFICIAL server: signing key {} from {key_from}",
            public.map(|k| k.fingerprint()).unwrap_or_default()
        );
    } else {
        log::info!(
            "community server: signing key {} from {key_from}; official feed from {}",
            public.map(|k| k.fingerprint()).unwrap_or_default(),
            truth_cfg.official_url.as_deref().unwrap_or("nowhere (off)")
        );
    }
    if public.is_some_and(|k| k.hex() == rugen_fair::trust::DEV_PUBLIC_KEY) {
        log::warn!(
            "signing with the PUBLIC development key: anybody can forge this server's signatures (local testing only)"
        );
    }
    if truth_cfg.admin_token.is_some() {
        log::info!("admin api enabled (/v1/admin/*)");
    }
    log::info!(
        "schema v{}, {} accounts, {}, data in {}",
        store.schema_version()?,
        store.account_count()?,
        store.season()?.name.to_lowercase(),
        s.data.display()
    );
    let relay = Arc::new(relay::Relay::default());
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
        truth: truth_cfg,
        turn: turn::TurnConfig::from_env(),
        high_ping_ms: env_f("RUGEN_HIGH_PING_MS").map_or(0, |v| v.max(1.0) as u32),
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
        relay.set_udp(socket.clone());
        let r = relay.clone();
        std::thread::spawn(move || {
            if let Err(e) = udp::serve(socket, r) {
                log::error!("udp: {e}");
            }
        });
    } else {
        log::info!(
            "udp relay off: nothing bound or advertised, matches relay over the /relay WebSocket only"
        );
    }
    if let Some(u) = &s.public_url {
        log::info!("public url {u}");
    }
    let api = api::Api::new(store, cfg, relay);
    api.sweep_packages();
    match &api.turn {
        Some(t) => t.log_startup(&api.store_lock()),
        None => log::info!("turn: off (set RUGEN_CF_TURN_KEY_ID + RUGEN_CF_TURN_TOKEN)"),
    }
    let workers = worker_threads();
    log::info!(
        "{workers} worker threads; limits {:?}",
        http::Limits::from_env()
    );
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .max_blocking_threads(32)
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(s.bind.as_str())
            .await
            .map_err(|e| format!("bind {}: {e}", s.bind))?;
        log::info!("http + websocket on {}", listener.local_addr()?);
        // relay sessions: idle ones expire (whether UDP is on or not)
        let r = api.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(Duration::from_secs(5));
            loop {
                every.tick().await;
                r.sweep_relay();
                // flee / disconnect claims the relay can confirm
                let a = r.clone();
                let _ = tokio::task::spawn_blocking(move || a.sweep_claims()).await;
            }
        });
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
        // community servers: keep the official feed fresh
        if api.truth.cfg.official_url.is_some() {
            let puller = api.clone();
            let every = Duration::from_secs(api.truth.cfg.pull_secs);
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(every);
                loop {
                    tick.tick().await;
                    let a = puller.clone();
                    match tokio::task::spawn_blocking(move || a.pull_official()).await {
                        Ok(Ok(f)) => log::info!(
                            "official feed #{}: {} blocked, {} ratings",
                            f.sequence,
                            f.blocked.len(),
                            f.ratings.len()
                        ),
                        Ok(Err(e)) => log::warn!("official feed: {e}"),
                        Err(e) => log::error!("official feed task: {e}"),
                    }
                }
            });
        }
        // TURN credentials: settle, revoke, enforce ceilings
        if api.turn.is_some() {
            let t = api.clone();
            tokio::spawn(async move {
                let mut every = tokio::time::interval(Duration::from_secs(10));
                loop {
                    every.tick().await;
                    let a = t.clone();
                    let _ = tokio::task::spawn_blocking(move || a.sweep_turn()).await;
                }
            });
        }
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

    #[test]
    fn worker_threads_respect_the_override_and_the_cores() {
        let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
        let n = worker_threads();
        assert!(n >= 2 && n <= cores.max(2));
        if let Some(q) = cgroup_cpus() {
            assert!(n <= q.max(2));
        }
    }
}
