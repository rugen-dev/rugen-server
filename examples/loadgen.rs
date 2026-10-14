//! Lobby load generator for `rugen-server`: N concurrent simulated game
//! clients doing what the rugen 0.6 client does in the ONLINE menu, ramped
//! in steps until the server breaks. (`loadtest` measures the match relay
//! with real-sized ggrs traffic; this one measures the whole hub.)
//!
//! The clients are [`loadgen`] (`src/loadgen.rs`, shared with the
//! server's own `POST /admin/bench`); see there for the exact mix. This
//! binary adds the real KFM / stage packages (prepared like the client
//! does, uploaded once by two setup clients: loopback servers only),
//! samples a local server process (`--server-pid`) and prints one row per
//! step.
//!
//! ```text
//! cargo run --release --example loadgen -- --server http://127.0.0.1:8080 \
//!     --steps 250,500,1000,2000 --ramp 10 --hold 30 --server-pid PID
//! ```
//!
//! Per step: requests/s, latency p50/p95/p99 (all HTTP calls), errors,
//! relay packets and ack latency, server RSS / threads / CPU (from
//! `/proc/PID`). A step breaks the server when errors exceed `--max-err`
//! (1 %) or p99 exceeds `--max-p99` (500 ms), or the process died; the run
//! stops there. See docs/performance.md for the method and results.

#[path = "../src/loadgen.rs"]
mod loadgen;

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

use loadgen::{Load, Mix, proc_sample};
use rugen_proto::FighterDecl;
use serde_json::{Value, json};

type Res<T> = Result<T, String>;

// ---------------------------------------------------------------- arguments

#[derive(Clone, Debug)]
struct Args {
    server: String,
    steps: Vec<usize>,
    ramp: u64,
    hold: u64,
    engine: String,
    relay_share: f64,
    dispute_share: f64,
    public_share: f64,
    named_share: f64,
    dispute_frames: usize,
    kfm: PathBuf,
    stages: PathBuf,
    data: PathBuf,
    stage: String,
    work: PathBuf,
    server_pid: Option<u32>,
    max_err: f64,
    max_p99: u64,
    out: Option<PathBuf>,
    timeout: u64,
}

const HELP: &str = "loadgen [--server URL] [--steps 250,500,1000] [--ramp 10] [--hold 30]
  [--engine 0.6.1 (the server's SIM_ENGINE: disputes get re-simulated)]
  [--relay-share 0.3] [--dispute-share 0.1] [--public-share 0.25] [--named-share 0.02]
  [--dispute-frames 3600] [--kfm DIR] [--stages DIR] [--data DIR] [--stage training]
  [--work DIR] [--server-pid PID] [--max-err 0.01] [--max-p99 500] [--timeout 10]
  [--out FILE.jsonl]";

fn args() -> Args {
    let v: Vec<String> = std::env::args().skip(1).collect();
    if v.iter().any(|a| a == "-h" || a == "--help") {
        println!("{HELP}");
        std::process::exit(0);
    }
    let get = |k: &str| {
        v.iter()
            .position(|a| a == k)
            .and_then(|i| v.get(i + 1).cloned())
    };
    let num = |k: &str, d: f64| get(k).and_then(|x| x.parse::<f64>().ok()).unwrap_or(d);
    let engine_dir = std::env::var("RUGEN_ENGINE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rugen-engine"));
    let reference = engine_dir.join("reference/mugen-1.1b1");
    Args {
        server: get("--server")
            .unwrap_or_else(|| "http://127.0.0.1:8080".into())
            .trim_end_matches('/')
            .to_string(),
        steps: get("--steps")
            .unwrap_or_else(|| "100".into())
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect(),
        ramp: num("--ramp", 10.0) as u64,
        hold: num("--hold", 30.0) as u64,
        engine: get("--engine").unwrap_or_else(|| "0.6.1".into()),
        relay_share: num("--relay-share", 0.3),
        dispute_share: num("--dispute-share", 0.1),
        public_share: num("--public-share", 0.25),
        named_share: num("--named-share", 0.02),
        dispute_frames: num("--dispute-frames", 3600.0) as usize,
        kfm: get("--kfm")
            .map(PathBuf::from)
            .unwrap_or_else(|| reference.join("chars/kfm")),
        stages: get("--stages")
            .map(PathBuf::from)
            .unwrap_or_else(|| engine_dir.join("motif/stages")),
        data: get("--data")
            .map(PathBuf::from)
            .unwrap_or_else(|| reference.join("data")),
        stage: get("--stage").unwrap_or_else(|| "training".into()),
        work: get("--work")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("rugen-loadgen")),
        server_pid: get("--server-pid").and_then(|x| x.parse().ok()),
        max_err: num("--max-err", 0.01),
        max_p99: num("--max-p99", 500.0) as u64,
        out: get("--out").map(PathBuf::from),
        timeout: num("--timeout", 10.0) as u64,
    }
}

// ---------------------------------------------------------------- metrics

fn self_cpu_secs() -> f64 {
    proc_sample(None).cpu_secs
}

// ---------------------------------------------------------------- setup

fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let to = dst.join(e.file_name());
        if e.file_type()?.is_dir() {
            copy_dir(&e.path(), &to)?;
        } else {
            std::fs::copy(e.path(), to)?;
        }
    }
    Ok(())
}

/// Declarations and content files of KFM and the stage, prepared exactly
/// like the client (rugen-content prepare → package → declare).
fn declare_content(a: &Args) -> Res<(FighterDecl, PathBuf, FighterDecl, PathBuf)> {
    let root = a.work.join("library");
    let _ = std::fs::remove_dir_all(&root);
    copy_dir(&a.kfm, &root.join("chars/kfm")).map_err(|e| format!("kfm: {e}"))?;
    copy_dir(&a.stages, &root.join("stages")).map_err(|e| format!("stages: {e}"))?;
    copy_dir(&a.data, &root.join("data")).map_err(|e| format!("data: {e}"))?;
    let lib = rugen_content::Library::discover(Some(&root));
    let ch = lib.find_char("kfm").ok_or("kfm not found")?;
    let (cd, cm) = lib.prepare_char(&ch).map_err(|e| e.to_string())?;
    let cp = lib.package(&cd, &cm).map_err(|e| e.to_string())?;
    let kfm = lib.declare(&cd, &cm).ok_or("kfm: no declaration")?;
    let st = lib
        .stages()
        .into_iter()
        .find(|e| e.id.eq_ignore_ascii_case(&a.stage))
        .ok_or_else(|| format!("stage {} not found", a.stage))?;
    let (sd, sm) = lib.prepare_stage(&st).map_err(|e| e.to_string())?;
    let sp = lib.package(&sd, &sm).map_err(|e| e.to_string())?;
    let stage = lib.declare(&sd, &sm).ok_or("stage: no declaration")?;
    Ok((kfm, cp, stage, sp))
}

async fn upload(a: &Args, ip: &str, key: &str, fp: &str, path: &Path) -> Res<()> {
    let http = reqwest::Client::new();
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let total = data.len();
    let mut off = 0;
    while off < total {
        let end = (off + (1 << 20)).min(total);
        let url = format!(
            "{}/pkg/{fp}/upload?key={key}&offset={off}&total={total}",
            a.server
        );
        let r = http
            .post(&url)
            .header("cf-connecting-ip", ip)
            .header("x-rugen-api", rugen_proto::API_VERSION.to_string())
            .header("user-agent", format!("rugen/{}", a.engine))
            .header("content-type", "application/octet-stream")
            .body(data[off..end].to_vec())
            .timeout(Duration::from_secs(120))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !r.status().is_success() {
            return Err(format!(
                "upload {fp}: {} {}",
                r.status(),
                r.text().await.unwrap_or_default()
            ));
        }
        off = end;
    }
    Ok(())
}

/// Two setup clients play one room matchup up to `sync` so the server holds
/// the KFM and stage packages every later matchup uses.
async fn warm_up(a: &Args, load: &Load, mix: &Mix, kfm_pkg: &Path, stage_pkg: &Path) -> Res<()> {
    let (mut ca, mut cb) = (load.setup_client(1), load.setup_client(2));
    ca.register().await?;
    cb.register().await?;
    let (ka, kb) = (ca.key().to_string(), cb.key().to_string());
    let room = ca
        .call(
            "POST",
            "/room",
            Some(json!({"key": ka, "char": "kfm", "public": false})),
        )
        .await?;
    let code = room["code"].as_str().ok_or("no code")?.to_string();
    let joined = cb
        .call(
            "POST",
            &format!("/room/{code}/join"),
            Some(json!({"key": kb, "char": "kfm"})),
        )
        .await?;
    let id = joined["matchup"]["id"].as_u64().ok_or("join: no matchup")?;
    ca.call(
        "POST",
        &format!("/matchup/{id}/pick"),
        Some(json!({"key": ka, "fighter": mix.fighter, "stage": mix.stage})),
    )
    .await?;
    cb.call(
        "POST",
        &format!("/matchup/{id}/pick"),
        Some(json!({"key": kb, "fighter": mix.fighter})),
    )
    .await?;
    let mut view = Value::Null;
    for (c, k) in [(&mut ca, &ka), (&mut cb, &kb)] {
        view = c
            .call(
                "POST",
                &format!("/matchup/{id}/accept"),
                Some(json!({"key": k, "unbalanced": true})),
            )
            .await?;
    }
    for fp in view["missing"].as_array().cloned().unwrap_or_default() {
        let fp = fp.as_str().unwrap_or("");
        let path = if fp == mix.fighter.fingerprint {
            kfm_pkg
        } else {
            stage_pkg
        };
        upload(a, ca.ip(), &ka, fp, path).await?;
    }
    let t = Instant::now();
    loop {
        let v = ca
            .call("GET", &format!("/matchup/{id}?key={ka}"), None)
            .await?;
        if v["phase"] == "sync" || v["phase"] == "started" {
            break;
        }
        if t.elapsed() > Duration::from_secs(120) {
            return Err(format!("warm-up stuck: {v}"));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    for (c, k) in [(&mut ca, &ka), (&mut cb, &kb)] {
        let _ = c
            .call(
                "POST",
                &format!("/matchup/{id}/leave"),
                Some(json!({"key": k})),
            )
            .await;
    }
    let _ = ca
        .call(
            "POST",
            &format!("/room/{code}/leave"),
            Some(json!({"key": ka})),
        )
        .await;
    Ok(())
}

// ---------------------------------------------------------------- driver

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    let a = args();
    let (kfm, kfm_pkg, stage, stage_pkg) = {
        let a2 = a.clone();
        tokio::task::spawn_blocking(move || declare_content(&a2))
            .await
            .unwrap()
            .unwrap_or_else(|e| {
                eprintln!("content: {e}");
                std::process::exit(2)
            })
    };
    let host = a
        .server
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    let addr: SocketAddr = host
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
        .unwrap_or_else(|| {
            eprintln!("--server: an http://host:port address");
            std::process::exit(2)
        });
    let mut mix = Mix::new(&a.engine, kfm, stage);
    mix.relay_share = a.relay_share;
    mix.dispute_share = a.dispute_share;
    mix.public_share = a.public_share;
    mix.named_share = a.named_share;
    mix.dispute_frames = a.dispute_frames;
    mix.timeout = Duration::from_secs(a.timeout);
    let mut load = Load::new(addr, mix.clone());
    if let Err(e) = warm_up(&a, &load, &mix, &kfm_pkg, &stage_pkg).await {
        eprintln!("warm-up: {e}");
        std::process::exit(2);
    }
    load.take();
    // server sampler: peak threads / RSS
    let max_threads = Arc::new(AtomicU64::new(0));
    let max_rss_kb = Arc::new(AtomicU64::new(0));
    {
        let (t, r, pid) = (max_threads.clone(), max_rss_kb.clone(), a.server_pid);
        tokio::spawn(async move {
            loop {
                if pid.is_some() {
                    let s = proc_sample(pid);
                    t.fetch_max(s.threads, Relaxed);
                    r.fetch_max((s.rss_mb * 1024.0) as u64, Relaxed);
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });
    }
    let mut out = a.out.as_ref().map(|p| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .unwrap()
    });
    println!(
        "| clients | alive | ws | req/s | p50 ms | p95 ms | p99 ms | err % (net/5xx/429/4xx) | relay pkt/s | relay p99 ms | matches | disputes | srv CPU % | srv RSS MB | srv threads | gen CPU % |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|");
    for &target in &a.steps {
        load.grow(target, Duration::from_secs(a.ramp)).await;
        // settle, then measure
        tokio::time::sleep(Duration::from_secs(3)).await;
        load.take();
        max_threads.store(0, Relaxed);
        max_rss_kb.store(0, Relaxed);
        let p0 = proc_sample(a.server_pid);
        let g0 = self_cpu_secs();
        let t0 = Instant::now();
        let mut died = false;
        while t0.elapsed() < Duration::from_secs(a.hold) {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if a.server_pid.is_some() && !proc_sample(a.server_pid).alive {
                died = true;
                break;
            }
        }
        let secs = t0.elapsed().as_secs_f64();
        let p1 = proc_sample(a.server_pid);
        let g1 = self_cpu_secs();
        let r = load.take();
        let (alive, presence, relaying) = load.alive();
        let total = r.total();
        let err = r.err_rate();
        let (p50, p95, p99) = (r.pct(0.5), r.pct(0.95), r.pct(0.99));
        let cpu = if p1.alive {
            (p1.cpu_secs - p0.cpu_secs) / secs * 100.0
        } else {
            0.0
        };
        let rss = max_rss_kb.load(Relaxed) as f64 / 1024.0;
        let threads = max_threads.load(Relaxed);
        let gen_cpu = (g1 - g0) / secs * 100.0;
        println!(
            "| {target} | {alive} | {presence} | {:.0} | {p50:.1} | {p95:.1} | {p99:.1} | {:.2} ({}/{}/{}/{}) | {:.0} | {:.1} | {} | {} | {cpu:.0} | {rss:.0} | {threads} | {gen_cpu:.0} |",
            total as f64 / secs,
            err * 100.0,
            r.e_net,
            r.e_5xx,
            r.e_429,
            r.e_4xx,
            r.udp_sent as f64 / secs,
            r.relay_pct(0.99),
            r.matches,
            r.disputes,
        );
        if let Some(f) = out.as_mut() {
            use std::io::Write;
            let _ = writeln!(
                f,
                "{}",
                json!({
                    "clients": target, "alive": alive, "presence": presence, "secs": secs,
                    "requests": total, "rps": total as f64 / secs,
                    "p50_ms": p50, "p95_ms": p95, "p99_ms": p99, "max_ms": r.pct(1.0),
                    "err": err, "e_net": r.e_net, "e_5xx": r.e_5xx, "e_429": r.e_429, "e_4xx": r.e_4xx,
                    "udp_sent_ps": r.udp_sent as f64 / secs, "udp_recv_ps": r.udp_recv as f64 / secs,
                    "relay_p50_ms": r.relay_pct(0.5), "relay_p99_ms": r.relay_pct(0.99),
                    "relaying": relaying,
                    "matches": r.matches, "disputes": r.disputes, "matchup_fail": r.matchup_fail,
                    "ws_fail": r.ws_fail,
                    "srv_cpu_pct": cpu, "srv_rss_mb": rss, "srv_threads": threads, "gen_cpu_pct": gen_cpu,
                    "died": died,
                    "routes": r.by_route.iter().map(|(k, (n, sum, max))| (k.clone(), json!({
                        "calls": n, "mean_ms": *sum as f64 / 1000.0 / (*n).max(1) as f64, "max_ms": *max as f64 / 1000.0,
                    }))).collect::<serde_json::Map<String, Value>>(),
                })
            );
        }
        if died {
            println!("server process died at {target} clients");
            break;
        }
        if err > a.max_err || p99 > a.max_p99 as f64 {
            println!(
                "breaking point at {target} clients: err {:.2} %, p99 {p99:.0} ms",
                err * 100.0
            );
            break;
        }
    }
    load.stop(Duration::from_secs(20)).await;
}
