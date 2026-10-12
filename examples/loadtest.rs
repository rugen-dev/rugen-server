//! Load generator for `rugen-server`: N concurrent casual matches without the
//! game. Each match is two fresh `loadtest-…` accounts doing what the real
//! client does (register → name → private room + join → pick KFM / stage →
//! accept → ready → relay ticket), then both players open the `/relay`
//! WebSocket and send ggrs-shaped traffic at 60 fps until the test ends.
//!
//! Traffic per player and direction (ggrs 0.11 + rugen defaults, bincode 1
//! sizes, each prefixed by the 1-byte rugen payload type and framed with the
//! 25-byte relay client header):
//!
//! ```text
//! Input          60/s  54 B payload (41 B struct + ~12 B RLE'd pending inputs)
//! InputAck       60/s  11 B   (one per received Input, carries the acked frame)
//! QualityReport   5/s  25 B   (every 200 ms)
//! QualityReply    5/s  23 B   (answer to the peer's report)
//! ChecksumReport  2/s  27 B   (desync detection every 30 frames)
//! HELLO keepalive every 5 s
//! ```
//!
//! The frame number of each Input is a sequence number; the peer's InputAck
//! echoes it, so relay RTT (player → server → peer → server → player) comes
//! from real-sized packets without extra echo traffic.
//!
//! Every rate-limited request (the server allows 120 per IP per 10 s, the
//! `/relay` upgrade included) goes through a client-side token bucket
//! (`--rate`, default 11.5/s) so a single-IP test does not trip the limiter.
//!
//! ```text
//! cargo run --release --example loadtest -- --server https://play.rugen.dev \
//!     --steps 5,20,50,100,200 --hold 60 --max-runtime 600 --out out.json
//! ```
//!
//! Stop rules (checked every second): p95 relay RTT over a 5 s window above
//! `--stop-rtt`, API / setup error rate or relay disconnects above
//! `--stop-err`, the client's own send loop below 90 % of 60 fps for 5 s, its
//! NIC above 90 % of `--uplink-bps` for 3 s, or `--max-runtime`. `--stop-rtt`
//! is absolute: from a far location set it to the 1-match baseline + margin.
//! At the end every match sends BYE and the host leaves its room.
//!
//! Package uploads (`--upload-fraction`) are refused unless the server is on
//! loopback: they exist to load a local test server only.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use rugen_proto::relay::{self as wire, Header, TOKEN_LEN};
use rugen_proto::{FighterDecl, SessionTicket};
use serde_json::{Value, json};
use tokio::sync::{oneshot, watch};
use tokio_tungstenite::tungstenite::Message;

const ENGINE: &str = "rugen 0.4.0";
const FRAME: Duration = Duration::from_micros(16_667);
const RING: usize = 1024;

// ---------------------------------------------------------------- arguments

#[derive(Clone, Debug)]
struct Args {
    server: String,
    steps: Vec<usize>,
    hold: u64,
    rate: f64,
    max_runtime: u64,
    kfm: PathBuf,
    stages: PathBuf,
    data: PathBuf,
    stage: String,
    upload_fraction: f64,
    upload_mb: u64,
    report: bool,
    out: Option<PathBuf>,
    timeline: Option<PathBuf>,
    input_bytes: usize,
    match_secs: u64,
    stop_rtt: u64,
    stop_err: f64,
    /// Measured uplink of this machine (bytes/s); 0 = no saturation rule.
    uplink: f64,
    work: PathBuf,
    /// Local server process to sample (CPU %, RSS) into the results.
    server_pid: Option<u32>,
}

const HELP: &str = "loadtest [--server URL] [--steps 5,20,50] [--hold 60] [--rate 11.5]
  [--max-runtime 600] [--kfm DIR] [--stages DIR] [--data DIR] [--stage training]
  [--upload-fraction 0.0 --upload-mb 50   (loopback servers only)]
  [--report] [--match-secs 0 (0 = until the test ends)] [--input-bytes 12]
  [--stop-rtt 250] [--stop-err 0.02] [--uplink-bps BYTES_PER_S] [--out FILE.json] [--timeline FILE.jsonl]
  [--work DIR] [--server-pid PID (local server: sample its CPU / RSS)]";

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
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Args {
        server: get("--server")
            .unwrap_or_else(|| "http://127.0.0.1:8080".into())
            .trim_end_matches('/')
            .to_string(),
        steps: get("--steps")
            .unwrap_or_else(|| "1".into())
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect(),
        hold: num("--hold", 60.0) as u64,
        rate: num("--rate", 11.5),
        max_runtime: num("--max-runtime", 600.0) as u64,
        kfm: get("--kfm")
            .map(PathBuf::from)
            .unwrap_or_else(|| here.join("../rugen/reference/mugen-1.1b1/chars/kfm")),
        stages: get("--stages")
            .map(PathBuf::from)
            .unwrap_or_else(|| here.join("../rugen/motif/stages")),
        data: get("--data")
            .map(PathBuf::from)
            .unwrap_or_else(|| here.join("../rugen/reference/mugen-1.1b1/data")),
        stage: get("--stage").unwrap_or_else(|| "training".into()),
        upload_fraction: num("--upload-fraction", 0.0),
        upload_mb: num("--upload-mb", 50.0) as u64,
        report: v.iter().any(|a| a == "--report"),
        out: get("--out").map(PathBuf::from),
        timeline: get("--timeline").map(PathBuf::from),
        input_bytes: num("--input-bytes", 12.0) as usize,
        match_secs: num("--match-secs", 0.0) as u64,
        stop_rtt: num("--stop-rtt", 250.0) as u64,
        stop_err: num("--stop-err", 0.02),
        uplink: num("--uplink-bps", 0.0),
        work: get("--work")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("rugen-loadtest")),
        server_pid: get("--server-pid").and_then(|x| x.parse().ok()),
    }
}

fn is_loopback(server: &str) -> bool {
    let host = rugen_net::online::url_host(server);
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

// ---------------------------------------------------------------- metrics

struct Hist(Vec<AtomicU64>);

impl Hist {
    const MAX: usize = 5000;
    fn new() -> Self {
        Self((0..=Self::MAX).map(|_| AtomicU64::new(0)).collect())
    }
    fn add(&self, ms: u64) {
        self.0[(ms as usize).min(Self::MAX)].fetch_add(1, Relaxed);
    }
    fn take(&self) -> Vec<u64> {
        self.0.iter().map(|b| b.swap(0, Relaxed)).collect()
    }
}

fn merge(a: &mut [u64], b: &[u64]) {
    for (x, y) in a.iter_mut().zip(b) {
        *x += y;
    }
}

fn pct(h: &[u64], p: f64) -> Option<u64> {
    let n: u64 = h.iter().sum();
    if n == 0 {
        return None;
    }
    let want = ((n as f64) * p).ceil().max(1.0) as u64;
    let mut acc = 0;
    for (ms, c) in h.iter().enumerate() {
        acc += c;
        if acc >= want {
            return Some(ms as u64);
        }
    }
    Some(Hist::MAX as u64)
}

fn pct_vec(v: &mut [u32], p: f64) -> Option<u32> {
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    let i = (((v.len() as f64) * p).ceil() as usize).clamp(1, v.len()) - 1;
    Some(v[i])
}

/// Counter slots.
mod c {
    pub const FRAMES_SENT: usize = 0;
    pub const BYTES_SENT: usize = 1;
    pub const FRAMES_RECV: usize = 2;
    pub const BYTES_RECV: usize = 3;
    pub const INPUTS_SENT: usize = 4;
    pub const INPUTS_RECV: usize = 5;
    pub const ACKS_RECV: usize = 6;
    pub const TICKS: usize = 7;
    pub const SLOW_SENDS: usize = 8;
    pub const RELAY_DROPS: usize = 9;
    pub const API_CALLS: usize = 10;
    pub const API_ERRORS: usize = 11;
    pub const API_429: usize = 12;
    pub const SETUP_FAIL: usize = 13;
    pub const MATCHES: usize = 14;
    pub const PLAYERS: usize = 15;
    pub const PEER_LOST: usize = 16;
    pub const UPLOAD_BYTES: usize = 17;
    pub const INPUT_GAPS: usize = 18;
    pub const N: usize = 19;
}

struct Ctr([AtomicU64; c::N]);

impl Ctr {
    fn add(&self, i: usize, v: u64) {
        self.0[i].fetch_add(v, Relaxed);
    }
    fn sub(&self, i: usize, v: u64) {
        self.0[i].fetch_sub(v, Relaxed);
    }
    fn get(&self, i: usize) -> u64 {
        self.0[i].load(Relaxed)
    }
    fn snap(&self) -> [u64; c::N] {
        std::array::from_fn(|i| self.get(i))
    }
}

struct ApiSample {
    step: usize,
    name: &'static str,
    ms: u32,
    status: u16,
}

#[derive(Default, Clone, Copy)]
struct Nic {
    rx: u64,
    tx: u64,
}

/// Bytes of the machine's real interfaces (no loopback / bridges).
fn nic() -> Nic {
    let text = std::fs::read_to_string("/proc/net/dev").unwrap_or_default();
    let mut n = Nic::default();
    for line in text.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if [
            "lo",
            "docker",
            "veth",
            "br-",
            "virbr",
            "tailscale",
            "podman",
        ]
        .iter()
        .any(|p| name.starts_with(p))
        {
            continue;
        }
        let f: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|x| x.parse().ok())
            .collect();
        if f.len() >= 9 {
            n.rx += f[0];
            n.tx += f[8];
        }
    }
    n
}

/// CPU seconds this process used.
fn cpu_secs() -> f64 {
    let s = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let after = s.rsplit_once(')').map(|x| x.1).unwrap_or("");
    let f: Vec<&str> = after.split_whitespace().collect();
    let t = |i: usize| f.get(i).and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0);
    // fields 14 / 15 of stat; index 11 / 12 after the ')' split
    (t(11) + t(12)) / 100.0
}

/// CPU seconds (user + system) of another local process.
fn proc_cpu_secs(pid: Option<u32>) -> f64 {
    let Some(pid) = pid else { return 0.0 };
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let after = s.rsplit_once(')').map(|x| x.1).unwrap_or("");
    let f: Vec<&str> = after.split_whitespace().collect();
    let t = |i: usize| f.get(i).and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0);
    (t(11) + t(12)) / 100.0
}

/// Resident memory of another local process, MB.
fn proc_rss_mb(pid: Option<u32>) -> f64 {
    let Some(pid) = pid else { return 0.0 };
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next()?.parse::<f64>().ok())
        .map_or(0.0, |kb| kb / 1024.0)
}

// ---------------------------------------------------------------- context

struct Ctx {
    a: Args,
    http: reqwest::Client,
    relay_url: String,
    bucket: Mutex<Instant>,
    ctr: Ctr,
    rtt_step: Hist,
    rtt_sec: Hist,
    api: Mutex<Vec<ApiSample>>,
    health: Mutex<Vec<(usize, u32, Value)>>,
    step: AtomicUsize,
    kfm: FighterDecl,
    stage: FighterDecl,
    run: String,
    /// Packages we may upload (loopback only): fingerprint → file.
    pkgs: Mutex<HashMap<String, PathBuf>>,
    /// Rooms to leave at the end: code → host key.
    rooms: Mutex<HashMap<String, String>>,
    abort: Mutex<Option<String>>,
    /// Relay transport kinds seen in tickets (API 4 `transports`).
    transports: Mutex<HashMap<String, usize>>,
    started: Instant,
}

type Res<T> = Result<T, String>;

impl Ctx {
    async fn throttle(&self) {
        let slot = {
            let mut next = self.bucket.lock().unwrap();
            let now = Instant::now();
            let s = (*next).max(now);
            *next = s + Duration::from_secs_f64(1.0 / self.a.rate);
            s
        };
        tokio::time::sleep_until(slot.into()).await;
    }

    async fn api(
        &self,
        name: &'static str,
        get: bool,
        path: &str,
        body: Option<Value>,
    ) -> Res<Value> {
        self.throttle().await;
        let url = format!("{}{path}", self.a.server);
        let t = Instant::now();
        let rb = if get {
            self.http.get(&url)
        } else {
            self.http.post(&url).json(&body.unwrap_or(json!({})))
        };
        let res = rb.send().await;
        let (status, out) = match res {
            Ok(r) => {
                let st = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                if st == 200 {
                    (st, Ok(v))
                } else {
                    let e = v
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    (st, Err(format!("{name}: http {st} {e}")))
                }
            }
            Err(e) => (0, Err(format!("{name}: {e}"))),
        };
        let ms = t.elapsed().as_millis() as u32;
        self.ctr.add(c::API_CALLS, 1);
        if out.is_err() {
            self.ctr.add(c::API_ERRORS, 1);
            if status == 429 {
                self.ctr.add(c::API_429, 1);
            }
        }
        self.api.lock().unwrap().push(ApiSample {
            step: self.step.load(Relaxed),
            name,
            ms,
            status,
        });
        out
    }

    fn aborted(&self) -> Option<String> {
        self.abort.lock().unwrap().clone()
    }

    fn set_abort(&self, why: String) {
        let mut a = self.abort.lock().unwrap();
        if a.is_none() {
            eprintln!("STOP: {why}");
            *a = Some(why);
        }
    }
}

// ---------------------------------------------------------------- content

/// Declarations (and package files) of KFM and the stage, computed exactly
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

/// A KFM variant with `mb` MB of incompressible padding in its sprites: a
/// new fingerprint the server must receive as an upload.
fn upload_variant(a: &Args, n: usize) -> Res<(FighterDecl, PathBuf)> {
    let root = a.work.join(format!("variant-{n}"));
    let _ = std::fs::remove_dir_all(&root);
    let dir = root.join(format!("chars/kfm_lt{n}"));
    copy_dir(&a.kfm, &dir).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(root.join("stages")).map_err(|e| e.to_string())?;
    copy_dir(&a.data, &root.join("data")).map_err(|e| e.to_string())?;
    let cns = dir.join("kfm.cns");
    let mut t = std::fs::read_to_string(&cns).map_err(|e| e.to_string())?;
    t.push_str(&format!("\n; loadtest variant {n}\n"));
    std::fs::write(&cns, t).map_err(|e| e.to_string())?;
    let mut sff = std::fs::read(dir.join("kfm.sff")).map_err(|e| e.to_string())?;
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15 ^ n as u64;
    for _ in 0..(a.upload_mb << 20) / 8 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        sff.extend_from_slice(&x.to_le_bytes());
    }
    std::fs::write(dir.join("kfm.sff"), sff).map_err(|e| e.to_string())?;
    let lib = rugen_content::Library::discover(Some(&root));
    let e = lib
        .find_char(&format!("kfm_lt{n}"))
        .ok_or("variant not found")?;
    let (d, m) = lib.prepare_char(&e).map_err(|e| e.to_string())?;
    let p = lib.package(&d, &m).map_err(|e| e.to_string())?;
    let decl = lib.declare(&d, &m).ok_or("variant: no declaration")?;
    Ok((decl, p))
}

fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for e in std::fs::read_dir(src)?.flatten() {
        let to = dst.join(e.file_name());
        if e.path().is_dir() {
            copy_dir(&e.path(), &to)?;
        } else {
            std::fs::copy(e.path(), &to)?;
        }
    }
    Ok(())
}

async fn upload(ctx: &Ctx, key: &str, fp: &str) -> Res<()> {
    let path = ctx
        .pkgs
        .lock()
        .unwrap()
        .get(fp)
        .cloned()
        .ok_or_else(|| format!("server lacks {fp} and we do not hold it"))?;
    let data = std::fs::read(&path).map_err(|e| e.to_string())?;
    let total = data.len();
    let mut off = 0usize;
    while off < total {
        let end = (off + (2 << 20)).min(total);
        let url = format!(
            "{}/pkg/{fp}/upload?key={key}&offset={off}&total={total}",
            ctx.a.server
        );
        let t = Instant::now();
        let r = ctx
            .http
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(data[off..end].to_vec())
            .timeout(Duration::from_secs(120))
            .send()
            .await
            .map_err(|e| format!("upload: {e}"))?;
        let st = r.status().as_u16();
        ctx.api.lock().unwrap().push(ApiSample {
            step: ctx.step.load(Relaxed),
            name: "upload_chunk",
            ms: t.elapsed().as_millis() as u32,
            status: st,
        });
        if st != 200 {
            return Err(format!(
                "upload: http {st} {}",
                r.text().await.unwrap_or_default()
            ));
        }
        ctx.ctr.add(c::UPLOAD_BYTES, (end - off) as u64);
        off = end;
    }
    Ok(())
}

// ---------------------------------------------------------------- one match

struct Setup {
    code: String,
    keys: [String; 2],
    ids: [u64; 2],
    match_id: u64,
    tickets: [SessionTicket; 2],
}

fn ticket_of(v: &Value) -> Option<SessionTicket> {
    serde_json::from_value(v.get("ticket")?.clone()).ok()
}

async fn setup(ctx: &Ctx, n: usize) -> Res<Setup> {
    // the challenger may bring a fresh 50 MB fighter (loopback only)
    let brings_new = ctx.a.upload_fraction > 0.0
        && ((n as f64 * ctx.a.upload_fraction).floor()
            != ((n as f64 - 1.0) * ctx.a.upload_fraction).floor());
    let fighter_b = if brings_new {
        let (a, n2) = (ctx.a.clone(), n);
        let (d, p) = tokio::task::spawn_blocking(move || upload_variant(&a, n2))
            .await
            .map_err(|e| e.to_string())??;
        ctx.pkgs.lock().unwrap().insert(d.fingerprint.clone(), p);
        d
    } else {
        ctx.kfm.clone()
    };
    let mut keys = Vec::new();
    let mut ids = Vec::new();
    for side in ["a", "b"] {
        let r = ctx.api("register", false, "/register", None).await?;
        let key = r["key"].as_str().ok_or("register: no key")?.to_string();
        ids.push(r["id"].as_u64().unwrap_or(0));
        let name = format!("loadtest-{}-{n}{side}", ctx.run);
        ctx.api(
            "profile",
            false,
            "/profile",
            Some(json!({"key": key, "name": name})),
        )
        .await?;
        keys.push(key);
    }
    let (ka, kb) = (keys[0].clone(), keys[1].clone());
    let room = ctx
        .api(
            "room_create",
            false,
            "/room",
            Some(json!({"key": ka, "char": "kfm", "name": format!("LOADTEST {}", ctx.run), "public": false})),
        )
        .await?;
    let code = room["code"].as_str().ok_or("room: no code")?.to_string();
    ctx.rooms.lock().unwrap().insert(code.clone(), ka.clone());
    let joined = ctx
        .api(
            "room_join",
            false,
            &format!("/room/{code}/join"),
            Some(json!({"key": kb, "char": "kfm"})),
        )
        .await?;
    let id = joined["matchup"]["id"].as_u64().ok_or("join: no matchup")?;
    ctx.api(
        "pick",
        false,
        &format!("/matchup/{id}/pick"),
        Some(json!({"key": ka, "fighter": ctx.kfm, "stage": ctx.stage})),
    )
    .await?;
    let v = ctx
        .api(
            "pick",
            false,
            &format!("/matchup/{id}/pick"),
            Some(json!({"key": kb, "fighter": fighter_b})),
        )
        .await?;
    let kind = v["verdict"]["kind"]
        .as_str()
        .unwrap_or("")
        .to_ascii_lowercase();
    if kind == "blocked" {
        return Err(format!("verdict blocked: {}", v["verdict"]));
    }
    let unbalanced = kind == "unbalanced";
    let mut view = Value::Null;
    for k in [&ka, &kb] {
        view = ctx
            .api(
                "accept",
                false,
                &format!("/matchup/{id}/accept"),
                Some(json!({"key": k, "unbalanced": unbalanced})),
            )
            .await?;
    }
    if view["phase"] == "failed" {
        return Err(format!("matchup failed: {}", view["error"]));
    }
    let missing: Vec<String> = view["missing"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if !missing.is_empty() {
        if !is_loopback(&ctx.a.server) {
            return Err(format!(
                "server lacks {missing:?}; uploads are disabled here"
            ));
        }
        for fp in &missing {
            // the server takes a package only from a player who picked it
            let k = if *fp == fighter_b.fingerprint && *fp != ctx.kfm.fingerprint {
                &kb
            } else {
                &ka
            };
            upload(ctx, k, fp).await?;
        }
        let t = Instant::now();
        loop {
            view = ctx
                .api(
                    "matchup_poll",
                    true,
                    &format!("/matchup/{id}?key={ka}"),
                    None,
                )
                .await?;
            if view["missing"].as_array().is_some_and(|m| m.is_empty()) && view["phase"] == "sync" {
                break;
            }
            if view["phase"] == "failed" || t.elapsed() > Duration::from_secs(120) {
                return Err(format!("sync: {}", view["error"]));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    let rules = view["rules"].clone();
    let report = json!({
        "p1": ctx.kfm.fingerprint, "p2": fighter_b.fingerprint, "stage": ctx.stage.fingerprint,
        "engine": ENGINE, "rules": rules,
    });
    ctx.api(
        "ready",
        false,
        &format!("/matchup/{id}/ready"),
        Some(json!({"key": ka, "ready": report})),
    )
    .await?;
    let vb = ctx
        .api(
            "ready",
            false,
            &format!("/matchup/{id}/ready"),
            Some(json!({"key": kb, "ready": report})),
        )
        .await?;
    let mut tb = ticket_of(&vb);
    let mut ta = None;
    for _ in 0..10 {
        if ta.is_none() {
            let v = ctx
                .api(
                    "matchup_poll",
                    true,
                    &format!("/matchup/{id}?key={ka}"),
                    None,
                )
                .await?;
            if v["phase"] == "failed" {
                return Err(format!("matchup failed: {}", v["error"]));
            }
            ta = ticket_of(&v);
        }
        if tb.is_none() {
            let v = ctx
                .api(
                    "matchup_poll",
                    true,
                    &format!("/matchup/{id}?key={kb}"),
                    None,
                )
                .await?;
            tb = ticket_of(&v);
        }
        if ta.is_some() && tb.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let (Some(ta), Some(tb)) = (ta, tb) else {
        return Err("no relay ticket".into());
    };
    {
        let mut seen = ctx.transports.lock().unwrap();
        for t in [&ta, &tb] {
            let kinds: Vec<&str> = t.transports.iter().map(|x| x.kind.as_str()).collect();
            *seen
                .entry(if kinds.is_empty() {
                    "(none: legacy ticket)".into()
                } else {
                    kinds.join("+")
                })
                .or_default() += 1;
        }
    }
    Ok(Setup {
        code,
        keys: [ka, kb],
        ids: [ids[0], ids[1]],
        match_id: id,
        tickets: [ta, tb],
    })
}

async fn run_match(
    ctx: Arc<Ctx>,
    n: usize,
    up: oneshot::Sender<Res<()>>,
    stop: watch::Receiver<bool>,
) {
    let s = match setup(&ctx, n).await {
        Ok(s) => s,
        Err(e) => {
            ctx.ctr.add(c::SETUP_FAIL, 1);
            let _ = up.send(Err(e));
            return;
        }
    };
    let end =
        (ctx.a.match_secs > 0).then(|| Instant::now() + Duration::from_secs(ctx.a.match_secs));
    let mut handles = Vec::new();
    let mut conns = Vec::new();
    for (slot, t) in s.tickets.iter().enumerate() {
        let (tx, rx) = oneshot::channel();
        conns.push(rx);
        handles.push(tokio::spawn(player(
            ctx.clone(),
            t.clone(),
            slot as u8,
            tx,
            stop.clone(),
            end,
        )));
    }
    let mut ok = Ok(());
    for rx in conns {
        match rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => ok = Err(e),
            Err(_) => ok = Err("player task died".into()),
        }
    }
    let running = ok.is_ok();
    if running {
        ctx.ctr.add(c::MATCHES, 1);
    } else {
        ctx.ctr.add(c::SETUP_FAIL, 1);
    }
    let _ = up.send(ok);
    for h in handles {
        let _ = h.await;
    }
    if running {
        ctx.ctr.sub(c::MATCHES, 1);
    }
    if ctx.a.report && running {
        // like the client: both report the winner (P1 here), no input evidence
        for k in &s.keys {
            let _ = ctx
                .api(
                    "result",
                    false,
                    "/result",
                    Some(
                        json!({"key": k, "match_id": s.match_id, "winner": s.ids[0], "frames": 0}),
                    ),
                )
                .await;
        }
    }
    leave(&ctx, &s.code).await;
}

async fn leave(ctx: &Ctx, code: &str) {
    let key = ctx.rooms.lock().unwrap().get(code).cloned();
    if let Some(key) = key
        && ctx
            .api(
                "room_leave",
                false,
                &format!("/room/{code}/leave"),
                Some(json!({"key": key})),
            )
            .await
            .is_ok()
    {
        ctx.rooms.lock().unwrap().remove(code);
    }
}

// ---------------------------------------------------------------- one player

fn input_payload(seq: u32, ack: u32, extra: usize) -> Vec<u8> {
    let mut p = Vec::with_capacity(42 + extra);
    p.push(0); // T_GGRS
    p.extend_from_slice(&0x1234u16.to_le_bytes()); // header.magic
    p.extend_from_slice(&2u32.to_le_bytes()); // MessageBody::Input
    p.extend_from_slice(&2u64.to_le_bytes()); // peer_connect_status len
    for _ in 0..2 {
        p.push(0);
        p.extend_from_slice(&(seq as i32).to_le_bytes());
    }
    p.push(0); // disconnect_requested
    p.extend_from_slice(&seq.to_le_bytes()); // start_frame = our sequence
    p.extend_from_slice(&ack.to_le_bytes()); // ack_frame
    p.extend_from_slice(&(extra as u64).to_le_bytes());
    p.extend((0..extra).map(|i| (seq as usize ^ i) as u8));
    p
}
const SEQ_AT: usize = 1 + 2 + 4 + 8 + 10 + 1;

fn small_payload(tag: u32, body: &[u8]) -> Vec<u8> {
    let mut p = vec![0];
    p.extend_from_slice(&0x1234u16.to_le_bytes());
    p.extend_from_slice(&tag.to_le_bytes());
    p.extend_from_slice(body);
    p
}

async fn player(
    ctx: Arc<Ctx>,
    t: SessionTicket,
    slot: u8,
    connected: oneshot::Sender<Res<()>>,
    mut stop: watch::Receiver<bool>,
    end: Option<Instant>,
) {
    let token: [u8; TOKEN_LEN] =
        match rugen_proto::from_hex(&t.token).and_then(|v| v.try_into().ok()) {
            Some(t) => t,
            None => {
                let _ = connected.send(Err("bad token".into()));
                return;
            }
        };
    let peer = 1 - slot;
    let frame = |kind: u8, to: u8, p: &[u8]| {
        wire::encode_client(
            Header {
                kind,
                from: slot,
                to,
                session: t.session,
            },
            &token,
            p,
        )
    };
    ctx.throttle().await;
    let tc = Instant::now();
    let ws = tokio_tungstenite::connect_async_with_config(&ctx.relay_url, None, true).await;
    ctx.api.lock().unwrap().push(ApiSample {
        step: ctx.step.load(Relaxed),
        name: "relay_ws_connect",
        ms: tc.elapsed().as_millis() as u32,
        status: if ws.is_ok() { 101 } else { 0 },
    });
    ctx.ctr.add(c::API_CALLS, 1);
    let mut ws = match ws {
        Ok((ws, _)) => ws,
        Err(e) => {
            ctx.ctr.add(c::API_ERRORS, 1);
            let _ = connected.send(Err(format!("relay ws: {e}")));
            return;
        }
    };
    // HELLO until both slots are connected
    let t0 = Instant::now();
    let mut last_hello = t0 - Duration::from_secs(1);
    let mut mask = 0u8;
    while mask & 0b11 != 0b11 {
        if t0.elapsed() > Duration::from_secs(30) {
            let _ = connected.send(Err(format!("peer never connected (mask {mask:b})")));
            return;
        }
        if last_hello.elapsed() >= Duration::from_millis(500) {
            if ws
                .send(Message::Binary(frame(wire::HELLO, 0, &[]).into()))
                .await
                .is_err()
            {
                let _ = connected.send(Err("relay ws closed during hello".into()));
                return;
            }
            last_hello = Instant::now();
        }
        match tokio::time::timeout(Duration::from_millis(100), ws.next()).await {
            Ok(Some(Ok(Message::Binary(b)))) => {
                if let Some((h, p)) = wire::decode_server(&b)
                    && matches!(h.kind, wire::ACK | wire::PEERS)
                    && let Some(&m) = p.first()
                {
                    mask = m;
                }
            }
            Ok(Some(Ok(_))) | Err(_) => {}
            Ok(None) | Ok(Some(Err(_))) => {
                let _ = connected.send(Err("relay ws closed".into()));
                return;
            }
        }
    }
    let _ = connected.send(Ok(()));
    ctx.ctr.add(c::PLAYERS, 1);

    let mut tick = tokio::time::interval(FRAME);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut sent_at: Vec<Option<Instant>> = vec![None; RING];
    let mut seq: u32 = 0;
    let mut peer_seq: u32 = 0;
    let mut last_qr = Instant::now();
    let mut last_hello = Instant::now();
    let end_sleep = tokio::time::sleep_until(
        end.unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400))
            .into(),
    );
    tokio::pin!(end_sleep);
    let mut outq: Vec<Vec<u8>> = Vec::with_capacity(4);
    let mut dropped = false;
    loop {
        tokio::select! {
            _ = tick.tick() => {
                seq = seq.wrapping_add(1);
                outq.push(frame(wire::DATA, peer, &input_payload(seq, peer_seq, ctx.a.input_bytes)));
                sent_at[seq as usize % RING] = Some(Instant::now());
                ctx.ctr.add(c::INPUTS_SENT, 1);
                ctx.ctr.add(c::TICKS, 1);
                if seq % 30 == 0 {
                    let mut b = vec![0u8; 16];
                    b.extend_from_slice(&seq.to_le_bytes());
                    outq.push(frame(wire::DATA, peer, &small_payload(6, &b)));
                }
                if last_qr.elapsed() >= Duration::from_millis(200) {
                    last_qr = Instant::now();
                    outq.push(frame(wire::DATA, peer, &small_payload(4, &[0u8; 18])));
                }
                if last_hello.elapsed() >= Duration::from_secs(5) {
                    last_hello = Instant::now();
                    outq.push(frame(wire::HELLO, 0, &[]));
                }
            }
            m = ws.next() => {
                match m {
                    Some(Ok(Message::Binary(b))) => {
                        ctx.ctr.add(c::FRAMES_RECV, 1);
                        ctx.ctr.add(c::BYTES_RECV, b.len() as u64);
                        let Some((h, p)) = wire::decode_server(&b) else { continue };
                        if h.kind == wire::PEERS && p.first().is_some_and(|m| m & 0b11 != 0b11) {
                            ctx.ctr.add(c::PEER_LOST, 1);
                        }
                        if h.kind != wire::DATA || p.len() < 7 || p[0] != 0 {
                            continue;
                        }
                        let tag = u32::from_le_bytes([p[3], p[4], p[5], p[6]]);
                        match tag {
                            2 if p.len() >= SEQ_AT + 4 => {
                                ctx.ctr.add(c::INPUTS_RECV, 1);
                                let got = u32::from_le_bytes(p[SEQ_AT..SEQ_AT + 4].try_into().unwrap());
                                if peer_seq > 0 && got > peer_seq + 1 {
                                    ctx.ctr.add(c::INPUT_GAPS, (got - peer_seq - 1) as u64);
                                }
                                peer_seq = peer_seq.max(got);
                                outq.push(frame(wire::DATA, peer, &small_payload(3, &peer_seq.to_le_bytes())));
                            }
                            3 if p.len() >= 11 => {
                                let s = u32::from_le_bytes(p[7..11].try_into().unwrap());
                                if let Some(at) = sent_at[s as usize % RING].take()
                                    && seq.wrapping_sub(s) < RING as u32
                                {
                                    ctx.ctr.add(c::ACKS_RECV, 1);
                                    let ms = at.elapsed().as_millis() as u64;
                                    ctx.rtt_step.add(ms);
                                    ctx.rtt_sec.add(ms);
                                }
                            }
                            4 => outq.push(frame(wire::DATA, peer, &small_payload(5, &[0u8; 16]))),
                            _ => {}
                        }
                    }
                    Some(Ok(_)) => {}
                    None | Some(Err(_)) => {
                        dropped = true;
                        break;
                    }
                }
            }
            _ = stop.changed() => break,
            _ = &mut end_sleep => break,
        }
        if !outq.is_empty() {
            let ts = Instant::now();
            let mut failed = false;
            for f in outq.drain(..) {
                ctx.ctr.add(c::FRAMES_SENT, 1);
                ctx.ctr.add(c::BYTES_SENT, f.len() as u64);
                if ws.feed(Message::Binary(f.into())).await.is_err() {
                    failed = true;
                    break;
                }
            }
            if failed || ws.flush().await.is_err() {
                dropped = true;
                break;
            }
            if ts.elapsed() > Duration::from_millis(50) {
                ctx.ctr.add(c::SLOW_SENDS, 1);
            }
        }
    }
    if dropped && !*stop.borrow() {
        ctx.ctr.add(c::RELAY_DROPS, 1);
    }
    ctx.ctr.sub(c::PLAYERS, 1);
    let _ = ws
        .send(Message::Binary(frame(wire::BYE, 0, &[]).into()))
        .await;
    let _ = ws.close(None).await;
}

// ---------------------------------------------------------------- driver

#[derive(serde::Serialize, Default, Clone)]
struct StepResult {
    target: usize,
    matches: u64,
    players: u64,
    ramp_secs: f64,
    hold_secs: f64,
    frames_sent_per_s: f64,
    frames_recv_per_s: f64,
    app_up_bytes_per_player_s: f64,
    app_down_bytes_per_player_s: f64,
    nic_tx_bytes_s: f64,
    nic_rx_bytes_s: f64,
    nic_tx_per_player_s: f64,
    nic_rx_per_player_s: f64,
    rtt_samples: u64,
    rtt_p50: Option<u64>,
    rtt_p95: Option<u64>,
    rtt_p99: Option<u64>,
    rtt_max: Option<u64>,
    /// Inputs that never arrived (sequence gaps at the receiver).
    input_loss: f64,
    /// 1 - received / sent over the hold (includes packets in flight at its edges).
    input_loss_raw: f64,
    ack_loss: f64,
    send_rate_ratio: f64,
    slow_sends: u64,
    api_calls: usize,
    api_p50: Option<u32>,
    api_p95: Option<u32>,
    api_p99: Option<u32>,
    api_by_name: HashMap<String, (usize, Option<u32>, Option<u32>)>,
    api_errors: u64,
    api_429: u64,
    setup_failures: u64,
    relay_drops: u64,
    peer_lost: u64,
    client_cpu_pct: f64,
    health_p50: Option<u32>,
    health_p95: Option<u32>,
    health_matches_max: u64,
    health_online_max: u64,
    /// `--server-pid`: the server's CPU over the hold (100 = one core) and
    /// its resident memory at the end of the hold.
    server_cpu_pct: f64,
    server_rss_mb: f64,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let a = args();
    if a.upload_fraction > 0.0 && !is_loopback(&a.server) {
        eprintln!("--upload-fraction is only allowed against a loopback server");
        std::process::exit(2);
    }
    std::fs::create_dir_all(&a.work).unwrap();
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
    eprintln!(
        "kfm {} ({} B), stage {} {} ({} B)",
        kfm.fingerprint, kfm.size, a.stage, stage.fingerprint, stage.size
    );
    let mut run = [0u8; 3];
    let _ = getrandom::getrandom(&mut run);
    let ctx = Arc::new(Ctx {
        relay_url: rugen_net::relay::relay_ws_url(&a.server),
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .pool_max_idle_per_host(64)
            .user_agent("rugen-loadtest/0.3.0")
            .build()
            .unwrap(),
        bucket: Mutex::new(Instant::now()),
        ctr: Ctr(std::array::from_fn(|_| AtomicU64::new(0))),
        rtt_step: Hist::new(),
        rtt_sec: Hist::new(),
        api: Mutex::new(Vec::new()),
        health: Mutex::new(Vec::new()),
        step: AtomicUsize::new(0),
        pkgs: Mutex::new(HashMap::from([
            (kfm.fingerprint.clone(), kfm_pkg),
            (stage.fingerprint.clone(), stage_pkg),
        ])),
        kfm,
        stage,
        run: rugen_proto::to_hex(&run),
        rooms: Mutex::new(HashMap::new()),
        abort: Mutex::new(None),
        transports: Mutex::new(HashMap::new()),
        started: Instant::now(),
        a,
    });
    let info = ctx
        .http
        .get(format!("{}/health", ctx.a.server))
        .send()
        .await
        .and_then(|r| r.error_for_status());
    let info: Value = match info {
        Ok(r) => r.json().await.unwrap_or_default(),
        Err(e) => {
            eprintln!("server unreachable: {e}");
            std::process::exit(2)
        }
    };
    eprintln!("server: {info} run {}", ctx.run);

    // preflight: the server must already hold KFM + the stage (or we upload, loopback only)
    {
        let r = ctx
            .api("register", false, "/register", None)
            .await
            .unwrap_or_else(|e| {
                eprintln!("preflight: {e}");
                std::process::exit(2)
            });
        let key = r["key"].as_str().unwrap_or("").to_string();
        let _ = ctx
            .api(
                "profile",
                false,
                "/profile",
                Some(json!({"key": key, "name": format!("loadtest-{}-probe", ctx.run)})),
            )
            .await;
        for fp in [ctx.kfm.fingerprint.clone(), ctx.stage.fingerprint.clone()] {
            let st = ctx
                .api("pkg_status", true, &format!("/pkg/{fp}?key={key}"), None)
                .await
                .unwrap_or_default();
            let complete = st["complete"].as_bool().unwrap_or(false);
            eprintln!("package {fp}: complete={complete}");
            if !complete {
                if is_loopback(&ctx.a.server) {
                    eprintln!("the first matchup uploads it (loopback server)");
                } else {
                    eprintln!("the server lacks {fp}; uploads are disabled for remote servers");
                    std::process::exit(2);
                }
            }
        }
    }

    let (stop_tx, stop_rx) = watch::channel(false);

    // /health probe every 2 s (not rate limited on the server)
    {
        let ctx = ctx.clone();
        let mut stop = stop_rx.clone();
        tokio::spawn(async move {
            loop {
                let t = Instant::now();
                let r = ctx
                    .http
                    .get(format!("{}/health", ctx.a.server))
                    .timeout(Duration::from_secs(10))
                    .send()
                    .await;
                let v = match r {
                    Ok(r) => r.json::<Value>().await.unwrap_or_default(),
                    Err(_) => Value::Null,
                };
                ctx.health.lock().unwrap().push((
                    ctx.step.load(Relaxed),
                    t.elapsed().as_millis() as u32,
                    v,
                ));
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                    _ = stop.changed() => break,
                }
            }
        });
    }

    // per-second sampler: timeline + stop rules
    let hold_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let step_base = Arc::new(Mutex::new(ctx.ctr.snap()));
    {
        let ctx = ctx.clone();
        let hold_flag = hold_flag.clone();
        let step_base = step_base.clone();
        let mut stop = stop_rx.clone();
        tokio::spawn(async move {
            let mut tl = ctx
                .a
                .timeline
                .as_ref()
                .and_then(|p| std::fs::File::create(p).ok());
            let mut prev = ctx.ctr.snap();
            let mut prev_nic = nic();
            let mut prev_cpu = cpu_secs();
            let mut prev_server_cpu = proc_cpu_secs(ctx.a.server_pid);
            let mut window: Vec<Vec<u64>> = Vec::new();
            let mut slow = 0;
            let mut full = 0;
            let mut every = tokio::time::interval(Duration::from_secs(1));
            every.tick().await;
            loop {
                tokio::select! {
                    _ = every.tick() => {}
                    _ = stop.changed() => break,
                }
                let now = ctx.ctr.snap();
                let n = nic();
                let cpu = cpu_secs();
                let server_cpu = proc_cpu_secs(ctx.a.server_pid);
                let d = |i: usize| now[i].saturating_sub(prev[i]);
                let h = ctx.rtt_sec.take();
                window.push(h.clone());
                if window.len() > 5 {
                    window.remove(0);
                }
                let mut w = vec![0u64; Hist::MAX + 1];
                for x in &window {
                    merge(&mut w, x);
                }
                let players = now[c::PLAYERS];
                let expected = players * 60;
                let ratio = if expected > 0 {
                    d(c::TICKS) as f64 / expected as f64
                } else {
                    1.0
                };
                let health = ctx
                    .health
                    .lock()
                    .unwrap()
                    .last()
                    .map(|x| x.2.clone())
                    .unwrap_or_default();
                let line = json!({
                    "t": ctx.started.elapsed().as_secs_f64(),
                    "step": ctx.step.load(Relaxed),
                    "hold": hold_flag.load(Relaxed),
                    "matches": now[c::MATCHES], "players": players,
                    "frames_sent": d(c::FRAMES_SENT), "frames_recv": d(c::FRAMES_RECV),
                    "app_tx": d(c::BYTES_SENT), "app_rx": d(c::BYTES_RECV),
                    "nic_tx": n.tx.saturating_sub(prev_nic.tx), "nic_rx": n.rx.saturating_sub(prev_nic.rx),
                    "tick_ratio": ratio,
                    "rtt_p50": pct(&h, 0.5), "rtt_p95": pct(&h, 0.95), "rtt_p99": pct(&h, 0.99),
                    "api_calls": d(c::API_CALLS), "api_errors": d(c::API_ERRORS),
                    "drops": d(c::RELAY_DROPS), "slow_sends": d(c::SLOW_SENDS),
                    "cpu_pct": (cpu - prev_cpu) * 100.0,
                    "server_cpu_pct": (server_cpu - prev_server_cpu) * 100.0,
                    "server_rss_mb": proc_rss_mb(ctx.a.server_pid),
                    "health": health,
                });
                eprintln!(
                    "t={:>5.0}s step={} matches={:>3} players={:>3} tx={:>7.0}kB/s rx={:>7.0}kB/s nic_tx={:>7.0}kB/s rtt p50/p95={:?}/{:?} send={:.2} cpu={:.0}% api={}/{}err",
                    ctx.started.elapsed().as_secs_f64(),
                    ctx.step.load(Relaxed),
                    now[c::MATCHES],
                    players,
                    d(c::BYTES_SENT) as f64 / 1e3,
                    d(c::BYTES_RECV) as f64 / 1e3,
                    n.tx.saturating_sub(prev_nic.tx) as f64 / 1e3,
                    pct(&h, 0.5),
                    pct(&h, 0.95),
                    ratio,
                    (cpu - prev_cpu) * 100.0,
                    d(c::API_CALLS),
                    d(c::API_ERRORS),
                );
                if let Some(f) = tl.as_mut() {
                    use std::io::Write;
                    let _ = writeln!(f, "{line}");
                }
                // stop rules
                let wn: u64 = w.iter().sum();
                if wn >= 200
                    && let Some(p95) = pct(&w, 0.95)
                    && p95 > ctx.a.stop_rtt
                {
                    ctx.set_abort(format!(
                        "p95 relay RTT {p95} ms > {} ms (5 s window)",
                        ctx.a.stop_rtt
                    ));
                }
                let base = *step_base.lock().unwrap();
                let calls = now[c::API_CALLS] - base[c::API_CALLS];
                let errs = now[c::API_ERRORS] - base[c::API_ERRORS] + now[c::SETUP_FAIL]
                    - base[c::SETUP_FAIL];
                if calls >= 20 && errs as f64 / calls as f64 > ctx.a.stop_err {
                    ctx.set_abort(format!(
                        "API error rate {errs}/{calls} > {:.0}%",
                        ctx.a.stop_err * 100.0
                    ));
                }
                let drops = now[c::RELAY_DROPS] - base[c::RELAY_DROPS];
                if players >= 10 && drops as f64 / players as f64 > ctx.a.stop_err {
                    ctx.set_abort(format!("relay drops {drops} of {players} players"));
                }
                if players >= 10 && ratio < 0.9 {
                    slow += 1;
                    if slow >= 5 {
                        ctx.set_abort(format!(
                            "client send rate {:.0}% of target for 5 s (client saturated)",
                            ratio * 100.0
                        ));
                    }
                } else {
                    slow = 0;
                }
                let tx = n.tx.saturating_sub(prev_nic.tx) as f64;
                if ctx.a.uplink > 0.0 && tx > 0.9 * ctx.a.uplink {
                    full += 1;
                    if full >= 3 {
                        ctx.set_abort(format!(
                            "client uplink saturated: {:.0} kB/s of {:.0} kB/s for 3 s",
                            tx / 1e3,
                            ctx.a.uplink / 1e3
                        ));
                    }
                } else {
                    full = 0;
                }
                if ctx.started.elapsed().as_secs() > ctx.a.max_runtime {
                    ctx.set_abort("max runtime reached".into());
                }
                prev = now;
                prev_nic = n;
                prev_cpu = cpu;
                prev_server_cpu = server_cpu;
            }
        });
    }

    let mut results: Vec<StepResult> = Vec::new();
    let mut tasks = Vec::new();
    let mut spawned = 0usize;
    let mut stop_reason = None;
    let cost_per_match = 15.0;
    for (i, &target) in ctx.a.steps.clone().iter().enumerate() {
        ctx.step.store(i, Relaxed);
        *step_base.lock().unwrap() = ctx.ctr.snap();
        let running = ctx.ctr.get(c::MATCHES) as usize;
        let new = target.saturating_sub(running);
        // time budget: ramp + hold + leaving every room at the end
        let need =
            (new as f64 * cost_per_match + target as f64) / ctx.a.rate + ctx.a.hold as f64 + 10.0;
        let left = ctx.a.max_runtime as f64 - ctx.started.elapsed().as_secs_f64();
        if need > left {
            stop_reason = Some(format!(
                "time budget: step {target} needs ~{need:.0} s, {left:.0} s left"
            ));
            break;
        }
        eprintln!("== step {i}: {target} matches (+{new})");
        let t_ramp = Instant::now();
        let mut ups = Vec::new();
        for _ in 0..new {
            spawned += 1;
            let (tx, rx) = oneshot::channel();
            ups.push(rx);
            tasks.push(tokio::spawn(run_match(
                ctx.clone(),
                spawned,
                tx,
                stop_rx.clone(),
            )));
        }
        let mut failures = Vec::new();
        for mut rx in ups {
            if ctx.aborted().is_some() {
                break;
            }
            let res = loop {
                tokio::select! {
                    r = &mut rx => break r.unwrap_or(Err("match task died".into())),
                    _ = tokio::time::sleep(Duration::from_millis(250)) => {
                        if ctx.aborted().is_some() {
                            break Err("aborted".into());
                        }
                    }
                }
            };
            if let Err(e) = res {
                failures.push(e);
            }
        }
        for f in failures.iter().take(5) {
            eprintln!("setup failure: {f}");
        }
        let ramp_secs = t_ramp.elapsed().as_secs_f64();
        if let Some(why) = ctx.aborted() {
            stop_reason = Some(why);
            break;
        }
        // hold
        let s0 = ctx.ctr.snap();
        let n0 = nic();
        let c0 = cpu_secs();
        let sc0 = proc_cpu_secs(ctx.a.server_pid);
        let _ = ctx.rtt_step.take();
        let health_from = ctx.health.lock().unwrap().len();
        hold_flag.store(true, Relaxed);
        let th = Instant::now();
        while th.elapsed() < Duration::from_secs(ctx.a.hold) && ctx.aborted().is_none() {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        hold_flag.store(false, Relaxed);
        let secs = th.elapsed().as_secs_f64();
        let s1 = ctx.ctr.snap();
        let n1 = nic();
        let c1 = cpu_secs();
        let sc1 = proc_cpu_secs(ctx.a.server_pid);
        let h = ctx.rtt_step.take();
        let d = |k: usize| s1[k].saturating_sub(s0[k]) as f64;
        let players = s1[c::PLAYERS].max(1);
        let base = *step_base.lock().unwrap();
        let mut r = StepResult {
            target,
            matches: s1[c::MATCHES],
            players: s1[c::PLAYERS],
            ramp_secs,
            hold_secs: secs,
            frames_sent_per_s: d(c::FRAMES_SENT) / secs,
            frames_recv_per_s: d(c::FRAMES_RECV) / secs,
            app_up_bytes_per_player_s: d(c::BYTES_SENT) / secs / players as f64,
            app_down_bytes_per_player_s: d(c::BYTES_RECV) / secs / players as f64,
            nic_tx_bytes_s: n1.tx.saturating_sub(n0.tx) as f64 / secs,
            nic_rx_bytes_s: n1.rx.saturating_sub(n0.rx) as f64 / secs,
            rtt_samples: h.iter().sum(),
            rtt_p50: pct(&h, 0.5),
            rtt_p95: pct(&h, 0.95),
            rtt_p99: pct(&h, 0.99),
            rtt_max: h.iter().rposition(|&x| x > 0).map(|x| x as u64),
            input_loss: if d(c::INPUTS_RECV) + d(c::INPUT_GAPS) > 0.0 {
                d(c::INPUT_GAPS) / (d(c::INPUTS_RECV) + d(c::INPUT_GAPS))
            } else {
                0.0
            },
            input_loss_raw: if d(c::INPUTS_SENT) > 0.0 {
                (1.0 - d(c::INPUTS_RECV) / d(c::INPUTS_SENT)).max(0.0)
            } else {
                0.0
            },
            ack_loss: if d(c::INPUTS_SENT) > 0.0 {
                (1.0 - d(c::ACKS_RECV) / d(c::INPUTS_SENT)).max(0.0)
            } else {
                0.0
            },
            send_rate_ratio: d(c::TICKS) / secs / (players as f64 * 60.0),
            slow_sends: d(c::SLOW_SENDS) as u64,
            api_errors: s1[c::API_ERRORS] - base[c::API_ERRORS],
            api_429: s1[c::API_429] - base[c::API_429],
            setup_failures: s1[c::SETUP_FAIL] - base[c::SETUP_FAIL],
            relay_drops: s1[c::RELAY_DROPS] - base[c::RELAY_DROPS],
            peer_lost: s1[c::PEER_LOST] - base[c::PEER_LOST],
            client_cpu_pct: (c1 - c0) / secs * 100.0,
            server_cpu_pct: (sc1 - sc0) / secs * 100.0,
            server_rss_mb: proc_rss_mb(ctx.a.server_pid),
            ..Default::default()
        };
        r.nic_tx_per_player_s = r.nic_tx_bytes_s / players as f64;
        r.nic_rx_per_player_s = r.nic_rx_bytes_s / players as f64;
        {
            let api = ctx.api.lock().unwrap();
            let mut all: Vec<u32> = api.iter().filter(|x| x.step == i).map(|x| x.ms).collect();
            r.api_calls = all.len();
            r.api_p50 = pct_vec(&mut all, 0.5);
            r.api_p95 = pct_vec(&mut all, 0.95);
            r.api_p99 = pct_vec(&mut all, 0.99);
            let mut by: HashMap<&str, Vec<u32>> = HashMap::new();
            for x in api.iter().filter(|x| x.step == i) {
                by.entry(x.name).or_default().push(x.ms);
            }
            for (k, mut v) in by {
                let n = v.len();
                let p50 = pct_vec(&mut v, 0.5);
                let p95 = pct_vec(&mut v, 0.95);
                r.api_by_name.insert(k.to_string(), (n, p50, p95));
            }
            let mut st: HashMap<u16, usize> = HashMap::new();
            for x in api
                .iter()
                .filter(|x| x.step == i && x.status != 200 && x.status != 101)
            {
                *st.entry(x.status).or_default() += 1;
            }
            if !st.is_empty() {
                eprintln!("non-200 statuses in step {i}: {st:?}");
            }
        }
        {
            let hs = ctx.health.lock().unwrap();
            let mut lat: Vec<u32> = hs[health_from..].iter().map(|x| x.1).collect();
            r.health_p50 = pct_vec(&mut lat, 0.5);
            r.health_p95 = pct_vec(&mut lat, 0.95);
            r.health_matches_max = hs[health_from..]
                .iter()
                .filter_map(|x| x.2["matches"].as_u64())
                .max()
                .unwrap_or(0);
            r.health_online_max = hs[health_from..]
                .iter()
                .filter_map(|x| x.2["online"].as_u64())
                .max()
                .unwrap_or(0);
        }
        eprintln!(
            "== step {i} done: {} matches, rtt p50/p95/p99 {:?}/{:?}/{:?} ms, loss {:.4}, api p95 {:?} ms, up {:.0} B/s/player (app), nic tx {:.0} B/s/player, server cpu {:.0}% rss {:.0} MB",
            r.matches,
            r.rtt_p50,
            r.rtt_p95,
            r.rtt_p99,
            r.input_loss,
            r.api_p95,
            r.app_up_bytes_per_player_s,
            r.nic_tx_per_player_s,
            r.server_cpu_pct,
            r.server_rss_mb
        );
        results.push(r);
        if let Some(why) = ctx.aborted() {
            stop_reason = Some(why);
            break;
        }
    }
    if stop_reason.is_none() {
        stop_reason = ctx.aborted();
    }
    // end: every match leaves its room
    ctx.step.store(ctx.a.steps.len(), Relaxed);
    let t_end = Instant::now();
    let _ = stop_tx.send(true);
    for t in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(120), t).await;
    }
    let left: Vec<String> = ctx.rooms.lock().unwrap().keys().cloned().collect();
    for code in left {
        leave(&ctx, &code).await;
    }
    let remaining = ctx.rooms.lock().unwrap().len();
    let health: Value = match ctx
        .http
        .get(format!("{}/health", ctx.a.server))
        .send()
        .await
    {
        Ok(r) => r.json().await.unwrap_or_default(),
        Err(_) => Value::Null,
    };
    eprintln!(
        "cleanup in {:.0} s, rooms not left: {remaining}; server now {health}",
        t_end.elapsed().as_secs_f64()
    );
    let summary = json!({
        "server": ctx.a.server,
        "run": ctx.run,
        "kfm": ctx.kfm.fingerprint,
        "stage": ctx.stage.fingerprint,
        "stop_reason": stop_reason,
        "total_secs": ctx.started.elapsed().as_secs_f64(),
        "matches_spawned": spawned,
        "rooms_not_left": remaining,
        "upload_bytes": ctx.ctr.get(c::UPLOAD_BYTES),
        "api_calls_total": ctx.ctr.get(c::API_CALLS),
        "api_errors_total": ctx.ctr.get(c::API_ERRORS),
        "api_429_total": ctx.ctr.get(c::API_429),
        "ticket_transports": *ctx.transports.lock().unwrap(),
        "steps": results,
        "health_after": health,
    });
    println!("{}", serde_json::to_string_pretty(&summary).unwrap());
    if let Some(p) = &ctx.a.out {
        let _ = std::fs::write(p, serde_json::to_string_pretty(&summary).unwrap());
    }
}
