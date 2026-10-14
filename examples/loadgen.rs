//! Lobby load generator for `rugen-server`: N concurrent simulated game
//! clients doing what the rugen 0.6 client does in the ONLINE menu, ramped
//! in steps until the server breaks. (`loadtest` measures the match relay
//! with real-sized ggrs traffic; this one measures the whole hub.)
//!
//! Every client (rates from `rugen-app` `online.rs` / `matchup.rs` and
//! `rugen-net` `online.rs`):
//!
//! ```text
//! POST /register (or, --named-share, POST /v1/account/register: Argon2id)
//! POST /profile                           once
//! GET  /ws?key=                           presence WebSocket, kept open
//! loop:
//!   lobby       GET /rooms every 5 s (10 s)
//!   then one of
//!   60 % queue  POST /queue (half ranked), GET /queue?key= every 1 s
//!               found → GET /matchup/{id}?key= every 400 ms + pick /
//!               accept / ready → relay ticket → the match (20–40 s;
//!               --relay-share of matches over the UDP relay at 60 packets/s
//!               per player) → POST /result (both sides); --dispute-share of
//!               ranked matches are disputed with input evidence (resim)
//!   25 % host   POST /room (--public-share public), GET /room/{code} every
//!               1 s for 30 s, POST /room/{code}/leave
//!   15 % idle   another 10 s of lobby
//! ```
//!
//! Each client sends its own `CF-Connecting-IP` (as behind the Cloudflare
//! Tunnel) and binds its UDP socket to its own 127.x.y.z, so per-IP limits
//! apply per client as in production. Before the first step, two setup
//! clients upload the KFM and stage packages once (loopback servers only).
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
//! stops there.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use rugen_proto::relay::{self as wire, Header, TOKEN_LEN};
use rugen_proto::{FighterDecl, SessionTicket};
use serde_json::{Value, json};

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

#[derive(Default)]
struct Stats {
    /// Latency of every HTTP call this step, µs.
    lat: Mutex<Vec<u32>>,
    /// Per endpoint: (calls, total µs, max µs).
    by_route: Mutex<std::collections::BTreeMap<String, (u64, u64, u64)>>,
    ok: AtomicU64,
    /// Connect / timeout / reset.
    e_net: AtomicU64,
    e_5xx: AtomicU64,
    e_429: AtomicU64,
    e_4xx: AtomicU64,
    /// Relay ack latency (my input → the peer's next input acking it), µs.
    relay_lat: Mutex<Vec<u32>>,
    udp_sent: AtomicU64,
    udp_recv: AtomicU64,
    matches: AtomicU64,
    disputes: AtomicU64,
    matchup_fail: AtomicU64,
    ws_fail: AtomicU64,
}

impl Stats {
    fn reset(&self) -> StepRaw {
        StepRaw {
            lat: std::mem::take(&mut *self.lat.lock().unwrap()),
            by_route: std::mem::take(&mut *self.by_route.lock().unwrap()),
            relay_lat: std::mem::take(&mut *self.relay_lat.lock().unwrap()),
            ok: self.ok.swap(0, Relaxed),
            e_net: self.e_net.swap(0, Relaxed),
            e_5xx: self.e_5xx.swap(0, Relaxed),
            e_429: self.e_429.swap(0, Relaxed),
            e_4xx: self.e_4xx.swap(0, Relaxed),
            udp_sent: self.udp_sent.swap(0, Relaxed),
            udp_recv: self.udp_recv.swap(0, Relaxed),
            matches: self.matches.swap(0, Relaxed),
            disputes: self.disputes.swap(0, Relaxed),
            matchup_fail: self.matchup_fail.swap(0, Relaxed),
            ws_fail: self.ws_fail.swap(0, Relaxed),
        }
    }
}

struct StepRaw {
    lat: Vec<u32>,
    by_route: std::collections::BTreeMap<String, (u64, u64, u64)>,
    relay_lat: Vec<u32>,
    ok: u64,
    e_net: u64,
    e_5xx: u64,
    e_429: u64,
    e_4xx: u64,
    udp_sent: u64,
    udp_recv: u64,
    matches: u64,
    disputes: u64,
    matchup_fail: u64,
    ws_fail: u64,
}

/// `GET /matchup/123?key=…` → `GET /matchup/{}`.
fn route_name(method: &str, path: &str) -> String {
    let path = path.split('?').next().unwrap_or("");
    let parts: Vec<&str> = path
        .split('/')
        .map(|p| {
            if p.chars().any(|c| c.is_ascii_digit())
                || (p.len() >= 4 && p.chars().all(|c| c.is_ascii_uppercase()))
            {
                "{}"
            } else {
                p
            }
        })
        .collect();
    format!("{method} {}", parts.join("/"))
}

fn pct(v: &[u32], p: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    let i = ((v.len() as f64 - 1.0) * p).round() as usize;
    f64::from(v[i.min(v.len() - 1)]) / 1000.0
}

#[derive(Clone, Copy, Default)]
struct ProcSample {
    cpu_secs: f64,
    rss_mb: f64,
    threads: u64,
    alive: bool,
}

fn proc_sample(pid: Option<u32>) -> ProcSample {
    let Some(pid) = pid else {
        return ProcSample::default();
    };
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return ProcSample::default();
    };
    let after = stat.rsplit_once(')').map(|x| x.1).unwrap_or("");
    let f: Vec<&str> = after.split_whitespace().collect();
    let t = |i: usize| f.get(i).and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0);
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let field = |k: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(k))
            .and_then(|v| v.split_whitespace().next()?.parse::<f64>().ok())
            .unwrap_or(0.0)
    };
    ProcSample {
        cpu_secs: (t(11) + t(12)) / 100.0,
        rss_mb: field("VmRSS:") / 1024.0,
        threads: field("Threads:") as u64,
        alive: true,
    }
}

fn self_cpu_secs() -> f64 {
    let s = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let after = s.rsplit_once(')').map(|x| x.1).unwrap_or("");
    let f: Vec<&str> = after.split_whitespace().collect();
    let t = |i: usize| f.get(i).and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0);
    (t(11) + t(12)) / 100.0
}

// ---------------------------------------------------------------- context

struct Ctx {
    a: Args,
    http: reqwest::Client,
    stats: Stats,
    stop: AtomicBool,
    kfm: FighterDecl,
    stage: FighterDecl,
    /// Clients alive / with presence open / in a relayed match.
    alive: AtomicI64,
    presence: AtomicI64,
    relaying: AtomicI64,
    /// Max resident server threads / RSS seen this step.
    max_threads: AtomicU64,
    max_rss_kb: AtomicU64,
    inputs_hex: String,
}

type Res<T> = Result<T, String>;

/// A tiny xorshift per client (no rand dependency).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn chance(&mut self, p: f64) -> bool {
        (self.next() % 1_000_000) as f64 / 1_000_000.0 < p
    }
}

/// Whether match `id` falls in a `share` (both players agree on it).
fn share_of(id: u64, salt: u64, share: f64) -> bool {
    let h = (id ^ salt).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 40;
    (h % 10_000) as f64 / 10_000.0 < share
}

struct Client {
    ctx: Arc<Ctx>,
    n: usize,
    ip: String,
    key: String,
    id: u64,
    rng: Rng,
}

impl Client {
    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> Res<Value> {
        let ctx = &self.ctx;
        let url = format!("{}{path}", ctx.a.server);
        let rb = match method {
            "GET" => ctx.http.get(&url),
            "DELETE" => ctx.http.delete(&url),
            _ => ctx.http.post(&url),
        };
        let rb = rb
            .header("cf-connecting-ip", &self.ip)
            .header("x-rugen-api", rugen_proto::API_VERSION.to_string())
            .header("user-agent", format!("rugen/{}", ctx.a.engine));
        let rb = match body {
            Some(b) => rb.json(&b),
            None => rb,
        };
        let t = Instant::now();
        let res = rb.send().await;
        let out = match res {
            Ok(r) => {
                let st = r.status().as_u16();
                match r.bytes().await {
                    Ok(b) if st == 200 => {
                        ctx.stats.ok.fetch_add(1, Relaxed);
                        Ok(serde_json::from_slice(&b).unwrap_or(Value::Null))
                    }
                    Ok(b) => {
                        let c = match st {
                            429 => &ctx.stats.e_429,
                            500.. => &ctx.stats.e_5xx,
                            _ => &ctx.stats.e_4xx,
                        };
                        c.fetch_add(1, Relaxed);
                        Err(format!(
                            "{method} {path}: http {st} {}",
                            String::from_utf8_lossy(&b[..b.len().min(200)])
                        ))
                    }
                    Err(e) => {
                        ctx.stats.e_net.fetch_add(1, Relaxed);
                        Err(format!("{method} {path}: {e}"))
                    }
                }
            }
            Err(e) => {
                ctx.stats.e_net.fetch_add(1, Relaxed);
                Err(format!("{method} {path}: {e}"))
            }
        };
        let us = t.elapsed().as_micros().min(u32::MAX as u128) as u32;
        ctx.stats.lat.lock().unwrap().push(us);
        {
            let mut m = ctx.stats.by_route.lock().unwrap();
            let e = m.entry(route_name(method, path)).or_default();
            e.0 += 1;
            e.1 += u64::from(us);
            e.2 = e.2.max(u64::from(us));
        }
        out
    }

    fn stopped(&self) -> bool {
        self.ctx.stop.load(Relaxed)
    }

    /// Sleep unless the run stops; false when it did.
    async fn nap(&self, d: Duration) -> bool {
        let end = Instant::now() + d;
        while Instant::now() < end {
            if self.stopped() {
                return false;
            }
            tokio::time::sleep((end - Instant::now()).min(Duration::from_millis(500))).await;
        }
        !self.stopped()
    }

    async fn login(&mut self) -> Res<()> {
        let named = self.rng.chance(self.ctx.a.named_share);
        let r = if named {
            let user = format!("lg{}x{}", self.n, self.rng.below(1 << 30));
            let pw = format!("pw-{}-{}", self.n, self.rng.next());
            self.call(
                "POST",
                "/v1/account/register",
                Some(json!({"username": user, "password": pw})),
            )
            .await?
        } else {
            self.call("POST", "/register", None).await?
        };
        self.key = r["key"].as_str().ok_or("register: no key")?.to_string();
        self.id = r["id"].as_u64().unwrap_or(0);
        self.call(
            "POST",
            "/profile",
            Some(json!({"key": self.key, "name": format!("LG{}", self.n)})),
        )
        .await?;
        Ok(())
    }

    async fn lobby(&self, secs: u64) -> bool {
        let end = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < end {
            let _ = self.call("GET", "/rooms", None).await;
            if !self.nap(Duration::from_secs(5)).await {
                return false;
            }
        }
        true
    }

    async fn host_room(&mut self) {
        let public = self.rng.chance(self.ctx.a.public_share);
        let Ok(r) = self
            .call(
                "POST",
                "/room",
                Some(json!({"key": self.key, "char": "kfm", "name": format!("LG ROOM {}", self.n), "public": public})),
            )
            .await
        else {
            return;
        };
        let Some(code) = r["code"].as_str().map(str::to_string) else {
            return;
        };
        let secs = 20 + self.rng.below(20);
        for _ in 0..secs {
            if !self.nap(Duration::from_secs(1)).await {
                break;
            }
            let _ = self
                .call("GET", &format!("/room/{code}?key={}", self.key), None)
                .await;
        }
        let _ = self
            .call(
                "POST",
                &format!("/room/{code}/leave"),
                Some(json!({"key": self.key})),
            )
            .await;
    }

    async fn queue(&mut self) {
        let ranked = self.rng.chance(0.5);
        let Ok(mut st) = self
            .call(
                "POST",
                "/queue",
                Some(json!({"key": self.key, "char": "kfm", "ranked": ranked})),
            )
            .await
        else {
            return;
        };
        let t = Instant::now();
        while st["found"].is_null() {
            if t.elapsed() > Duration::from_secs(40) || !self.nap(Duration::from_secs(1)).await {
                let _ = self
                    .call("DELETE", "/queue", Some(json!({"key": self.key})))
                    .await;
                return;
            }
            match self
                .call("GET", &format!("/queue?key={}", self.key), None)
                .await
            {
                Ok(v) => st = v,
                Err(_) => continue,
            }
        }
        let found = st["found"].clone();
        let id = found["match_id"].as_u64().unwrap_or(0);
        let side = found["side"].as_u64().unwrap_or(0) as u8;
        let opp = found["opponent"]["id"].as_u64().unwrap_or(0);
        match self.matchup(id, side).await {
            Some(ticket) => self.play(id, side, opp, ranked, ticket).await,
            None => {
                self.ctx.stats.matchup_fail.fetch_add(1, Relaxed);
                let _ = self
                    .call(
                        "POST",
                        &format!("/matchup/{id}/leave"),
                        Some(json!({"key": self.key})),
                    )
                    .await;
            }
        }
    }

    /// The matchup phase as the client's matchup worker runs it: a poll
    /// every 400 ms and the next step whenever the view allows it.
    async fn matchup(&self, id: u64, side: u8) -> Option<SessionTicket> {
        let me = usize::from(side == 2);
        let t = Instant::now();
        let (mut picked, mut accepted, mut readied) = (false, false, false);
        while t.elapsed() < Duration::from_secs(40) {
            if !self.nap(Duration::from_millis(400)).await {
                return None;
            }
            let Ok(v) = self
                .call("GET", &format!("/matchup/{id}?key={}", self.key), None)
                .await
            else {
                continue;
            };
            if let Some(tk) = v.get("ticket").filter(|t| !t.is_null()) {
                return serde_json::from_value(tk.clone()).ok();
            }
            match v["phase"].as_str().unwrap_or("") {
                "pick" if !picked && v["fighters"][me].is_null() => {
                    let mut b = json!({"key": self.key, "fighter": self.ctx.kfm});
                    if side == 1 {
                        b["stage"] = json!(self.ctx.stage);
                    }
                    picked = self
                        .call("POST", &format!("/matchup/{id}/pick"), Some(b))
                        .await
                        .is_ok();
                }
                "confirm" if !accepted && v["accepted"][me] != true => {
                    let unbalanced = v["verdict"]["kind"]
                        .as_str()
                        .is_some_and(|k| k.eq_ignore_ascii_case("unbalanced"));
                    accepted = self
                        .call(
                            "POST",
                            &format!("/matchup/{id}/accept"),
                            Some(json!({"key": self.key, "unbalanced": unbalanced})),
                        )
                        .await
                        .is_ok();
                }
                "sync"
                    if !readied
                        && v["missing"].as_array().is_none_or(|m| m.is_empty())
                        && v["ready"][me] != true =>
                {
                    let report = json!({
                        "p1": v["fighters"][0]["decl"]["fingerprint"],
                        "p2": v["fighters"][1]["decl"]["fingerprint"],
                        "stage": v["stage"]["decl"]["fingerprint"],
                        "engine": format!("rugen {}", self.ctx.a.engine),
                        "rules": v["rules"],
                    });
                    match self
                        .call(
                            "POST",
                            &format!("/matchup/{id}/ready"),
                            Some(json!({"key": self.key, "ready": report})),
                        )
                        .await
                    {
                        Ok(r) => {
                            readied = true;
                            if let Some(tk) = r.get("ticket").filter(|t| !t.is_null()) {
                                return serde_json::from_value(tk.clone()).ok();
                            }
                        }
                        Err(e) => log::debug!("ready: {e}"),
                    }
                }
                "failed" => {
                    log::debug!("matchup {id} failed: {}", v["error"]);
                    return None;
                }
                _ => {}
            }
        }
        None
    }

    async fn play(&mut self, id: u64, side: u8, opp: u64, ranked: bool, t: SessionTicket) {
        self.ctx.stats.matches.fetch_add(1, Relaxed);
        let secs = 20 + (id % 21);
        if share_of(id, 1, self.ctx.a.relay_share) && t.udp.is_some() {
            self.ctx.relaying.fetch_add(1, Relaxed);
            relay(&self.ctx, self.n, &t, Duration::from_secs(secs)).await;
            self.ctx.relaying.fetch_sub(1, Relaxed);
        } else if !self.nap(Duration::from_secs(secs)).await {
            return;
        }
        let p1 = if side == 1 { self.id } else { opp };
        let body = if ranked && share_of(id, 2, self.ctx.a.dispute_share) {
            if side == 1 {
                self.ctx.stats.disputes.fetch_add(1, Relaxed);
            }
            // both claim the win, same inputs, different checksums
            json!({"key": self.key, "match_id": id, "winner": self.id,
                "frames": self.ctx.a.dispute_frames, "inputs": self.ctx.inputs_hex,
                "checksum": 1000 + u64::from(side)})
        } else {
            json!({"key": self.key, "match_id": id, "winner": p1, "frames": 60 * secs})
        };
        let _ = self.call("POST", "/result", Some(body)).await;
    }
}

/// Presence WebSocket, kept open with the client's reconnect backoff.
async fn presence(ctx: Arc<Ctx>, key: String, ip: String) {
    let ws = ctx.a.server.replacen("http", "ws", 1);
    let url = format!("{ws}/ws?key={key}");
    let mut backoff = Duration::from_secs(1);
    while !ctx.stop.load(Relaxed) {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut req = match url.as_str().into_client_request() {
            Ok(r) => r,
            Err(_) => return,
        };
        if let Ok(h) = ip.parse() {
            req.headers_mut().insert("cf-connecting-ip", h);
        }
        match tokio_tungstenite::connect_async(req).await {
            Ok((mut s, _)) => {
                backoff = Duration::from_secs(1);
                ctx.presence.fetch_add(1, Relaxed);
                loop {
                    match tokio::time::timeout(Duration::from_millis(500), s.next()).await {
                        Ok(Some(Ok(_))) => {}
                        Ok(_) => break,
                        Err(_) if ctx.stop.load(Relaxed) => break,
                        Err(_) => {}
                    }
                }
                ctx.presence.fetch_sub(1, Relaxed);
                let _ = s.close(None).await;
            }
            Err(_) => {
                ctx.stats.ws_fail.fetch_add(1, Relaxed);
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

/// ggrs-shaped Input of `seq` acking the peer's `ack` (54 B like the game).
fn input_payload(seq: u32, ack: u32) -> Vec<u8> {
    let mut p = Vec::with_capacity(54);
    p.push(0); // T_GGRS
    p.extend_from_slice(&0x1234u16.to_le_bytes());
    p.extend_from_slice(&2u32.to_le_bytes()); // MessageBody::Input
    p.extend_from_slice(&2u64.to_le_bytes());
    for _ in 0..2 {
        p.push(0);
        p.extend_from_slice(&(seq as i32).to_le_bytes());
    }
    p.push(0);
    p.extend_from_slice(&seq.to_le_bytes());
    p.extend_from_slice(&ack.to_le_bytes());
    p.extend_from_slice(&12u64.to_le_bytes());
    p.extend((0..12).map(|i| (seq as usize ^ i) as u8));
    p
}
const SEQ_AT: usize = 1 + 2 + 4 + 8 + 10 + 1;
const RING: usize = 512;

/// One player's side of a match over the UDP relay: HELLO until both slots
/// are there, then an Input every frame (60/s) and a HELLO every 5 s.
async fn relay(ctx: &Ctx, n: usize, t: &SessionTicket, dur: Duration) {
    let Some(token) =
        rugen_proto::from_hex(&t.token).and_then(|v| <[u8; TOKEN_LEN]>::try_from(v).ok())
    else {
        return;
    };
    let Some(server) = t
        .udp
        .as_deref()
        .and_then(|u| std::net::ToSocketAddrs::to_socket_addrs(u).ok()?.next())
    else {
        return;
    };
    let local = format!(
        "127.{}.{}.{}:0",
        1 + (n >> 16) % 250,
        (n >> 8) & 255,
        (n & 255).max(1)
    );
    let Ok(sock) = tokio::net::UdpSocket::bind(&local).await else {
        return;
    };
    let peer = 1 - t.slot;
    let frame = |kind: u8, to: u8, p: &[u8]| {
        wire::encode_client(
            Header {
                kind,
                from: t.slot,
                to,
                session: t.session,
            },
            &token,
            p,
        )
    };
    let send = |b: Vec<u8>| {
        let s = &sock;
        async move {
            if s.send_to(&b, server).await.is_ok() {
                ctx.stats.udp_sent.fetch_add(1, Relaxed);
            }
        }
    };
    let mut buf = [0u8; 2048];
    let t0 = Instant::now();
    let mut mask = 0u8;
    let mut last_hello = t0 - Duration::from_secs(1);
    while mask & 0b11 != 0b11 {
        if t0.elapsed() > Duration::from_secs(15) || ctx.stop.load(Relaxed) {
            return;
        }
        if last_hello.elapsed() >= Duration::from_millis(500) {
            send(frame(wire::HELLO, 0, &[])).await;
            last_hello = Instant::now();
        }
        if let Ok(Ok((len, _))) =
            tokio::time::timeout(Duration::from_millis(100), sock.recv_from(&mut buf)).await
        {
            ctx.stats.udp_recv.fetch_add(1, Relaxed);
            if let Some((h, p)) = wire::decode_server(&buf[..len])
                && matches!(h.kind, wire::ACK | wire::PEERS)
                && let Some(&m) = p.first()
            {
                mask = m;
            }
        }
    }
    let end = Instant::now() + dur;
    let mut tick = tokio::time::interval(Duration::from_micros(16_667));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut sent_at = vec![None::<Instant>; RING];
    let (mut seq, mut peer_seq, mut acked) = (0u32, 0u32, 0u32);
    let mut lat = Vec::new();
    let mut last_hello = Instant::now();
    while Instant::now() < end && !ctx.stop.load(Relaxed) {
        tokio::select! {
            _ = tick.tick() => {
                seq += 1;
                sent_at[seq as usize % RING] = Some(Instant::now());
                send(frame(wire::DATA, peer, &input_payload(seq, peer_seq))).await;
                if last_hello.elapsed() >= Duration::from_secs(5) {
                    last_hello = Instant::now();
                    send(frame(wire::HELLO, 0, &[])).await;
                }
            }
            r = sock.recv_from(&mut buf) => {
                let Ok((len, _)) = r else { continue };
                ctx.stats.udp_recv.fetch_add(1, Relaxed);
                let Some((h, p)) = wire::decode_server(&buf[..len]) else { continue };
                if h.kind != wire::DATA || p.len() < SEQ_AT + 8 {
                    continue;
                }
                let got = u32::from_le_bytes(p[SEQ_AT..SEQ_AT + 4].try_into().unwrap());
                let ack = u32::from_le_bytes(p[SEQ_AT + 4..SEQ_AT + 8].try_into().unwrap());
                peer_seq = peer_seq.max(got);
                if ack > acked && seq.wrapping_sub(ack) < RING as u32 {
                    acked = ack;
                    if let Some(at) = sent_at[ack as usize % RING].take() {
                        lat.push(at.elapsed().as_micros() as u32);
                    }
                }
            }
        }
        if lat.len() >= 64 {
            ctx.stats.relay_lat.lock().unwrap().append(&mut lat);
        }
    }
    ctx.stats.relay_lat.lock().unwrap().append(&mut lat);
    send(frame(wire::BYE, 0, &[])).await;
}

async fn client(ctx: Arc<Ctx>, n: usize) {
    let mut c = Client {
        ctx: ctx.clone(),
        n,
        ip: format!("10.{}.{}.{}", (n >> 16) & 255, (n >> 8) & 255, n & 255),
        key: String::new(),
        id: 0,
        rng: Rng(0x2545_F491_4F6C_DD1D ^ ((n as u64 + 1) * 0x9E37_79B9)),
    };
    // the client retries entering the server
    loop {
        match c.login().await {
            Ok(()) => break,
            Err(e) => {
                log::debug!("client {n}: {e}");
                if !c.nap(Duration::from_secs(5)).await {
                    return;
                }
            }
        }
    }
    ctx.alive.fetch_add(1, Relaxed);
    let pres = tokio::spawn(presence(ctx.clone(), c.key.clone(), c.ip.clone()));
    while !c.stopped() {
        if !c.lobby(10).await {
            break;
        }
        match c.rng.below(100) {
            0..60 => c.queue().await,
            60..85 => c.host_room().await,
            _ => {
                c.lobby(10).await;
            }
        }
    }
    ctx.alive.fetch_sub(1, Relaxed);
    let _ = pres.await;
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

async fn upload(c: &Client, fp: &str, path: &Path) -> Res<()> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let total = data.len();
    let mut off = 0;
    while off < total {
        let end = (off + (1 << 20)).min(total);
        let url = format!(
            "{}/pkg/{fp}/upload?key={}&offset={off}&total={total}",
            c.ctx.a.server, c.key
        );
        let r = c
            .ctx
            .http
            .post(&url)
            .header("cf-connecting-ip", &c.ip)
            .header("x-rugen-api", rugen_proto::API_VERSION.to_string())
            .header("user-agent", format!("rugen/{}", c.ctx.a.engine))
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
async fn warm_up(ctx: &Arc<Ctx>, kfm_pkg: &Path, stage_pkg: &Path) -> Res<()> {
    let mk = |n: usize| Client {
        ctx: ctx.clone(),
        n,
        ip: format!("10.255.255.{n}"),
        key: String::new(),
        id: 0,
        rng: Rng(n as u64 + 7),
    };
    let (mut a, mut b) = (mk(1), mk(2));
    a.rng.0 = 99; // never named
    b.rng.0 = 98;
    for c in [&mut a, &mut b] {
        let r = c.call("POST", "/register", None).await?;
        c.key = r["key"].as_str().ok_or("no key")?.to_string();
        c.id = r["id"].as_u64().unwrap_or(0);
    }
    let room = a
        .call(
            "POST",
            "/room",
            Some(json!({"key": a.key, "char": "kfm", "public": false})),
        )
        .await?;
    let code = room["code"].as_str().ok_or("no code")?.to_string();
    let joined = b
        .call(
            "POST",
            &format!("/room/{code}/join"),
            Some(json!({"key": b.key, "char": "kfm"})),
        )
        .await?;
    let id = joined["matchup"]["id"].as_u64().ok_or("join: no matchup")?;
    a.call(
        "POST",
        &format!("/matchup/{id}/pick"),
        Some(json!({"key": a.key, "fighter": ctx.kfm, "stage": ctx.stage})),
    )
    .await?;
    b.call(
        "POST",
        &format!("/matchup/{id}/pick"),
        Some(json!({"key": b.key, "fighter": ctx.kfm})),
    )
    .await?;
    let mut view = Value::Null;
    for c in [&a, &b] {
        view = c
            .call(
                "POST",
                &format!("/matchup/{id}/accept"),
                Some(json!({"key": c.key, "unbalanced": true})),
            )
            .await?;
    }
    for fp in view["missing"].as_array().cloned().unwrap_or_default() {
        let fp = fp.as_str().unwrap_or("");
        let path = if fp == ctx.kfm.fingerprint {
            kfm_pkg
        } else {
            stage_pkg
        };
        upload(&a, fp, path).await?;
    }
    let t = Instant::now();
    loop {
        let v = a
            .call("GET", &format!("/matchup/{id}?key={}", a.key), None)
            .await?;
        if v["phase"] == "sync" || v["phase"] == "started" {
            break;
        }
        if t.elapsed() > Duration::from_secs(120) {
            return Err(format!("warm-up stuck: {v}"));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    for c in [&a, &b] {
        let _ = c
            .call(
                "POST",
                &format!("/matchup/{id}/leave"),
                Some(json!({"key": c.key})),
            )
            .await;
    }
    let _ = a
        .call(
            "POST",
            &format!("/room/{code}/leave"),
            Some(json!({"key": a.key})),
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
    let http = reqwest::Client::builder()
        .pool_max_idle_per_host(usize::MAX)
        .pool_idle_timeout(Duration::from_secs(60))
        .tcp_nodelay(true)
        .timeout(Duration::from_secs(a.timeout))
        .build()
        .unwrap();
    let inputs = vec![0u8; a.dispute_frames * 4];
    let ctx = Arc::new(Ctx {
        inputs_hex: rugen_proto::to_hex(&inputs),
        a: a.clone(),
        http,
        stats: Stats::default(),
        stop: AtomicBool::new(false),
        kfm,
        stage,
        alive: AtomicI64::new(0),
        presence: AtomicI64::new(0),
        relaying: AtomicI64::new(0),
        max_threads: AtomicU64::new(0),
        max_rss_kb: AtomicU64::new(0),
    });
    if let Err(e) = warm_up(&ctx, &kfm_pkg, &stage_pkg).await {
        eprintln!("warm-up: {e}");
        std::process::exit(2);
    }
    ctx.stats.reset();
    // server sampler: peak threads / RSS
    {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            loop {
                let s = proc_sample(ctx.a.server_pid);
                ctx.max_threads.fetch_max(s.threads, Relaxed);
                ctx.max_rss_kb
                    .fetch_max((s.rss_mb * 1024.0) as u64, Relaxed);
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
    let mut spawned = 0usize;
    let mut handles = Vec::new();
    for &target in &a.steps {
        let add = target.saturating_sub(spawned);
        let gap = Duration::from_secs_f64(a.ramp as f64 / add.max(1) as f64);
        for _ in 0..add {
            spawned += 1;
            handles.push(tokio::spawn(client(ctx.clone(), spawned)));
            tokio::time::sleep(gap).await;
        }
        // settle, then measure
        tokio::time::sleep(Duration::from_secs(3)).await;
        ctx.stats.reset();
        ctx.max_threads.store(0, Relaxed);
        ctx.max_rss_kb.store(0, Relaxed);
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
        let mut r = ctx.stats.reset();
        r.lat.sort_unstable();
        r.relay_lat.sort_unstable();
        let total = r.ok + r.e_net + r.e_5xx + r.e_429 + r.e_4xx;
        let errs = r.e_net + r.e_5xx + r.e_429 + r.e_4xx;
        let err = errs as f64 / total.max(1) as f64;
        let (p50, p95, p99) = (pct(&r.lat, 0.5), pct(&r.lat, 0.95), pct(&r.lat, 0.99));
        let cpu = if p1.alive {
            (p1.cpu_secs - p0.cpu_secs) / secs * 100.0
        } else {
            0.0
        };
        let rss = ctx.max_rss_kb.load(Relaxed) as f64 / 1024.0;
        let threads = ctx.max_threads.load(Relaxed);
        let gen_cpu = (g1 - g0) / secs * 100.0;
        println!(
            "| {target} | {} | {} | {:.0} | {p50:.1} | {p95:.1} | {p99:.1} | {:.2} ({}/{}/{}/{}) | {:.0} | {:.1} | {} | {} | {cpu:.0} | {rss:.0} | {threads} | {gen_cpu:.0} |",
            ctx.alive.load(Relaxed),
            ctx.presence.load(Relaxed),
            total as f64 / secs,
            err * 100.0,
            r.e_net,
            r.e_5xx,
            r.e_429,
            r.e_4xx,
            r.udp_sent as f64 / secs,
            pct(&r.relay_lat, 0.99),
            r.matches,
            r.disputes,
        );
        if let Some(f) = out.as_mut() {
            use std::io::Write;
            let _ = writeln!(
                f,
                "{}",
                json!({
                    "clients": target, "alive": ctx.alive.load(Relaxed),
                    "presence": ctx.presence.load(Relaxed), "secs": secs,
                    "requests": total, "rps": total as f64 / secs,
                    "p50_ms": p50, "p95_ms": p95, "p99_ms": p99, "max_ms": pct(&r.lat, 1.0),
                    "err": err, "e_net": r.e_net, "e_5xx": r.e_5xx, "e_429": r.e_429, "e_4xx": r.e_4xx,
                    "udp_sent_ps": r.udp_sent as f64 / secs, "udp_recv_ps": r.udp_recv as f64 / secs,
                    "relay_p50_ms": pct(&r.relay_lat, 0.5), "relay_p99_ms": pct(&r.relay_lat, 0.99),
                    "relaying": ctx.relaying.load(Relaxed),
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
    ctx.stop.store(true, Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(20), async {
        for h in handles {
            let _ = h.await;
        }
    })
    .await;
}
