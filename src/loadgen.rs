//! Simulated game clients: the load of `examples/loadgen.rs` and of the
//! server's own self-benchmark (`POST /admin/bench`, [`crate::bench`]).
//! Self-contained (also compiled into the example through `#[path]`).
//!
//! Every client does what the rugen 0.6 client does in the ONLINE menu
//! (rates from `rugen-app` `online.rs` / `matchup.rs`, `rugen-net`
//! `online.rs`):
//!
//! ```text
//! POST /register (or, `named_share`, POST /v1/account/register: Argon2id)
//! POST /profile                           once
//! GET  /ws?key=                           presence WebSocket, kept open
//! loop:
//!   lobby       GET /rooms every 5 s (10 s)
//!   then one of
//!   60 % queue  POST /queue (half ranked), GET /queue?key= every 1 s
//!               found → GET /matchup/{id}?key= every 400 ms + pick /
//!               accept / ready → relay ticket → the match (20–40 s;
//!               `relay_share` of matches over the UDP relay at 60 packets/s
//!               per player) → POST /result (both sides); `dispute_share` of
//!               ranked matches are disputed with input evidence
//!   25 % host   POST /room (`public_share` public), GET /room/{code} every
//!               1 s for 20–40 s, POST /room/{code}/leave
//!   15 % idle   another 10 s of lobby
//! ```
//!
//! Relayed players also feed the match's input log (a `STREAM` datagram
//! every 15 frames, as the game does), and **viewers** ([`Load::grow_viewers`])
//! watch live matches like the game's WATCH: `GET /v1/live` every 10 s to
//! pick one (viewer `n` takes match `n` of the list, so viewers spread over
//! the live matches), then `GET /v1/live/{id}?from=N` every 400 ms for the
//! frames since the last answer, a new pick when the match ends or is full.
//!
//! Each client sends its own `CF-Connecting-IP` (as behind the Cloudflare
//! Tunnel) and binds its UDP socket to its own 127.x.y.z, so per-IP limits
//! apply per client as in production. Each client keeps one HTTP/1.1
//! connection (hyper) and its WebSocket.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Full};
use rugen_proto::relay::{self as wire, Header, TOKEN_LEN};
use rugen_proto::{FighterDecl, SessionTicket};
use serde_json::{Value, json};

/// What the simulated clients do.
#[derive(Clone, Debug)]
pub struct Mix {
    /// Game version in `User-Agent` and ready reports (`0.6.1`).
    pub engine: String,
    pub relay_share: f64,
    pub dispute_share: f64,
    pub public_share: f64,
    pub named_share: f64,
    /// Frames of input evidence a disputed report carries.
    pub dispute_frames: usize,
    /// The fighter every client picks, and the stage P1 brings.
    pub fighter: FighterDecl,
    pub stage: FighterDecl,
    /// Per-request timeout.
    pub timeout: Duration,
}

impl Mix {
    /// The default mix with these fighter / stage declarations.
    pub fn new(engine: &str, fighter: FighterDecl, stage: FighterDecl) -> Self {
        Self {
            engine: engine.to_string(),
            relay_share: 0.3,
            dispute_share: 0.1,
            public_share: 0.25,
            named_share: 0.02,
            dispute_frames: 3600,
            fighter,
            stage,
            timeout: Duration::from_secs(10),
        }
    }
}

/// Counters and latencies since the last [`Load::take`].
#[derive(Default)]
struct Stats {
    lat: Mutex<Vec<u32>>,
    by_route: Mutex<BTreeMap<String, (u64, u64, u64)>>,
    ok: AtomicU64,
    e_net: AtomicU64,
    e_5xx: AtomicU64,
    e_429: AtomicU64,
    e_4xx: AtomicU64,
    relay_lat: Mutex<Vec<u32>>,
    udp_sent: AtomicU64,
    udp_recv: AtomicU64,
    matches: AtomicU64,
    disputes: AtomicU64,
    matchup_fail: AtomicU64,
    ws_fail: AtomicU64,
    relay_fail: AtomicU64,
    /// A few distinct failures (`route: status message`), for diagnosis.
    err_samples: Mutex<Vec<String>>,
    /// Viewers: chunk requests, their latency (µs), bytes received,
    /// "this match is full" answers, other failures.
    viewer_polls: AtomicU64,
    viewer_lat: Mutex<Vec<u32>>,
    viewer_bytes: AtomicU64,
    viewer_full: AtomicU64,
    viewer_errors: AtomicU64,
}

/// Distinct failure messages kept per window.
const ERR_SAMPLES: usize = 8;

/// One measurement window.
#[derive(Default)]
pub struct Sample {
    /// Every HTTP call's latency, µs, sorted.
    pub lat: Vec<u32>,
    /// Per endpoint: (calls, total µs, max µs).
    pub by_route: BTreeMap<String, (u64, u64, u64)>,
    pub ok: u64,
    /// Connect / timeout / reset.
    pub e_net: u64,
    pub e_5xx: u64,
    pub e_429: u64,
    pub e_4xx: u64,
    /// Relay ack latency (my input → the peer's next input acking it), µs, sorted.
    pub relay_lat: Vec<u32>,
    pub udp_sent: u64,
    pub udp_recv: u64,
    pub matches: u64,
    pub disputes: u64,
    pub matchup_fail: u64,
    pub ws_fail: u64,
    /// Relayed matches that could not start (UDP bind / handshake).
    pub relay_fail: u64,
    /// A few distinct failures (`route: status message`).
    pub err_samples: Vec<String>,
    /// Viewers' live chunk requests, their latency (µs, sorted), bytes,
    /// "this match is full" answers and other failures.
    pub viewer_polls: u64,
    pub viewer_lat: Vec<u32>,
    pub viewer_bytes: u64,
    pub viewer_full: u64,
    pub viewer_errors: u64,
}

impl Sample {
    pub fn total(&self) -> u64 {
        self.ok + self.errors()
    }
    pub fn errors(&self) -> u64 {
        self.e_net + self.e_5xx + self.e_429 + self.e_4xx
    }
    pub fn err_rate(&self) -> f64 {
        self.errors() as f64 / self.total().max(1) as f64
    }
    /// Latency percentile of the HTTP calls, ms.
    pub fn pct(&self, p: f64) -> f64 {
        pct(&self.lat, p)
    }
    pub fn relay_pct(&self, p: f64) -> f64 {
        pct(&self.relay_lat, p)
    }
}

/// Percentile `p` of sorted µs latencies, in ms.
pub fn percentile_ms(v: &[u32], p: f64) -> f64 {
    pct(v, p)
}

fn pct(v: &[u32], p: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    let i = ((v.len() as f64 - 1.0) * p).round() as usize;
    f64::from(v[i.min(v.len() - 1)]) / 1000.0
}

/// `GET /matchup/123?key=…` → `GET /matchup/{}`.
pub fn route_name(method: &str, path: &str) -> String {
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

/// Resident memory, threads and CPU seconds of a process (`/proc`).
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcSample {
    pub cpu_secs: f64,
    pub rss_mb: f64,
    pub threads: u64,
    pub alive: bool,
}

/// `pid` `None` = this process: CPU time from `getrusage` (no `/proc`
/// needed), memory and threads from `/proc/self` with fallbacks
/// (`statm`, the `task` directory).
pub fn proc_sample(pid: Option<u32>) -> ProcSample {
    let dir = pid.map_or_else(|| "/proc/self".to_string(), |p| format!("/proc/{p}"));
    let stat = std::fs::read_to_string(format!("{dir}/stat")).ok();
    let status = std::fs::read_to_string(format!("{dir}/status")).unwrap_or_default();
    let field = |k: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(k))
            .and_then(|v| v.split_whitespace().next()?.parse::<f64>().ok())
    };
    let stat_cpu = stat.as_deref().map(|stat| {
        let after = stat.rsplit_once(')').map(|x| x.1).unwrap_or("");
        let f: Vec<&str> = after.split_whitespace().collect();
        let t = |i: usize| f.get(i).and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0);
        // utime + stime, clock ticks (100 Hz on Linux)
        (t(11) + t(12)) / 100.0
    });
    let cpu_secs = match pid {
        None => self_cpu_secs().or(stat_cpu),
        Some(_) => stat_cpu,
    };
    let rss_mb = field("VmRSS:").map(|kb| kb / 1024.0).or_else(|| {
        // resident pages, 4 KiB on the platforms we run on
        let statm = std::fs::read_to_string(format!("{dir}/statm")).ok()?;
        let pages: f64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        Some(pages * 4096.0 / (1024.0 * 1024.0))
    });
    let threads = field("Threads:").map(|t| t as u64).or_else(|| {
        std::fs::read_dir(format!("{dir}/task"))
            .ok()
            .map(|d| d.count() as u64)
    });
    ProcSample {
        cpu_secs: cpu_secs.unwrap_or(0.0),
        rss_mb: rss_mb.unwrap_or(0.0),
        threads: threads.unwrap_or(0),
        alive: stat.is_some() || cpu_secs.is_some(),
    }
}

/// CPU seconds (user + system) of this process, from `getrusage`.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn self_cpu_secs() -> Option<f64> {
    // SAFETY: getrusage fills the zeroed struct it is given, nothing else
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } != 0 {
        return None;
    }
    let secs = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    Some(secs(ru.ru_utime) + secs(ru.ru_stime))
}

#[cfg(not(target_os = "linux"))]
fn self_cpu_secs() -> Option<f64> {
    None
}

struct Ctx {
    addr: SocketAddr,
    mix: Mix,
    stats: Stats,
    stop: AtomicBool,
    alive: AtomicI64,
    presence: AtomicI64,
    relaying: AtomicI64,
    /// Viewers following a match right now.
    watching: AtomicI64,
    inputs_hex: String,
}

/// N simulated clients against one server.
pub struct Load {
    ctx: Arc<Ctx>,
    handles: Vec<tokio::task::JoinHandle<()>>,
    spawned: usize,
    viewers: usize,
}

impl Load {
    /// Clients for the HTTP server at `addr` (loopback).
    pub fn new(addr: SocketAddr, mix: Mix) -> Self {
        let inputs = vec![0u8; mix.dispute_frames * 4];
        Self {
            ctx: Arc::new(Ctx {
                addr,
                inputs_hex: rugen_proto::to_hex(&inputs),
                mix,
                stats: Stats::default(),
                stop: AtomicBool::new(false),
                alive: AtomicI64::new(0),
                presence: AtomicI64::new(0),
                relaying: AtomicI64::new(0),
                watching: AtomicI64::new(0),
            }),
            handles: Vec::new(),
            spawned: 0,
            viewers: 0,
        }
    }

    /// Clients started so far.
    pub fn clients(&self) -> usize {
        self.spawned
    }

    /// Clients logged in / with presence open / in a relayed match.
    pub fn alive(&self) -> (i64, i64, i64) {
        let c = &self.ctx;
        (
            c.alive.load(Relaxed),
            c.presence.load(Relaxed),
            c.relaying.load(Relaxed),
        )
    }

    /// Viewers started so far, and those following a match right now.
    pub fn viewers(&self) -> (usize, i64) {
        (self.viewers, self.ctx.watching.load(Relaxed))
    }

    /// Start viewers up to `target`, spread over `ramp`.
    pub async fn grow_viewers(&mut self, target: usize, ramp: Duration) {
        let add = target.saturating_sub(self.viewers);
        let gap = ramp.div_f64(add.max(1) as f64);
        for _ in 0..add {
            if self.ctx.stop.load(Relaxed) {
                return;
            }
            self.viewers += 1;
            self.handles
                .push(tokio::spawn(viewer(self.ctx.clone(), self.viewers)));
            if !gap.is_zero() {
                tokio::time::sleep(gap).await;
            }
        }
    }

    /// Start clients up to `target`, spread over `ramp`.
    pub async fn grow(&mut self, target: usize, ramp: Duration) {
        let add = target.saturating_sub(self.spawned);
        let gap = ramp.div_f64(add.max(1) as f64);
        for _ in 0..add {
            if self.ctx.stop.load(Relaxed) {
                return;
            }
            self.spawned += 1;
            self.handles
                .push(tokio::spawn(client(self.ctx.clone(), self.spawned)));
            if !gap.is_zero() {
                tokio::time::sleep(gap).await;
            }
        }
    }

    /// Counters since the last call (and reset them).
    pub fn take(&self) -> Sample {
        let s = &self.ctx.stats;
        let mut out = Sample {
            lat: std::mem::take(&mut *s.lat.lock().unwrap_or_else(|p| p.into_inner())),
            by_route: std::mem::take(&mut *s.by_route.lock().unwrap_or_else(|p| p.into_inner())),
            relay_lat: std::mem::take(&mut *s.relay_lat.lock().unwrap_or_else(|p| p.into_inner())),
            ok: s.ok.swap(0, Relaxed),
            e_net: s.e_net.swap(0, Relaxed),
            e_5xx: s.e_5xx.swap(0, Relaxed),
            e_429: s.e_429.swap(0, Relaxed),
            e_4xx: s.e_4xx.swap(0, Relaxed),
            udp_sent: s.udp_sent.swap(0, Relaxed),
            udp_recv: s.udp_recv.swap(0, Relaxed),
            matches: s.matches.swap(0, Relaxed),
            disputes: s.disputes.swap(0, Relaxed),
            matchup_fail: s.matchup_fail.swap(0, Relaxed),
            ws_fail: s.ws_fail.swap(0, Relaxed),
            relay_fail: s.relay_fail.swap(0, Relaxed),
            err_samples: std::mem::take(
                &mut *s.err_samples.lock().unwrap_or_else(|p| p.into_inner()),
            ),
            viewer_polls: s.viewer_polls.swap(0, Relaxed),
            viewer_lat: std::mem::take(
                &mut *s.viewer_lat.lock().unwrap_or_else(|p| p.into_inner()),
            ),
            viewer_bytes: s.viewer_bytes.swap(0, Relaxed),
            viewer_full: s.viewer_full.swap(0, Relaxed),
            viewer_errors: s.viewer_errors.swap(0, Relaxed),
        };
        out.viewer_lat.sort_unstable();
        out.lat.sort_unstable();
        out.relay_lat.sort_unstable();
        out
    }

    /// Latency percentile and error rate of the calls since the last
    /// [`Self::take`], without resetting (abort checks).
    pub fn peek(&self) -> (f64, f64, u64) {
        let s = &self.ctx.stats;
        let mut lat = s.lat.lock().unwrap_or_else(|p| p.into_inner()).clone();
        lat.sort_unstable();
        let ok = s.ok.load(Relaxed);
        let errs = s.e_net.load(Relaxed)
            + s.e_5xx.load(Relaxed)
            + s.e_429.load(Relaxed)
            + s.e_4xx.load(Relaxed);
        (
            pct(&lat, 0.99),
            errs as f64 / (ok + errs).max(1) as f64,
            ok + errs,
        )
    }

    /// Stop every client (each finishes its current call), waiting at most
    /// `wait`.
    pub async fn stop(self, wait: Duration) {
        self.ctx.stop.store(true, Relaxed);
        let all = futures_util::future::join_all(self.handles);
        if tokio::time::timeout(wait, all).await.is_err() {
            log::debug!("loadgen: some clients did not stop in time");
        }
    }
}

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

type Sender = hyper::client::conn::http1::SendRequest<Full<Bytes>>;

/// One simulated player.
pub struct Client {
    ctx: Arc<Ctx>,
    n: usize,
    ip: String,
    key: String,
    id: u64,
    rng: Rng,
    conn: Option<Sender>,
}

enum Fail {
    Net(String),
    Status(u16, String),
}

impl Client {
    fn new(ctx: Arc<Ctx>, n: usize) -> Self {
        Self {
            ctx,
            n,
            ip: format!("10.{}.{}.{}", (n >> 16) & 255, (n >> 8) & 255, n & 255),
            key: String::new(),
            id: 0,
            rng: Rng(0x2545_F491_4F6C_DD1D ^ ((n as u64 + 1) * 0x9E37_79B9)),
            conn: None,
        }
    }

    async fn send(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Vec<u8>, Fail> {
        if self.conn.as_ref().is_none_or(|c| c.is_closed()) {
            let tcp = tokio::net::TcpStream::connect(self.ctx.addr)
                .await
                .map_err(|e| Fail::Net(e.to_string()))?;
            let _ = tcp.set_nodelay(true);
            let (sender, conn) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp))
                    .await
                    .map_err(|e| Fail::Net(e.to_string()))?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            self.conn = Some(sender);
        }
        let Some(sender) = self.conn.as_mut() else {
            return Err(Fail::Net("no connection".into()));
        };
        sender.ready().await.map_err(|e| Fail::Net(e.to_string()))?;
        let bytes = body.map(|b| serde_json::to_vec(b).unwrap_or_default());
        let mut rb = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("host", self.ctx.addr.to_string())
            .header("cf-connecting-ip", &self.ip)
            .header("x-rugen-api", rugen_proto::API_VERSION.to_string())
            .header("user-agent", format!("rugen/{}", self.ctx.mix.engine));
        if bytes.is_some() {
            rb = rb.header("content-type", "application/json");
        }
        let req = rb
            .body(Full::new(Bytes::from(bytes.unwrap_or_default())))
            .map_err(|e| Fail::Net(e.to_string()))?;
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| Fail::Net(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| Fail::Net(e.to_string()))?
            .to_bytes();
        if status == 200 {
            Ok(body.to_vec())
        } else {
            Err(Fail::Status(
                status,
                String::from_utf8_lossy(&body[..body.len().min(200)]).into_owned(),
            ))
        }
    }

    async fn call(
        &mut self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, String> {
        let t = Instant::now();
        let timeout = self.ctx.mix.timeout;
        let r = match tokio::time::timeout(timeout, self.send(method, path, body.as_ref())).await {
            Ok(r) => r,
            Err(_) => {
                self.conn = None;
                Err(Fail::Net("timeout".into()))
            }
        };
        let s = &self.ctx.stats;
        let out = match r {
            Ok(b) => {
                s.ok.fetch_add(1, Relaxed);
                Ok(serde_json::from_slice(&b).unwrap_or(Value::Null))
            }
            Err(Fail::Status(st, msg)) => {
                match st {
                    429 => &s.e_429,
                    500.. => &s.e_5xx,
                    _ => &s.e_4xx,
                }
                .fetch_add(1, Relaxed);
                Err(format!("{method} {path}: http {st} {msg}"))
            }
            Err(Fail::Net(e)) => {
                self.conn = None;
                s.e_net.fetch_add(1, Relaxed);
                Err(format!("{method} {path}: {e}"))
            }
        };
        let us = t.elapsed().as_micros().min(u128::from(u32::MAX)) as u32;
        s.lat.lock().unwrap_or_else(|p| p.into_inner()).push(us);
        let route = route_name(method, path);
        if let Err(e) = &out {
            let mut v = s.err_samples.lock().unwrap_or_else(|p| p.into_inner());
            // `METHOD /path?...: reason` → `METHOD /route: reason`
            let why = e.split_once(": ").map_or(e.as_str(), |x| x.1);
            let line = format!("{route}: {why}");
            let line: String = line.chars().take(160).collect();
            if v.len() < ERR_SAMPLES && !v.contains(&line) {
                v.push(line);
            }
        }
        let mut m = s.by_route.lock().unwrap_or_else(|p| p.into_inner());
        let e = m.entry(route).or_default();
        e.0 += 1;
        e.1 += u64::from(us);
        e.2 = e.2.max(u64::from(us));
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

    async fn login(&mut self) -> Result<(), String> {
        let named = self.rng.chance(self.ctx.mix.named_share);
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
        let body = json!({"key": self.key, "name": format!("LG{}", self.n)});
        self.call("POST", "/profile", Some(body)).await?;
        Ok(())
    }

    async fn lobby(&mut self, secs: u64) -> bool {
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
        let public = self.rng.chance(self.ctx.mix.public_share);
        let body = json!({"key": self.key, "char": "kfm", "name": format!("LG ROOM {}", self.n), "public": public});
        let Ok(r) = self.call("POST", "/room", Some(body)).await else {
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
            let path = format!("/room/{code}?key={}", self.key);
            let _ = self.call("GET", &path, None).await;
        }
        let body = json!({"key": self.key});
        let _ = self
            .call("POST", &format!("/room/{code}/leave"), Some(body))
            .await;
    }

    async fn queue(&mut self) {
        let ranked = self.rng.chance(0.5);
        let body = json!({"key": self.key, "char": "kfm", "ranked": ranked});
        let Ok(mut st) = self.call("POST", "/queue", Some(body)).await else {
            return;
        };
        let t = Instant::now();
        while st["found"].is_null() {
            if t.elapsed() > Duration::from_secs(40) || !self.nap(Duration::from_secs(1)).await {
                let body = json!({"key": self.key});
                let _ = self.call("DELETE", "/queue", Some(body)).await;
                return;
            }
            let path = format!("/queue?key={}", self.key);
            if let Ok(v) = self.call("GET", &path, None).await {
                st = v;
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
                let body = json!({"key": self.key});
                let _ = self
                    .call("POST", &format!("/matchup/{id}/leave"), Some(body))
                    .await;
            }
        }
    }

    /// The matchup phase as the client's matchup worker runs it: a poll
    /// every 400 ms and the next step whenever the view allows it.
    async fn matchup(&mut self, id: u64, side: u8) -> Option<SessionTicket> {
        let me = usize::from(side == 2);
        let t = Instant::now();
        let (mut picked, mut accepted, mut readied) = (false, false, false);
        while t.elapsed() < Duration::from_secs(40) {
            if !self.nap(Duration::from_millis(400)).await {
                return None;
            }
            let path = format!("/matchup/{id}?key={}", self.key);
            let Ok(v) = self.call("GET", &path, None).await else {
                continue;
            };
            if let Some(tk) = v.get("ticket").filter(|t| !t.is_null()) {
                return serde_json::from_value(tk.clone()).ok();
            }
            match v["phase"].as_str().unwrap_or("") {
                "pick" if !picked && v["fighters"][me].is_null() => {
                    let mut b = json!({"key": self.key, "fighter": self.ctx.mix.fighter});
                    if side == 1 {
                        b["stage"] = json!(self.ctx.mix.stage);
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
                    let b = json!({"key": self.key, "unbalanced": unbalanced});
                    accepted = self
                        .call("POST", &format!("/matchup/{id}/accept"), Some(b))
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
                        "engine": format!("rugen {}", self.ctx.mix.engine),
                        "rules": v["rules"],
                    });
                    let b = json!({"key": self.key, "ready": report});
                    if let Ok(r) = self
                        .call("POST", &format!("/matchup/{id}/ready"), Some(b))
                        .await
                    {
                        readied = true;
                        if let Some(tk) = r.get("ticket").filter(|t| !t.is_null()) {
                            return serde_json::from_value(tk.clone()).ok();
                        }
                    }
                }
                "failed" => return None,
                _ => {}
            }
        }
        None
    }

    async fn play(&mut self, id: u64, side: u8, opp: u64, ranked: bool, t: SessionTicket) {
        self.ctx.stats.matches.fetch_add(1, Relaxed);
        let secs = 20 + (id % 21);
        if share_of(id, 1, self.ctx.mix.relay_share) {
            self.ctx.relaying.fetch_add(1, Relaxed);
            relay(&self.ctx, self.n, &t, Duration::from_secs(secs)).await;
            self.ctx.relaying.fetch_sub(1, Relaxed);
        } else if !self.nap(Duration::from_secs(secs)).await {
            return;
        }
        let p1 = if side == 1 { self.id } else { opp };
        let body = if ranked && share_of(id, 2, self.ctx.mix.dispute_share) {
            if side == 1 {
                self.ctx.stats.disputes.fetch_add(1, Relaxed);
            }
            // both claim the win, same inputs, different checksums
            json!({"key": self.key, "match_id": id, "winner": self.id,
                "frames": self.ctx.mix.dispute_frames, "inputs": self.ctx.inputs_hex,
                "checksum": 1000 + u64::from(side)})
        } else {
            json!({"key": self.key, "match_id": id, "winner": p1, "frames": 60 * secs})
        };
        let _ = self.call("POST", "/result", Some(body)).await;
    }
}

/// Presence WebSocket, kept open with the client's reconnect backoff.
async fn presence(ctx: Arc<Ctx>, key: String, ip: String) {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let url = format!("ws://{}/ws?key={key}", ctx.addr);
    let mut backoff = Duration::from_secs(1);
    while !ctx.stop.load(Relaxed) {
        let Ok(mut req) = url.as_str().into_client_request() else {
            return;
        };
        if let Ok(h) = ip.parse() {
            req.headers_mut().insert("cf-connecting-ip", h);
        }
        let ws = match tokio::net::TcpStream::connect(ctx.addr).await {
            Ok(tcp) => tokio_tungstenite::client_async(req, tcp).await.ok(),
            Err(_) => None,
        };
        match ws {
            Some((mut s, _)) => {
                backoff = Duration::from_secs(1);
                ctx.presence.fetch_add(1, Relaxed);
                loop {
                    // reading also answers the server's pings
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
            None => {
                ctx.stats.ws_fail.fetch_add(1, Relaxed);
            }
        }
        if ctx.stop.load(Relaxed) {
            return;
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
        ctx.stats.relay_fail.fetch_add(1, Relaxed);
        return;
    };
    let Some(server) = t
        .udp
        .as_deref()
        .and_then(|u| std::net::ToSocketAddrs::to_socket_addrs(u).ok()?.next())
    else {
        ctx.stats.relay_fail.fetch_add(1, Relaxed);
        return;
    };
    let local = format!(
        "127.{}.{}.{}:0",
        1 + (n >> 16) % 250,
        (n >> 8) & 255,
        (n & 255).max(1)
    );
    let sock = match tokio::net::UdpSocket::bind(&local).await {
        Ok(s) => s,
        Err(e) => {
            log::debug!("relay: bind {local}: {e}");
            ctx.stats.relay_fail.fetch_add(1, Relaxed);
            return;
        }
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
        if ctx.stop.load(Relaxed) {
            return;
        }
        if t0.elapsed() > Duration::from_secs(15) {
            ctx.stats.relay_fail.fetch_add(1, Relaxed);
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
    // the match's input log: confirmed frames every 15 (as the game)
    let mut streamed = 0u32;
    let mut lat = Vec::new();
    let mut last_hello = Instant::now();
    while Instant::now() < end && !ctx.stop.load(Relaxed) {
        tokio::select! {
            _ = tick.tick() => {
                seq += 1;
                sent_at[seq as usize % RING] = Some(Instant::now());
                send(frame(wire::DATA, peer, &input_payload(seq, peer_seq))).await;
                if t.live && seq - streamed >= 15 {
                    let frames: Vec<[u16; 2]> =
                        (streamed..seq).map(|f| [f as u16, f as u16]).collect();
                    let p = rugen_proto::stream::encode_upload(streamed, &frames);
                    send(frame(wire::STREAM, 0xFF, &p)).await;
                    streamed = seq;
                }
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
                let mut word = [0u8; 4];
                word.copy_from_slice(&p[SEQ_AT..SEQ_AT + 4]);
                let got = u32::from_le_bytes(word);
                word.copy_from_slice(&p[SEQ_AT + 4..SEQ_AT + 8]);
                let ack = u32::from_le_bytes(word);
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
            ctx.stats
                .relay_lat
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .append(&mut lat);
        }
    }
    ctx.stats
        .relay_lat
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .append(&mut lat);
    send(frame(wire::BYE, 0, &[])).await;
}

async fn client(ctx: Arc<Ctx>, n: usize) {
    let mut c = Client::new(ctx.clone(), n);
    // the client retries entering the server
    while let Err(e) = c.login().await {
        log::debug!("client {n}: {e}");
        if !c.nap(Duration::from_secs(5)).await {
            return;
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

/// One viewer: pick a live match, follow it 400 ms at a time, pick again
/// when it ends (or is full).
async fn viewer(ctx: Arc<Ctx>, n: usize) {
    let mut c = Client::new(ctx.clone(), 2_000_000 + n);
    while let Err(e) = c.call("POST", "/register", None).await.and_then(|r| {
        c.key = r["key"].as_str().ok_or("register: no key")?.to_string();
        Ok(())
    }) {
        log::debug!("viewer {n}: {e}");
        if !c.nap(Duration::from_secs(5)).await {
            return;
        }
    }
    let s = &ctx.stats;
    while !c.stopped() {
        let list = c
            .call("GET", &format!("/v1/live?key={}", c.key), None)
            .await
            .unwrap_or_default();
        let ids: Vec<u64> = list
            .as_array()
            .map(|a| a.iter().filter_map(|m| m["match_id"].as_u64()).collect())
            .unwrap_or_default();
        let Some(&id) = ids.get(n % ids.len().max(1)) else {
            if !c.nap(Duration::from_secs(2)).await {
                return;
            }
            continue;
        };
        ctx.watching.fetch_add(1, Relaxed);
        let mut have = 0u32;
        let picked = Instant::now();
        loop {
            let t = Instant::now();
            let path = format!("/v1/live/{id}?key={}&from={have}", c.key);
            let r = tokio::time::timeout(ctx.mix.timeout, c.send("GET", &path, None)).await;
            s.viewer_polls.fetch_add(1, Relaxed);
            s.viewer_lat
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(t.elapsed().as_micros() as u32);
            let again = match r {
                Ok(Ok(b)) => {
                    s.viewer_bytes.fetch_add(b.len() as u64, Relaxed);
                    match rugen_proto::stream::decode_chunk(&b) {
                        Some(ch) => {
                            have = ch.from + ch.inputs.len() as u32;
                            !(ch.ended && have >= ch.total)
                        }
                        None => false,
                    }
                }
                Ok(Err(Fail::Status(409, _))) => {
                    s.viewer_full.fetch_add(1, Relaxed);
                    false
                }
                Ok(Err(Fail::Status(404, _))) => false,
                Ok(Err(_)) | Err(_) => {
                    if r.is_err() {
                        c.conn = None;
                    }
                    s.viewer_errors.fetch_add(1, Relaxed);
                    false
                }
            };
            // a fresh pick every minute: new matches get viewers too
            if !again || picked.elapsed() > Duration::from_secs(60) {
                break;
            }
            if !c.nap(Duration::from_millis(400)).await {
                break;
            }
        }
        ctx.watching.fetch_sub(1, Relaxed);
        if !c.nap(Duration::from_millis(500)).await {
            return;
        }
    }
}

/// A client outside the load (setup steps: uploads, warm-up matchups).
pub struct Setup(Client);

impl Load {
    /// A setup client `n` (its own IP in 10.255.255.0/24, never named).
    pub fn setup_client(&self, n: u8) -> Setup {
        let mut c = Client::new(self.ctx.clone(), 0);
        c.ip = format!("10.255.255.{n}");
        Setup(c)
    }
}

impl Setup {
    /// Register anonymously; the key.
    pub async fn register(&mut self) -> Result<String, String> {
        let r = self.0.call("POST", "/register", None).await?;
        self.0.key = r["key"].as_str().ok_or("register: no key")?.to_string();
        self.0.id = r["id"].as_u64().unwrap_or(0);
        Ok(self.0.key.clone())
    }

    pub fn key(&self) -> &str {
        &self.0.key
    }

    pub fn ip(&self) -> &str {
        &self.0.ip
    }

    /// A JSON call counted with the load's numbers.
    pub async fn call(
        &mut self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, String> {
        self.0.call(method, path, body).await
    }
}
