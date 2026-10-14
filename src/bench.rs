//! Self-benchmark (`POST /admin/bench`, `RUGEN_BENCH=1` + the admin token):
//! measure the hardware the server really runs on.
//!
//! A run starts a second, throw-away server inside this process: its own
//! store in a fresh temporary directory (`RUGEN_BENCH_DIR`, default the
//! system temp dir; never under the data directory), its own relay on
//! random 127.0.0.1 ports, no backups, no official feed, no TURN, no
//! re-simulation. The simulated clients of [`crate::loadgen`] then load it
//! in steps from this same process, so the load generator shares the
//! container's CPU quota with the server it measures: the numbers are a
//! lower bound of what the server alone sustains.
//!
//! Limits: one run at a time, at most 5000 clients per step and 5 minutes
//! per run; a run aborts by itself when p99 exceeds 2 s or more than 5 % of
//! the calls fail. The temporary directory goes when the run ends,
//! however it ends.
//!
//! The matchups use a synthetic fighter and stage stored directly in the
//! throw-away store (no content files needed), so matches start and their
//! relay traffic flows; disputed matches are recorded but never
//! re-simulated.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rugen_proto::FighterDecl;
use serde::Serialize;
use serde_json::{Value, json};

use crate::api::{Api, ApiConfig};
use crate::loadgen::{Load, Mix, proc_sample};
use crate::relay::Relay;
use crate::store::{PackageRow, Store, now};

/// Clients a step may ask for.
pub const MAX_CLIENTS: u64 = 5000;
/// Longest run (setup, every step, teardown excluded).
pub const MAX_RUN: Duration = Duration::from_secs(300);
/// A run aborts above this p99 ...
pub const ABORT_P99_MS: f64 = 2000.0;
/// ... or this share of failed calls.
pub const ABORT_ERR: f64 = 0.05;
/// Settling time after a step's ramp before measuring.
const SETTLE: Duration = Duration::from_secs(2);
/// Setup allowance counted into the time limit.
const SETUP: Duration = Duration::from_secs(5);

/// Shown with every result.
pub const NOTE: &str = "the load generator runs inside this server process and shares its CPU \
quota (and memory) with the instance it measures: read these numbers as a lower bound";

/// What `POST /admin/bench` asks for.
#[derive(Clone, Debug, PartialEq)]
pub struct Plan {
    pub steps: Vec<u64>,
    pub hold: Duration,
    pub ramp: Duration,
}

impl Plan {
    /// Validate a request body (`steps`, `hold_secs` = 40, `ramp_secs` =
    /// 10, `mix` = "default").
    pub fn parse(v: &Value) -> Result<Self, String> {
        let steps: Vec<u64> = v
            .get("steps")
            .and_then(Value::as_array)
            .ok_or("steps: a list of client counts")?
            .iter()
            .map(|s| {
                s.as_u64()
                    .filter(|&n| n > 0)
                    .ok_or("steps: positive integers")
            })
            .collect::<Result<_, _>>()?;
        if steps.is_empty() || steps.len() > 20 {
            return Err("steps: 1 to 20 of them".into());
        }
        if let Some(&n) = steps.iter().find(|&&n| n > MAX_CLIENTS) {
            return Err(format!("steps: {n} clients, at most {MAX_CLIENTS}"));
        }
        let secs = |k: &str, d: u64, max: u64| -> Result<Duration, String> {
            match v.get(k) {
                None | Some(Value::Null) => Ok(Duration::from_secs(d)),
                Some(x) => x
                    .as_u64()
                    .filter(|&s| s <= max)
                    .map(Duration::from_secs)
                    .ok_or_else(|| format!("{k}: 0 to {max} seconds")),
            }
        };
        let hold = secs("hold_secs", 40, 120)?.max(Duration::from_secs(1));
        let ramp = secs("ramp_secs", 10, 30)?;
        match v.get("mix").and_then(Value::as_str) {
            None | Some("default") => {}
            Some(m) => return Err(format!("mix: unknown {m:?} (only \"default\")")),
        }
        let plan = Self { steps, hold, ramp };
        if plan.duration() > MAX_RUN {
            return Err(format!(
                "this plan takes {} s, at most {} s: fewer steps or a shorter hold",
                plan.duration().as_secs(),
                MAX_RUN.as_secs()
            ));
        }
        Ok(plan)
    }

    /// Time the plan takes when nothing aborts.
    pub fn duration(&self) -> Duration {
        SETUP + (self.ramp + SETTLE + self.hold) * self.steps.len() as u32
    }
}

/// One measured step.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    pub clients: u64,
    pub alive: i64,
    pub presence: i64,
    pub req_s: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub errors: u64,
    pub err_pct: f64,
    /// Whole process (server + bench instance + load generator).
    pub cpu_pct: f64,
    pub rss_mb: f64,
    pub threads: u64,
    pub relay_pkt_s: f64,
    pub matches: u64,
}

/// A run, as `GET /admin/bench` shows it.
#[derive(Clone, Debug, Serialize)]
pub struct Run {
    pub id: String,
    /// `running`, `done`, `aborted` or `failed`.
    pub state: &'static str,
    pub started: u64,
    pub finished: Option<u64>,
    pub steps: Vec<u64>,
    pub hold_secs: u64,
    pub ramp_secs: u64,
    pub rows: Vec<Row>,
    pub reason: Option<String>,
    pub note: &'static str,
}

/// The bench of one server: at most one run at a time, the last one kept.
#[derive(Default)]
pub struct Bench {
    last: Arc<Mutex<Option<Run>>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Bench {
    /// The last run (running or finished).
    pub fn status(&self) -> Option<Run> {
        lock(&self.last).clone()
    }

    /// Start a run of `plan` in the background; its id, or `None` when one
    /// is running. `data` is the real data directory (the bench refuses a
    /// temporary directory inside it).
    pub fn start(&self, plan: Plan, data: Option<PathBuf>) -> Option<String> {
        let id = crate::store::random_hex(4);
        {
            let mut last = lock(&self.last);
            if last.as_ref().is_some_and(|r| r.state == "running") {
                return None;
            }
            *last = Some(Run {
                id: id.clone(),
                state: "running",
                started: now(),
                finished: None,
                steps: plan.steps.clone(),
                hold_secs: plan.hold.as_secs(),
                ramp_secs: plan.ramp.as_secs(),
                rows: Vec::new(),
                reason: None,
                note: NOTE,
            });
        }
        let (last, run_id) = (self.last.clone(), id.clone());
        let spawned = std::thread::Builder::new()
            .name("rugen-bench".into())
            .spawn(move || {
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(&plan, data.as_deref(), &last, &run_id)
                }));
                let (state, reason) = match r {
                    Ok(Ok(None)) => ("done", None),
                    Ok(Ok(Some(why))) => ("aborted", Some(why)),
                    Ok(Err(e)) => ("failed", Some(e)),
                    Err(_) => ("failed", Some("the bench panicked".to_string())),
                };
                log::info!(
                    "bench {run_id}: {state}{}",
                    reason
                        .as_deref()
                        .map(|r| format!(": {r}"))
                        .unwrap_or_default()
                );
                if let Some(r) = lock(&last).as_mut().filter(|r| r.id == run_id) {
                    r.state = state;
                    r.reason = reason;
                    r.finished = Some(now());
                }
            });
        if let Err(e) = spawned {
            if let Some(r) = lock(&self.last).as_mut() {
                r.state = "failed";
                r.reason = Some(format!("bench thread: {e}"));
                r.finished = Some(now());
            }
        }
        Some(id)
    }
}

/// The temporary directory of a run; removed when dropped.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.0) {
            log::warn!("bench: could not remove {}: {e}", self.0.display());
        }
    }
}

/// Where runs keep their throw-away data.
fn bench_base() -> PathBuf {
    std::env::var("RUGEN_BENCH_DIR")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map_or_else(std::env::temp_dir, PathBuf::from)
}

/// A fresh directory for run `id`, never inside `data`.
fn temp_dir(id: &str, data: Option<&Path>) -> Result<TempDir, String> {
    let base = bench_base();
    std::fs::create_dir_all(&base).map_err(|e| {
        format!(
            "bench directory {}: {e} (set RUGEN_BENCH_DIR)",
            base.display()
        )
    })?;
    let base = base
        .canonicalize()
        .map_err(|e| format!("bench directory {}: {e}", base.display()))?;
    if let Some(d) = data.and_then(|d| d.canonicalize().ok())
        && base.starts_with(&d)
    {
        return Err(format!(
            "bench directory {} is inside the data directory: set RUGEN_BENCH_DIR elsewhere",
            base.display()
        ));
    }
    let dir = base.join(format!("rugen-bench-{id}"));
    std::fs::create_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(TempDir(dir))
}

/// The synthetic fighter and stage every bench client picks, stored in the
/// throw-away instance as if uploaded.
fn seed(api: &Api) -> Result<(FighterDecl, FighterDecl), String> {
    let profile = rugen_proto::FairnessProfile {
        life: 1000,
        power_max: 3000,
        attack: 100,
        defence: 100,
        walk_fwd: 2.4,
        run_fwd: 4.6,
        jump_y: -8.4,
        states: 200,
        hitdefs: 60,
        max_hit_damage: 120,
        est_combo_damage: 300,
        supers: 2,
        min_super_cost: 1000,
        throws: 1,
        ..Default::default()
    };
    let mut out = Vec::new();
    for (kind, name, ext) in [
        (rugen_fair::Kind::Char, "BENCH", "char"),
        (rugen_fair::Kind::Stage, "BENCH STAGE", "stage"),
    ] {
        let fp = rugen_fair::sha256_hex(format!("rugen-bench-{ext}").as_bytes());
        let path = api.packages.path_for(&fp, kind);
        std::fs::write(&path, b"rugen bench placeholder")
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let profile = (ext == "char").then(|| profile.clone());
        api.store()
            .put_package(&PackageRow {
                fingerprint: fp.clone(),
                kind: ext.into(),
                size: 1024,
                name: name.into(),
                author: "rugen".into(),
                def: format!("bench-{ext}.def"),
                profile: profile.clone(),
                uploader: 0,
                created: now(),
                last_used: now(),
                keep_until: 0,
            })
            .map_err(|e| format!("seed: {e}"))?;
        out.push(FighterDecl {
            fingerprint: fp,
            kind: ext.into(),
            id: format!("bench_{ext}"),
            name: name.into(),
            author: "rugen".into(),
            def: format!("bench-{ext}.def"),
            size: 1024,
            profile,
            portrait: None,
        });
    }
    let stage = out.pop().ok_or("seed")?;
    let fighter = out.pop().ok_or("seed")?;
    Ok((fighter, stage))
}

/// One run: `Ok(None)` done, `Ok(Some(why))` aborted, `Err` failed.
fn run(
    plan: &Plan,
    data: Option<&Path>,
    last: &Mutex<Option<Run>>,
    id: &str,
) -> Result<Option<String>, String> {
    let dir = temp_dir(id, data)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(16)
        .thread_name("rugen-bench-rt")
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    let out = rt.block_on(instance(plan, &dir.0, last, id));
    rt.shutdown_timeout(Duration::from_secs(5));
    drop(dir);
    out
}

/// Start the throw-away server, load it step by step, tear it down.
async fn instance(
    plan: &Plan,
    dir: &Path,
    last: &Mutex<Option<Run>>,
    id: &str,
) -> Result<Option<String>, String> {
    let deadline = Instant::now() + MAX_RUN;
    let udp =
        Arc::new(std::net::UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("bench udp: {e}"))?);
    let udp_addr = udp.local_addr().map_err(|e| e.to_string())?;
    let relay = Arc::new(Relay::default());
    relay.set_udp(udp.clone());
    let stop_udp = Arc::new(AtomicBool::new(false));
    let udp_thread = {
        let (r, stop) = (relay.clone(), stop_udp.clone());
        std::thread::Builder::new()
            .name("rugen-bench-udp".into())
            .spawn(move || crate::udp::serve_until(udp, r, Some(stop)))
            .map_err(|e| format!("bench udp thread: {e}"))?
    };
    let store = Store::open(Some(dir)).map_err(|e| format!("bench store: {e}"))?;
    let api = Api::new(
        store,
        ApiConfig {
            name: format!("bench {id}"),
            udp_public: Some(udp_addr.to_string()),
            data: Some(dir.to_path_buf()),
            ..Default::default()
        },
        relay,
    );
    let out = match seed(&api) {
        Ok((fighter, stage)) => {
            serve_and_load(plan, &api, fighter, stage, deadline, last, id).await
        }
        Err(e) => Err(e),
    };
    stop_udp.store(true, Relaxed);
    let _ = tokio::task::spawn_blocking(move || udp_thread.join()).await;
    drop(api);
    out
}

async fn serve_and_load(
    plan: &Plan,
    api: &Arc<Api>,
    fighter: FighterDecl,
    stage: FighterDecl,
    deadline: Instant,
    last: &Mutex<Option<Run>>,
    id: &str,
) -> Result<Option<String>, String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bench http: {e}"))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(crate::http::serve(listener, api.clone(), async move {
        let _ = stop_rx.await;
    }));
    let engine = crate::compat::SIM_ENGINE.unwrap_or("0.6.2");
    let mut load = Load::new(addr, Mix::new(engine, fighter, stage));
    let out = steps(plan, &mut load, deadline, last, id).await;
    load.stop(Duration::from_secs(10)).await;
    let _ = stop_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(10), server).await;
    Ok(out)
}

/// The steps; `Some(why)` when the run aborted.
async fn steps(
    plan: &Plan,
    load: &mut Load,
    deadline: Instant,
    last: &Mutex<Option<Run>>,
    id: &str,
) -> Option<String> {
    for &target in &plan.steps {
        let aborted = |why: String| Some(format!("{target} clients: {why}"));
        if Instant::now() + plan.ramp + SETTLE + plan.hold > deadline {
            return aborted("the 5 minute limit".into());
        }
        load.grow(target as usize, plan.ramp).await;
        tokio::time::sleep(SETTLE).await;
        load.take();
        let p0 = proc_sample(None);
        let t0 = Instant::now();
        let mut threads = p0.threads;
        let mut rss = p0.rss_mb;
        let mut why = None;
        while t0.elapsed() < plan.hold {
            tokio::time::sleep(Duration::from_secs(1).min(plan.hold)).await;
            let p = proc_sample(None);
            threads = threads.max(p.threads);
            rss = rss.max(p.rss_mb);
            let (p99, err, calls) = load.peek();
            if calls >= 20 && p99 > ABORT_P99_MS {
                why = Some(format!("p99 {p99:.0} ms above {ABORT_P99_MS:.0} ms"));
            } else if calls >= 20 && err > ABORT_ERR {
                why = Some(format!("{:.1} % of the calls failed", err * 100.0));
            } else if Instant::now() > deadline {
                why = Some("the 5 minute limit".into());
            }
            if why.is_some() {
                break;
            }
        }
        let secs = t0.elapsed().as_secs_f64().max(0.001);
        let p1 = proc_sample(None);
        let s = load.take();
        let (alive, presence, _) = load.alive();
        let row = Row {
            clients: target,
            alive,
            presence,
            req_s: s.total() as f64 / secs,
            p50_ms: s.pct(0.5),
            p95_ms: s.pct(0.95),
            p99_ms: s.pct(0.99),
            errors: s.errors(),
            err_pct: s.err_rate() * 100.0,
            cpu_pct: (p1.cpu_secs - p0.cpu_secs) / secs * 100.0,
            rss_mb: rss.max(p1.rss_mb),
            threads: threads.max(p1.threads),
            relay_pkt_s: s.udp_sent as f64 / secs,
            matches: s.matches,
        };
        log::info!(
            "bench {id}: {target} clients, {:.0} req/s, p99 {:.1} ms, {:.2} % errors, CPU {:.0} %",
            row.req_s,
            row.p99_ms,
            row.err_pct,
            row.cpu_pct
        );
        if let Some(r) = lock(last).as_mut().filter(|r| r.id == id) {
            r.rows.push(row);
        }
        if let Some(w) = why {
            return aborted(w);
        }
    }
    None
}

/// `GET /admin/bench` body.
pub fn status_json(run: Option<Run>) -> Value {
    match run {
        Some(r) => json!(r),
        None => json!({ "state": "none", "note": NOTE }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_are_validated_and_limited() {
        let p = Plan::parse(&json!({"steps": [10, 20]})).unwrap();
        assert_eq!(p.hold, Duration::from_secs(40));
        assert_eq!(p.ramp, Duration::from_secs(10));
        for bad in [
            json!({}),
            json!({"steps": []}),
            json!({"steps": [0]}),
            json!({"steps": [5001]}),
            json!({"steps": [10], "mix": "other"}),
            json!({"steps": [10], "hold_secs": 500}),
            // 6 x (10 + 2 + 40) + 5 > 300 s
            json!({"steps": [1, 2, 3, 4, 5, 6]}),
        ] {
            assert!(Plan::parse(&bad).is_err(), "{bad}");
        }
        assert!(Plan::parse(&json!({"steps": [5000], "hold_secs": 60})).is_ok());
    }
}
