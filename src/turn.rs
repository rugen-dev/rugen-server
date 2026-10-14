//! Cloudflare Realtime TURN for matches: short-lived credentials per player
//! and match, under a hard monthly byte budget so the operator never pays.
//!
//! With `RUGEN_CF_TURN_KEY_ID` + `RUGEN_CF_TURN_TOKEN` set, the server asks
//! Cloudflare for one credential per player when a match enters its sync
//! phase (TTL = expected match length + margin) and puts a `turn`
//! transport first in both players' tickets. The players then relay their
//! ggrs traffic through Cloudflare's anycast TURN servers (the server only
//! forwards each one's relayed address to the other) and fall back to the
//! server relay on their own if TURN does not work.
//!
//! Budget (bytes, per UTC calendar month like Cloudflare's billing):
//! every credential reserves `ttl × rate × 2 directions × safety` when
//! issued and is settled down to `max(reported × safety, reservation / 4)`
//! when it ends (both players' clients report their TURN byte counters in
//! relay hellos). `used = max(reserved, client reports, Cloudflare
//! analytics)`; at `RUGEN_TURN_SOFT_PERCENT` only ranked matches still get
//! TURN, at the cap none (matches use the server relay). Credentials are
//! revoked as soon as a player reports the result, the relay session ends
//! or a credential's reported traffic passes its ceiling. Spectators never
//! get TURN. Per-account and per-IP caps limit TURN matches per hour / day.
//!
//! Secrets (the API token, credentials) are never logged.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rugen_proto::{RelayTransport, Rules};
use serde_json::{Value, json};

use crate::relay::Relay;
use crate::store::{Store, TurnMonth, now};
use crate::workers::Workers;

/// Cloudflare bills decimal gigabytes.
pub const GB: u64 = 1_000_000_000;
/// Cloudflare Realtime free allowance (SFU + TURN egress, per month).
pub const CF_FREE_GB: u64 = 1000;

#[derive(Clone)]
pub struct TurnConfig {
    pub key_id: String,
    token: String,
    /// `https://rtc.live.cloudflare.com/v1` (tests point it at a mock).
    pub api: String,
    pub graphql: String,
    /// Account id + API token with "Account Analytics: Read", to cross-check
    /// usage against Cloudflare's own numbers.
    analytics: Option<(String, String)>,
    /// Hard monthly cap in bytes.
    pub budget: u64,
    pub soft_percent: u64,
    pub per_hour: u32,
    pub per_day: u32,
    pub ip_per_hour: u32,
    pub ip_per_day: u32,
    /// Estimated bytes per second per player per direction.
    pub rate: u64,
    pub safety: f64,
    /// Longest credential life in seconds.
    pub ttl_max: u64,
}

impl std::fmt::Debug for TurnConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnConfig")
            .field("key_id", &self.key_id)
            .field("token", &"<redacted>")
            .field("analytics", &self.analytics.is_some())
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

impl TurnConfig {
    pub fn from_env() -> Option<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let get = |k: &str| {
            get(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let num = |k: &str, d: u64| get(k).and_then(|v| v.parse::<u64>().ok()).unwrap_or(d);
        let key_id = get("RUGEN_CF_TURN_KEY_ID")?;
        let token = get("RUGEN_CF_TURN_TOKEN")?;
        let analytics = get("RUGEN_CF_ACCOUNT_ID").zip(get("RUGEN_CF_ANALYTICS_TOKEN"));
        Some(Self {
            key_id,
            token,
            api: get("RUGEN_CF_TURN_API")
                .unwrap_or_else(|| "https://rtc.live.cloudflare.com/v1".into())
                .trim_end_matches('/')
                .to_string(),
            graphql: get("RUGEN_CF_GRAPHQL")
                .unwrap_or_else(|| "https://api.cloudflare.com/client/v4/graphql".into()),
            analytics,
            // half the free allowance by default; never more than the
            // allowance unless the operator says so explicitly
            budget: num("RUGEN_TURN_BUDGET_GB", CF_FREE_GB / 2).saturating_mul(GB),
            soft_percent: num("RUGEN_TURN_SOFT_PERCENT", 80).clamp(1, 100),
            per_hour: num("RUGEN_TURN_MAX_MATCHES_PER_HOUR", 12) as u32,
            per_day: num("RUGEN_TURN_MAX_MATCHES_PER_DAY", 60) as u32,
            ip_per_hour: num("RUGEN_TURN_MAX_MATCHES_PER_HOUR_IP", 24) as u32,
            ip_per_day: num("RUGEN_TURN_MAX_MATCHES_PER_DAY_IP", 120) as u32,
            rate: num("RUGEN_TURN_RATE_ESTIMATE", 8000).max(1000),
            safety: get("RUGEN_TURN_SAFETY")
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(2.0)
                .max(1.0),
            ttl_max: num("RUGEN_TURN_TTL_MAX", 1800).clamp(120, 48 * 3600),
        })
    }

    /// Bytes reserved for one player's credential living `ttl` seconds.
    pub fn reserve(&self, ttl: u64) -> u64 {
        (ttl as f64 * self.rate as f64 * 2.0 * self.safety) as u64
    }

    /// Reported bytes (both directions) above which a credential is revoked.
    pub fn ceiling(&self, ttl: u64) -> u64 {
        ttl * self.rate * 2 * 4
    }
}

/// Credential life for a match: every round played to the time limit
/// (infinite rounds count as 4 minutes), intros / KOs and a sync margin.
pub fn match_ttl(rules: &Rules, max: u64) -> u64 {
    let rounds = (2 * rules.rounds.clamp(1, 5) as u64).saturating_sub(1);
    let round = match rules.round_time {
        0 => 240,
        t => t.min(999) as u64,
    } + 25;
    (rounds * round + 90).clamp(180, max)
}

/// `YYYY-MM` (UTC) of a unix time.
pub fn month_of(unix: u64) -> String {
    // civil-from-days (Howard Hinnant)
    let z = (unix / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}")
}

/// First and last day (`YYYY-MM-DD`) of a `YYYY-MM` month.
fn month_days(month: &str) -> (String, String) {
    let (y, m) = month.split_once('-').unwrap_or(("1970", "01"));
    let (y, m): (i64, u32) = (y.parse().unwrap_or(1970), m.parse().unwrap_or(1));
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let last = match m {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (format!("{month}-01"), format!("{month}-{last:02}"))
}

/// One credential handed to a player.
struct Issued {
    username: String,
    match_id: u64,
    session: u32,
    slot: u8,
    created: Instant,
    ttl: u64,
    reserve: u64,
    month: String,
    reported: u64,
    done: bool,
}

/// Credentials fetched ahead of a match start.
struct Prepared {
    created: Instant,
    ttl: u64,
    players: [u64; 2],
    /// `None` while the request runs.
    result: Option<Result<Vec<(String, RelayTransport)>, String>>,
}

#[derive(Default)]
struct State {
    prepared: HashMap<u64, Prepared>,
    issued: Vec<Issued>,
    /// Issue times (unix) per `a:<account>` / `i:<ip>`, last 24 h.
    history: HashMap<String, VecDeque<u64>>,
    ips: HashMap<u64, (IpAddr, Instant)>,
    /// Cloudflare refused / failed: wait before asking again.
    backoff_until: Option<Instant>,
    month: String,
    last_poll: Option<Instant>,
    /// Cloudflare analytics result waiting to be stored.
    cf_usage: Option<(String, u64)>,
    warned: HashMap<&'static str, String>,
}

pub struct Turn {
    pub cfg: TurnConfig,
    agent: ureq::Agent,
    state: Mutex<State>,
    /// Cloudflare API calls (credentials, revocations, analytics) run on
    /// these few threads, never one thread per match.
    calls: Workers<Call>,
}

/// One background Cloudflare API call.
type Call = Box<dyn FnOnce() + Send>;
/// Threads making Cloudflare API calls.
const CALL_THREADS: usize = 2;
/// Calls waiting for them; a full queue skips TURN for a match (it starts
/// without, like when the credentials are late) or a revocation (the
/// credential then expires with its TTL, already paid for in the budget).
const CALL_QUEUE: usize = 256;

fn lock(m: &Mutex<State>) -> MutexGuard<'_, State> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Why a match gets no TURN (logged, numbers only).
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Budget,
    Soft,
    AccountCap,
    IpCap,
    Backoff,
}

impl Turn {
    pub fn new(cfg: TurnConfig) -> Arc<Self> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(8)))
            .http_status_as_error(false)
            .build()
            .into();
        Arc::new(Self {
            cfg,
            agent,
            state: Mutex::new(State {
                month: month_of(now()),
                ..Default::default()
            }),
            calls: Workers::spawn("rugen-turn", CALL_THREADS, CALL_QUEUE, 0, |call: Call| {
                call()
            })
            .expect("TURN API threads"),
        })
    }

    /// Remember where an account last called from (memory only, never
    /// logged or sent anywhere): the per-IP caps use it.
    pub fn note_ip(&self, account: u64, ip: IpAddr) {
        let mut s = lock(&self.state);
        if s.ips.len() > 100_000 {
            s.ips
                .retain(|_, (_, t)| t.elapsed() < Duration::from_secs(86_400));
        }
        s.ips.insert(account, (ip, Instant::now()));
    }

    /// Bytes a whole match reserves (two players).
    pub fn match_cost(&self, ttl: u64) -> u64 {
        2 * self.cfg.reserve(ttl)
    }

    #[cfg(test)]
    pub fn usage(&self, store: &Store) -> crate::store::DbResult<TurnMonth> {
        store.turn_usage(&month_of(now()))
    }

    /// May a match with `players` get TURN now?
    fn allowed(
        &self,
        s: &mut State,
        store: &Store,
        players: [u64; 2],
        ranked: bool,
        ttl: u64,
    ) -> Result<(), Refusal> {
        if s.backoff_until.is_some_and(|t| Instant::now() < t) {
            return Err(Refusal::Backoff);
        }
        let month = month_of(now());
        let used = store
            .turn_usage(&month)
            .map(|u| u.used())
            .unwrap_or(u64::MAX);
        if used.saturating_add(self.match_cost(ttl)) > self.cfg.budget {
            if s.warned.get("hard") != Some(&month) {
                log::warn!(
                    "turn: monthly budget reached ({:.2} of {:.0} GB); matches use the server relay until next month",
                    used as f64 / GB as f64,
                    self.cfg.budget as f64 / GB as f64
                );
                s.warned.insert("hard", month);
            }
            return Err(Refusal::Budget);
        }
        if used.saturating_mul(100) >= self.cfg.budget.saturating_mul(self.cfg.soft_percent) {
            if s.warned.get("soft") != Some(&month) {
                log::warn!(
                    "turn: {:.2} of {:.0} GB used this month (≥ {} %): TURN for ranked matches only",
                    used as f64 / GB as f64,
                    self.cfg.budget as f64 / GB as f64,
                    self.cfg.soft_percent
                );
                s.warned.insert("soft", month);
            }
            if !ranked {
                return Err(Refusal::Soft);
            }
        }
        let t = now();
        let count = |s: &mut State, key: String, hour: u32, day: u32| {
            let h = s.history.entry(key).or_default();
            while h.front().is_some_and(|&x| x + 86_400 <= t) {
                h.pop_front();
            }
            let last_hour = h.iter().filter(|&&x| x + 3600 > t).count() as u32;
            last_hour < hour && (h.len() as u32) < day
        };
        for p in players {
            if !count(s, format!("a:{p}"), self.cfg.per_hour, self.cfg.per_day) {
                return Err(Refusal::AccountCap);
            }
            if let Some((ip, _)) = s.ips.get(&p).copied()
                && !count(
                    s,
                    format!("i:{ip}"),
                    self.cfg.ip_per_hour,
                    self.cfg.ip_per_day,
                )
            {
                return Err(Refusal::IpCap);
            }
        }
        Ok(())
    }

    /// Start fetching credentials for a match about to start (sync phase).
    /// Idempotent; does nothing when the match may not use TURN.
    pub fn prepare(
        self: &Arc<Self>,
        store: &Store,
        match_id: u64,
        players: [u64; 2],
        ranked: bool,
        rules: &Rules,
    ) {
        let ttl = match_ttl(rules, self.cfg.ttl_max);
        {
            let mut s = lock(&self.state);
            if s.prepared.contains_key(&match_id) {
                return;
            }
            if let Err(why) = self.allowed(&mut s, store, players, ranked, ttl) {
                log::debug!("turn: match {match_id} without TURN ({why:?})");
                return;
            }
            s.prepared.insert(
                match_id,
                Prepared {
                    created: Instant::now(),
                    ttl,
                    players,
                    result: None,
                },
            );
        }
        let me = self.clone();
        let queued = self.calls.submit(Box::new(move || {
            let r = (0..2)
                .map(|_| me.generate(ttl))
                .collect::<Result<Vec<_>, String>>();
            let mut s = lock(&me.state);
            if let Err(e) = &r {
                log::warn!("turn: credentials for match {match_id} failed: {e}");
                s.backoff_until = Some(Instant::now() + Duration::from_secs(60));
            }
            if let Some(p) = s.prepared.get_mut(&match_id) {
                p.result = Some(r);
            } else if let Ok(v) = r {
                drop(s);
                me.revoke(v.into_iter().map(|(u, _)| u).collect());
            }
        }));
        if !queued {
            // the match starts without TURN
            lock(&self.state).prepared.remove(&match_id);
        }
    }

    /// The `turn` transports for P1 and P2 if credentials are ready (the
    /// match starts now). Reserves the budget. Empty = no TURN.
    pub fn take(&self, store: &Store, match_id: u64, session: u32) -> Vec<Option<RelayTransport>> {
        let mut s = lock(&self.state);
        let Some(p) = s.prepared.get(&match_id) else {
            return Vec::new();
        };
        let Some(Ok(_)) = &p.result else {
            // still running (or failed): start without; a late answer is
            // revoked by the sweep
            return Vec::new();
        };
        let Some(p) = s.prepared.remove(&match_id) else {
            return Vec::new();
        };
        let Some(Ok(creds)) = p.result else {
            return Vec::new();
        };
        let users: Vec<String> = creds.iter().map(|(u, _)| u.clone()).collect();
        // the budget may have moved since prepare
        let month = month_of(now());
        let cost = self.match_cost(p.ttl);
        let used = store
            .turn_usage(&month)
            .map(|u| u.used())
            .unwrap_or(u64::MAX);
        if used.saturating_add(cost) > self.cfg.budget
            || store.turn_add(&month, cost as i64, 0, 2).is_err()
        {
            drop(s);
            self.revoke(users);
            return Vec::new();
        }
        let t = now();
        for a in p.players {
            s.history.entry(format!("a:{a}")).or_default().push_back(t);
            if let Some((ip, _)) = s.ips.get(&a).copied() {
                s.history.entry(format!("i:{ip}")).or_default().push_back(t);
            }
        }
        let reserve = self.cfg.reserve(p.ttl);
        for (slot, (username, _)) in creds.iter().enumerate() {
            s.issued.push(Issued {
                username: username.clone(),
                match_id,
                session,
                slot: slot as u8,
                created: Instant::now(),
                ttl: p.ttl,
                reserve,
                month: month.clone(),
                reported: 0,
                done: false,
            });
        }
        log::info!(
            "turn: match {match_id} relays through Cloudflare TURN (ttl {} s, {:.1} MB reserved)",
            p.ttl,
            cost as f64 / 1e6
        );
        creds.into_iter().map(|(_, t)| Some(t)).collect()
    }

    /// A player reported the result: its credential is no longer needed.
    pub fn finished(&self, store: &Store, match_id: u64, slot: u8, reported: Option<u64>) {
        let mut done = Vec::new();
        {
            let mut s = lock(&self.state);
            for i in s.issued.iter_mut() {
                if i.match_id == match_id && i.slot == slot && !i.done {
                    if let Some(r) = reported {
                        i.reported = i.reported.max(r);
                    }
                    i.done = true;
                    done.push(i.username.clone());
                    self.settle(store, i);
                }
            }
            s.issued.retain(|i| !i.done);
        }
        self.revoke(done);
    }

    /// Give back the unused part of a credential's reservation.
    fn settle(&self, store: &Store, i: &Issued) {
        let actual = (i.reported as f64 * self.cfg.safety) as u64;
        let charge = actual.max(i.reserve / 4);
        let delta = charge as i64 - i.reserve as i64;
        if let Err(e) = store.turn_add(&i.month, delta, i.reported, 0) {
            log::error!("turn: accounting: {e}");
        }
    }

    /// Periodic housekeeping: settle / revoke ended credentials, enforce
    /// per-credential ceilings, drop stale prepared credentials, store
    /// Cloudflare's analytics, log the month. Never holds the relay lock
    /// together with the state lock.
    pub fn sweep(self: &Arc<Self>, store: &Store, relay: &Relay) {
        let keys: Vec<(u32, u8)> = lock(&self.state)
            .issued
            .iter()
            .map(|i| (i.session, i.slot))
            .collect();
        let bytes: Vec<Option<(u64, u64)>> = keys
            .iter()
            .map(|&(id, slot)| relay.turn_bytes(id, slot))
            .collect();
        let mut revoke = Vec::new();
        {
            let mut s = lock(&self.state);
            let s = &mut *s;
            for (i, b) in s.issued.iter_mut().zip(bytes) {
                if let Some((rx, tx)) = b {
                    i.reported = i.reported.max(rx + tx);
                }
                let expired = i.created.elapsed() >= Duration::from_secs(i.ttl);
                let over = i.reported > self.cfg.ceiling(i.ttl);
                if over {
                    log::warn!(
                        "turn: match {} slot {} passed its traffic ceiling ({} bytes), revoking",
                        i.match_id,
                        i.slot,
                        i.reported
                    );
                }
                if b.is_none() || expired || over {
                    i.done = true;
                    self.settle(store, i);
                    if !expired {
                        revoke.push(i.username.clone());
                    }
                }
            }
            s.issued.retain(|i| !i.done);
            s.prepared.retain(|_, p| {
                let stale = p.created.elapsed() > Duration::from_secs(600);
                if stale && let Some(Ok(v)) = &p.result {
                    revoke.extend(v.iter().map(|(u, _)| u.clone()));
                }
                !stale
            });
            let month = month_of(now());
            if let Some((m, b)) = s.cf_usage.take()
                && let Err(e) = store.turn_set_cloudflare(&m, b)
            {
                log::error!("turn: accounting: {e}");
            }
            if month != s.month {
                let old = std::mem::replace(&mut s.month, month.clone());
                if let Ok(u) = store.turn_usage(&old) {
                    log_month(&old, &u, self.cfg.budget);
                }
            }
            if self.cfg.analytics.is_some()
                && s.last_poll
                    .is_none_or(|t| t.elapsed() >= Duration::from_secs(900))
            {
                s.last_poll = Some(Instant::now());
                let me = self.clone();
                self.calls
                    .submit(Box::new(move || match me.cloudflare_usage(&month) {
                        Ok(b) => lock(&me.state).cf_usage = Some((month, b)),
                        Err(e) => log::warn!("turn: Cloudflare analytics: {e}"),
                    }));
            }
        }
        self.revoke(revoke);
    }

    /// Numbers for `/health`.
    pub fn status(&self, store: &Store) -> Value {
        let month = month_of(now());
        let u = store.turn_usage(&month).unwrap_or_default();
        let used = u.used();
        json!({
            "month": month,
            "used_gb": (used as f64 / GB as f64 * 1000.0).round() / 1000.0,
            "cap_gb": self.cfg.budget as f64 / GB as f64,
            "issuing": used < self.cfg.budget,
            "ranked_only": used.saturating_mul(100) >= self.cfg.budget.saturating_mul(self.cfg.soft_percent),
            "matches": u.credentials / 2,
        })
    }

    pub fn log_startup(&self, store: &Store) {
        let month = month_of(now());
        if let Ok(u) = store.turn_usage(&month) {
            log::info!(
                "turn: Cloudflare TURN on (key {}…), {month}: {:.2} of {:.0} GB used",
                self.cfg.key_id.chars().take(6).collect::<String>(),
                u.used() as f64 / GB as f64,
                self.cfg.budget as f64 / GB as f64
            );
        }
        if self.cfg.budget > CF_FREE_GB * GB {
            log::warn!(
                "turn: RUGEN_TURN_BUDGET_GB is above Cloudflare's free {CF_FREE_GB} GB per month"
            );
        }
    }

    // ---- Cloudflare API

    fn post(&self, url: &str, token: &str, body: &Value) -> Result<(u16, String), String> {
        let mut r = self
            .agent
            .post(url)
            .header("Authorization", &format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .send(body.to_string())
            .map_err(|e| e.to_string())?;
        let status = r.status().as_u16();
        let text = r
            .body_mut()
            .with_config()
            .limit(1 << 20)
            .read_to_string()
            .map_err(|e| e.to_string())?;
        Ok((status, text))
    }

    /// One credential: (username, ticket transport).
    fn generate(&self, ttl: u64) -> Result<(String, RelayTransport), String> {
        let url = format!(
            "{}/turn/keys/{}/credentials/generate-ice-servers",
            self.cfg.api, self.cfg.key_id
        );
        let (status, text) = self.post(&url, &self.cfg.token, &json!({ "ttl": ttl }))?;
        if !(200..300).contains(&status) {
            return Err(format!("HTTP {status}"));
        }
        let v: Value = serde_json::from_str(&text).map_err(|_| "bad JSON".to_string())?;
        parse_ice_servers(&v, now() + ttl).ok_or_else(|| "no TURN server in answer".into())
    }

    /// Revoke credentials in the background (best effort).
    fn revoke(&self, users: Vec<String>) {
        if users.is_empty() {
            return;
        }
        let (api, key, token, agent) = (
            self.cfg.api.clone(),
            self.cfg.key_id.clone(),
            self.cfg.token.clone(),
            self.agent.clone(),
        );
        self.calls.submit(Box::new(move || {
            for u in users {
                let url = format!("{api}/turn/keys/{key}/credentials/{u}/revoke");
                let r = agent
                    .post(&url)
                    .header("Authorization", &format!("Bearer {token}"))
                    .send_empty();
                match r {
                    Ok(r) if r.status().is_success() => {}
                    Ok(r) => log::debug!("turn: revoke: HTTP {}", r.status().as_u16()),
                    Err(e) => log::debug!("turn: revoke: {e}"),
                }
            }
        }));
    }

    /// This month's TURN bytes (egress + ingress) from Cloudflare's GraphQL
    /// analytics for our key.
    fn cloudflare_usage(&self, month: &str) -> Result<u64, String> {
        let Some((account, token)) = &self.cfg.analytics else {
            return Err("not configured".into());
        };
        let (from, to) = month_days(month);
        let query = "query TurnUsage($account: String!, $key: String!, $from: Date!, $to: Date!) { \
            viewer { accounts(filter: { accountTag: $account }) { \
            callsTurnUsageAdaptiveGroups(limit: 1, filter: { keyId: $key, date_geq: $from, date_leq: $to }) { \
            sum { egressBytes ingressBytes } } } } }";
        let body = json!({
            "query": query,
            "variables": { "account": account, "key": self.cfg.key_id, "from": from, "to": to },
        });
        let (status, text) = self.post(&self.cfg.graphql, token, &body)?;
        if !(200..300).contains(&status) {
            return Err(format!("HTTP {status}"));
        }
        let v: Value = serde_json::from_str(&text).map_err(|_| "bad JSON".to_string())?;
        if let Some(e) = v
            .get("errors")
            .and_then(Value::as_array)
            .filter(|e| !e.is_empty())
        {
            return Err(format!("{} error(s)", e.len()));
        }
        let groups = v
            .pointer("/data/viewer/accounts/0/callsTurnUsageAdaptiveGroups")
            .and_then(Value::as_array)
            .ok_or("unexpected answer")?;
        Ok(groups
            .iter()
            .map(|g| {
                let n = |k: &str| g.pointer(&format!("/sum/{k}")).and_then(Value::as_u64);
                n("egressBytes").unwrap_or(0) + n("ingressBytes").unwrap_or(0)
            })
            .sum())
    }
}

fn log_month(month: &str, u: &TurnMonth, budget: u64) {
    log::info!(
        "turn: {month} closed: {} matches, {:.3} GB counted (reported {:.3} GB, Cloudflare {:.3} GB) of {:.0} GB",
        u.credentials / 2,
        u.used() as f64 / GB as f64,
        u.reported as f64 / GB as f64,
        u.cloudflare as f64 / GB as f64,
        budget as f64 / GB as f64
    );
}

/// `generate-ice-servers` answer → (username, `turn` transport). STUN-only
/// entries and port 53 URLs are dropped.
pub fn parse_ice_servers(v: &Value, expires: u64) -> Option<(String, RelayTransport)> {
    for s in v.get("iceServers")?.as_array()? {
        let (Some(user), Some(cred)) = (
            s.get("username").and_then(Value::as_str),
            s.get("credential").and_then(Value::as_str),
        ) else {
            continue;
        };
        let urls: Vec<String> = match s.get("urls")? {
            Value::String(u) => vec![u.clone()],
            Value::Array(a) => a
                .iter()
                .filter_map(|u| u.as_str().map(String::from))
                .collect(),
            _ => continue,
        }
        .into_iter()
        .filter(|u| u.starts_with("turn:") || u.starts_with("turns:"))
        .filter(|u| !u.contains(":53?") && !u.ends_with(":53"))
        .collect();
        if !urls.is_empty() {
            return Some((
                user.to_string(),
                RelayTransport::turn(urls, user, cred, expires),
            ));
        }
    }
    None
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A stand-in for Cloudflare: generate-ice-servers, revoke, GraphQL.
    pub(crate) struct MockCf {
        pub url: String,
        pub generated: Arc<AtomicUsize>,
        pub revoked: Arc<Mutex<Vec<String>>>,
        pub auth_seen: Arc<Mutex<Vec<String>>>,
    }

    pub(crate) fn mock_cf(cf_bytes: u64) -> MockCf {
        mock_cf_with(cf_bytes, None)
    }

    /// `real`: hand out these TURN urls / username / password (a local
    /// coturn) instead of fake ones.
    pub(crate) fn mock_cf_with(
        cf_bytes: u64,
        real: Option<(Vec<String>, String, String)>,
    ) -> MockCf {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let generated = Arc::new(AtomicUsize::new(0));
        let revoked = Arc::new(Mutex::new(Vec::new()));
        let auth_seen = Arc::new(Mutex::new(Vec::new()));
        let (g, r, a) = (generated.clone(), revoked.clone(), auth_seen.clone());
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(mut c) = c else { continue };
                let mut rd = BufReader::new(c.try_clone().unwrap());
                let mut line = String::new();
                if rd.read_line(&mut line).is_err() {
                    continue;
                }
                let path = line.split(' ').nth(1).unwrap_or("").to_string();
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    if rd.read_line(&mut h).is_err() || h == "\r\n" || h.is_empty() {
                        break;
                    }
                    let lower = h.to_ascii_lowercase();
                    if let Some(v) = lower.strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                    if let Some(v) = lower.strip_prefix("authorization:") {
                        a.lock().unwrap().push(v.trim().to_string());
                    }
                }
                let mut body = vec![0; len];
                let _ = rd.read_exact(&mut body);
                let (status, out) = if path.ends_with("/generate-ice-servers") {
                    let n = g.fetch_add(1, Ordering::SeqCst);
                    let ttl = serde_json::from_slice::<Value>(&body)
                        .ok()
                        .and_then(|v| v["ttl"].as_u64())
                        .unwrap_or(0);
                    let (urls, user, cred) = real.clone().unwrap_or_else(|| {
                        (
                            vec![
                                "turn:turn.example:3478?transport=udp".into(),
                                "turn:turn.example:53?transport=udp".into(),
                                "turns:turn.example:443?transport=tcp".into(),
                            ],
                            format!("user{n}-ttl{ttl}"),
                            format!("secret{n}"),
                        )
                    });
                    (
                        "201 Created",
                        json!({"iceServers": [
                            {"urls": ["stun:stun.example:3478"]},
                            {"urls": urls, "username": user, "credential": cred}
                        ]})
                        .to_string(),
                    )
                } else if path.ends_with("/revoke") {
                    let u = path.rsplit('/').nth(1).unwrap_or("").to_string();
                    r.lock().unwrap().push(u);
                    ("204 No Content", String::new())
                } else if path.ends_with("/graphql") {
                    (
                        "200 OK",
                        json!({"data": {"viewer": {"accounts": [{"callsTurnUsageAdaptiveGroups": [
                            {"sum": {"egressBytes": cf_bytes / 2, "ingressBytes": cf_bytes - cf_bytes / 2}}
                        ]}]}}, "errors": null})
                        .to_string(),
                    )
                } else {
                    ("404 Not Found", String::new())
                };
                let _ = write!(
                    c,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}",
                    out.len()
                );
            }
        });
        MockCf {
            url,
            generated,
            revoked,
            auth_seen,
        }
    }

    pub(crate) fn config(url: &str, extra: &[(&str, &str)]) -> TurnConfig {
        let mut env: HashMap<String, String> = [
            ("RUGEN_CF_TURN_KEY_ID", "key123"),
            ("RUGEN_CF_TURN_TOKEN", "tok-secret"),
            ("RUGEN_CF_TURN_API", url),
            ("RUGEN_CF_GRAPHQL", &format!("{url}/graphql")),
        ]
        .iter()
        .chain(extra)
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        env.retain(|_, v| !v.is_empty());
        TurnConfig::from_lookup(|k| env.get(k).cloned()).unwrap()
    }

    fn wait_ready(t: &Turn, id: u64) {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            if lock(&t.state)
                .prepared
                .get(&id)
                .is_some_and(|p| p.result.is_some())
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("credentials never arrived");
    }

    #[test]
    fn config_needs_both_secrets_and_never_prints_them() {
        assert!(TurnConfig::from_lookup(|_| None).is_none());
        assert!(
            TurnConfig::from_lookup(|k| (k == "RUGEN_CF_TURN_KEY_ID").then(|| "k".into()))
                .is_none()
        );
        let c = config("http://x", &[]);
        assert_eq!(c.budget, 500 * GB);
        assert!(!format!("{c:?}").contains("tok-secret"));
    }

    #[test]
    fn months_and_ttls() {
        assert_eq!(month_of(0), "1970-01");
        assert_eq!(month_of(1_706_745_599), "2024-01"); // 2024-01-31 23:59:59
        assert_eq!(month_of(1_706_745_600), "2024-02");
        assert_eq!(month_of(1_709_251_199), "2024-02"); // leap day end
        assert_eq!(month_of(1_791_763_200), "2026-10");
        assert_eq!(
            month_days("2024-02"),
            ("2024-02-01".into(), "2024-02-29".into())
        );
        assert_eq!(month_days("2026-11").1, "2026-11-30");
        let r = Rules::default(); // 2 rounds to win, 99 s
        assert_eq!(match_ttl(&r, 1800), 3 * (99 + 25) + 90);
        let inf = Rules {
            round_time: 0,
            rounds: 5,
            ..Default::default()
        };
        assert_eq!(match_ttl(&inf, 1800), 1800);
    }

    #[test]
    fn ice_servers_are_parsed() {
        let v = json!({"iceServers": [
            {"urls": ["stun:stun.cloudflare.com:3478"]},
            {"urls": ["turn:turn.cloudflare.com:3478?transport=udp",
                      "turn:turn.cloudflare.com:53?transport=udp"],
             "username": "u", "credential": "c"}]});
        let (u, t) = parse_ice_servers(&v, 9).unwrap();
        assert_eq!(u, "u");
        assert_eq!(t.kind, "turn");
        assert_eq!(t.urls, vec!["turn:turn.cloudflare.com:3478?transport=udp"]);
        assert_eq!((t.credential.as_str(), t.expires), ("c", 9));
        assert!(parse_ice_servers(&json!({"iceServers": []}), 0).is_none());
    }

    fn players(s: &mut Store) -> [u64; 2] {
        [s.register().unwrap().id, s.register().unwrap().id]
    }

    #[test]
    fn credentials_are_issued_reserved_settled_and_revoked() {
        let cf = mock_cf(0);
        let t = Turn::new(config(&cf.url, &[]));
        let mut store = Store::open(None).unwrap();
        let p = players(&mut store);
        let rules = Rules::default();
        t.prepare(&store, 7, p, false, &rules);
        wait_ready(&t, 7);
        let tr = t.take(&store, 7, 0xAB);
        assert_eq!(tr.len(), 2);
        let a = tr[0].as_ref().unwrap();
        let ttl = match_ttl(&rules, 1800);
        assert!(a.username.ends_with(&format!("ttl{ttl}")), "{}", a.username);
        assert_eq!(a.urls.len(), 2, "port 53 dropped");
        assert_ne!(a.username, tr[1].as_ref().unwrap().username);
        assert!(
            cf.auth_seen
                .lock()
                .unwrap()
                .iter()
                .all(|h| h == "bearer tok-secret")
        );
        let u = t.usage(&store).unwrap();
        assert_eq!(u.reserved, t.match_cost(ttl));
        assert_eq!(u.credentials, 2);
        // P1 reports: its credential is settled to a quarter (no traffic
        // reported) and revoked
        t.finished(&store, 7, 0, Some(0));
        let after = t.usage(&store).unwrap();
        let r = t.cfg.reserve(ttl);
        assert_eq!(after.reserved, u.reserved - (r - r / 4));
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(*cf.revoked.lock().unwrap(), vec![a.username.clone()]);
        // the relay session is gone: P2's credential ends too
        let relay = Relay::default();
        t.sweep(&store, &relay);
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(cf.revoked.lock().unwrap().len(), 2);
        assert!(lock(&t.state).issued.is_empty());
        // taking twice gives nothing
        assert!(t.take(&store, 7, 0xAB).is_empty());
    }

    #[test]
    fn heavy_reported_traffic_is_charged_and_cut() {
        let cf = mock_cf(0);
        let t = Turn::new(config(&cf.url, &[]));
        let mut store = Store::open(None).unwrap();
        let p = players(&mut store);
        let relay = Relay::default();
        let (session, tokens) = relay.create(&p).unwrap();
        t.prepare(&store, 8, p, true, &Rules::default());
        wait_ready(&t, 8);
        assert_eq!(t.take(&store, 8, session).len(), 2);
        let ttl = match_ttl(&Rules::default(), 1800);
        let before = t.usage(&store).unwrap().reserved;
        // P2 claims (via its hello) far more traffic than the ceiling
        let huge = t.cfg.ceiling(ttl) + 1;
        let mut hello = huge.to_be_bytes().to_vec();
        hello.extend(0u64.to_be_bytes());
        let pkt = rugen_proto::relay::encode_client(
            rugen_proto::relay::Header {
                kind: rugen_proto::relay::HELLO,
                from: 1,
                to: 0,
                session,
            },
            &tokens[1],
            &hello,
        );
        let (c, _rx) = relay.ws_connect();
        relay.on_packet(&pkt, &crate::relay::Route::Ws(c), Instant::now());
        t.sweep(&store, &relay);
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(cf.revoked.lock().unwrap().len(), 1, "P2 revoked");
        let after = t.usage(&store).unwrap();
        // charged what it reported (× safety) instead of the reservation
        let expect = before - t.cfg.reserve(ttl) + (huge as f64 * t.cfg.safety) as u64;
        assert_eq!(after.reserved, expect);
        assert_eq!(after.reported, huge);
    }

    #[test]
    fn budget_soft_limit_caps_and_month_rollover() {
        let cf = mock_cf(0);
        let mut store = Store::open(None).unwrap();
        // a budget for exactly two default matches
        let probe = Turn::new(config(&cf.url, &[]));
        let cost = probe.match_cost(match_ttl(&Rules::default(), 1800));
        let gb = (2 * cost).div_ceil(GB).max(1);
        let t = Turn::new(config(
            &cf.url,
            &[
                ("RUGEN_TURN_BUDGET_GB", &gb.to_string()),
                ("RUGEN_TURN_MAX_MATCHES_PER_HOUR", "2"),
            ],
        ));
        let month = month_of(now());
        let budget = t.cfg.budget;
        let p = players(&mut store);
        let mut state = State::default();
        assert_eq!(
            t.allowed(&mut state, &store, p, false, 400),
            Ok(()),
            "fresh month"
        );
        // just below the soft line: everyone; above it: ranked only
        store
            .turn_add(&month, (budget * 79 / 100) as i64, 0, 0)
            .unwrap();
        assert_eq!(t.allowed(&mut state, &store, p, false, 1), Ok(()));
        store.turn_add(&month, (budget / 50) as i64, 0, 0).unwrap();
        assert_eq!(
            t.allowed(&mut state, &store, p, false, 1),
            Err(Refusal::Soft)
        );
        assert_eq!(t.allowed(&mut state, &store, p, true, 1), Ok(()));
        // at the cap: nobody, and no turn transport is handed out
        store.turn_add(&month, budget as i64, 0, 0).unwrap();
        assert_eq!(
            t.allowed(&mut state, &store, p, true, 1),
            Err(Refusal::Budget)
        );
        t.prepare(&store, 9, p, true, &Rules::default());
        assert!(t.take(&store, 9, 1).is_empty());
        assert_eq!(
            cf.generated.load(Ordering::SeqCst),
            0,
            "Cloudflare not asked"
        );
        // Cloudflare's own number counts when it is higher
        store.turn_set_cloudflare("1999-01", 5).unwrap();
        assert_eq!(store.turn_usage("1999-01").unwrap().used(), 5);
        // a new month starts from zero
        assert_eq!(store.turn_usage("2999-12").unwrap().used(), 0);
        // per-account cap: 2 TURN matches per hour
        let t2 = Turn::new(config(&cf.url, &[("RUGEN_TURN_MAX_MATCHES_PER_HOUR", "2")]));
        let mut fresh = Store::open(None).unwrap();
        let q = players(&mut fresh);
        for id in 0..3u64 {
            t2.prepare(&fresh, 100 + id, q, false, &Rules::default());
            if id < 2 {
                wait_ready(&t2, 100 + id);
                assert_eq!(t2.take(&fresh, 100 + id, 5).len(), 2);
            } else {
                assert!(t2.take(&fresh, 100 + id, 5).is_empty(), "third refused");
            }
        }
        // per-IP cap counts different accounts behind one address
        let t3 = Turn::new(config(
            &cf.url,
            &[("RUGEN_TURN_MAX_MATCHES_PER_HOUR_IP", "1")],
        ));
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let (r1, r2) = (players(&mut fresh), players(&mut fresh));
        t3.note_ip(r1[0], ip);
        t3.note_ip(r2[1], ip);
        t3.prepare(&fresh, 200, r1, false, &Rules::default());
        wait_ready(&t3, 200);
        assert_eq!(t3.take(&fresh, 200, 6).len(), 2);
        let mut st = lock(&t3.state);
        assert_eq!(
            t3.allowed(&mut st, &fresh, r2, false, 400),
            Err(Refusal::IpCap)
        );
    }

    #[test]
    fn usage_survives_a_restart_and_cloudflare_numbers_are_polled() {
        let dir = std::env::temp_dir().join(format!("rugen-turn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let month = month_of(now());
        {
            let s = Store::open(Some(&dir)).unwrap();
            s.turn_add(&month, 1234, 56, 2).unwrap();
        }
        let s = Store::open(Some(&dir)).unwrap();
        let u = s.turn_usage(&month).unwrap();
        assert_eq!((u.reserved, u.reported, u.credentials), (1234, 56, 2));
        // analytics: Cloudflare reports more than we counted → that wins
        let cf = mock_cf(9_000_000);
        let t = Turn::new(config(
            &cf.url,
            &[
                ("RUGEN_CF_ACCOUNT_ID", "acc"),
                ("RUGEN_CF_ANALYTICS_TOKEN", "an-secret"),
            ],
        ));
        assert_eq!(t.cloudflare_usage(&month).unwrap(), 9_000_000);
        let relay = Relay::default();
        t.sweep(&s, &relay); // starts the poll
        let start = Instant::now();
        while lock(&t.state).cf_usage.is_none() && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        t.sweep(&s, &relay); // stores it
        assert_eq!(s.turn_usage(&month).unwrap().used(), 9_000_000);
        let st = t.status(&s);
        assert_eq!(st["month"], month);
        assert_eq!(st["issuing"], true);
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
