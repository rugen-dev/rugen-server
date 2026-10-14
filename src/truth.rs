//! Official vs community servers, signatures and the global truth feed.
//!
//! Every server signs with an Ed25519 key (`RUGEN_SIGNING_KEY`,
//! `RUGEN_SIGNING_KEY_FILE` or `<data>/signing.key`, generated on first
//! start). The **official** server is the one whose key is the official key
//! baked into the game (`rugen_fair::trust::OFFICIAL_KEY`, overridable here
//! with `RUGEN_OFFICIAL_KEY`); every other server is a community server.
//!
//! * `GET /v1/truth`: this server's blocklist + community ratings, signed.
//!   Only the official server's feed means anything to players.
//! * Community servers pull the official feed (`RUGEN_OFFICIAL_URL`, every
//!   `RUGEN_OFFICIAL_PULL` seconds), verify it against the official key,
//!   reject stale / rolled-back copies, and enforce its blocklist in their
//!   matchup verdicts ("blocked by the official server"). They mirror the
//!   verified blob at `GET /v1/truth/official`.
//! * Verdicts and settled results are signed ([`Truth::sign`]); clients only
//!   show OFFICIAL stamps for signatures by the official key.
//! * Moderation: the blocklist is edited by the operator (admin API with
//!   `RUGEN_ADMIN_TOKEN`, or `--block` / `--unblock` on the command line)
//!   and by automatic rules (server analysis, repeated profile lies,
//!   repeated desyncs; [`AutoBlock`]).

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rugen_fair::trust::{self, PublicKey, SigningKey, TrustError};
use rugen_proto::{CharRating, SignedBlob, TRUST_VERSION, TruthFeed};
use serde::Serialize;

use crate::store::{DbResult, Store};

/// Automatic blocklist rules (0 disables a counter rule).
#[derive(Clone, Debug, PartialEq)]
pub struct AutoBlock {
    /// Distinct players caught declaring a false profile for a fingerprint.
    pub liars: u32,
    /// Matches with a reported desync a fingerprint took part in.
    pub desyncs: u32,
    /// The server's own analysis of an uploaded package finds a block-level cheat.
    pub analysis: bool,
}

impl Default for AutoBlock {
    fn default() -> Self {
        Self {
            liars: 3,
            desyncs: 10,
            analysis: true,
        }
    }
}

pub struct TruthConfig {
    /// This server's signing key (`None`: signs nothing, tests only).
    pub key: Option<SigningKey>,
    /// Whose feed and signatures are official.
    pub official_key: Option<PublicKey>,
    /// Where community servers pull the official feed from (`None` = never).
    pub official_url: Option<String>,
    pub pull_secs: u64,
    /// `RUGEN_ADMIN_TOKEN`: enables the admin API.
    pub admin_token: Option<String>,
    pub auto: AutoBlock,
}

impl Default for TruthConfig {
    fn default() -> Self {
        Self {
            key: None,
            official_key: trust::official_key(),
            official_url: None,
            pull_secs: 900,
            admin_token: None,
            auto: AutoBlock::default(),
        }
    }
}

fn env(k: &str) -> Option<String> {
    std::env::var(k)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// `https://host/` → `https://host`; `host:port` → `http://host:port`.
pub fn base_url(s: &str) -> String {
    let s = s.trim().trim_end_matches('/');
    if s.contains("://") {
        s.to_string()
    } else {
        format!("http://{s}")
    }
}

/// The signing key: `RUGEN_SIGNING_KEY` (seed, hex / base64), else
/// `RUGEN_SIGNING_KEY_FILE`, else `<data>/signing.key`, else a new key
/// written there. Returns the key and where it came from.
pub fn load_key(data: &Path) -> Result<(SigningKey, String), String> {
    if let Some(v) = env("RUGEN_SIGNING_KEY") {
        let k = SigningKey::parse(&v)
            .ok_or("RUGEN_SIGNING_KEY: expected a 32-byte seed (64 hex digits or base64)")?;
        return Ok((k, "RUGEN_SIGNING_KEY".into()));
    }
    let (path, must_exist) = match env("RUGEN_SIGNING_KEY_FILE") {
        Some(f) => (PathBuf::from(f), true),
        None => (data.join("signing.key"), false),
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let k = SigningKey::parse(text.trim())
                .ok_or_else(|| format!("{}: not a 32-byte seed", path.display()))?;
            Ok((k, path.display().to_string()))
        }
        Err(e) if must_exist => Err(format!("{}: {e}", path.display())),
        Err(_) => {
            let k = SigningKey::generate().map_err(|e| e.to_string())?;
            write_secret(&path, &format!("{}\n", k.seed_hex()))
                .map_err(|e| format!("{}: {e}", path.display()))?;
            Ok((k, format!("{} (new community key)", path.display())))
        }
    }
}

fn write_secret(path: &Path, text: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(text.as_bytes())
    }
    #[cfg(not(unix))]
    std::fs::write(path, text)
}

impl TruthConfig {
    /// From the environment (see the module docs); `key` loaded by the caller.
    pub fn from_env(key: Option<SigningKey>) -> Result<Self, String> {
        let official_key = match env("RUGEN_OFFICIAL_KEY") {
            Some(v) => Some(
                PublicKey::parse(&v).ok_or("RUGEN_OFFICIAL_KEY: expected a 32-byte public key")?,
            ),
            None => trust::official_key(),
        };
        let mut cfg = Self {
            key,
            official_key,
            ..Self::default()
        };
        cfg.official_url = match env("RUGEN_OFFICIAL_URL").as_deref() {
            Some("off" | "none" | "0" | "false") => None,
            Some(u) => Some(base_url(u)),
            None => Some(base_url(trust::OFFICIAL_SERVER)),
        };
        if cfg.is_official() {
            cfg.official_url = None;
        }
        let num = |k: &str| env(k).and_then(|v| v.parse::<u64>().ok());
        cfg.pull_secs = num("RUGEN_OFFICIAL_PULL").unwrap_or(900).max(30);
        cfg.admin_token = env("RUGEN_ADMIN_TOKEN");
        let d = AutoBlock::default();
        cfg.auto = AutoBlock {
            liars: num("RUGEN_AUTO_BLOCK_LIARS").map_or(d.liars, |v| v as u32),
            desyncs: num("RUGEN_AUTO_BLOCK_DESYNCS").map_or(d.desyncs, |v| v as u32),
            analysis: !matches!(
                env("RUGEN_AUTO_BLOCK_ANALYSIS").as_deref(),
                Some("off" | "0" | "false")
            ),
        };
        Ok(cfg)
    }

    /// This server holds the official key.
    pub fn is_official(&self) -> bool {
        match (&self.key, &self.official_key) {
            (Some(k), Some(o)) => k.public() == *o,
            _ => false,
        }
    }
}

/// The official feed a community server holds, and the highest sequence
/// it ever accepted (rollback protection survives a stale feed).
#[derive(Default)]
struct Held {
    feed: Option<(TruthFeed, SignedBlob)>,
    have: u64,
}

pub struct Truth {
    pub cfg: TruthConfig,
    name: String,
    held: Mutex<Held>,
    /// Own signed feed: (made at, sequence, blob).
    own: Mutex<Option<(Instant, u64, SignedBlob)>>,
    persist: Option<PathBuf>,
}

/// Own feed copies are re-signed at most this often.
const OWN_FEED_CACHE: Duration = Duration::from_secs(60);
/// Ratings published in a feed.
const FEED_RATINGS: usize = 5000;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Truth {
    /// `data` = where the last verified official feed is kept across restarts.
    pub fn new(cfg: TruthConfig, name: &str, data: Option<&Path>) -> Self {
        let t = Self {
            cfg,
            name: name.to_string(),
            held: Mutex::new(Held::default()),
            own: Mutex::new(None),
            persist: data.map(|d| d.join("official_truth.json")),
        };
        if let Some(p) = &t.persist
            && !t.is_official()
            && let Ok(text) = std::fs::read_to_string(p)
            && let Ok(blob) = serde_json::from_str::<SignedBlob>(&text)
        {
            match t.accept(blob, false) {
                Ok(f) => log::info!(
                    "official feed #{} from disk: {} blocked",
                    f.sequence,
                    f.blocked.len()
                ),
                Err(e) => log::warn!("official feed on disk ignored: {e}"),
            }
        }
        t
    }

    pub fn is_official(&self) -> bool {
        self.cfg.is_official()
    }

    pub fn public_key(&self) -> Option<PublicKey> {
        self.cfg.key.as_ref().map(SigningKey::public)
    }

    /// Sign a statement with this server's key.
    pub fn sign<T: Serialize>(&self, purpose: &str, statement: &T) -> Option<SignedBlob> {
        let key = self.cfg.key.as_ref()?;
        match key.sign(purpose, statement) {
            Ok(b) => Some(b),
            Err(e) => {
                log::error!("signing {purpose}: {e}");
                None
            }
        }
    }

    /// Verify, freshness-check and keep an official feed blob.
    fn accept(&self, blob: SignedBlob, save: bool) -> Result<TruthFeed, TrustError> {
        let key = self.cfg.official_key.ok_or(TrustError::BadKey)?;
        let mut held = lock(&self.held);
        let (feed, _) = trust::open::<TruthFeed>(&blob, rugen_proto::purpose::TRUTH, Some(&key))?;
        // remember the sequence even when this copy is already stale
        let check = trust::check_feed(&feed, trust::now(), held.have);
        if matches!(check, Err(TrustError::Stale(_))) {
            held.have = held.have.max(feed.sequence);
        }
        check?;
        held.have = feed.sequence;
        held.feed = Some((feed.clone(), blob.clone()));
        drop(held);
        if save && let Some(p) = &self.persist {
            if let Err(e) = std::fs::write(p, serde_json::to_vec(&blob).unwrap_or_default()) {
                log::warn!("{}: {e}", p.display());
            }
        }
        Ok(feed)
    }

    /// Take an official feed blob (from a pull or a test).
    pub fn accept_official(&self, blob: SignedBlob) -> Result<TruthFeed, TrustError> {
        self.accept(blob, true)
    }

    /// The fresh official feed this community server holds.
    pub fn official_feed(&self) -> Option<TruthFeed> {
        let held = lock(&self.held);
        let (f, _) = held.feed.as_ref()?;
        (f.expires_at > trust::now()).then(|| f.clone())
    }

    /// The verified official blob, verbatim (mirror for clients).
    pub fn official_blob(&self) -> Option<SignedBlob> {
        let held = lock(&self.held);
        let (f, b) = held.feed.as_ref()?;
        (f.expires_at > trust::now()).then(|| b.clone())
    }

    /// Fetch `<official>/v1/truth` and accept it (blocking).
    pub fn pull_official(&self) -> Result<TruthFeed, String> {
        let base = self
            .cfg
            .official_url
            .clone()
            .ok_or("official feed disabled")?;
        let url = format!("{base}/v1/truth");
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .http_status_as_error(false)
            .user_agent(concat!("rugen-server/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        let mut resp = agent.get(&url).call().map_err(|e| format!("{url}: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| format!("{url}: {e}"))?;
        if status != 200 {
            return Err(format!("{url}: http {status}"));
        }
        let blob: SignedBlob =
            serde_json::from_str(&text).map_err(|e| format!("{url}: not a signed feed: {e}"))?;
        self.accept_official(blob)
            .map_err(|e| format!("{url}: rejected: {e}"))
    }

    /// Why `fp` may not be played here: this server's blocklist (which is
    /// the official one on the official server), then the official feed.
    pub fn block_reason(&self, store: &Store, fp: &str) -> Option<String> {
        if let Ok(Some(b)) = store.blocked(fp) {
            let by = if self.is_official() {
                "blocked by the official server"
            } else {
                "blocked by this server"
            };
            return Some(format!("{by} ({})", b.reason));
        }
        let feed = self.official_feed()?;
        let b = feed.blocked(fp)?;
        Some(format!("blocked by the official server ({})", b.reason))
    }

    /// Community rating used in verdicts: ours, or the official one when
    /// it rests on more games.
    pub fn rating(&self, store: &Store, fp: &str) -> Option<CharRating> {
        let local = store.char_rating(fp).ok().flatten();
        let official = self.official_feed().and_then(|f| {
            f.rating(fp).map(|r| CharRating {
                rating: r.rating,
                games: r.games,
                wins: r.wins,
            })
        });
        match (local, official) {
            (Some(l), Some(o)) if o.games > l.games => Some(o),
            (Some(l), _) => Some(l),
            (None, o) => o,
        }
    }

    /// This server's own feed, signed (cached briefly).
    pub fn own_feed(&self, store: &Store) -> DbResult<Option<SignedBlob>> {
        if self.cfg.key.is_none() {
            return Ok(None);
        }
        let seq = store.truth_seq()?;
        let mut own = lock(&self.own);
        if let Some((at, s, blob)) = own.as_ref()
            && *s == seq
            && at.elapsed() < OWN_FEED_CACHE
        {
            return Ok(Some(blob.clone()));
        }
        // sequence and lists from one snapshot (a block landing meanwhile
        // comes with its new sequence)
        let (seq, blocked, ratings) = store.feed(FEED_RATINGS)?;
        let now = trust::now();
        let feed = TruthFeed {
            v: TRUST_VERSION,
            server: self.name.clone(),
            issued_at: now,
            expires_at: now + trust::FEED_VALIDITY,
            sequence: seq,
            blocked,
            ratings,
        };
        let blob = self.sign(rugen_proto::purpose::TRUTH, &feed);
        if let Some(b) = &blob {
            *own = Some((Instant::now(), seq, b.clone()));
        }
        Ok(blob)
    }

    /// Constant-time admin token check (false when the admin API is off).
    pub fn admin_ok(&self, token: &str) -> bool {
        let Some(want) = &self.cfg.admin_token else {
            return false;
        };
        let (a, b) = (want.as_bytes(), token.as_bytes());
        a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rugen_proto::BlockEntry;

    fn feed(now: u64, seq: u64, fp: &str) -> TruthFeed {
        TruthFeed {
            v: TRUST_VERSION,
            server: "official".into(),
            issued_at: now,
            expires_at: now + trust::FEED_VALIDITY,
            sequence: seq,
            blocked: vec![BlockEntry {
                fingerprint: fp.into(),
                reason: "infinite regen".into(),
                since: now,
                source: "admin".into(),
            }],
            ratings: vec![],
        }
    }

    fn community(dir: Option<&Path>) -> Truth {
        Truth::new(
            TruthConfig {
                key: Some(SigningKey::generate().unwrap()),
                official_key: Some(SigningKey::dev().public()),
                ..TruthConfig::default()
            },
            "community",
            dir,
        )
    }

    #[test]
    fn official_mode_comes_from_holding_the_official_key() {
        let official = TruthConfig {
            key: Some(SigningKey::dev()),
            official_key: Some(SigningKey::dev().public()),
            ..TruthConfig::default()
        };
        assert!(official.is_official());
        assert!(!community(None).is_official());
        assert!(!TruthConfig::default().is_official(), "no key, no official");
    }

    #[test]
    fn community_accepts_only_fresh_official_feeds_and_persists_them() {
        let dir = crate::testkit::tmp("truth");
        let fp = "c".repeat(64);
        let t = community(Some(&dir));
        let now = trust::now();
        // signed by somebody else: rejected
        let rogue = SigningKey::generate().unwrap();
        let forged = rogue
            .sign(rugen_proto::purpose::TRUTH, &feed(now, 5, &fp))
            .unwrap();
        assert!(matches!(
            t.accept_official(forged),
            Err(TrustError::WrongKey { .. })
        ));
        // stale: rejected
        let old = SigningKey::dev()
            .sign(
                rugen_proto::purpose::TRUTH,
                &feed(now - trust::FEED_VALIDITY - 10, 4, &fp),
            )
            .unwrap();
        assert!(matches!(t.accept_official(old), Err(TrustError::Stale(_))));
        assert!(t.official_feed().is_none());
        // genuine
        let good = SigningKey::dev()
            .sign(rugen_proto::purpose::TRUTH, &feed(now, 5, &fp))
            .unwrap();
        t.accept_official(good.clone()).unwrap();
        let store = Store::open(None).unwrap();
        assert_eq!(
            t.block_reason(&store, &fp).unwrap(),
            "blocked by the official server (infinite regen)"
        );
        assert_eq!(t.official_blob(), Some(good));
        // an older sequence never replaces it
        let older = SigningKey::dev()
            .sign(rugen_proto::purpose::TRUTH, &feed(now, 3, &"d".repeat(64)))
            .unwrap();
        assert!(matches!(
            t.accept_official(older),
            Err(TrustError::Rollback { got: 3, have: 5 })
        ));
        // a restart reloads the verified feed
        let again = community(Some(&dir));
        assert!(again.block_reason(&store, &fp).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admin_token_check() {
        let mut cfg = TruthConfig::default();
        let t = Truth::new(TruthConfig::default(), "x", None);
        assert!(!t.admin_ok(""), "admin API off without a token");
        cfg.admin_token = Some("s3cret".into());
        let t = Truth::new(cfg, "x", None);
        assert!(t.admin_ok("s3cret"));
        assert!(!t.admin_ok("s3cre"));
        assert!(!t.admin_ok("s3creT"));
    }
}
