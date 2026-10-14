//! Off-site backups to any S3-compatible bucket (AWS S3, Cloudflare R2,
//! MinIO, Backblaze B2, Wasabi), configured by one URL:
//!
//! ```text
//! RUGEN_BACKUP_S3=s3://ACCESS_KEY:SECRET_KEY@HOST/BUCKET/optional/prefix?region=auto
//! RUGEN_BACKUP_RETENTION_DAYS   days backups are kept (newest always)   7
//! RUGEN_BACKUP_INCLUDE          extras: packages, signing-key            (none)
//! ```
//!
//! `s3+http://` talks plain HTTP (local MinIO); `?style=virtual` uses
//! `bucket.host` addressing instead of path style. Percent-encode the key
//! and secret when they contain `/`, `+`, `@`, `:` or `?` (`/` → `%2F`).
//!
//! **One automatic backup a day**, at [`DAILY_AT`] (03:00 UTC). The time
//! survives restarts: on start the bucket is listed, and when the newest
//! backup is older than a day one runs [`BOOT_DELAY`] after boot; otherwise
//! the next slot is waited for. A slot is skipped when a backup already
//! succeeded in the [`MIN_GAP`] (6 h) before it, so a catch-up or a manual
//! backup just before 03:00 doesn't cause a second one. Manual backups (`POST /v1/admin/backup`,
//! `--backup-now`) come on top.
//!
//! A backup is a consistent snapshot of `rugen.db` (`VACUUM INTO` on a
//! second connection: the server keeps running and its store lock is never
//! taken), zstd-compressed and streamed up, plus a manifest. Everything
//! goes into a tree of its own under the configured prefix (which may be
//! empty), with year / month folders:
//!
//! ```text
//! <prefix>/backups/db/YYYY/MM/rugen-backup-YYYYMMDDTHHMMSSZ-<version>.db.zst
//! <prefix>/backups/db/YYYY/MM/rugen-backup-YYYYMMDDTHHMMSSZ-<version>.json         manifest (sha256, sizes, schema)
//! <prefix>/backups/keys/YYYY/MM/rugen-backup-YYYYMMDDTHHMMSSZ-<version>.signing.key only with RUGEN_BACKUP_INCLUDE=signing-key
//! <prefix>/backups/packages/<fingerprint>.<ext>                                    only with RUGEN_BACKUP_INCLUDE=packages
//! ```
//!
//! `<prefix>/chars/` and `<prefix>/stages/` are reserved for content
//! uploads later; backups never touch anything outside `<prefix>/backups/`
//! except the one-time cleanup of the legacy flat layout below.
//!
//! Packages are caches (24 h after last use by default) of files players
//! upload again on demand, up to gigabytes: they are opt-in and uploaded
//! incrementally (content-addressed names; an object of the same name and
//! size is never sent twice). After each successful backup, backup sets
//! older than the retention are deleted, the newest complete one always
//! stays; only objects named like ours are ever touched.
//!
//! **Legacy layout.** Servers up to 0.6.0 wrote flat
//! `<prefix>/rugen-backup-*.db.zst` / `.json` objects. Restore and the
//! listings still see them (restore `latest` falls back to them when no
//! backup of the new layout exists). After the next successful backup in
//! the new layout, exactly those flat `rugen-backup-*.db.zst` and
//! `rugen-backup-*.json` objects directly under `<prefix>/` are deleted;
//! nothing else is.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::s3::{Object, S3, S3Error, S3Target, amz_date, parse_amz_date, rfc3339};
use crate::store::now;

/// Seconds after midnight UTC of the daily automatic backup.
pub const DAILY_AT: u64 = 3 * 3600;
/// A backup older than this at start runs again soon after boot.
pub const STALE: u64 = 24 * 3600;
/// The first automatic backup after boot waits this long (a redeploy
/// should not add a backup to its own start-up load).
pub const BOOT_DELAY: u64 = 5 * 60;
/// A daily slot is skipped when a backup succeeded this recently (a boot
/// catch-up or a manual backup just before 03:00). Short enough that a
/// backup made in the afternoon never skips the next night.
pub const MIN_GAP: u64 = 6 * 3600;
/// A failed automatic backup is retried once after this long.
pub const RETRY_AFTER: u64 = 3600;
/// Manual backups: at most one per this long.
pub const MANUAL_COOLDOWN: Duration = Duration::from_secs(10 * 60);
pub const DEFAULT_RETENTION_DAYS: u64 = 7;
const NAME_PREFIX: &str = "rugen-backup-";
/// Local directory of the packages under `RUGEN_DATA`.
const PACKAGES_DIR: &str = "packages";
/// The bucket tree, relative to the configured prefix.
const DB_DIR: &str = "backups/db";
const KEYS_DIR: &str = "backups/keys";
const REMOTE_PACKAGES_DIR: &str = "backups/packages";
const MANIFEST_FORMAT: u32 = 1;

// ---- configuration

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupConfig {
    pub target: S3Target,
    pub retention_days: u64,
    pub include_packages: bool,
    pub include_key: bool,
}

/// What the environment asked for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum BackupSetting {
    #[default]
    Off,
    /// Set but unusable: the reason (never contains the secret).
    Invalid(String),
    On(BackupConfig),
}

impl BackupSetting {
    pub fn from_env() -> Self {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        Self::parse(
            env("RUGEN_BACKUP_S3").as_deref(),
            env("RUGEN_BACKUP_RETENTION_DAYS").as_deref(),
            env("RUGEN_BACKUP_INCLUDE").as_deref(),
        )
    }

    pub fn parse(url: Option<&str>, retention: Option<&str>, include: Option<&str>) -> Self {
        let (url, retention, include) = (
            url.map(unquote).filter(|v| !v.is_empty()),
            retention.map(unquote).filter(|v| !v.is_empty()),
            include.map(unquote),
        );
        let Some(url) = url else {
            return Self::Off;
        };
        let target = match parse_url(url) {
            Ok(t) => t,
            Err(e) => return Self::Invalid(format!("RUGEN_BACKUP_S3: {e}")),
        };
        let retention_days = match retention.map(|r| r.parse::<u64>()) {
            None => DEFAULT_RETENTION_DAYS,
            Some(Ok(d)) if (1..=36_500).contains(&d) => d,
            Some(_) => {
                return Self::Invalid(
                    "RUGEN_BACKUP_RETENTION_DAYS: a whole number of days, at least 1".into(),
                );
            }
        };
        let (mut include_packages, mut include_key) = (false, false);
        for item in include
            .unwrap_or("")
            .split([',', ' '])
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            match item.to_ascii_lowercase().as_str() {
                "packages" => include_packages = true,
                "signing-key" | "signing_key" | "key" => include_key = true,
                _ => {
                    return Self::Invalid(
                        "RUGEN_BACKUP_INCLUDE: comma-separated list of packages, signing-key"
                            .into(),
                    );
                }
            }
        }
        Self::On(BackupConfig {
            target,
            retention_days,
            include_packages,
            include_key,
        })
    }
}

/// An env value without surrounding whitespace and one pair of matching
/// quotes (`"…"` or `'…'`): a quoted value in an env file or compose
/// `environment:` list often arrives with its quotes.
pub fn unquote(v: &str) -> &str {
    let v = v.trim();
    for q in ['"', '\''] {
        if v.len() >= 2
            && let Some(inner) = v.strip_prefix(q).and_then(|r| r.strip_suffix(q))
        {
            return inner.trim();
        }
    }
    v
}

fn percent_decode(s: &str) -> Result<String, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or("bad percent-encoding in the credentials or path")?;
            out.push(hex);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "credentials are not UTF-8".to_string())
}

/// Parse `s3://KEY:SECRET@HOST[:PORT]/BUCKET[/prefix][?region=..&style=..]`.
/// Error messages never repeat the input (it holds the secret).
pub fn parse_url(url: &str) -> Result<S3Target, String> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("s3+http://") {
        ("http", r)
    } else if let Some(r) = url
        .strip_prefix("s3+https://")
        .or_else(|| url.strip_prefix("s3://"))
    {
        ("https", r)
    } else {
        return Err("must start with s3://, s3+https:// or s3+http://".into());
    };
    // the credentials end at the last `@` before the query
    let before_query = rest.find('?').map_or(rest, |q| &rest[..q]);
    let at = before_query
        .rfind('@')
        .ok_or("missing ACCESS_KEY:SECRET_KEY@ before the host")?;
    let (userinfo, rest) = (&rest[..at], &rest[at + 1..]);
    let (key, secret) = userinfo
        .split_once(':')
        .ok_or("missing ACCESS_KEY:SECRET_KEY@ before the host")?;
    let (access_key, secret_key) = (percent_decode(key)?, percent_decode(secret)?);
    if access_key.is_empty() || secret_key.is_empty() {
        return Err("empty access key or secret key".into());
    }
    let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let mut host = host.to_ascii_lowercase();
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
    {
        return Err("bad endpoint host".into());
    }
    let default_port = if scheme == "https" { ":443" } else { ":80" };
    if let Some(h) = host.strip_suffix(default_port) {
        host = h.to_string();
    }
    if let Some((_, port)) = host.rsplit_once(':')
        && !host.ends_with(']')
        && port.parse::<u16>().is_err()
    {
        return Err("bad endpoint port".into());
    }
    let path = percent_decode(path.trim_matches('/'))?;
    let (bucket, prefix) = path.split_once('/').unwrap_or((path.as_str(), ""));
    if bucket.is_empty() {
        return Err("missing /BUCKET after the host".into());
    }
    if !bucket
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err("bad bucket name".into());
    }
    let prefix = prefix
        .split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("/");
    let (mut region, mut virtual_style) = (None, false);
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        match k {
            "region" if !v.is_empty() => region = Some(percent_decode(v)?),
            "style" if v == "virtual" => virtual_style = true,
            "style" if v == "path" => virtual_style = false,
            _ => return Err("unknown option (known: region=..., style=path|virtual)".into()),
        }
    }
    let region = region.unwrap_or_else(|| guess_region(&host));
    Ok(S3Target {
        scheme,
        host,
        bucket: bucket.to_string(),
        prefix,
        region,
        virtual_style,
        access_key,
        secret_key,
    })
}

/// Region when the URL has no `?region=`: from AWS / B2 / Wasabi host
/// names, `auto` for R2, else `us-east-1` (what MinIO expects).
fn guess_region(host: &str) -> String {
    let host = host.split(':').next().unwrap_or(host);
    if host.ends_with(".r2.cloudflarestorage.com") {
        return "auto".into();
    }
    for suffix in [".amazonaws.com", ".backblazeb2.com", ".wasabisys.com"] {
        if let Some(head) = host.strip_suffix(suffix) {
            // s3.eu-west-1, s3.dualstack.eu-west-1, s3-eu-west-1, bucket.s3.eu-west-1
            let last = head.rsplit('.').next().unwrap_or("");
            let r = last.strip_prefix("s3-").unwrap_or(last);
            if !r.is_empty() && r != "s3" {
                return r.to_string();
            }
        }
    }
    "us-east-1".into()
}

/// `r2`, `aws` or `other`, from the host suffix (shown on `/health`).
pub fn provider(host: &str) -> &'static str {
    let host = host.split(':').next().unwrap_or(host);
    if host.ends_with(".r2.cloudflarestorage.com") {
        "r2"
    } else if host.ends_with(".amazonaws.com") || host == "amazonaws.com" {
        "aws"
    } else {
        "other"
    }
}

/// The URL with the credentials replaced (for logs).
pub fn redact(url: &str) -> String {
    let Some(i) = url.find("://") else {
        return "(unparsable)".into();
    };
    let rest = &url[i + 3..];
    let before_query = rest.find('?').map_or(rest, |q| &rest[..q]);
    match before_query.rfind('@') {
        Some(at) => format!("{}***:***@{}", &url[..i + 3], &rest[at + 1..]),
        None => url.to_string(),
    }
}

// ---- naming and retention

/// A backup set: the objects sharing one `rugen-backup-<ts>-<version>` stem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupSet {
    pub stem: String,
    pub time: u64,
    /// The `.db.zst` object (key, size).
    pub db: Option<(String, u64)>,
    pub manifest: Option<String>,
    /// Every object of the set (full keys).
    pub keys: Vec<String>,
    /// Flat `<prefix>/rugen-backup-*` objects of servers up to 0.6.0.
    pub legacy: bool,
}

impl BackupSet {
    /// Database and manifest both present.
    pub fn complete(&self) -> bool {
        self.db.is_some() && self.manifest.is_some()
    }
}

const SUFFIXES: [&str; 3] = [".db.zst", ".json", ".signing.key"];

/// `(stem, time, suffix)` of an object name (no prefix) of ours.
pub fn parse_name(name: &str) -> Option<(&str, u64, &'static str)> {
    if name.contains('/') {
        return None;
    }
    let ts = name.strip_prefix(NAME_PREFIX)?.get(..16)?;
    let time = parse_amz_date(ts)?;
    let suffix = SUFFIXES.into_iter().find(|s| name.ends_with(s))?;
    let stem = &name[..name.len() - suffix.len()];
    (stem.len() > NAME_PREFIX.len() + 16).then_some((stem, time, suffix))
}

/// `<dir>/YYYY/MM` (relative to the prefix) of a backup made at `t`.
pub fn dated_dir(dir: &str, t: u64) -> String {
    let (y, m, ..) = crate::s3::civil(t);
    format!("{dir}/{y:04}/{m:02}")
}

/// `key` relative to `prefix` (`None` when it lies outside).
fn relative<'a>(key: &'a str, prefix: &str) -> Option<&'a str> {
    if prefix.is_empty() {
        Some(key)
    } else {
        key.strip_prefix(prefix)?.strip_prefix('/')
    }
}

/// `(name, legacy)` of an object of ours, from its key relative to the
/// prefix: anywhere under `backups/db/` (database, manifest) or
/// `backups/keys/` (signing key), or a flat database / manifest directly
/// under the prefix (the legacy layout).
fn classify(rel: &str) -> Option<(&str, bool)> {
    if !rel.contains('/') {
        return is_legacy_name(rel).then_some((rel, true));
    }
    let name = rel.rsplit('/').next()?;
    let ok = if rel.starts_with(&format!("{DB_DIR}/")) {
        name.ends_with(".db.zst") || name.ends_with(".json")
    } else if rel.starts_with(&format!("{KEYS_DIR}/")) {
        name.ends_with(".signing.key")
    } else {
        false
    };
    ok.then_some((name, false))
}

/// Group a listing of the prefix into backup sets, newest first (at the
/// same time, the new layout before the legacy one).
pub fn group(objects: &[Object], prefix: &str) -> Vec<BackupSet> {
    let mut sets: Vec<BackupSet> = Vec::new();
    for o in objects {
        let Some((name, legacy)) = relative(&o.key, prefix).and_then(classify) else {
            continue;
        };
        let Some((stem, time, suffix)) = parse_name(name) else {
            continue;
        };
        let i = match sets
            .iter()
            .position(|s| s.stem == stem && s.legacy == legacy)
        {
            Some(i) => i,
            None => {
                sets.push(BackupSet {
                    stem: stem.to_string(),
                    time,
                    db: None,
                    manifest: None,
                    keys: Vec::new(),
                    legacy,
                });
                sets.len() - 1
            }
        };
        let s = &mut sets[i];
        s.keys.push(o.key.clone());
        match suffix {
            ".db.zst" => s.db = Some((o.key.clone(), o.size)),
            ".json" => s.manifest = Some(o.key.clone()),
            _ => {}
        }
    }
    sets.sort_by(|a, b| {
        b.time
            .cmp(&a.time)
            .then_with(|| b.stem.cmp(&a.stem))
            .then_with(|| a.legacy.cmp(&b.legacy))
    });
    sets
}

/// Stems to delete: older than `days`, except the newest complete set
/// (or the newest set when none is complete), which always stays.
pub fn expired(sets: &[BackupSet], now: u64, days: u64) -> Vec<String> {
    let cutoff = now.saturating_sub(days.saturating_mul(86_400));
    let keep = sets
        .iter()
        .find(|s| s.complete())
        .or_else(|| sets.first())
        .map(|s| s.stem.clone());
    sets.iter()
        .filter(|s| s.time < cutoff && Some(&s.stem) != keep.as_ref())
        .map(|s| s.stem.clone())
        .collect()
}

// ---- schedule

/// The first daily slot strictly after `t`.
pub fn next_slot(t: u64) -> u64 {
    let day = t - t % 86_400;
    let slot = day + DAILY_AT;
    if slot > t { slot } else { slot + 86_400 }
}

/// The next automatic backup after a success at `last` (or a failure
/// with `last` the newest success): the first slot that is not within
/// [`MIN_GAP`] of it.
pub fn next_after(now: u64, last: Option<u64>) -> u64 {
    let from = last.map_or(now, |l| now.max(l + MIN_GAP));
    next_slot(from.saturating_sub(1).max(now))
}

/// The first automatic backup after boot, given the newest backup found.
pub fn first_run(now: u64, last: Option<u64>) -> u64 {
    match last {
        Some(l) if now.saturating_sub(l) < STALE => next_after(now, Some(l)),
        _ => now + BOOT_DELAY,
    }
}

// ---- the job

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilePart {
    /// Object name relative to the prefix.
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DbPart {
    pub name: String,
    /// Compressed bytes (the object).
    pub size: u64,
    pub sha256: String,
    pub raw_size: u64,
    pub raw_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackagesPart {
    /// Directory under the prefix.
    pub dir: String,
    pub count: u64,
    pub bytes: u64,
    /// Sent by this backup (the others were there already).
    pub uploaded: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub format: u32,
    pub server_version: String,
    pub schema_version: u64,
    pub created: String,
    pub created_unix: u64,
    pub db: DbPart,
    pub signing_key: Option<FilePart>,
    pub packages: Option<PackagesPart>,
}

/// Write a consistent copy of the database `db` to `out` through a
/// connection of its own (WAL: writers carry on meanwhile).
pub fn snapshot_file(db: &Path, out: &Path) -> Result<(), String> {
    use rusqlite::{Connection, OpenFlags};
    let _ = std::fs::remove_file(out);
    let c = Connection::open_with_flags(
        db,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("open database: {e}"))?;
    c.busy_timeout(Duration::from_secs(30))
        .map_err(|e| e.to_string())?;
    c.execute("VACUUM INTO ?1", [out.to_string_lossy().as_ref()])
        .map_err(|e| format!("snapshot: {e}"))?;
    Ok(())
}

struct Hashing<T> {
    inner: T,
    h: Sha256,
    n: u64,
}

impl<T> Hashing<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            h: Sha256::new(),
            n: 0,
        }
    }
    fn done(self) -> (String, u64) {
        (rugen_proto::to_hex(&self.h.finalize()), self.n)
    }
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.h.update(&buf[..n]);
        self.n += n as u64;
        Ok(n)
    }
}

impl<W: Write> Write for Hashing<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.h.update(&buf[..n]);
        self.n += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// What a finished backup reports.
#[derive(Clone, Debug)]
pub struct Report {
    pub stem: String,
    pub db_key: String,
    pub size: u64,
    pub raw_size: u64,
    pub packages_uploaded: u64,
    pub deleted: usize,
    /// Legacy flat objects deleted (database and manifest objects).
    pub legacy_deleted: usize,
    pub created: u64,
}

/// The backup work, independent of the server (`--backup-now` runs it too).
pub struct Runner<'a> {
    pub cfg: &'a BackupConfig,
    pub s3: &'a S3,
    /// `RUGEN_DATA` (signing key, packages); `None` = in-memory tests.
    pub data: Option<&'a Path>,
    /// Scratch directory for the snapshot.
    pub work: &'a Path,
}

impl Runner<'_> {
    pub fn run(&self, snapshot: &dyn Fn(&Path) -> Result<(), String>) -> Result<Report, String> {
        std::fs::create_dir_all(self.work).map_err(|e| format!("scratch dir: {e}"))?;
        let snap = self.work.join("snapshot.db");
        let zst = self.work.join("snapshot.db.zst");
        let r = self.run_with(snapshot, &snap, &zst);
        let _ = std::fs::remove_file(&snap);
        let _ = std::fs::remove_file(&zst);
        r
    }

    fn run_with(
        &self,
        snapshot: &dyn Fn(&Path) -> Result<(), String>,
        snap: &Path,
        zst: &Path,
    ) -> Result<Report, String> {
        let s3 = self.s3;
        let created = now();
        let stem = format!(
            "{NAME_PREFIX}{}-{}",
            amz_date(created),
            env!("CARGO_PKG_VERSION")
        );
        snapshot(snap)?;
        let schema_version = rusqlite::Connection::open(snap)
            .and_then(|c| c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0)))
            .map_err(|e| format!("snapshot: {e}"))? as u64;
        // compress: bounded memory (streaming, level 3)
        let (raw_sha256, raw_size) = {
            let src = std::fs::File::open(snap).map_err(|e| format!("snapshot: {e}"))?;
            let mut src = Hashing::new(std::io::BufReader::new(src));
            let out = std::fs::File::create(zst).map_err(|e| format!("compress: {e}"))?;
            let mut out = std::io::BufWriter::new(out);
            zstd::stream::copy_encode(&mut src, &mut out, 3)
                .map_err(|e| format!("compress: {e}"))?;
            out.flush().map_err(|e| format!("compress: {e}"))?;
            src.done()
        };
        let db_name = format!("{}/{stem}.db.zst", dated_dir(DB_DIR, created));
        let db_key = s3.key(&db_name);
        let size = std::fs::metadata(zst).map_or(0, |m| m.len());
        let sha256 = s3.put_file(&db_key, zst).map_err(|e| fail(&e))?;
        let signing_key = match (self.cfg.include_key, self.data) {
            (true, Some(d)) if d.join("signing.key").is_file() => {
                let name = format!("{}/{stem}.signing.key", dated_dir(KEYS_DIR, created));
                let path = d.join("signing.key");
                let sha = s3.put_file(&s3.key(&name), &path).map_err(|e| fail(&e))?;
                Some(FilePart {
                    name,
                    size: std::fs::metadata(&path).map_or(0, |m| m.len()),
                    sha256: sha,
                })
            }
            (true, _) => {
                log::warn!(
                    "backup: RUGEN_BACKUP_INCLUDE=signing-key but there is no <data>/signing.key (a key from RUGEN_SIGNING_KEY lives in your secrets, not here)"
                );
                None
            }
            _ => None,
        };
        let packages = match (self.cfg.include_packages, self.data) {
            (true, Some(d)) => Some(self.packages(&d.join(PACKAGES_DIR))?),
            _ => None,
        };
        let packages_uploaded = packages.as_ref().map_or(0, |p| p.uploaded);
        let manifest = Manifest {
            format: MANIFEST_FORMAT,
            server_version: env!("CARGO_PKG_VERSION").into(),
            schema_version,
            created: rfc3339(created),
            created_unix: created,
            db: DbPart {
                name: db_name,
                size,
                sha256,
                raw_size,
                raw_sha256,
            },
            signing_key,
            packages,
        };
        let body = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
        let manifest_name = format!("{}/{stem}.json", dated_dir(DB_DIR, created));
        s3.put_bytes(&s3.key(&manifest_name), &body, "application/json")
            .map_err(|e| fail(&e))?;
        // a complete backup of the new layout is up: the flat one can go
        let legacy_deleted = self.delete_legacy().unwrap_or_else(|e| {
            log::warn!("backup: legacy cleanup: {e}");
            0
        });
        let deleted = self.retention().unwrap_or_else(|e| {
            log::warn!("backup: retention: {e}");
            0
        });
        Ok(Report {
            stem,
            db_key,
            size,
            raw_size,
            packages_uploaded,
            deleted,
            legacy_deleted,
            created,
        })
    }

    /// Upload the packages the bucket does not have yet (same name + size).
    fn packages(&self, dir: &Path) -> Result<PackagesPart, String> {
        let s3 = self.s3;
        let remote_prefix = s3.key(REMOTE_PACKAGES_DIR);
        let remote = s3
            .list(&format!("{remote_prefix}/"))
            .map_err(|e| fail(&e))?;
        let have: std::collections::HashMap<&str, u64> =
            remote.iter().map(|o| (o.key.as_str(), o.size)).collect();
        let (mut count, mut bytes, mut uploaded) = (0u64, 0u64, 0u64);
        let mut local = std::collections::HashSet::new();
        for e in std::fs::read_dir(dir)
            .map(|r| r.flatten().collect::<Vec<_>>())
            .unwrap_or_default()
        {
            let path = e.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !path.is_file() || name.starts_with('.') || !is_package_name(name) {
                continue;
            }
            let len = e.metadata().map_or(0, |m| m.len());
            let key = format!("{remote_prefix}/{name}");
            count += 1;
            bytes += len;
            if have.get(key.as_str()) != Some(&len) {
                s3.put_file(&key, &path).map_err(|e| fail(&e))?;
                uploaded += 1;
            }
            local.insert(key);
        }
        // packages gone locally go once older than the retention
        let cutoff = now().saturating_sub(self.cfg.retention_days * 86_400);
        for o in &remote {
            if !local.contains(&o.key) && o.modified < cutoff && o.modified > 0 {
                if let Err(e) = s3.delete(&o.key) {
                    log::warn!("backup: delete old package: {e}");
                }
            }
        }
        Ok(PackagesPart {
            dir: REMOTE_PACKAGES_DIR.into(),
            count,
            bytes,
            uploaded,
        })
    }

    /// Delete the legacy flat objects: exactly `<prefix>/rugen-backup-*`
    /// ending in `.db.zst` or `.json`, nothing deeper, nothing else.
    /// Returns how many objects went.
    pub fn delete_legacy(&self) -> Result<usize, S3Error> {
        let s3 = self.s3;
        let prefix = &s3.target.prefix;
        let mut n = 0;
        for o in s3.list(&s3.key(NAME_PREFIX))? {
            if relative(&o.key, prefix).is_some_and(is_legacy_name) {
                s3.delete(&o.key)?;
                n += 1;
            }
        }
        if n > 0 {
            log::info!("backup: {n} objects of the old flat layout deleted");
        }
        Ok(n)
    }

    /// Delete expired backup sets of the new layout. Returns how many
    /// sets went.
    pub fn retention(&self) -> Result<usize, S3Error> {
        let s3 = self.s3;
        let sets: Vec<BackupSet> = list_sets(s3)?.into_iter().filter(|s| !s.legacy).collect();
        let gone = expired(&sets, now(), self.cfg.retention_days);
        for stem in &gone {
            if let Some(set) = sets.iter().find(|s| &s.stem == stem) {
                for k in &set.keys {
                    s3.delete(k)?;
                }
            }
        }
        if !gone.is_empty() {
            log::info!(
                "backup: retention {} days, {} old backups deleted",
                self.cfg.retention_days,
                gone.len()
            );
        }
        Ok(gone.len())
    }
}

/// A legacy flat object name (relative to the prefix) the cleanup deletes.
fn is_legacy_name(rel: &str) -> bool {
    !rel.contains('/')
        && rel.starts_with(NAME_PREFIX)
        && (rel.ends_with(".db.zst") || rel.ends_with(".json"))
}

fn is_package_name(name: &str) -> bool {
    let Some((fp, ext)) = name.split_once('.') else {
        return false;
    };
    rugen_proto::is_fingerprint(fp) && matches!(ext, "rgc" | "rgs" | "rgpk")
}

/// Log the details, keep the short form.
fn fail(e: &S3Error) -> String {
    log::warn!("backup: {e}");
    e.short()
}

/// The backup sets under the configured prefix, newest first: everything
/// under `backups/db/` and `backups/keys/` (recursively, all pages), plus
/// the legacy flat objects.
pub fn list_sets(s3: &S3) -> Result<Vec<BackupSet>, S3Error> {
    let mut objects = s3.list(&format!("{}/", s3.key(DB_DIR)))?;
    objects.extend(s3.list(&format!("{}/", s3.key(KEYS_DIR)))?);
    objects.extend(s3.list(&s3.key(NAME_PREFIX))?);
    Ok(group(&objects, &s3.target.prefix))
}

// ---- server-side state: jobs, schedule, health

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    Manual,
    Scheduled,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StartError {
    /// Backups are off or misconfigured.
    Off,
    /// One is running (its job id).
    Running(u64),
    /// Manual backups: seconds until the next one is allowed.
    Cooldown(u64),
}

#[derive(Default)]
struct State {
    job_seq: u64,
    running: Option<(u64, Trigger, u64)>,
    last_success: Option<u64>,
    last_error: Option<String>,
    last_size: u64,
    last_key: Option<String>,
    next_at: Option<u64>,
    last_manual: Option<Instant>,
    retried: bool,
    /// The last finished job: (id, ok).
    finished: Option<(u64, bool)>,
}

pub type Snapshot = Arc<dyn Fn(&Path) -> Result<(), String> + Send + Sync>;

pub struct Backups {
    pub setting: BackupSetting,
    s3: Option<S3>,
    data: Option<PathBuf>,
    work: PathBuf,
    state: Mutex<State>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Backups {
    pub fn new(setting: BackupSetting, data: Option<&Path>) -> Arc<Self> {
        let s3 = match &setting {
            BackupSetting::On(c) => Some(S3::new(c.target.clone())),
            _ => None,
        };
        let work = data.map_or_else(
            || std::env::temp_dir().join(format!("rugen-backup-{}", crate::store::random_hex(6))),
            |d| d.join("backup-tmp"),
        );
        Arc::new(Self {
            setting,
            s3,
            data: data.map(Path::to_path_buf),
            work,
            state: Mutex::new(State::default()),
        })
    }

    pub fn config(&self) -> Option<&BackupConfig> {
        match &self.setting {
            BackupSetting::On(c) => Some(c),
            _ => None,
        }
    }

    /// One line for the start-up log (no secrets).
    pub fn describe(&self) -> String {
        match &self.setting {
            BackupSetting::Off => "backups: off (set RUGEN_BACKUP_S3)".into(),
            BackupSetting::Invalid(e) => format!("backups: MISCONFIGURED, disabled: {e}"),
            BackupSetting::On(c) => {
                let t = &c.target;
                let mut extra = Vec::new();
                if c.include_packages {
                    extra.push("packages");
                }
                if c.include_key {
                    extra.push("signing key");
                }
                format!(
                    "backups: daily at {:02}:00 UTC to {} ({}, bucket {}{}{}), keep {} days{}",
                    DAILY_AT / 3600,
                    t.host,
                    provider(&t.host),
                    t.bucket,
                    if t.prefix.is_empty() { "" } else { "/" },
                    t.prefix,
                    c.retention_days,
                    if extra.is_empty() {
                        String::new()
                    } else {
                        format!(", with {}", extra.join(" + "))
                    }
                )
            }
        }
    }

    /// Start a backup on a thread of its own. Returns the job id.
    pub fn start(
        self: &Arc<Self>,
        trigger: Trigger,
        snapshot: Snapshot,
    ) -> Result<u64, StartError> {
        if self.s3.is_none() {
            return Err(StartError::Off);
        }
        let id = {
            let mut st = lock(&self.state);
            if let Some((id, ..)) = st.running {
                return Err(StartError::Running(id));
            }
            if trigger == Trigger::Manual {
                if let Some(t) = st.last_manual
                    && t.elapsed() < MANUAL_COOLDOWN
                {
                    return Err(StartError::Cooldown(
                        (MANUAL_COOLDOWN - t.elapsed()).as_secs().max(1),
                    ));
                }
                st.last_manual = Some(Instant::now());
            }
            st.job_seq += 1;
            st.running = Some((st.job_seq, trigger, now()));
            st.job_seq
        };
        let me = self.clone();
        let spawned = std::thread::Builder::new()
            .name("backup".into())
            .spawn(move || me.execute(id, trigger, &*snapshot));
        if let Err(e) = spawned {
            let mut st = lock(&self.state);
            st.running = None;
            st.last_error = Some(format!("could not start: {e}"));
            return Err(StartError::Off);
        }
        Ok(id)
    }

    /// Run job `id` here (it is marked running already).
    fn execute(&self, id: u64, trigger: Trigger, snapshot: &dyn Fn(&Path) -> Result<(), String>) {
        let (Some(cfg), Some(s3)) = (self.config(), self.s3.as_ref()) else {
            return;
        };
        let t0 = Instant::now();
        let r = Runner {
            cfg,
            s3,
            data: self.data.as_deref(),
            work: &self.work,
        }
        .run(snapshot);
        let mut st = lock(&self.state);
        st.running = None;
        st.finished = Some((id, r.is_ok()));
        match r {
            Ok(rep) => {
                log::info!(
                    "backup {id} ({}): {} ({} KB, {} KB raw{}) in {:.1} s",
                    if trigger == Trigger::Manual {
                        "manual"
                    } else {
                        "daily"
                    },
                    rep.db_key,
                    rep.size >> 10,
                    rep.raw_size >> 10,
                    if rep.packages_uploaded > 0 {
                        format!(", {} packages sent", rep.packages_uploaded)
                    } else {
                        String::new()
                    },
                    t0.elapsed().as_secs_f32()
                );
                st.last_success = Some(rep.created);
                st.last_error = None;
                st.last_size = rep.size;
                st.last_key = Some(rep.stem);
                st.retried = false;
                st.next_at = Some(next_after(now(), st.last_success));
            }
            Err(e) => {
                log::warn!("backup {id} failed: {e}");
                st.last_error = Some(e.chars().take(160).collect());
                if trigger == Trigger::Scheduled {
                    st.next_at = Some(if st.retried {
                        st.retried = false;
                        next_after(now(), st.last_success)
                    } else {
                        st.retried = true;
                        now() + RETRY_AFTER
                    });
                }
            }
        }
    }

    /// The daily schedule, forever, on a thread of its own: learns the
    /// newest backup from the bucket, then starts backups when due.
    pub fn spawn_scheduler(self: &Arc<Self>, snapshot: Snapshot) {
        if self.s3.is_none() {
            return;
        }
        let me = self.clone();
        let newest = |s3: &S3| -> Result<Option<(u64, u64)>, S3Error> {
            Ok(list_sets(s3)?
                .into_iter()
                .find(BackupSet::complete)
                .map(|s| (s.time, s.db.map_or(0, |d| d.1))))
        };
        let spawned = std::thread::Builder::new()
            .name("backup-schedule".into())
            .spawn(move || {
                let Some(s3) = me.s3.as_ref() else {
                    return;
                };
                let found = match newest(s3) {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!("backup: listing the bucket: {e}");
                        lock(&me.state).last_error = Some(e.short());
                        None
                    }
                };
                {
                    let mut st = lock(&me.state);
                    if let Some((t, size)) = found
                        && st.last_success.is_none_or(|l| l < t)
                    {
                        st.last_success = Some(t);
                        st.last_size = size;
                    }
                    let next = first_run(now(), st.last_success);
                    st.next_at = Some(next);
                    log::info!("backup: next daily backup at {}", rfc3339(next));
                }
                loop {
                    std::thread::sleep(Duration::from_secs(30));
                    let due = {
                        let st = lock(&me.state);
                        st.running.is_none() && st.next_at.is_some_and(|t| now() >= t)
                    };
                    if due {
                        match me.start(Trigger::Scheduled, snapshot.clone()) {
                            Ok(_) | Err(StartError::Running(_)) => {}
                            Err(_) => return,
                        }
                        // the job sets the next time when it ends; until then
                        // nothing is due
                        let mut st = lock(&me.state);
                        if st.running.is_some() {
                            st.next_at = None;
                        }
                    }
                }
            });
        if let Err(e) = spawned {
            log::error!("backup scheduler: {e}");
        }
    }

    /// The `backup` object of `/health`: no endpoint, bucket or key.
    pub fn health(&self) -> Value {
        let st = lock(&self.state);
        let t = |v: Option<u64>| v.map(rfc3339);
        match &self.setting {
            BackupSetting::Off => json!({
                "configured": false, "status": "off", "provider": null,
                "retention_days": null, "last_success": null, "last_error": null,
                "last_size_bytes": 0, "next_at": null, "running": false,
            }),
            BackupSetting::Invalid(e) => json!({
                "configured": false, "status": "misconfigured", "provider": null,
                "retention_days": null, "last_success": null, "last_error": e,
                "last_size_bytes": 0, "next_at": null, "running": false,
            }),
            BackupSetting::On(c) => json!({
                "configured": true,
                "status": if st.last_error.is_some() { "failing" } else { "ok" },
                "provider": provider(&c.target.host),
                "retention_days": c.retention_days,
                "last_success": t(st.last_success),
                "last_error": st.last_error,
                "last_size_bytes": st.last_size,
                "next_at": t(st.next_at),
                "running": st.running.is_some(),
            }),
        }
    }

    /// `GET /v1/admin/backup/status`: health plus job details.
    pub fn status(&self) -> Value {
        let mut v = self.health();
        let st = lock(&self.state);
        v["job"] = match st.running {
            Some((id, trigger, started)) => json!({
                "id": id, "state": "running",
                "trigger": if trigger == Trigger::Manual { "manual" } else { "daily" },
                "started": rfc3339(started),
            }),
            None => match st.finished {
                Some((id, ok)) => json!({ "id": id, "state": if ok { "done" } else { "failed" } }),
                None => Value::Null,
            },
        };
        v["last_backup"] = st.last_key.clone().map_or(Value::Null, Value::from);
        if let Some(c) = self.config() {
            v["include"] = json!({ "packages": c.include_packages, "signing_key": c.include_key });
            v["daily_at"] = format!("{:02}:00Z", DAILY_AT / 3600).into();
        }
        v
    }

    /// `GET /v1/admin/backups`: the backup sets in the bucket, newest first.
    pub fn list(&self) -> Result<Value, String> {
        let s3 = self.s3.as_ref().ok_or("backups are not configured")?;
        let sets = list_sets(s3).map_err(|e| fail(&e))?;
        Ok(json!({
            "backups": sets.iter().map(|s| json!({
                "key": s.db.as_ref().map(|d| d.0.clone()),
                "name": s.stem,
                "time": rfc3339(s.time),
                "size": s.db.as_ref().map_or(0, |d| d.1),
                "complete": s.complete(),
                "legacy": s.legacy,
            })).collect::<Vec<_>>(),
        }))
    }
}

// ---- restore

/// `--restore <object key | name | latest>` into `data` (server stopped).
/// Prints what it did; returns an error message on failure.
pub fn restore(cfg: &BackupConfig, data: &Path, which: &str) -> Result<String, String> {
    let s3 = S3::new(cfg.target.clone());
    let sets = list_sets(&s3).map_err(|e| e.to_string())?;
    let set = if which == "latest" {
        // the new layout first; the flat one of servers up to 0.6.0 when
        // there is none yet
        sets.iter()
            .find(|s| s.complete() && !s.legacy)
            .or_else(|| sets.iter().find(|s| s.complete()))
    } else {
        let name = which.rsplit('/').next().unwrap_or(which);
        let stem = SUFFIXES
            .into_iter()
            .find_map(|s| name.strip_suffix(s))
            .unwrap_or(name);
        sets.iter().find(|s| s.stem == stem)
    }
    .ok_or_else(|| format!("no backup {which} in the bucket (see GET /v1/admin/backups)"))?;
    let manifest_key = set
        .manifest
        .as_ref()
        .ok_or("that backup has no manifest (incomplete): pick another")?;
    let manifest: Manifest = serde_json::from_slice(
        &s3.get_bytes(manifest_key, 1 << 20)
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("manifest: {e}"))?;
    std::fs::create_dir_all(data).map_err(|e| e.to_string())?;
    let zst = data.join("rugen.db.restore.zst");
    let raw = data.join("rugen.db.restore");
    let cleanup = || {
        let _ = std::fs::remove_file(&zst);
        let _ = std::fs::remove_file(&raw);
    };
    let r = (|| -> Result<(), String> {
        let (sha, len) = s3
            .get_to_file(&s3.key(&manifest.db.name), &zst)
            .map_err(|e| e.to_string())?;
        if sha != manifest.db.sha256 || len != manifest.db.size {
            return Err("downloaded database does not match the manifest sha256".into());
        }
        let src = std::fs::File::open(&zst).map_err(|e| e.to_string())?;
        let out = std::fs::File::create(&raw).map_err(|e| e.to_string())?;
        let mut out = Hashing::new(std::io::BufWriter::new(out));
        zstd::stream::copy_decode(std::io::BufReader::new(src), &mut out)
            .map_err(|e| format!("decompress: {e}"))?;
        out.flush().map_err(|e| e.to_string())?;
        let (raw_sha, raw_len) = out.done();
        if raw_sha != manifest.db.raw_sha256 || raw_len != manifest.db.raw_size {
            return Err("decompressed database does not match the manifest sha256".into());
        }
        let ok: String = rusqlite::Connection::open(&raw)
            .and_then(|c| c.query_row("PRAGMA integrity_check", [], |r| r.get(0)))
            .map_err(|e| format!("integrity check: {e}"))?;
        if ok != "ok" {
            return Err(format!("integrity check: {ok}"));
        }
        Ok(())
    })();
    if let Err(e) = r {
        cleanup();
        return Err(e);
    }
    let _ = std::fs::remove_file(&zst);
    let stamp = amz_date(now());
    let mut report = Vec::new();
    // the old database: WAL folded in, then kept as a .bak
    let db = data.join("rugen.db");
    if db.exists() {
        if let Ok(c) = rusqlite::Connection::open(&db) {
            let _ = c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
        }
        let bak = data.join(format!("rugen.db.{stamp}.bak"));
        std::fs::rename(&db, &bak).map_err(|e| format!("keep the old database: {e}"))?;
        for ext in ["-wal", "-shm"] {
            let side = data.join(format!("rugen.db{ext}"));
            if side.exists() {
                let _ = std::fs::rename(&side, data.join(format!("rugen.db.{stamp}.bak{ext}")));
            }
        }
        report.push(format!("old database kept as {}", bak.display()));
    }
    std::fs::rename(&raw, &db).map_err(|e| format!("swap in the restored database: {e}"))?;
    report.insert(
        0,
        format!(
            "restored {} (created {}, server {}, schema v{})",
            set.stem, manifest.created, manifest.server_version, manifest.schema_version
        ),
    );
    if let Some(k) = &manifest.signing_key {
        let tmp = data.join("signing.key.restore");
        let (sha, _) = s3
            .get_to_file(&s3.key(&k.name), &tmp)
            .map_err(|e| e.to_string())?;
        if sha != k.sha256 {
            let _ = std::fs::remove_file(&tmp);
            return Err(
                "signing key does not match the manifest sha256 (database restored)".into(),
            );
        }
        let key = data.join("signing.key");
        if key.exists() {
            let _ = std::fs::rename(&key, data.join(format!("signing.key.{stamp}.bak")));
        }
        std::fs::rename(&tmp, &key).map_err(|e| e.to_string())?;
        report.push("signing key restored to <data>/signing.key".into());
    }
    if let Some(p) = &manifest.packages {
        let n = restore_packages(&s3, data, &db, &p.dir)?;
        report.push(format!("{n} packages downloaded"));
    }
    Ok(report.join("\n"))
}

/// Download the packages the restored database knows and the disk lacks.
fn restore_packages(s3: &S3, data: &Path, db: &Path, dir: &str) -> Result<usize, String> {
    let wanted: std::collections::HashSet<String> = rusqlite::Connection::open(db)
        .and_then(|c| {
            let mut st = c.prepare("SELECT fingerprint FROM packages")?;
            st.query_map([], |r| r.get::<_, String>(0))?.collect()
        })
        .map_err(|e| format!("packages: {e}"))?;
    let local = data.join(PACKAGES_DIR);
    std::fs::create_dir_all(&local).map_err(|e| e.to_string())?;
    let remote_prefix = format!("{}/", s3.key(dir));
    let mut n = 0;
    for o in s3.list(&remote_prefix).map_err(|e| e.to_string())? {
        let Some(name) = o.key.strip_prefix(&remote_prefix) else {
            continue;
        };
        let fp = name.split('.').next().unwrap_or("");
        let path = local.join(name);
        if !is_package_name(name) || !wanted.contains(fp) || path.exists() {
            continue;
        }
        let tmp = local.join(format!(".{name}.restore"));
        let (_, len) = s3.get_to_file(&o.key, &tmp).map_err(|e| e.to_string())?;
        if len != o.size {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("package {name}: short download"));
        }
        std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on(s: BackupSetting) -> BackupConfig {
        match s {
            BackupSetting::On(c) => c,
            other => panic!("not on: {other:?}"),
        }
    }

    #[test]
    fn parses_aws_r2_minio_urls() {
        let aws =
            parse_url("s3://AKIA:sec@s3.eu-west-1.amazonaws.com/bucket?region=eu-west-1").unwrap();
        assert_eq!(
            (
                aws.scheme,
                aws.host.as_str(),
                aws.bucket.as_str(),
                aws.prefix.as_str()
            ),
            ("https", "s3.eu-west-1.amazonaws.com", "bucket", "")
        );
        assert_eq!(aws.region, "eu-west-1");
        assert!(!aws.virtual_style);
        assert_eq!(provider(&aws.host), "aws");
        // region guessed from the AWS host
        let aws = parse_url("s3://k:s@s3.ap-south-1.amazonaws.com/b").unwrap();
        assert_eq!(aws.region, "ap-south-1");
        assert_eq!(
            parse_url("s3://k:s@s3.amazonaws.com/b").unwrap().region,
            "us-east-1"
        );

        let r2 =
            parse_url("s3://k:s@0123abcd.r2.cloudflarestorage.com/rugen/backups/prod/?region=auto")
                .unwrap();
        assert_eq!(r2.bucket, "rugen");
        assert_eq!(r2.prefix, "backups/prod");
        assert_eq!(r2.region, "auto");
        assert_eq!(provider(&r2.host), "r2");
        assert_eq!(
            parse_url("s3://k:s@x.r2.cloudflarestorage.com/b")
                .unwrap()
                .region,
            "auto"
        );

        let minio = parse_url("s3+http://minio:minio123@localhost:9000/rugen").unwrap();
        assert_eq!(
            (minio.scheme, minio.host.as_str()),
            ("http", "localhost:9000")
        );
        assert_eq!(minio.region, "us-east-1");
        assert_eq!(provider(&minio.host), "other");

        let v = parse_url("s3+https://k:s@S3.Wasabisys.com:443/b?style=virtual").unwrap();
        assert_eq!(
            v.host, "s3.wasabisys.com",
            "default port stripped, lowercased"
        );
        assert!(v.virtual_style);
        let b2 = parse_url("s3://k:s@s3.us-west-004.backblazeb2.com/b").unwrap();
        assert_eq!(b2.region, "us-west-004");
    }

    #[test]
    fn decodes_percent_encoded_secrets() {
        let t = parse_url("s3://AKIA%2BX:wJal%2FrXU%2Bt%40k%3Ay@host.example/b").unwrap();
        assert_eq!(t.access_key, "AKIA+X");
        assert_eq!(t.secret_key, "wJal/rXU+t@k:y");
        // a raw `+` stays a plus (not form encoding); a raw `/` still parses
        let t = parse_url("s3://k:a+b/c@host.example/b").unwrap();
        assert_eq!(t.secret_key, "a+b/c");
        assert_eq!(t.bucket, "b");
    }

    #[test]
    fn rejects_bad_urls_without_echoing_the_secret() {
        for bad in [
            "https://k:TOPSECRET@h/b",
            "s3://h/b",
            "s3://k@h/b",
            "s3://:TOPSECRET@h/b",
            "s3://k:TOPSECRET@/b",
            "s3://k:TOPSECRET@host",
            "s3://k:TOPSECRET@host/",
            "s3://k:TOPSECRET@host/b?colour=red",
            "s3://k:TOPSECRET@host:99999/b",
            "s3://k:TOP%zzSECRET@host/b",
            "s3://k:TOPSECRET@ho st/b",
        ] {
            let e = parse_url(bad).expect_err(bad);
            assert!(!e.contains("TOPSECRET") && !e.contains("TOP"), "{e}");
        }
        let s = BackupSetting::parse(Some("s3://k:TOPSECRET@host"), None, None);
        assert!(
            matches!(&s, BackupSetting::Invalid(e) if e.starts_with("RUGEN_BACKUP_S3") && !e.contains("TOPSECRET"))
        );
        assert!(!format!("{s:?}").contains("TOPSECRET"));
        assert_eq!(
            redact("s3://k:TOPSECRET@host/b?region=x"),
            "s3://***:***@host/b?region=x"
        );
    }

    #[test]
    fn debug_never_prints_credentials() {
        let c = on(BackupSetting::parse(
            Some("s3://AKIAXYZ:TOPSECRET@h.example/b"),
            None,
            None,
        ));
        let d = format!("{c:?}");
        assert!(!d.contains("TOPSECRET") && !d.contains("AKIAXYZ"), "{d}");
    }

    #[test]
    fn retention_and_include_settings() {
        let url = Some("s3://k:s@h.example/b");
        let c = on(BackupSetting::parse(url, None, None));
        assert_eq!(c.retention_days, 7);
        assert!(!c.include_packages && !c.include_key);
        assert_eq!(
            on(BackupSetting::parse(url, Some("30"), None)).retention_days,
            30
        );
        assert_eq!(
            on(BackupSetting::parse(url, Some(" 365 "), None)).retention_days,
            365
        );
        for bad in ["0", "-1", "7d", "x"] {
            assert!(matches!(
                BackupSetting::parse(url, Some(bad), None),
                BackupSetting::Invalid(_)
            ));
        }
        let c = on(BackupSetting::parse(
            url,
            None,
            Some("packages, signing-key"),
        ));
        assert!(c.include_packages && c.include_key);
        assert!(matches!(
            BackupSetting::parse(url, None, Some("everything")),
            BackupSetting::Invalid(_)
        ));
        assert_eq!(
            BackupSetting::parse(None, Some("3"), None),
            BackupSetting::Off
        );
    }

    fn obj(key: &str, size: u64) -> Object {
        Object {
            key: key.into(),
            size,
            modified: 0,
        }
    }

    #[test]
    fn groups_backup_sets_and_ignores_foreign_objects() {
        let objs = [
            obj(
                "p/backups/db/2026/10/rugen-backup-20261001T030000Z-0.6.0.db.zst",
                10,
            ),
            obj(
                "p/backups/db/2026/10/rugen-backup-20261001T030000Z-0.6.0.json",
                1,
            ),
            obj(
                "p/backups/keys/2026/10/rugen-backup-20261001T030000Z-0.6.0.signing.key",
                1,
            ),
            obj(
                "p/backups/db/2026/10/rugen-backup-20261002T030000Z-0.7.0.db.zst",
                20,
            ),
            obj("p/notes.txt", 5),
            obj(
                "p/backups/packages/rugen-backup-20261001T030000Z-0.6.0.db.zst",
                5,
            ),
            obj("p/chars/rugen-backup-20261001T030000Z-0.6.0.db.zst", 5),
            obj(
                "p/backups/db/2026/10/rugen-backup-20261003T030000Z-0.6.0.signing.key",
                5,
            ),
            obj(
                "other/backups/db/2026/10/rugen-backup-20261003T030000Z-0.6.0.db.zst",
                5,
            ),
            obj("p/backups/db/2026/10/rugen-backup-garbage.db.zst", 5),
            // legacy flat objects: a set of their own
            obj("p/rugen-backup-20261001T030000Z-0.6.0.db.zst", 10),
            obj("p/rugen-backup-20261001T030000Z-0.6.0.json", 1),
        ];
        let sets = group(&objs, "p");
        assert_eq!(sets.len(), 3, "{sets:?}");
        assert_eq!(sets[0].stem, "rugen-backup-20261002T030000Z-0.7.0");
        assert!(!sets[0].complete() && !sets[0].legacy);
        assert_eq!(sets[1].stem, "rugen-backup-20261001T030000Z-0.6.0");
        assert!(sets[1].complete() && !sets[1].legacy, "new layout first");
        assert_eq!(sets[1].keys.len(), 3, "database, manifest, signing key");
        assert!(sets[2].complete() && sets[2].legacy);
        assert_eq!(group(&objs[..1], "").len(), 0, "prefix mismatch: not ours");
        // an empty prefix: the tree sits at the bucket root
        let root = [
            obj(
                "backups/db/2026/10/rugen-backup-20261013T141050Z-0.6.0.db.zst",
                1,
            ),
            obj("rugen-backup-20261013T141050Z-0.6.0.json", 1),
            obj("chars/x/rugen-backup-20261013T141050Z-0.6.0.json", 1),
        ];
        let sets = group(&root, "");
        assert_eq!(sets.len(), 2);
        assert!(!sets[0].legacy && sets[1].legacy);
    }

    #[test]
    fn dated_layout_and_legacy_names() {
        let t = parse_amz_date("20261013T141050Z").unwrap();
        assert_eq!(dated_dir(DB_DIR, t), "backups/db/2026/10");
        assert_eq!(
            dated_dir(KEYS_DIR, parse_amz_date("20270105T000000Z").unwrap()),
            "backups/keys/2027/01"
        );
        assert!(is_legacy_name("rugen-backup-20261013T141050Z-0.6.0.db.zst"));
        assert!(is_legacy_name("rugen-backup-20261013T141050Z-0.6.0.json"));
        for keep in [
            "rugen-backup-20261013T141050Z-0.6.0.signing.key",
            "rugen-backup-notes.txt",
            "backups/db/2026/10/rugen-backup-20261013T141050Z-0.6.0.json",
            "chars/rugen-backup-x.json",
            "my-rugen-backup-x.json",
        ] {
            assert!(!is_legacy_name(keep), "{keep}");
        }
    }

    #[test]
    fn env_values_lose_whitespace_and_one_pair_of_quotes() {
        assert_eq!(unquote("  \"s3://k:s@h/b\"  "), "s3://k:s@h/b");
        assert_eq!(unquote("'14'"), "14");
        assert_eq!(unquote(" 7 "), "7");
        assert_eq!(unquote("\"\"x\"\""), "\"x\"", "one pair only");
        assert_eq!(unquote("\"x'"), "\"x'", "mismatched quotes stay");
        assert_eq!(unquote("\""), "\"");
        for url in [
            "\"s3://k:s@h.example/b/p?region=auto\"",
            "'s3://k:s@h.example/b/p?region=auto'",
            " \" s3://k:s@h.example/b/p?region=auto \"\n",
        ] {
            let c = on(BackupSetting::parse(
                Some(url),
                Some("\"14\""),
                Some("'packages'"),
            ));
            assert_eq!(
                (c.target.bucket.as_str(), c.target.prefix.as_str()),
                ("b", "p")
            );
            assert_eq!(c.target.region, "auto");
            assert_eq!(c.retention_days, 14);
            assert!(c.include_packages);
        }
        assert_eq!(
            on(BackupSetting::parse(
                Some("s3://k:s@h/b"),
                Some("' 30 '"),
                None
            ))
            .retention_days,
            30
        );
        // quoted but empty: off / the default
        assert_eq!(
            BackupSetting::parse(Some("\"\""), None, None),
            BackupSetting::Off
        );
        assert_eq!(
            on(BackupSetting::parse(Some("s3://k:s@h/b"), Some("''"), None)).retention_days,
            DEFAULT_RETENTION_DAYS
        );
    }

    fn set(day: u32, complete: bool) -> BackupSet {
        let stem = format!("rugen-backup-202610{day:02}T030000Z-0.6.0");
        BackupSet {
            time: parse_amz_date(&format!("202610{day:02}T030000Z")).unwrap(),
            db: Some((format!("{stem}.db.zst"), 1)),
            manifest: complete.then(|| format!("{stem}.json")),
            keys: vec![],
            legacy: false,
            stem,
        }
    }

    #[test]
    fn retention_deletes_old_sets_but_keeps_the_newest() {
        let now = parse_amz_date("20261020T120000Z").unwrap();
        // newest first, as group() returns them
        let sets: Vec<BackupSet> = (1..=20).rev().map(|d| set(d, true)).collect();
        let gone = expired(&sets, now, 7);
        // cutoff 2026-10-13 12:00: days 1..=13 go
        assert_eq!(gone.len(), 13);
        assert!(gone.iter().all(|s| s.as_str() < "rugen-backup-20261014"));
        assert_eq!(expired(&sets, now, 30).len(), 0);
        // everything old: the newest stays anyway
        let old: Vec<BackupSet> = (1..=3).rev().map(|d| set(d, true)).collect();
        let gone = expired(&old, now, 7);
        assert_eq!(gone.len(), 2);
        assert!(!gone.contains(&old[0].stem));
        // the newest complete one stays, not an incomplete newer one
        let mixed = vec![set(3, false), set(2, true), set(1, true)];
        let gone = expired(&mixed, now, 7);
        assert_eq!(gone, vec![mixed[0].stem.clone(), mixed[2].stem.clone()]);
        assert!(expired(&[], now, 7).is_empty());
    }

    #[test]
    fn daily_schedule() {
        let at = |s: &str| parse_amz_date(s).unwrap();
        assert_eq!(next_slot(at("20261013T010000Z")), at("20261013T030000Z"));
        assert_eq!(next_slot(at("20261013T030000Z")), at("20261014T030000Z"));
        assert_eq!(next_slot(at("20261013T235959Z")), at("20261014T030000Z"));
        let now = at("20261013T120000Z");
        // nothing yet / stale: soon after boot
        assert_eq!(first_run(now, None), now + BOOT_DELAY);
        assert_eq!(first_run(now, Some(now - STALE - 1)), now + BOOT_DELAY);
        // today's 03:00 ran: tomorrow's slot, restarts change nothing
        assert_eq!(
            first_run(now, Some(at("20261013T030012Z"))),
            at("20261014T030000Z")
        );
        // yesterday's ran at 03:00, booting at 02:00: today's 03:00
        let early = at("20261013T020000Z");
        assert_eq!(
            first_run(early, Some(at("20261012T030000Z"))),
            at("20261013T030000Z")
        );
        // a boot catch-up at 02:58 skips the 03:00 slot two minutes later
        let catchup = at("20261013T025800Z");
        assert_eq!(next_after(catchup, Some(catchup)), at("20261014T030000Z"));
        // the first backup in the afternoon (14:24) keeps the next night
        let afternoon = at("20261013T142408Z");
        assert_eq!(
            next_after(afternoon, Some(afternoon)),
            at("20261014T030000Z")
        );
        assert_eq!(
            first_run(at("20261014T090000Z"), Some(afternoon)),
            at("20261015T030000Z")
        );
        // a manual backup at 23:00 is within MIN_GAP of 03:00: skipped
        let manual = at("20261013T230000Z");
        assert_eq!(next_after(manual, Some(manual)), at("20261015T030000Z"));
        // never two automatic backups within MIN_GAP
        for h in 0..48 {
            let t = now + h * 1800;
            assert!(next_after(t, Some(t)) >= t + MIN_GAP);
        }
    }

    #[test]
    fn health_shape_has_no_secrets() {
        let off = Backups::new(BackupSetting::Off, None).health();
        assert_eq!(off["configured"], false);
        assert_eq!(off["status"], "off");
        let bad = Backups::new(
            BackupSetting::parse(Some("s3://k:TOPSECRET@h"), None, None),
            None,
        )
        .health();
        assert_eq!(bad["configured"], false);
        assert_eq!(bad["status"], "misconfigured");
        assert!(bad["last_error"].as_str().unwrap().contains("BUCKET"));
        let b = Backups::new(
            BackupSetting::parse(
                Some("s3://AKIAXYZ:TOPSECRET@acct.r2.cloudflarestorage.com/mybucket/pre"),
                Some("14"),
                None,
            ),
            None,
        );
        let h = b.health();
        let mut keys: Vec<&str> = h.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "configured",
                "last_error",
                "last_size_bytes",
                "last_success",
                "next_at",
                "provider",
                "retention_days",
                "running",
                "status"
            ]
        );
        assert_eq!(h["configured"], true);
        assert_eq!(h["provider"], "r2");
        assert_eq!(h["retention_days"], 14);
        assert_eq!(h["running"], false);
        assert!(h["last_success"].is_null() && h["next_at"].is_null());
        let text = h.to_string() + &b.status().to_string();
        for secret in [
            "TOPSECRET",
            "AKIAXYZ",
            "mybucket",
            "acct",
            "cloudflarestorage",
            "pre\"",
        ] {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
    }

    #[test]
    fn manual_backups_are_rate_limited_and_exclusive() {
        let b = Backups::new(
            BackupSetting::parse(Some("s3+http://k:s@127.0.0.1:9/b"), None, None),
            None,
        );
        let slow: Snapshot = Arc::new(|_| {
            std::thread::sleep(Duration::from_millis(300));
            Err("stop".into())
        });
        let id = b.start(Trigger::Manual, slow.clone()).unwrap();
        assert_eq!(
            b.start(Trigger::Scheduled, slow.clone()),
            Err(StartError::Running(id))
        );
        assert!(b.health()["running"].as_bool().unwrap());
        while b.health()["running"].as_bool().unwrap() {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            matches!(b.start(Trigger::Manual, slow.clone()), Err(StartError::Cooldown(s)) if s > 500)
        );
        assert_eq!(b.health()["last_error"], "stop");
        assert_eq!(b.status()["job"]["state"], "failed");
        let off = Backups::new(BackupSetting::Off, None);
        assert_eq!(off.start(Trigger::Manual, slow), Err(StartError::Off));
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "rugen-backup-{tag}-{}",
            crate::store::random_hex(6)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The owner's case: no prefix, one backup of 0.6.0 flat at the bucket
    /// root. Restore finds it until a backup of the new layout exists; the
    /// first successful one deletes exactly the flat `.db.zst` / `.json`.
    #[test]
    fn legacy_flat_backups_are_restored_then_cleaned_up() {
        use crate::s3_fake::FakeS3;
        let fake = FakeS3::start("backup-of-backups", "AK", "SK", "auto");
        let url = format!(
            "s3+http://AK:SK@127.0.0.1:{}/backup-of-backups?region=auto",
            fake.port
        );
        let cfg = on(BackupSetting::parse(Some(&url), None, None));
        assert_eq!(cfg.target.prefix, "");
        let s3 = S3::new(cfg.target.clone());
        let data = temp_dir("legacy");
        {
            let store = crate::store::Store::open(Some(&data)).unwrap();
            store.register().unwrap();
        }
        let db = data.join("rugen.db");
        let work = data.join("backup-tmp");
        let runner = Runner {
            cfg: &cfg,
            s3: &s3,
            data: Some(&data),
            work: &work,
        };

        // make a genuine flat backup as 0.6.0 wrote it: move a fresh set
        // to the bucket root, the manifest naming the flat database
        let made = runner.run(&|out| snapshot_file(&db, out)).unwrap();
        let legacy = "rugen-backup-20261013T141050Z-0.6.0";
        {
            let mut objs = fake.objects.lock().unwrap();
            let manifest_key = made.db_key.replace(".db.zst", ".json");
            let body = objs.remove(&made.db_key).unwrap();
            objs.insert(format!("{legacy}.db.zst"), body);
            let mut m: Manifest =
                serde_json::from_slice(&objs.remove(&manifest_key).unwrap().body).unwrap();
            m.db.name = format!("{legacy}.db.zst");
            let body = serde_json::to_vec(&m).unwrap();
            objs.insert(
                format!("{legacy}.json"),
                crate::s3_fake::Stored { body, modified: 1 },
            );
        }
        assert!(list_sets(&s3).unwrap().iter().all(|s| s.legacy));
        // things the cleanup must leave alone
        for k in [
            format!("{legacy}.signing.key"),
            "rugen-backup-notes.txt".into(),
            "chars/kfm/rugen-backup-20261013T141050Z-0.6.0.json".into(),
            "stages/rugen-backup-x.db.zst".into(),
            "README.md".into(),
        ] {
            fake.put(&k, b"keep", 1);
        }

        // no backup of the new layout yet: restore finds the flat one
        let target = temp_dir("legacy-restore");
        let out = restore(&cfg, &target, "latest").unwrap();
        assert!(out.contains(legacy), "{out}");
        assert!(restore(&cfg, &target, legacy).is_ok());
        assert!(restore(&cfg, &target, &format!("{legacy}.db.zst")).is_ok());
        let b = Backups::new(BackupSetting::On(cfg.clone()), None);
        let rows = b.list().unwrap()["backups"].clone();
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["legacy"], true);
        assert_eq!(rows[0]["key"], format!("{legacy}.db.zst"));

        // a failed backup deletes nothing
        assert!(runner.run(&|_| Err("disk full".into())).is_err());
        assert!(fake.keys().contains(&format!("{legacy}.json")));

        // the next successful backup: new layout up, flat objects gone
        let rep = runner.run(&|out| snapshot_file(&db, out)).unwrap();
        assert_eq!(rep.legacy_deleted, 2);
        assert_eq!(rep.deleted, 0, "retention ignores the flat layout");
        let keys = fake.keys();
        assert!(rep.db_key.starts_with("backups/db/"), "{}", rep.db_key);
        assert!(keys.contains(&rep.db_key));
        assert!(!keys.contains(&format!("{legacy}.db.zst")), "{keys:?}");
        assert!(!keys.contains(&format!("{legacy}.json")), "{keys:?}");
        for k in [
            format!("{legacy}.signing.key"),
            "rugen-backup-notes.txt".into(),
            "chars/kfm/rugen-backup-20261013T141050Z-0.6.0.json".into(),
            "stages/rugen-backup-x.db.zst".into(),
            "README.md".into(),
        ] {
            assert!(keys.contains(&k), "{k} stays: {keys:?}");
        }
        let sets = list_sets(&s3).unwrap();
        assert_eq!(sets.len(), 1);
        assert!(!sets[0].legacy);
        assert!(
            restore(&cfg, &target, "latest")
                .unwrap()
                .contains(&rep.stem)
        );
        assert_eq!(*fake.rejected.lock().unwrap(), 0);
        let _ = std::fs::remove_dir_all(&data);
        let _ = std::fs::remove_dir_all(&target);
    }

    /// Backup, incremental packages, retention and restore against the
    /// in-process fake S3 (signatures checked on every request).
    #[test]
    fn full_cycle_against_a_fake_s3() {
        use crate::s3_fake::FakeS3;
        let fake = FakeS3::start("rugen", "AKTEST", "se/cr+et", "auto");
        let url = format!(
            "s3+http://AKTEST:se%2Fcr%2Bet@127.0.0.1:{}/rugen/prod/eu?region=auto",
            fake.port
        );
        let cfg = on(BackupSetting::parse(
            Some(&url),
            Some("7"),
            Some("packages,signing-key"),
        ));
        let s3 = S3::new(cfg.target.clone());

        let data = temp_dir("data");
        let fp = "ab".repeat(32);
        {
            let store = crate::store::Store::open(Some(&data)).unwrap();
            let a = store.register().unwrap();
            store.register().unwrap();
            store
                .put_package(&crate::store::PackageRow {
                    fingerprint: fp.clone(),
                    kind: "char".into(),
                    size: 5,
                    name: "x".into(),
                    author: "y".into(),
                    def: "x.def".into(),
                    profile: None,
                    uploader: a.id,
                    created: now(),
                    last_used: now(),
                    keep_until: 0,
                })
                .unwrap();
        }
        std::fs::write(data.join("signing.key"), "00".repeat(32)).unwrap();
        std::fs::create_dir_all(data.join("packages/partial")).unwrap();
        std::fs::write(data.join(format!("packages/{fp}.rgc")), b"hello").unwrap();
        std::fs::write(data.join("packages/partial/x.part"), b"skip me").unwrap();

        // an old backup set and foreign objects: retention drops the set only
        fake.put(
            "prod/eu/backups/db/2020/01/rugen-backup-20200101T030000Z-0.5.0.db.zst",
            b"old",
            1,
        );
        fake.put(
            "prod/eu/backups/db/2020/01/rugen-backup-20200101T030000Z-0.5.0.json",
            b"{}",
            1,
        );
        fake.put(
            "prod/eu/backups/keys/2020/01/rugen-backup-20200101T030000Z-0.5.0.signing.key",
            b"k",
            1,
        );
        fake.put("prod/eu/README.txt", b"mine", 1);
        fake.put("prod/eu/chars/kfm.zip", b"char", 1);
        fake.put("prod/eu/packages/old.rgc", b"pre-layout package", 1);
        // more objects than one listing page (backups of other months too)
        for i in 0..4 {
            fake.put(
                &format!(
                    "prod/eu/backups/packages/{}.rgc",
                    format!("{i:02}").repeat(32)
                ),
                b"p",
                1,
            );
            fake.put(
                &format!(
                    "prod/eu/backups/db/2019/{:02}/rugen-backup-2019{:02}01T030000Z-0.4.0.db.zst",
                    i + 1,
                    i + 1
                ),
                b"older",
                1,
            );
        }

        let work = data.join("backup-tmp");
        let db = data.join("rugen.db");
        let runner = Runner {
            cfg: &cfg,
            s3: &s3,
            data: Some(&data),
            work: &work,
        };
        let rep = runner.run(&|out| snapshot_file(&db, out)).unwrap();
        assert_eq!(
            *fake.rejected.lock().unwrap(),
            0,
            "every request signed correctly"
        );
        assert_eq!(rep.packages_uploaded, 1);
        assert_eq!(rep.deleted, 5, "the 2020 set and the four 2019 ones");
        assert_eq!(rep.legacy_deleted, 0);
        let keys = fake.keys();
        let month = format!("prod/eu/{}", dated_dir(DB_DIR, rep.created));
        assert!(month.starts_with("prod/eu/backups/db/20"), "{month}");
        assert_eq!(rep.db_key, format!("{month}/{}.db.zst", rep.stem));
        assert!(keys.contains(&rep.db_key), "{keys:?}");
        assert!(keys.contains(&format!("{month}/{}.json", rep.stem)));
        assert!(keys.contains(&format!(
            "prod/eu/{}/{}.signing.key",
            dated_dir(KEYS_DIR, rep.created),
            rep.stem
        )));
        assert!(keys.contains(&format!("prod/eu/backups/packages/{fp}.rgc")));
        for foreign in [
            "prod/eu/README.txt",
            "prod/eu/chars/kfm.zip",
            "prod/eu/packages/old.rgc",
        ] {
            assert!(
                keys.contains(&foreign.to_string()),
                "foreign {foreign} stays"
            );
        }
        assert!(!keys.iter().any(|k| k.contains("20200101")), "{keys:?}");
        assert!(!keys.iter().any(|k| k.contains("2019")), "{keys:?}");
        assert!(!keys.iter().any(|k| k.contains("part")));
        // stale remote packages that are gone locally were deleted
        assert_eq!(
            keys.iter()
                .filter(|k| k.contains("/backups/packages/"))
                .count(),
            1
        );
        assert!(
            keys.iter().all(|k| k.starts_with("prod/eu/backups/")
                || [
                    "prod/eu/README.txt",
                    "prod/eu/chars/kfm.zip",
                    "prod/eu/packages/old.rgc"
                ]
                .contains(&k.as_str())),
            "{keys:?}"
        );
        assert!(!work.join("snapshot.db").exists() && !work.join("snapshot.db.zst").exists());
        let manifest: Manifest = serde_json::from_slice(
            &fake.objects.lock().unwrap()[&format!("{month}/{}.json", rep.stem)].body,
        )
        .unwrap();
        assert_eq!(
            manifest.db.name,
            format!("{}/{}.db.zst", dated_dir(DB_DIR, rep.created), rep.stem)
        );
        assert_eq!(manifest.packages.as_ref().unwrap().dir, "backups/packages");
        assert_eq!(
            manifest.schema_version,
            crate::store::Store::open(Some(&data))
                .unwrap()
                .schema_version()
                .unwrap() as u64
        );
        assert_eq!(manifest.db.size, rep.size);

        // incremental: the package is not sent twice
        std::thread::sleep(Duration::from_millis(1100));
        let rep2 = runner.run(&|out| snapshot_file(&db, out)).unwrap();
        assert_eq!(rep2.packages_uploaded, 0);
        assert_eq!(list_sets(&s3).unwrap().len(), 2);

        // restore the newest into a fresh box that has a different database
        let target = temp_dir("restore");
        {
            let other = crate::store::Store::open(Some(&target)).unwrap();
            for _ in 0..5 {
                other.register().unwrap();
            }
        }
        let out = restore(&cfg, &target, "latest").unwrap();
        assert!(out.contains(&rep2.stem), "{out}");
        let restored = crate::store::Store::open(Some(&target)).unwrap();
        assert_eq!(restored.account_count().unwrap(), 2);
        let baks: Vec<_> = std::fs::read_dir(&target)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".bak"))
            .collect();
        assert_eq!(baks.len(), 1, "old database kept: {baks:?}");
        assert_eq!(
            std::fs::read(target.join(format!("packages/{fp}.rgc"))).unwrap(),
            b"hello"
        );
        assert_eq!(
            std::fs::read_to_string(target.join("signing.key")).unwrap(),
            "00".repeat(32)
        );
        // by key and by name too; a tampered object is refused
        let first = rep.db_key.clone();
        assert!(restore(&cfg, &target, &first).is_ok());
        assert!(
            restore(&cfg, &target, &rep.stem)
                .unwrap()
                .contains(&rep.stem)
        );
        fake.objects
            .lock()
            .unwrap()
            .get_mut(&first)
            .unwrap()
            .body
            .push(0);
        let e = restore(&cfg, &target, &first).unwrap_err();
        assert!(e.contains("sha256"), "{e}");
        assert!(restore(&cfg, &target, "rugen-backup-19990101T000000Z-0.1.0").is_err());

        // a wrong secret: a short error without host or bucket
        let bad = on(BackupSetting::parse(
            Some(&format!(
                "s3+http://AKTEST:nope@127.0.0.1:{}/rugen/prod/eu",
                fake.port
            )),
            None,
            None,
        ));
        let e = list_sets(&S3::new(bad.target)).unwrap_err();
        assert_eq!(e.short(), "LIST: HTTP 403 SignatureDoesNotMatch");
        let _ = std::fs::remove_dir_all(&data);
        let _ = std::fs::remove_dir_all(&target);
    }
}
