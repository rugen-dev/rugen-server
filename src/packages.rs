//! Temporary content packages (`<RUGEN_DATA>/packages/<fingerprint>.rgc`
//! for characters, `.rgs` for stages).
//!
//! Players upload the content file (`.rgc` / `.rgs`) of the character /
//! stage they bring (chunked, resumable per account); the server opens it,
//! **recomputes the fingerprint and the fairness profile from its
//! content** and only then stores it, content-addressed. Nothing is
//! unpacked: the engine reads the file in place.
//! Opponents download it (ranged reads, resumable). Packages are caches:
//! they expire `RUGEN_PKG_TTL` after their last use, the oldest go first
//! when the total passes `RUGEN_PKG_MAX_TOTAL`, and packages of stored
//! ranked replays are kept until their `keep_until`.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::store::{PackageRow, Store, now};

#[derive(Clone, Debug)]
pub struct PkgConfig {
    /// Expiry after the last use, seconds.
    pub ttl_secs: u64,
    /// Total bytes kept (LRU eviction above).
    pub max_total: u64,
    /// Largest package (compressed) accepted.
    pub max_pkg: u64,
    /// Upload bytes per account per hour.
    pub account_rate: u64,
    /// Upload bytes per client IP per hour (HTTP layer).
    pub ip_rate: u64,
}

impl Default for PkgConfig {
    fn default() -> Self {
        Self {
            ttl_secs: 24 * 3600,
            max_total: 5 << 30,
            max_pkg: 150 << 20,
            account_rate: 1 << 30,
            ip_rate: 2 << 30,
        }
    }
}

/// `150MB`, `5GB`, `512k`, `1048576` → bytes.
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim().to_ascii_lowercase();
    let s = s.trim_end_matches('b').trim_end_matches('i');
    let (num, mul) = match s.chars().last()? {
        'k' => (&s[..s.len() - 1], 1u64 << 10),
        'm' => (&s[..s.len() - 1], 1 << 20),
        'g' => (&s[..s.len() - 1], 1 << 30),
        't' => (&s[..s.len() - 1], 1 << 40),
        _ => (s, 1),
    };
    let v: f64 = num.trim().parse().ok()?;
    (v >= 0.0).then_some((v * mul as f64) as u64)
}

/// `24h`, `90m`, `2d`, `3600` (seconds) → seconds.
pub fn parse_duration(s: &str) -> Option<u64> {
    let s = s.trim().to_ascii_lowercase();
    let (num, mul) = match s.chars().last()? {
        's' => (&s[..s.len() - 1], 1u64),
        'm' => (&s[..s.len() - 1], 60),
        'h' => (&s[..s.len() - 1], 3600),
        'd' => (&s[..s.len() - 1], 86400),
        _ => (s.as_str(), 1),
    };
    num.trim().parse::<u64>().ok().map(|v| v * mul)
}

impl PkgConfig {
    /// From `RUGEN_PKG_TTL`, `RUGEN_PKG_MAX_TOTAL`, `RUGEN_PKG_MAX`,
    /// `RUGEN_PKG_RATE_ACCOUNT`, `RUGEN_PKG_RATE_IP`.
    pub fn from_env() -> Self {
        let d = Self::default();
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        Self {
            ttl_secs: env("RUGEN_PKG_TTL")
                .and_then(|v| parse_duration(&v))
                .unwrap_or(d.ttl_secs),
            max_total: env("RUGEN_PKG_MAX_TOTAL")
                .and_then(|v| parse_size(&v))
                .unwrap_or(d.max_total),
            max_pkg: env("RUGEN_PKG_MAX")
                .and_then(|v| parse_size(&v))
                .unwrap_or(d.max_pkg),
            account_rate: env("RUGEN_PKG_RATE_ACCOUNT")
                .and_then(|v| parse_size(&v))
                .unwrap_or(d.account_rate),
            ip_rate: env("RUGEN_PKG_RATE_IP")
                .and_then(|v| parse_size(&v))
                .unwrap_or(d.ip_rate),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum UploadError {
    /// The chunk does not start where the partial upload ends (resume from here).
    Offset(u64),
    TooLarge,
    Io(String),
}

/// Result of verifying a finished upload.
#[derive(Debug)]
pub enum Verified {
    /// Stored: fingerprint and profile recomputed by the server.
    Stored(Box<PackageRow>),
    /// The files hash to something else than the fingerprint they were uploaded as.
    Mismatch { actual: String },
    /// Not a valid package at all.
    Invalid(String),
}

pub struct Packages {
    dir: PathBuf,
    pub cfg: PkgConfig,
}

impl Packages {
    /// `None` keeps packages in a fresh temp directory (tests, in-memory stores).
    pub fn open(data: Option<&Path>, cfg: PkgConfig) -> std::io::Result<Self> {
        let dir = match data {
            Some(d) => d.join("packages"),
            None => {
                std::env::temp_dir().join(format!("rugen-packages-{}", crate::store::random_hex(6)))
            }
        };
        std::fs::create_dir_all(dir.join("partial"))?;
        // files of an interrupted verification
        let _ = std::fs::remove_dir_all(dir.join("verify"));
        Ok(Self { dir, cfg })
    }

    /// Another view of an existing packages directory (tests).
    #[cfg(test)]
    pub fn at(dir: &Path, cfg: PkgConfig) -> Self {
        Self {
            dir: dir.to_path_buf(),
            cfg,
        }
    }

    #[cfg(test)]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Where package `fp` is stored (`.rgc` unless a stage `.rgs` is there).
    pub fn path(&self, fp: &str) -> PathBuf {
        let stage = self.dir.join(format!("{fp}.rgs"));
        if stage.is_file() {
            stage
        } else {
            self.dir.join(format!("{fp}.rgc"))
        }
    }

    /// Where package `fp` of `kind` is stored.
    pub fn path_for(&self, fp: &str, kind: rugen_fair::Kind) -> PathBuf {
        self.dir
            .join(format!("{fp}.{}", rugen_fair::package::ext(kind)))
    }

    fn partial(&self, fp: &str, account: u64) -> PathBuf {
        self.dir
            .join("partial")
            .join(format!("{fp}.{account}.part"))
    }

    pub fn has(&self, fp: &str) -> bool {
        self.path(fp).is_file()
    }

    /// The verified content of a stored package (re-simulation).
    #[cfg_attr(not(feature = "resim"), allow(dead_code))]
    pub fn verified(&self, fp: &str) -> rugen_fair::Result<rugen_fair::package::Verified> {
        rugen_fair::package::verify(&self.path(fp), self.cfg.max_pkg.saturating_mul(6))
    }

    pub fn partial_len(&self, fp: &str, account: u64) -> u64 {
        std::fs::metadata(self.partial(fp, account)).map_or(0, |m| m.len())
    }

    /// Append a chunk at `offset` of a `total`-byte upload. Returns the new length.
    pub fn append(
        &self,
        fp: &str,
        account: u64,
        offset: u64,
        total: u64,
        bytes: &[u8],
    ) -> Result<u64, UploadError> {
        if total > self.cfg.max_pkg || offset + bytes.len() as u64 > total {
            return Err(UploadError::TooLarge);
        }
        let path = self.partial(fp, account);
        let cur = self.partial_len(fp, account);
        if offset != cur {
            return Err(UploadError::Offset(cur));
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| UploadError::Io(e.to_string()))?;
        f.write_all(bytes)
            .map_err(|e| UploadError::Io(e.to_string()))?;
        Ok(cur + bytes.len() as u64)
    }

    pub fn drop_partial(&self, fp: &str, account: u64) {
        let _ = std::fs::remove_file(self.partial(fp, account));
    }

    /// Verify a complete partial upload: open it as a content file,
    /// recompute fingerprint and profile, store on success. The partial
    /// file is consumed either way.
    pub fn finalize(&self, fp: &str, account: u64) -> Verified {
        let part = self.partial(fp, account);
        let kind = match rugen_fair::package::read_header(&part) {
            Ok((kind, _)) => kind,
            Err(e) => {
                let _ = std::fs::remove_file(&part);
                return Verified::Invalid(e.to_string());
            }
        };
        // checked under a name with the content-file extension the readers need
        let checking = self.dir.join("verify").join(format!(
            "{fp}.{account}.{}.{}",
            crate::store::random_hex(4),
            rugen_fair::package::ext(kind)
        ));
        let moved = std::fs::create_dir_all(self.dir.join("verify"))
            .and_then(|()| std::fs::rename(&part, &checking));
        if let Err(e) = moved {
            let _ = std::fs::remove_file(&part);
            return Verified::Invalid(format!("store: {e}"));
        }
        match self.verify_file(&checking, fp, account) {
            Ok(row) => {
                rugen_formats::vfs::forget(&checking);
                if let Err(e) = std::fs::rename(&checking, self.path_for(fp, kind)) {
                    let _ = std::fs::remove_file(&checking);
                    return Verified::Invalid(format!("store: {e}"));
                }
                Verified::Stored(row)
            }
            Err(v) => {
                rugen_formats::vfs::forget(&checking);
                let _ = std::fs::remove_file(&checking);
                v
            }
        }
    }

    fn verify_file(
        &self,
        file: &Path,
        fp: &str,
        account: u64,
    ) -> Result<Box<PackageRow>, Verified> {
        let size = std::fs::metadata(file)
            .map_err(|e| Verified::Invalid(e.to_string()))?
            .len();
        // decompressed content may be a few times the package
        let u = rugen_fair::package::verify(file, self.cfg.max_pkg.saturating_mul(6))
            .map_err(|e| Verified::Invalid(e.to_string()))?;
        if u.fingerprint != fp {
            return Err(Verified::Mismatch {
                actual: u.fingerprint,
            });
        }
        if u.claimed != fp {
            return Err(Verified::Invalid("header names another fingerprint".into()));
        }
        let def = rugen_formats::def::Def::open(u.def_path()).ok();
        let info = |k: &str| {
            def.as_ref()
                .and_then(|d| d.section("info"))
                .and_then(|s| s.str(k))
                .unwrap_or("")
                .chars()
                .take(48)
                .collect::<String>()
        };
        let profile = match u.kind {
            rugen_fair::Kind::Char => Some(
                rugen_fair::profile::analyze(&u.files)
                    .map_err(|e| Verified::Invalid(format!("profile: {e}")))?,
            ),
            rugen_fair::Kind::Stage => None,
        };
        let name = {
            let n = info("displayname");
            if n.is_empty() { info("name") } else { n }
        };
        let t = now();
        Ok(Box::new(PackageRow {
            fingerprint: fp.to_string(),
            kind: u.kind.as_str().into(),
            size,
            name,
            author: info("author"),
            def: u.def.clone(),
            profile,
            uploader: account,
            created: t,
            last_used: t,
            keep_until: 0,
        }))
    }

    /// Up to `len` bytes of a stored package from `offset`.
    pub fn read(&self, fp: &str, offset: u64, len: u64) -> std::io::Result<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(self.path(fp))?;
        f.seek(SeekFrom::Start(offset))?;
        let mut buf = Vec::with_capacity(len.min(8 << 20) as usize);
        f.take(len).read_to_end(&mut buf)?;
        Ok(buf)
    }

    /// Expire (TTL, unless kept for a replay) and evict (LRU above the total
    /// cap) packages, drop stale partial uploads and orphan files. Returns
    /// the fingerprints removed.
    pub fn sweep(&self, store: &mut Store) -> Vec<String> {
        let t = now();
        let mut removed = Vec::new();
        let rows = match store.packages_lru() {
            Ok(r) => r,
            Err(e) => {
                log::error!("packages: {e}");
                return removed;
            }
        };
        let mut live: Vec<PackageRow> = Vec::new();
        for r in rows {
            let expired = r.last_used + self.cfg.ttl_secs < t && r.keep_until < t;
            if expired || !self.has(&r.fingerprint) {
                removed.push(r.fingerprint.clone());
            } else {
                live.push(r);
            }
        }
        let mut total: u64 = live.iter().map(|r| r.size).sum();
        if total > self.cfg.max_total {
            // least recently used first, replay-kept ones last
            live.sort_by_key(|r| (r.keep_until >= t, r.last_used));
            for r in &live {
                if total <= self.cfg.max_total {
                    break;
                }
                total = total.saturating_sub(r.size);
                removed.push(r.fingerprint.clone());
            }
        }
        for fp in &removed {
            let path = self.path(fp);
            rugen_formats::vfs::forget(&path);
            let _ = std::fs::remove_file(path);
            let _ = store.delete_package(fp);
        }
        // orphans (files without rows) and partial uploads older than the TTL
        let known: std::collections::HashSet<String> = store
            .packages_lru()
            .map(|v| v.into_iter().map(|r| r.fingerprint).collect())
            .unwrap_or_default();
        if let Ok(rd) = std::fs::read_dir(&self.dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                // a just-verified upload is renamed in before its row is
                // written (outside the store lock): leave young files alone
                let young = e
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|m| m.elapsed().ok())
                    .is_none_or(|age| age.as_secs() < 600);
                // RGPK packages of API 4 servers: never served again
                if name.ends_with(".rgpk") {
                    let _ = std::fs::remove_file(e.path());
                    continue;
                }
                let fp = name
                    .strip_suffix(".rgc")
                    .or_else(|| name.strip_suffix(".rgs"));
                if let Some(fp) = fp
                    && !known.contains(fp)
                    && !young
                {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        if let Ok(rd) = std::fs::read_dir(self.dir.join("partial")) {
            for e in rd.flatten() {
                let old = e
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|m| m.elapsed().ok())
                    .is_some_and(|age| age.as_secs() > self.cfg.ttl_secs);
                if old {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        if !removed.is_empty() {
            log::info!("packages: removed {} (ttl / size cap)", removed.len());
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_durations() {
        assert_eq!(parse_size("150MB"), Some(150 << 20));
        assert_eq!(parse_size("5GB"), Some(5 << 30));
        assert_eq!(parse_size("5GiB"), Some(5 << 30));
        assert_eq!(parse_size("512k"), Some(512 << 10));
        assert_eq!(parse_size("1000"), Some(1000));
        assert_eq!(parse_size("x"), None);
        assert_eq!(parse_duration("24h"), Some(86400));
        assert_eq!(parse_duration("90m"), Some(5400));
        assert_eq!(parse_duration("2d"), Some(172800));
        assert_eq!(parse_duration("30"), Some(30));
    }
}
