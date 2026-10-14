//! Packages served from an S3-compatible bucket (Cloudflare R2): players
//! download a fighter straight from the bucket through a short-lived
//! presigned URL instead of through this server.
//!
//! `RUGEN_PKG_S3` takes the same one-line URL as `RUGEN_BACKUP_S3` (it may
//! be the same bucket). Every verified package is copied once, content
//! addressed, to `<prefix>/chars/<sha256>.<ext>` (`chars/` is reserved for
//! it) by one low-priority thread; `GET /pkg/{fp}/url` then answers with a
//! presigned `GET` valid [`URL_SECS`] (15 minutes). Clients that do not ask
//! (rugen 0.6.0-0.6.3), an object not uploaded (yet), a bucket error or the
//! free-tier guard all fall back to the direct download from this server.
//!
//! Objects follow their packages: deleted with them, and anything older
//! than `RUGEN_PKG_DAYS` goes at the next sweep (an R2 lifecycle rule is the
//! recommended safety net). Free-tier guard: above `RUGEN_PKG_S3_MAX_GB`
//! (8) stored under `chars/`, nothing new is uploaded (served directly).
//! `/health` and `/admin/stats` show `packages_r2` (counts and the last
//! error, never the endpoint, bucket or keys).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use crate::s3::{S3, S3Target};
use crate::workers::Workers;

/// Lifetime of a presigned download URL.
pub const URL_SECS: u64 = 15 * 60;
/// Default free-tier guard, GB.
pub const DEFAULT_MAX_GB: u64 = 8;
const QUEUE: usize = 256;
const NICE: i32 = 10;

/// What the environment asked for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum R2Setting {
    #[default]
    Off,
    /// Set but unusable: why (never contains the secret).
    Invalid(String),
    On {
        target: S3Target,
        max_bytes: u64,
    },
}

impl R2Setting {
    pub fn from_env() -> Self {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        Self::parse(
            env("RUGEN_PKG_S3").as_deref(),
            env("RUGEN_PKG_S3_MAX_GB").as_deref(),
        )
    }

    pub fn parse(url: Option<&str>, max_gb: Option<&str>) -> Self {
        let Some(url) = url.map(crate::backup::unquote).filter(|v| !v.is_empty()) else {
            return Self::Off;
        };
        let target = match crate::backup::parse_url(url) {
            Ok(t) => t,
            Err(e) => return Self::Invalid(format!("RUGEN_PKG_S3: {e}")),
        };
        let max_gb = match max_gb.map(crate::backup::unquote).map(str::parse::<f64>) {
            None => DEFAULT_MAX_GB as f64,
            Some(Ok(g)) if g >= 0.0 => g,
            Some(_) => return Self::Invalid("RUGEN_PKG_S3_MAX_GB: a number of GB".into()),
        };
        Self::On {
            target,
            max_bytes: (max_gb * (1u64 << 30) as f64) as u64,
        }
    }
}

enum Job {
    /// Copy package `fp` (the file at the path) to the bucket.
    Upload(String, PathBuf),
    /// Delete an object key.
    Delete(String),
    /// List `chars/`: totals, and delete what outlived the age limit.
    Reconcile,
}

#[derive(Default)]
struct State {
    /// Objects under `chars/`: sha256 → (key, bytes).
    objects: HashMap<String, (String, u64)>,
    /// Package fingerprint → sha256 of its file.
    by_fp: HashMap<String, String>,
    /// Packages known to be uploading.
    pending: usize,
    last_error: Option<String>,
    /// Above the free-tier guard: new packages are served directly.
    full: bool,
    listed: bool,
}

impl State {
    fn bytes(&self) -> u64 {
        self.objects.values().map(|o| o.1).sum()
    }
}

pub struct PkgR2 {
    s3: S3,
    max_bytes: u64,
    max_age_secs: u64,
    state: Mutex<State>,
}

/// The bucket side plus its worker.
pub struct R2 {
    pub inner: Arc<PkgR2>,
    jobs: Option<Workers<Job>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl R2 {
    /// Start the worker and a first listing.
    pub fn new(target: S3Target, max_bytes: u64, max_age_secs: u64) -> Self {
        let inner = Arc::new(PkgR2 {
            s3: S3::new(target),
            max_bytes,
            max_age_secs,
            state: Mutex::new(State::default()),
        });
        let w = inner.clone();
        let jobs = Workers::spawn("rugen-r2", 1, QUEUE, NICE, move |j: Job| match j {
            Job::Upload(fp, path) => w.upload(&fp, &path),
            Job::Delete(key) => w.delete(&key),
            Job::Reconcile => w.reconcile(),
        })
        .map_err(|e| log::error!("packages r2: {e}"))
        .ok();
        let r = Self { inner, jobs };
        r.reconcile();
        r
    }

    fn submit(&self, j: Job) {
        if let Some(w) = &self.jobs
            && !w.submit(j)
        {
            lock(&self.inner.state).last_error = Some("queue full".into());
        }
    }

    /// A package was stored: copy it to the bucket (once per content).
    pub fn stored(&self, fp: &str, path: &Path) {
        lock(&self.inner.state).pending += 1;
        self.submit(Job::Upload(fp.to_string(), path.to_path_buf()));
    }

    /// Packages were deleted: their objects go too.
    pub fn forget(&self, fps: &[String]) {
        let keys: Vec<String> = {
            let mut st = lock(&self.inner.state);
            let mut keys = Vec::new();
            for fp in fps {
                let Some(sha) = st.by_fp.remove(fp) else {
                    continue;
                };
                if st.by_fp.values().any(|s| *s == sha) {
                    continue;
                }
                if let Some((key, _)) = st.objects.remove(&sha) {
                    keys.push(key);
                }
            }
            keys
        };
        for k in keys {
            self.submit(Job::Delete(k));
        }
    }

    /// List the bucket again (totals, the age limit).
    pub fn reconcile(&self) {
        self.submit(Job::Reconcile);
    }

    /// A presigned URL for package `fp` stored at `path`, with the file's
    /// sha256 and size, when its object is in the bucket.
    pub fn url(&self, fp: &str, path: &Path) -> Option<(String, String, u64)> {
        let known = {
            let st = lock(&self.inner.state);
            if st.objects.is_empty() {
                return None;
            }
            st.by_fp.get(fp).cloned()
        };
        // after a restart: hash the file once
        let sha = match known {
            Some(s) => s,
            None => {
                let (sha, _) = crate::s3::sha256_file(path).ok()?;
                lock(&self.inner.state)
                    .by_fp
                    .insert(fp.to_string(), sha.clone());
                sha
            }
        };
        let (key, size) = lock(&self.inner.state).objects.get(&sha).cloned()?;
        Some((self.inner.s3.presign_get(&key, URL_SECS), sha, size))
    }

    /// `/health` and `/admin/stats`: numbers and the last error only.
    pub fn health(&self) -> Value {
        let st = lock(&self.inner.state);
        json!({
            "configured": true,
            "objects": st.objects.len(),
            "bytes": st.bytes(),
            "max_bytes": self.inner.max_bytes,
            "full": st.full,
            "pending": st.pending,
            "last_error": st.last_error,
        })
    }

    /// Wait until the worker is idle (tests).
    #[cfg(test)]
    pub fn idle(&self) {
        let t = std::time::Instant::now();
        while self.jobs.as_ref().is_some_and(|j| j.queued() > 0)
            || lock(&self.inner.state).pending > 0
        {
            assert!(t.elapsed().as_secs() < 30, "r2 worker stuck");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // the job being run
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// `/health` when `RUGEN_PKG_S3` is unset or invalid.
pub fn health_off(setting: &R2Setting) -> Value {
    json!({
        "configured": false,
        "last_error": match setting {
            R2Setting::Invalid(e) => Some(e.clone()),
            _ => None,
        },
    })
}

impl PkgR2 {
    fn key_for(&self, sha: &str, ext: &str) -> String {
        self.s3.key(&format!("chars/{sha}.{ext}"))
    }

    fn fail(&self, what: &str, e: &crate::s3::S3Error) {
        log::warn!("packages r2: {what}: {e}");
        lock(&self.state).last_error = Some(format!("{what}: {}", e.short()));
    }

    fn upload(&self, fp: &str, path: &Path) {
        let done = |st: &mut State| st.pending = st.pending.saturating_sub(1);
        let (sha, size) = match crate::s3::sha256_file(path) {
            Ok(v) => v,
            Err(e) => {
                let mut st = lock(&self.state);
                done(&mut st);
                st.last_error = Some(format!("read package: {e}"));
                return;
            }
        };
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("rgc");
        let key = self.key_for(&sha, ext);
        {
            let mut st = lock(&self.state);
            st.by_fp.insert(fp.to_string(), sha.clone());
            if st.objects.contains_key(&sha) {
                done(&mut st);
                return;
            }
            if st.bytes() + size > self.max_bytes {
                st.full = true;
                done(&mut st);
                log::info!(
                    "packages r2: {} served directly (bucket at its {} MB guard)",
                    rugen_fair::short(fp),
                    self.max_bytes >> 20
                );
                return;
            }
        }
        let r = self.s3.put_file(&key, path);
        let mut st = lock(&self.state);
        done(&mut st);
        match r {
            Ok(_) => {
                st.objects.insert(sha, (key, size));
                st.last_error = None;
                log::info!(
                    "packages r2: {} uploaded ({} KB)",
                    rugen_fair::short(fp),
                    size >> 10
                );
            }
            Err(e) => {
                drop(st);
                self.fail("upload", &e);
            }
        }
    }

    fn delete(&self, key: &str) {
        if let Err(e) = self.s3.delete(key) {
            self.fail("delete", &e);
        }
    }

    fn reconcile(&self) {
        let prefix = self.s3.key("chars/");
        let list = match self.s3.list(&prefix) {
            Ok(l) => l,
            Err(e) => return self.fail("list", &e),
        };
        let now = crate::store::now();
        let mut objects = HashMap::new();
        let mut gone = 0;
        for o in list {
            let name = o.key.strip_prefix(&prefix).unwrap_or(&o.key);
            let Some((sha, _ext)) = name.split_once('.') else {
                continue;
            };
            if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            // the same age limit as the packages themselves
            if o.modified > 0 && o.modified + self.max_age_secs < now {
                match self.s3.delete(&o.key) {
                    Ok(()) => gone += 1,
                    Err(e) => self.fail("delete", &e),
                }
                continue;
            }
            objects.insert(sha.to_string(), (o.key.clone(), o.size));
        }
        let mut st = lock(&self.state);
        st.objects = objects;
        st.full = st.bytes() >= self.max_bytes;
        st.listed = true;
        if gone > 0 {
            log::info!("packages r2: {gone} expired objects deleted");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3_fake::FakeS3;

    fn target(fake: &FakeS3, prefix: &str) -> S3Target {
        match R2Setting::parse(
            Some(&format!(
                "s3+http://AK:S%2FK@127.0.0.1:{}/pkgs{prefix}?region=auto",
                fake.port
            )),
            None,
        ) {
            R2Setting::On { target, max_bytes } => {
                assert_eq!(max_bytes, 8 << 30, "8 GB by default");
                target
            }
            other => panic!("{other:?}"),
        }
    }

    fn file(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    fn get(url: &str) -> (u16, Vec<u8>) {
        let mut r = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .new_agent()
            .get(url)
            .call()
            .unwrap();
        (r.status().as_u16(), r.body_mut().read_to_vec().unwrap())
    }

    #[test]
    fn settings() {
        assert_eq!(R2Setting::parse(None, None), R2Setting::Off);
        assert_eq!(R2Setting::parse(Some("  "), None), R2Setting::Off);
        let R2Setting::Invalid(e) = R2Setting::parse(Some("http://x:y@h/b"), None) else {
            panic!()
        };
        assert!(e.starts_with("RUGEN_PKG_S3:") && !e.contains("x:y"), "{e}");
        let ok = "s3://k:s@abc.r2.cloudflarestorage.com/bucket";
        let R2Setting::On { max_bytes, .. } = R2Setting::parse(Some(ok), Some("0.5")) else {
            panic!()
        };
        assert_eq!(max_bytes, 512 << 20);
        assert!(matches!(
            R2Setting::parse(Some(ok), Some("lots")),
            R2Setting::Invalid(_)
        ));
    }

    #[test]
    fn uploads_once_presigns_and_follows_the_packages() {
        let fake = FakeS3::start("pkgs", "AK", "S/K", "auto");
        let r2 = R2::new(target(&fake, "/srv"), 8 << 30, 3 * 86400);
        r2.idle();
        let dir = crate::testkit::tmp("r2");
        let (a, b) = ("aa".repeat(32), "bb".repeat(32));
        let pa = file(&dir, &format!("{a}.rgc"), b"fighter one");
        // nothing in the bucket yet: served directly
        assert!(r2.url(&a, &pa).is_none());
        r2.stored(&a, &pa);
        r2.idle();
        let keys = fake.keys();
        let sha = crate::s3::sha256_file(&pa).unwrap().0;
        assert_eq!(keys, vec![format!("srv/chars/{sha}.rgc")]);
        // the same content under another fingerprint: uploaded once
        let pb = file(&dir.join("other"), &format!("{b}.rgc"), b"fighter one");
        r2.stored(&b, &pb);
        r2.idle();
        assert_eq!(fake.keys().len(), 1);
        // a presigned GET the fake accepts, nothing secret in it
        let (url, got_sha, size) = r2.url(&a, &pa).unwrap();
        assert_eq!((got_sha.as_str(), size), (sha.as_str(), 11));
        assert!(url.contains("X-Amz-Signature=") && url.contains("X-Amz-Expires=900"));
        assert!(!url.contains("S/K") && !url.contains("S%2FK"));
        assert_eq!(get(&url), (200, b"fighter one".to_vec()));
        // a tampered URL is refused
        assert_eq!(
            get(&url.replace("X-Amz-Expires=900", "X-Amz-Expires=9000")).0,
            403
        );
        let h = r2.health();
        assert_eq!(
            (h["objects"].as_u64(), h["bytes"].as_u64()),
            (Some(1), Some(11))
        );
        assert_eq!(h["configured"], true);
        assert!(!h.to_string().contains("127.0.0.1"));
        // one of two fingerprints gone: the object stays; both gone: it goes
        r2.forget(std::slice::from_ref(&a));
        r2.idle();
        assert_eq!(fake.keys().len(), 1);
        r2.forget(std::slice::from_ref(&b));
        r2.idle();
        assert!(fake.keys().is_empty());
        // the age limit: an object older than the package days goes at the sweep
        let now = crate::store::now();
        fake.put(
            &format!("srv/chars/{}.rgc", "cc".repeat(32)),
            b"old",
            now - 3 * 86400 - 60,
        );
        fake.put(
            &format!("srv/chars/{}.rgc", "dd".repeat(32)),
            b"new",
            now - 3600,
        );
        fake.put("srv/backups/db/x.db.zst", b"not ours", now - 9 * 86400);
        r2.reconcile();
        r2.idle();
        assert_eq!(
            fake.keys(),
            vec![
                "srv/backups/db/x.db.zst".to_string(),
                format!("srv/chars/{}.rgc", "dd".repeat(32))
            ]
        );
        assert_eq!(r2.health()["objects"], 1);
        assert_eq!(*fake.rejected.lock().unwrap(), 1, "only the tampered URL");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn above_the_guard_packages_are_served_directly() {
        let fake = FakeS3::start("pkgs", "AK", "S/K", "auto");
        let r2 = R2::new(target(&fake, ""), 20, 3 * 86400);
        let dir = crate::testkit::tmp("r2-cap");
        let (a, b) = ("aa".repeat(32), "bb".repeat(32));
        let pa = file(&dir, &format!("{a}.rgc"), b"0123456789abcdef");
        let pb = file(&dir, &format!("{b}.rgc"), b"another 16 bytes");
        r2.stored(&a, &pa);
        r2.stored(&b, &pb);
        r2.idle();
        assert_eq!(fake.keys().len(), 1, "the second would pass 20 bytes");
        assert!(r2.url(&a, &pa).is_some());
        assert!(r2.url(&b, &pb).is_none(), "served directly");
        let h = r2.health();
        assert_eq!(
            (h["full"].as_bool(), h["bytes"].as_u64()),
            (Some(true), Some(16))
        );
        // an unreachable bucket: an error on /health, downloads stay direct
        let gone = R2::new(
            match R2Setting::parse(Some("s3+http://AK:SK@127.0.0.1:9/pkgs"), None) {
                R2Setting::On { target, .. } => target,
                _ => unreachable!(),
            },
            8 << 30,
            86400,
        );
        gone.stored(&a, &pa);
        gone.idle();
        assert!(gone.url(&a, &pa).is_none());
        let e = gone.health()["last_error"].as_str().unwrap().to_string();
        assert!(!e.contains("SK") && !e.contains("127.0.0.1"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
