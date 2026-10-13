//! API 4 clients (rugen 0.5 and earlier): their packages and fingerprints.
//!
//! Until every player has updated, the server serves both generations side
//! by side (see [`crate::compat`]). An API 4 client uploads an **RGPK**
//! package (the canonical gameplay files byte for byte, zstd-compressed)
//! and fingerprints content with **`rugen-fp-1`** (sha256 over the bytes of
//! every file of the set, sounds and sprite files included). That format
//! left the engine with API 5, so the server keeps its own copy here: the
//! exact wire format and hash of engine v0.4.0 / v0.5.0
//! (`rugen-fair/src/package.rs` and `fingerprint_of` there), verified the
//! same defensive way (safe relative paths only, no duplicates, entry and
//! size caps, the unpacked set must be exactly the canonical set of its
//! def). The canonical file set and the fairness profile come from
//! `rugen-fair` itself: they did not change between the two generations,
//! so the server's analysis of an API 4 package still equals what an
//! honest 0.5 client declares.
//!
//! ```text
//! "RGPK" version:u8 kind:u8 fingerprint:[64 ascii]      (clear header)
//! zstd( def_len:u16 def  count:u32  { path_len:u16 path size:u64 bytes }* )
//! ```

use std::io::Read;
use std::path::{Path, PathBuf};

use rugen_fair::files::{ContentFiles, canon, content_files, safe_rel};
use rugen_fair::{Error, Kind, Result};
use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 4] = b"RGPK";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 4 + 1 + 1 + 64;
/// Entries a package may hold.
pub const MAX_ENTRIES: usize = 512;
/// File extension of a stored API 4 package.
pub const EXT: &str = "rgpk";

/// What a package file starts with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// RGPK (API 4).
    Rgpk,
    /// `.rgc` / `.rgs` content file (API 5).
    Rgc,
    /// A zip archive (what 0.5 players keep their characters in).
    Zip,
    Unknown,
}

/// The format of a package from its first bytes.
pub fn sniff(head: &[u8]) -> Format {
    if head.starts_with(MAGIC) {
        Format::Rgpk
    } else if head.starts_with(rugen_formats::rgc::MAGIC_CHAR)
        || head.starts_with(rugen_formats::rgc::MAGIC_STAGE)
    {
        Format::Rgc
    } else if head.starts_with(b"PK\x03\x04") {
        Format::Zip
    } else {
        Format::Unknown
    }
}

/// [`sniff`] of the file at `path`.
pub fn sniff_file(path: &Path) -> Format {
    let mut head = [0u8; 8];
    let n = std::fs::File::open(path)
        .and_then(|mut f| f.read(&mut head))
        .unwrap_or(0);
    sniff(&head[..n])
}

/// `rugen-fp-1` of a canonical file set: sha256 over `rugen-fp-1 / kind /
/// def` and the sorted `(lowercase path, sha256 of the bytes)` list.
pub fn fingerprint(files: &ContentFiles) -> Result<String> {
    let mut rows: Vec<(String, String)> = Vec::with_capacity(files.entries.len());
    for e in &files.entries {
        let bytes = rugen_formats::vfs::read(&e.source)
            .map_err(|err| Error::Content(format!("{}: {err}", e.path)))?;
        rows.push((e.canon.clone(), rugen_fair::sha256_hex(&bytes)));
    }
    Ok(fingerprint_of(files.kind, &files.def, rows))
}

fn fingerprint_of(kind: Kind, def: &str, mut rows: Vec<(String, String)>) -> String {
    rows.sort();
    rows.dedup_by(|a, b| a.0 == b.0);
    let mut h = Sha256::new();
    h.update(b"rugen-fp-1\n");
    h.update(kind.as_str().as_bytes());
    h.update(b"\n");
    h.update(canon(def).as_bytes());
    h.update(b"\n");
    for (path, sum) in rows {
        h.update(path.as_bytes());
        h.update([0]);
        h.update(sum.as_bytes());
        h.update(b"\n");
    }
    rugen_fair::hex(&h.finalize())
}

fn get_str(r: &mut impl Read) -> Result<String> {
    let mut n = [0u8; 2];
    r.read_exact(&mut n)?;
    let mut b = vec![0u8; u16::from_le_bytes(n) as usize];
    r.read_exact(&mut b)?;
    String::from_utf8(b).map_err(|_| Error::Package("path is not utf-8".into()))
}

/// The clear header of a package: kind and claimed fingerprint.
pub fn read_header(r: &mut impl Read) -> Result<(Kind, String)> {
    let mut h = [0u8; HEADER_LEN];
    r.read_exact(&mut h)
        .map_err(|_| Error::Package("truncated header".into()))?;
    if &h[..4] != MAGIC {
        return Err(Error::Package("not a rugen package".into()));
    }
    if h[4] != VERSION {
        return Err(Error::Package(format!("package version {}", h[4])));
    }
    let kind = match h[5] {
        0 => Kind::Char,
        1 => Kind::Stage,
        k => return Err(Error::Package(format!("unknown kind {k}"))),
    };
    let fingerprint = String::from_utf8(h[6..].to_vec())
        .ok()
        .filter(|f| rugen_proto::is_fingerprint(f))
        .ok_or_else(|| Error::Package("bad fingerprint in header".into()))?;
    Ok((kind, fingerprint))
}

/// An unpacked, re-verified package.
#[derive(Clone, Debug)]
pub struct Unpacked {
    pub kind: Kind,
    pub dir: PathBuf,
    /// Main def inside `dir`.
    pub def: String,
    /// Fingerprint the package claimed.
    pub claimed: String,
    /// `rugen-fp-1` recomputed from the unpacked files.
    pub fingerprint: String,
    pub files: ContentFiles,
}

impl Unpacked {
    pub fn def_path(&self) -> PathBuf {
        self.dir.join(&self.def)
    }
}

/// Unpack a package into the new directory `dest` (must not exist yet),
/// refusing more than `max_bytes` of content, then recompute its canonical
/// file set and fingerprint. `dest` is removed on error.
pub fn unpack(r: impl Read, dest: &Path, max_bytes: u64) -> Result<Unpacked> {
    if dest.exists() {
        return Err(Error::Package(format!("{} already exists", dest.display())));
    }
    std::fs::create_dir_all(dest)?;
    let out = unpack_inner(r, dest, max_bytes);
    if out.is_err() {
        let _ = std::fs::remove_dir_all(dest);
    }
    out
}

fn unpack_inner(mut r: impl Read, dest: &Path, max_bytes: u64) -> Result<Unpacked> {
    let (kind, claimed) = read_header(&mut r)?;
    let mut z = zstd::stream::read::Decoder::new(r)?;
    let def = get_str(&mut z)?;
    let mut n = [0u8; 4];
    z.read_exact(&mut n)?;
    let count = u32::from_le_bytes(n) as usize;
    if count == 0 || count > MAX_ENTRIES {
        return Err(Error::Package(format!("{count} entries")));
    }
    let mut seen: Vec<String> = Vec::with_capacity(count);
    let mut total = 0u64;
    for _ in 0..count {
        let path = get_str(&mut z)?;
        if !safe_rel(&path) {
            return Err(Error::Package(format!("unsafe path {path:?}")));
        }
        let c = canon(&path);
        if seen.contains(&c) {
            return Err(Error::Package(format!("duplicate entry {path:?}")));
        }
        seen.push(c);
        let mut sz = [0u8; 8];
        z.read_exact(&mut sz)?;
        let size = u64::from_le_bytes(sz);
        total = total.saturating_add(size);
        if total > max_bytes {
            return Err(Error::Package(format!(
                "content larger than {} MB",
                max_bytes / (1024 * 1024)
            )));
        }
        let target = dest.join(&path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = std::fs::File::create(&target)?;
        let copied = std::io::copy(&mut (&mut z).take(size), &mut f)?;
        if copied != size {
            return Err(Error::Package(format!("{path}: truncated")));
        }
    }
    // nothing may follow the last entry
    let mut extra = [0u8; 1];
    if z.read(&mut extra)? != 0 {
        return Err(Error::Package("trailing data".into()));
    }
    if !safe_rel(&def) || !seen.contains(&canon(&def)) || def.contains('/') {
        return Err(Error::Package(format!("bad main def {def:?}")));
    }
    let files = content_files(kind, &dest.join(&def), None)?;
    let mut want: Vec<&str> = files.entries.iter().map(|e| e.canon.as_str()).collect();
    want.sort_unstable();
    seen.sort_unstable();
    if want != seen.iter().map(String::as_str).collect::<Vec<_>>() {
        let extra: Vec<&String> = seen
            .iter()
            .filter(|s| !want.contains(&s.as_str()))
            .collect();
        return Err(Error::Package(format!(
            "file set does not match its def (unreferenced: {extra:?})"
        )));
    }
    let fingerprint = fingerprint(&files)?;
    Ok(Unpacked {
        kind,
        dir: dest.to_path_buf(),
        def,
        claimed,
        fingerprint,
        files,
    })
}

/// Write the package of `files` (whose fingerprint is `fp`) to `out`, as a
/// 0.5 client does (tests).
#[cfg(test)]
pub fn write(files: &ContentFiles, fp: &str, out: impl std::io::Write) -> Result<()> {
    use std::io::Write;
    let put_str = |w: &mut dyn Write, s: &str| -> Result<()> {
        w.write_all(&(s.len() as u16).to_le_bytes())?;
        w.write_all(s.as_bytes())?;
        Ok(())
    };
    let mut out = out;
    out.write_all(MAGIC)?;
    out.write_all(&[
        VERSION,
        match files.kind {
            Kind::Char => 0,
            Kind::Stage => 1,
        },
    ])?;
    out.write_all(fp.as_bytes())?;
    let mut z = zstd::stream::write::Encoder::new(out, 3)?;
    put_str(&mut z, &files.def)?;
    z.write_all(&(files.entries.len() as u32).to_le_bytes())?;
    for e in &files.entries {
        let data = std::fs::read(&e.source)?;
        put_str(&mut z, &e.path)?;
        z.write_all(&(data.len() as u64).to_le_bytes())?;
        z.write_all(&data)?;
    }
    z.finish()?.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{tiny_char, tmp};

    /// The `rugen-fp-1` of a known file set, computed by engine v0.5.0
    /// (`rugen_fair::fingerprint`) for these exact files: guards the hash
    /// against drifting from what 0.5 clients compute.
    #[test]
    fn fp1_matches_the_engine_v0_5_hash() {
        let root = tmp("legacy-fp");
        let dir = root.join("k");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("k.def"),
            "[Files]\ncmd = k.cmd\ncns = k.cns\nsprite = K.SFF\nanim = k.air\nsound = k.snd\nstcommon = common1.cns\n",
        )
        .unwrap();
        for (f, body) in [
            ("k.cmd", "cmd"),
            ("k.cns", "[Data]\nlife = 1000\n"),
            ("K.SFF", "sprites"),
            ("k.air", "[Begin Action 0]\n0,0, 0,0, 10\n"),
            ("k.snd", "sounds"),
            ("common1.cns", "[Statedef 0]\n"),
            ("readme.txt", "junk is not part of it"),
        ] {
            std::fs::write(dir.join(f), body).unwrap();
        }
        let files = content_files(Kind::Char, &dir.join("k.def"), None).unwrap();
        assert_eq!(
            fingerprint(&files).unwrap(),
            "8bb454a4919adb19e51358ef402166b5a888b5e7f47a8e9ed6e37f09aec47cb4",
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn roundtrip_and_hostile_packages() {
        let root = tmp("legacy-pkg");
        let def = tiny_char(&root.join("src"), "Old", "");
        std::fs::write(root.join("src/readme.txt"), "hello").unwrap();
        let files = content_files(Kind::Char, &def, None).unwrap();
        let fp = fingerprint(&files).unwrap();
        let mut bytes = Vec::new();
        write(&files, &fp, &mut bytes).unwrap();
        assert_eq!(sniff(&bytes), Format::Rgpk);
        let u = unpack(&bytes[..], &root.join("out"), 1 << 20).unwrap();
        assert_eq!(u.fingerprint, fp);
        assert_eq!(u.claimed, fp);
        assert!(!root.join("out/readme.txt").exists());
        // a second unpack into the same place, size cap, truncation
        assert!(unpack(&bytes[..], &root.join("out"), 1 << 20).is_err());
        assert!(unpack(&bytes[..], &root.join("b"), 10).is_err());
        assert!(!root.join("b").exists(), "cleaned up");
        assert!(unpack(&bytes[..bytes.len() / 2], &root.join("c"), 1 << 20).is_err());
        // the fingerprint is not the API 5 one
        assert_ne!(fp, rugen_fair::fingerprint(&files).unwrap());
        assert_eq!(sniff(b"PK\x03\x04rest"), Format::Zip);
        assert_eq!(sniff(b"RUGENRGC"), Format::Rgc);
        assert_eq!(sniff(b"??"), Format::Unknown);
        let _ = std::fs::remove_dir_all(&root);
    }
}
