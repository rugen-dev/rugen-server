//! A minimal S3 client: AWS Signature V4 written out by hand over the
//! `ureq` agent the server already has (no AWS SDK, no extra crates).
//!
//! It speaks the subset every S3-compatible store implements the same way
//! (AWS S3, Cloudflare R2, MinIO, Backblaze B2, Wasabi): `PUT` / `GET` /
//! `DELETE` of one object and `ListObjectsV2`. Uploads stream from a file
//! with a fixed `Content-Length` and the payload's sha256 in
//! `x-amz-content-sha256` (one pass to hash, one to send: memory stays at
//! one copy buffer whatever the size). A single `PUT` takes up to 5 GB,
//! far above anything this server stores, so there is no multipart code.
//!
//! Errors never contain credentials; [`S3Error::short`] is also free of the
//! endpoint and bucket so it can be shown on `/health`.

use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};

/// Where objects go and how to sign for them.
#[derive(Clone, PartialEq, Eq)]
pub struct S3Target {
    /// `https` or `http`.
    pub scheme: &'static str,
    /// `host[:port]` of the endpoint (default ports stripped).
    pub host: String,
    pub bucket: String,
    /// Key prefix without leading / trailing `/` (may be empty).
    pub prefix: String,
    pub region: String,
    /// Virtual-hosted style (`bucket.host`) instead of path style.
    pub virtual_style: bool,
    pub access_key: String,
    pub secret_key: String,
}

impl std::fmt::Debug for S3Target {
    /// Never prints the keys.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Target")
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("region", &self.region)
            .field("virtual_style", &self.virtual_style)
            .finish_non_exhaustive()
    }
}

/// One object of a listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    pub key: String,
    pub size: u64,
    /// `LastModified`, unix seconds (0 when unparsable).
    pub modified: u64,
}

#[derive(Debug)]
pub enum S3Error {
    /// The store answered with an error status.
    Status {
        op: &'static str,
        status: u16,
        code: String,
    },
    /// Connection, TLS, timeout.
    Network { op: &'static str, detail: String },
    /// Local file I/O.
    Io(String),
    /// A response we could not understand, or a failed check.
    Invalid(String),
}

impl S3Error {
    /// For `/health`: no host, no bucket, no key.
    pub fn short(&self) -> String {
        match self {
            S3Error::Status { op, status, code } if code.is_empty() => {
                format!("{op}: HTTP {status}")
            }
            S3Error::Status { op, status, code } => format!("{op}: HTTP {status} {code}"),
            S3Error::Network { op, .. } => format!("{op}: network error"),
            S3Error::Io(_) => "local file error".into(),
            S3Error::Invalid(m) => m.clone(),
        }
    }
}

impl std::fmt::Display for S3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            S3Error::Network { op, detail } => write!(f, "{op}: {detail}"),
            S3Error::Io(e) => write!(f, "file: {e}"),
            other => f.write_str(&other.short()),
        }
    }
}

impl std::error::Error for S3Error {}

impl From<std::io::Error> for S3Error {
    fn from(e: std::io::Error) -> Self {
        S3Error::Io(e.to_string())
    }
}

pub type S3Result<T> = Result<T, S3Error>;

/// Copy buffer of uploads / downloads / hashing.
const BUF: usize = 64 * 1024;

pub struct S3 {
    pub target: S3Target,
    agent: ureq::Agent,
}

impl S3 {
    pub fn new(target: S3Target) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_connect(Some(Duration::from_secs(15)))
            .timeout_recv_response(Some(Duration::from_secs(120)))
            // big bodies: bounded per transfer, not per call
            .timeout_send_body(Some(Duration::from_secs(3600)))
            .timeout_recv_body(Some(Duration::from_secs(3600)))
            .build()
            .into();
        Self { target, agent }
    }

    /// The full key of `name` under the configured prefix.
    pub fn key(&self, name: &str) -> String {
        if self.target.prefix.is_empty() {
            name.to_string()
        } else {
            format!("{}/{name}", self.target.prefix)
        }
    }

    /// `(host header, canonical path)` of an object key (`""` = the bucket).
    fn locate(&self, key: &str) -> (String, String) {
        let t = &self.target;
        let enc_key = uri_encode(key, false);
        if t.virtual_style {
            (format!("{}.{}", t.bucket, t.host), format!("/{enc_key}"))
        } else if key.is_empty() {
            (t.host.clone(), format!("/{}", uri_encode(&t.bucket, true)))
        } else {
            (
                t.host.clone(),
                format!("/{}/{enc_key}", uri_encode(&t.bucket, true)),
            )
        }
    }

    /// Signed headers of a request.
    fn sign(
        &self,
        method: &str,
        host: &str,
        path: &str,
        query: &[(String, String)],
        payload_sha: &str,
    ) -> Vec<(String, String)> {
        let date = amz_date(crate::store::now());
        let headers = vec![
            ("host".to_string(), host.to_string()),
            ("x-amz-content-sha256".to_string(), payload_sha.to_string()),
            ("x-amz-date".to_string(), date.clone()),
        ];
        let auth = authorization(
            &self.target.access_key,
            &self.target.secret_key,
            &self.target.region,
            method,
            path,
            query,
            &headers,
            payload_sha,
            &date,
        );
        let mut out: Vec<(String, String)> = headers.into_iter().skip(1).collect();
        out.push(("authorization".into(), auth));
        out
    }

    fn url(&self, host: &str, path: &str, query: &[(String, String)]) -> String {
        let q = canonical_query(query);
        if q.is_empty() {
            format!("{}://{host}{path}", self.target.scheme)
        } else {
            format!("{}://{host}{path}?{q}", self.target.scheme)
        }
    }

    /// Upload a file as `key`, streamed. Returns the sha256 (hex) sent.
    pub fn put_file(&self, key: &str, file: &Path) -> S3Result<String> {
        let (sha, len) = sha256_file(file)?;
        let (host, path) = self.locate(key);
        let mut req = self.agent.put(self.url(&host, &path, &[]));
        for (k, v) in self.sign("PUT", &host, &path, &[], &sha) {
            req = req.header(k, v);
        }
        let mut f = std::fs::File::open(file)?;
        let res = req
            .header("content-length", len.to_string())
            .header("content-type", "application/octet-stream")
            .send(ureq::SendBody::from_reader(&mut f))
            .map_err(|e| net("PUT", e))?;
        check("PUT", res)?;
        Ok(sha)
    }

    /// Upload a small in-memory object.
    pub fn put_bytes(&self, key: &str, bytes: &[u8], content_type: &str) -> S3Result<()> {
        let sha = rugen_proto::to_hex(&Sha256::digest(bytes));
        let (host, path) = self.locate(key);
        let mut req = self.agent.put(self.url(&host, &path, &[]));
        for (k, v) in self.sign("PUT", &host, &path, &[], &sha) {
            req = req.header(k, v);
        }
        let res = req
            .header("content-type", content_type)
            .send(bytes)
            .map_err(|e| net("PUT", e))?;
        check("PUT", res).map(|_| ())
    }

    /// Download `key` into `file` (streamed). Returns `(sha256 hex, bytes)`.
    pub fn get_to_file(&self, key: &str, file: &Path) -> S3Result<(String, u64)> {
        let res = self.get(key)?;
        let mut reader = res.into_body().into_reader();
        let mut out = std::io::BufWriter::new(std::fs::File::create(file)?);
        let mut h = Sha256::new();
        let mut buf = vec![0u8; BUF];
        let mut total = 0u64;
        loop {
            let n = reader.read(&mut buf).map_err(|e| S3Error::Network {
                op: "GET",
                detail: e.to_string(),
            })?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            out.write_all(&buf[..n])?;
            total += n as u64;
        }
        out.flush()?;
        out.get_ref().sync_all()?;
        Ok((rugen_proto::to_hex(&h.finalize()), total))
    }

    /// Download a small object (at most `limit` bytes).
    pub fn get_bytes(&self, key: &str, limit: u64) -> S3Result<Vec<u8>> {
        let res = self.get(key)?;
        res.into_body()
            .into_with_config()
            .limit(limit)
            .read_to_vec()
            .map_err(|e| net("GET", e))
    }

    fn get(&self, key: &str) -> S3Result<ureq::http::Response<ureq::Body>> {
        let (host, path) = self.locate(key);
        let mut req = self.agent.get(self.url(&host, &path, &[]));
        for (k, v) in self.sign("GET", &host, &path, &[], EMPTY_SHA256) {
            req = req.header(k, v);
        }
        check("GET", req.call().map_err(|e| net("GET", e))?)
    }

    pub fn delete(&self, key: &str) -> S3Result<()> {
        let (host, path) = self.locate(key);
        let mut req = self.agent.delete(self.url(&host, &path, &[]));
        for (k, v) in self.sign("DELETE", &host, &path, &[], EMPTY_SHA256) {
            req = req.header(k, v);
        }
        check("DELETE", req.call().map_err(|e| net("DELETE", e))?).map(|_| ())
    }

    /// Every object whose key starts with `prefix` (all pages).
    pub fn list(&self, prefix: &str) -> S3Result<Vec<Object>> {
        let (host, path) = self.locate("");
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        // a runaway listing (a store ignoring the token) must end
        for _ in 0..10_000 {
            let mut query = vec![
                ("list-type".to_string(), "2".to_string()),
                ("prefix".to_string(), prefix.to_string()),
            ];
            if let Some(t) = &token {
                query.push(("continuation-token".into(), t.clone()));
            }
            query.sort();
            let mut req = self.agent.get(self.url(&host, &path, &query));
            for (k, v) in self.sign("GET", &host, &path, &query, EMPTY_SHA256) {
                req = req.header(k, v);
            }
            let res = check("LIST", req.call().map_err(|e| net("LIST", e))?)?;
            let xml = res
                .into_body()
                .into_with_config()
                .limit(16 << 20)
                .read_to_string()
                .map_err(|e| net("LIST", e))?;
            let page = parse_list(&xml);
            out.extend(page.objects);
            match page.next {
                Some(t) if page.truncated => token = Some(t),
                _ => return Ok(out),
            }
        }
        Err(S3Error::Invalid("LIST: too many pages".into()))
    }
}

fn net(op: &'static str, e: ureq::Error) -> S3Error {
    S3Error::Network {
        op,
        detail: e.to_string(),
    }
}

/// 2xx passes; anything else becomes [`S3Error::Status`] with the S3 `<Code>`.
fn check(
    op: &'static str,
    res: ureq::http::Response<ureq::Body>,
) -> S3Result<ureq::http::Response<ureq::Body>> {
    let status = res.status().as_u16();
    if (200..300).contains(&status) {
        return Ok(res);
    }
    let body = res
        .into_body()
        .into_with_config()
        .limit(8 * 1024)
        .read_to_string()
        .unwrap_or_default();
    let code = xml_tag(&body, "Code")
        .map(|c| {
            c.chars()
                .filter(char::is_ascii_alphanumeric)
                .take(48)
                .collect()
        })
        .unwrap_or_default();
    Err(S3Error::Status { op, status, code })
}

/// `(sha256 hex, length)` of a file, streamed.
pub fn sha256_file(path: &Path) -> std::io::Result<(String, u64)> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; BUF];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        total += n as u64;
    }
    Ok((rugen_proto::to_hex(&h.finalize()), total))
}

// ---- Signature V4

pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(msg);
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// RFC 3986 encoding as SigV4 wants it (`/` kept in paths when `slash` is false).
pub fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn canonical_query(query: &[(String, String)]) -> String {
    let mut q: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
        .collect();
    q.sort();
    q.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// The `Authorization` header value. `headers` are lowercase names; all of
/// them are signed.
#[allow(clippy::too_many_arguments)]
pub fn authorization(
    access_key: &str,
    secret_key: &str,
    region: &str,
    method: &str,
    path: &str,
    query: &[(String, String)],
    headers: &[(String, String)],
    payload_sha: &str,
    amz_date: &str,
) -> String {
    let mut hs: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    hs.sort();
    let canonical_headers: String = hs.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed: String = hs
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let creq = format!(
        "{method}\n{path}\n{}\n{canonical_headers}\n{signed}\n{payload_sha}",
        canonical_query(query)
    );
    let day = &amz_date[..8];
    let scope = format!("{day}/{region}/s3/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        rugen_proto::to_hex(&Sha256::digest(creq.as_bytes()))
    );
    let k = hmac(format!("AWS4{secret_key}").as_bytes(), day.as_bytes());
    let k = hmac(&k, region.as_bytes());
    let k = hmac(&k, b"s3");
    let k = hmac(&k, b"aws4_request");
    let sig = rugen_proto::to_hex(&hmac(&k, to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={sig}"
    )
}

// ---- time

/// `(year, month, day, hour, minute, second)` of unix seconds (UTC).
pub fn civil(t: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (t / 86_400) as i64;
    let rem = t % 86_400;
    // Howard Hinnant's civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (
        y,
        m,
        d,
        (rem / 3600) as u32,
        (rem % 3600 / 60) as u32,
        (rem % 60) as u32,
    )
}

/// Unix seconds of a UTC civil time.
pub fn unix(y: i64, m: u32, d: u32, hh: u32, mm: u32, ss: u32) -> Option<u64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let t = days * 86_400 + i64::from(hh) * 3600 + i64::from(mm) * 60 + i64::from(ss);
    u64::try_from(t).ok()
}

/// `20130524T000000Z` (also the backup object timestamp).
pub fn amz_date(t: u64) -> String {
    let (y, mo, d, h, mi, s) = civil(t);
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

/// `2013-05-24T00:00:00Z`.
pub fn rfc3339(t: u64) -> String {
    let (y, mo, d, h, mi, s) = civil(t);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Parses [`amz_date`] (`YYYYMMDDTHHMMSSZ`).
pub fn parse_amz_date(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<u32>().ok();
    unix(
        i64::from(n(0..4)?),
        n(4..6)?,
        n(6..8)?,
        n(9..11)?,
        n(11..13)?,
        n(13..15)?,
    )
}

/// Parses `2013-05-24T00:00:00(.000)Z` (S3 `LastModified`).
pub fn parse_rfc3339(s: &str) -> Option<u64> {
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<u32>().ok();
    if s.len() < 20 || s.as_bytes()[10] != b'T' {
        return None;
    }
    unix(
        i64::from(n(0..4)?),
        n(5..7)?,
        n(8..10)?,
        n(11..13)?,
        n(14..16)?,
        n(17..19)?,
    )
}

// ---- XML (ListObjectsV2 / Error), just enough

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

fn xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = start + xml[start..].find(&close)?;
    Some(xml_unescape(&xml[start..end]))
}

struct ListPage {
    objects: Vec<Object>,
    truncated: bool,
    next: Option<String>,
}

fn parse_list(xml: &str) -> ListPage {
    let mut objects = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<Contents>") {
        let after = &rest[i + "<Contents>".len()..];
        let Some(end) = after.find("</Contents>") else {
            break;
        };
        let block = &after[..end];
        if let Some(key) = xml_tag(block, "Key") {
            objects.push(Object {
                key,
                size: xml_tag(block, "Size")
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0),
                modified: xml_tag(block, "LastModified")
                    .and_then(|s| parse_rfc3339(s.trim()))
                    .unwrap_or(0),
            });
        }
        rest = &after[end..];
    }
    ListPage {
        objects,
        truncated: xml_tag(xml, "IsTruncated").is_some_and(|v| v.trim() == "true"),
        next: xml_tag(xml, "NextContinuationToken"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> String {
        v.to_string()
    }

    /// The worked "GET Object" example of the AWS SigV4 documentation
    /// (signing a Range header, virtual-hosted style).
    #[test]
    fn sigv4_matches_the_aws_get_object_example() {
        let headers = [
            (s("host"), s("examplebucket.s3.amazonaws.com")),
            (s("range"), s("bytes=0-9")),
            (s("x-amz-content-sha256"), s(EMPTY_SHA256)),
            (s("x-amz-date"), s("20130524T000000Z")),
        ];
        let auth = authorization(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "GET",
            "/test.txt",
            &[],
            &headers,
            EMPTY_SHA256,
            "20130524T000000Z",
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    /// The "GET Bucket (List Objects)" example: query parameters signed.
    #[test]
    fn sigv4_matches_the_aws_list_example() {
        let headers = [
            (s("host"), s("examplebucket.s3.amazonaws.com")),
            (s("x-amz-content-sha256"), s(EMPTY_SHA256)),
            (s("x-amz-date"), s("20130524T000000Z")),
        ];
        let auth = authorization(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "GET",
            "/",
            &[(s("max-keys"), s("2")), (s("prefix"), s("J"))],
            &headers,
            EMPTY_SHA256,
            "20130524T000000Z",
        );
        assert!(auth.ends_with(
            "Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
        ));
    }

    #[test]
    fn hmac_matches_rfc4231_case_2() {
        assert_eq!(
            rugen_proto::to_hex(&hmac(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn dates_round_trip() {
        assert_eq!(amz_date(1_369_353_600), "20130524T000000Z");
        assert_eq!(rfc3339(1_369_353_600), "2013-05-24T00:00:00Z");
        assert_eq!(parse_amz_date("20130524T000000Z"), Some(1_369_353_600));
        assert_eq!(
            parse_rfc3339("2013-05-24T00:00:00.000Z"),
            Some(1_369_353_600)
        );
        for t in [0u64, 951_782_400, 4_102_444_799, 1_791_000_000] {
            assert_eq!(parse_amz_date(&amz_date(t)), Some(t));
            assert_eq!(parse_rfc3339(&rfc3339(t)), Some(t));
        }
        assert_eq!(parse_amz_date("2013-05-24"), None);
    }

    #[test]
    fn list_xml_parses_pages() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult><Name>b</Name><Prefix>p/</Prefix><KeyCount>2</KeyCount>
<IsTruncated>true</IsTruncated><NextContinuationToken>abc&amp;d</NextContinuationToken>
<Contents><Key>p/a &amp; b</Key><LastModified>2013-05-24T00:00:00.000Z</LastModified><Size>12</Size></Contents>
<Contents><Key>p/c</Key><LastModified>2013-05-25T00:00:00Z</LastModified><Size>3</Size></Contents>
</ListBucketResult>"#;
        let p = parse_list(xml);
        assert_eq!(p.objects.len(), 2);
        assert_eq!(p.objects[0].key, "p/a & b");
        assert_eq!(p.objects[0].size, 12);
        assert_eq!(p.objects[1].modified, 1_369_440_000);
        assert!(p.truncated);
        assert_eq!(p.next.as_deref(), Some("abc&d"));
        assert!(
            !parse_list("<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>")
                .truncated
        );
    }

    #[test]
    fn uri_encoding_follows_sigv4() {
        assert_eq!(uri_encode("a b/c+d~", false), "a%20b/c%2Bd~");
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
    }
}
