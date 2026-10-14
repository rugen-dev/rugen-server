//! A tiny in-process S3 for tests (no MinIO offline): path-style `PUT` /
//! `GET` / `DELETE` and `ListObjectsV2` with small pages (continuation
//! tokens get exercised). Every request must carry a valid SigV4
//! `Authorization` (recomputed with the fake's own copy of the secret),
//! `x-amz-date`, and an `x-amz-content-sha256` matching the body.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use crate::s3::authorization;

#[derive(Clone)]
pub struct Stored {
    pub body: Vec<u8>,
    /// Unix seconds (tests may backdate it).
    pub modified: u64,
}

pub struct FakeS3 {
    pub port: u16,
    pub objects: Arc<Mutex<BTreeMap<String, Stored>>>,
    /// Requests that failed the signature checks.
    pub rejected: Arc<Mutex<u32>>,
    /// Presigned GETs served.
    pub presigned: Arc<Mutex<u32>>,
}

const PAGE: usize = 3;

impl FakeS3 {
    pub fn start(bucket: &str, access_key: &str, secret: &str, region: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let objects = Arc::new(Mutex::new(BTreeMap::new()));
        let rejected = Arc::new(Mutex::new(0));
        let presigned = Arc::new(Mutex::new(0));
        let ctx = Arc::new((
            bucket.to_string(),
            access_key.to_string(),
            secret.to_string(),
            region.to_string(),
            objects.clone(),
            rejected.clone(),
            presigned.clone(),
        ));
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let ctx = ctx.clone();
                std::thread::spawn(move || {
                    let _ = serve(stream, &ctx);
                });
            }
        });
        Self {
            port,
            objects,
            rejected,
            presigned,
        }
    }

    pub fn keys(&self) -> Vec<String> {
        self.objects.lock().unwrap().keys().cloned().collect()
    }

    pub fn put(&self, key: &str, body: &[u8], modified: u64) {
        self.objects.lock().unwrap().insert(
            key.into(),
            Stored {
                body: body.to_vec(),
                modified,
            },
        );
    }
}

type Ctx = (
    String,
    String,
    String,
    String,
    Arc<Mutex<BTreeMap<String, Stored>>>,
    Arc<Mutex<u32>>,
    Arc<Mutex<u32>>,
);

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(v) = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn respond(s: &mut TcpStream, status: u16, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    write!(
        s,
        "HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )?;
    s.write_all(body)
}

fn error(s: &mut TcpStream, status: u16, code: &str) -> std::io::Result<()> {
    let xml = format!("<?xml version=\"1.0\"?><Error><Code>{code}</Code></Error>");
    respond(s, status, "application/xml", xml.as_bytes())
}

fn serve(stream: TcpStream, ctx: &Ctx) -> std::io::Result<()> {
    let (bucket, ak, secret, region, objects, rejected, presigned) = ctx;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut out = stream;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let mut parts = line.split_whitespace();
        let (method, target) = (
            parts.next().unwrap_or("").to_string(),
            parts.next().unwrap_or("").to_string(),
        );
        let mut headers: Vec<(String, String)> = Vec::new();
        loop {
            let mut h = String::new();
            reader.read_line(&mut h)?;
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':') {
                headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
            }
        }
        let header = |k: &str| headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let len: usize = header("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        assert!(
            header("transfer-encoding").is_none(),
            "S3 needs a Content-Length"
        );
        let mut body = vec![0u8; len];
        reader.read_exact(&mut body)?;
        let (raw_path, raw_query) = target.split_once('?').unwrap_or((&target, ""));
        let query: Vec<(String, String)> = raw_query
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|kv| {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                (decode(k), decode(v))
            })
            .collect();
        // a presigned GET (SigV4 query signing)
        if let Some(sig) = query
            .iter()
            .find(|(k, _)| k == "X-Amz-Signature")
            .map(|(_, v)| v.clone())
        {
            let q = |k: &str| query.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
            let (date, expires) = (q("X-Amz-Date").unwrap_or_default(), q("X-Amz-Expires"));
            let expires: u64 = expires.and_then(|e| e.parse().ok()).unwrap_or(0);
            let want = (date.len() == 16).then(|| {
                crate::s3::presign_query(
                    ak,
                    secret,
                    region,
                    &header("host").unwrap_or_default(),
                    raw_path,
                    &date,
                    expires,
                )
            });
            let fresh = crate::s3::parse_amz_date(&date)
                .is_some_and(|t| t + expires >= crate::store::now());
            let good = want
                .as_ref()
                .and_then(|w| w.last())
                .is_some_and(|(_, s)| *s == sig);
            if method != "GET" || !good || !fresh {
                *rejected.lock().unwrap() += 1;
                error(
                    &mut out,
                    403,
                    if fresh {
                        "SignatureDoesNotMatch"
                    } else {
                        "AccessDenied"
                    },
                )?;
                continue;
            }
            let key = decode(raw_path)
                .strip_prefix('/')
                .and_then(|p| p.strip_prefix(bucket.as_str()))
                .and_then(|p| p.strip_prefix('/'))
                .unwrap_or("")
                .to_string();
            let body = objects.lock().unwrap().get(&key).map(|o| o.body.clone());
            match body {
                Some(b) => {
                    *presigned.lock().unwrap() += 1;
                    respond(&mut out, 200, "application/octet-stream", &b)?
                }
                None => error(&mut out, 404, "NoSuchKey")?,
            }
            continue;
        }
        // signature checks
        let payload = header("x-amz-content-sha256").unwrap_or_default();
        let date = header("x-amz-date").unwrap_or_default();
        let auth = header("authorization").unwrap_or_default();
        let signed = [
            ("host".to_string(), header("host").unwrap_or_default()),
            ("x-amz-content-sha256".to_string(), payload.clone()),
            ("x-amz-date".to_string(), date.clone()),
        ];
        let want = (date.len() == 16).then(|| {
            authorization(
                ak, secret, region, &method, raw_path, &query, &signed, &payload, &date,
            )
        });
        let body_ok = payload == rugen_proto::to_hex(&Sha256::digest(&body));
        if want.as_deref() != Some(auth.as_str()) || !body_ok {
            *rejected.lock().unwrap() += 1;
            error(&mut out, 403, "SignatureDoesNotMatch")?;
            continue;
        }
        let path = decode(raw_path);
        let Some(rest) = path
            .strip_prefix('/')
            .and_then(|p| p.strip_prefix(bucket.as_str()))
        else {
            error(&mut out, 404, "NoSuchBucket")?;
            continue;
        };
        let key = rest.strip_prefix('/').unwrap_or("");
        let mut objs = objects.lock().unwrap();
        match (method.as_str(), key) {
            ("GET", "") => {
                let q = |k: &str| query.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
                assert_eq!(q("list-type").as_deref(), Some("2"));
                let prefix = q("prefix").unwrap_or_default();
                let after = q("continuation-token").unwrap_or_default();
                let matching: Vec<(&String, &Stored)> = objs
                    .iter()
                    .filter(|(k, _)| k.starts_with(&prefix) && k.as_str() > after.as_str())
                    .collect();
                let page = &matching[..matching.len().min(PAGE)];
                let truncated = matching.len() > PAGE;
                let mut xml = String::from("<?xml version=\"1.0\"?><ListBucketResult>");
                xml += &format!("<IsTruncated>{truncated}</IsTruncated>");
                if truncated {
                    xml += &format!(
                        "<NextContinuationToken>{}</NextContinuationToken>",
                        page.last().unwrap().0.replace('&', "&amp;")
                    );
                }
                for (k, o) in page {
                    xml += &format!(
                        "<Contents><Key>{}</Key><LastModified>{}</LastModified><Size>{}</Size></Contents>",
                        k.replace('&', "&amp;"),
                        crate::s3::rfc3339(o.modified).replace('Z', ".000Z"),
                        o.body.len()
                    );
                }
                xml += "</ListBucketResult>";
                respond(&mut out, 200, "application/xml", xml.as_bytes())?;
            }
            ("PUT", k) if !k.is_empty() => {
                objs.insert(
                    k.to_string(),
                    Stored {
                        body,
                        modified: crate::store::now(),
                    },
                );
                respond(&mut out, 200, "text/plain", b"")?;
            }
            ("GET", k) => match objs.get(k) {
                Some(o) => respond(&mut out, 200, "application/octet-stream", &o.body)?,
                None => error(&mut out, 404, "NoSuchKey")?,
            },
            ("DELETE", k) => {
                objs.remove(k);
                write!(out, "HTTP/1.1 204 No Content\r\n\r\n")?;
            }
            _ => error(&mut out, 405, "MethodNotAllowed")?,
        }
    }
}
