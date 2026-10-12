//! Minimal HTTP/1.1 server over std: one thread per connection, JSON in and
//! out, hard limits on everything (header size, body size, time, requests per
//! IP). Enough for a game API; not a general web server.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_HEADERS: usize = 32;
const MAX_LINE: usize = 4096;
const MAX_BODY: usize = 64 * 1024;
/// Requests allowed per IP per window.
const RATE_LIMIT: u32 = 120;
const RATE_WINDOW: Duration = Duration::from_secs(10);

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub body: Vec<u8>,
    #[allow(dead_code)]
    pub peer: IpAddr,
}

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(status: u16, v: &serde_json::Value) -> Self {
        Self {
            status,
            body: serde_json::to_vec(v).unwrap_or_default(),
        }
    }
}

pub type Handler = Arc<dyn Fn(Request) -> Response + Send + Sync>;

#[derive(Default)]
struct RateLimiter {
    hits: HashMap<IpAddr, (Instant, u32)>,
}

impl RateLimiter {
    fn allow(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        if self.hits.len() > 50_000 {
            self.hits
                .retain(|_, (t, _)| now.duration_since(*t) < RATE_WINDOW);
        }
        let e = self.hits.entry(ip).or_insert((now, 0));
        if now.duration_since(e.0) >= RATE_WINDOW {
            *e = (now, 0);
        }
        e.1 += 1;
        e.1 <= RATE_LIMIT
    }
}

pub fn serve(port: u16, handler: Handler) -> std::io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    log::info!("api listening on tcp/{port}");
    let limiter = Arc::new(Mutex::new(RateLimiter::default()));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let handler = handler.clone();
        let limiter = limiter.clone();
        std::thread::spawn(move || {
            if let Err(e) = handle(stream, &handler, &limiter) {
                log::debug!("http: {e}");
            }
        });
    }
    Ok(())
}

fn handle(
    mut stream: TcpStream,
    handler: &Handler,
    limiter: &Mutex<RateLimiter>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let peer = stream.peer_addr()?.ip();
    let allowed = limiter.lock().map(|mut l| l.allow(peer)).unwrap_or(false);
    if !allowed {
        return write_response(
            &mut stream,
            &Response::json(429, &serde_json::json!({ "error": "rate limited" })),
        );
    }
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.by_ref().take(MAX_LINE as u64).read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return write_response(
            &mut stream,
            &Response::json(400, &serde_json::json!({ "error": "bad request" })),
        );
    };
    let (method, target) = (method.to_string(), target.to_string());
    let target_log = target.clone();
    let mut content_length = 0usize;
    for _ in 0..MAX_HEADERS {
        let mut h = String::new();
        reader.by_ref().take(MAX_LINE as u64).read_line(&mut h)?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':')
            && k.eq_ignore_ascii_case("content-length")
        {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    if content_length > MAX_BODY {
        return write_response(
            &mut stream,
            &Response::json(413, &serde_json::json!({ "error": "body too large" })),
        );
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), parse_query(q)),
        None => (target, HashMap::new()),
    };
    log::debug!("{peer} {method} {target_log}");
    let resp = handler(Request {
        method,
        path,
        query,
        body,
        peer,
    });
    write_response(&mut stream, &resp)
}

fn parse_query(q: &str) -> HashMap<String, String> {
    q.split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn write_response(stream: &mut TcpStream, r: &Response) -> std::io::Result<()> {
    let reason = match r.status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        r.status,
        reason,
        r.body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&r.body)?;
    stream.flush()
}
