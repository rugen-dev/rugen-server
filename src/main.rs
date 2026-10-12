//! `rugen-server [--port 7777] [--data dir] [--name "my server"]`
//!
//! One binary, two listeners on the same port number:
//! * UDP: rendezvous that pairs the two sides of a room (NAT hole punching)
//! * TCP: JSON API — anonymous accounts, profiles, custom rooms, ranked
//!   matchmaking with Elo and seasons, leaderboard (see `api.rs`)
//!
//! Replaces the former `rugen-relay` binary (same UDP protocol).

#![forbid(unsafe_code)]

mod api;
mod elo;
mod http;
mod store;
mod udp;

use std::path::PathBuf;
use std::sync::Arc;

fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opt = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1).cloned())
    };
    // legacy: a bare number is the port
    let port: u16 = opt("--port")
        .or_else(|| args.first().filter(|a| !a.starts_with("--")).cloned())
        .and_then(|p| p.parse().ok())
        .unwrap_or(7777);
    let data = opt("--data")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("rugen-server-data"));
    let name = opt("--name").unwrap_or_else(|| "rugen server".into());

    let store = store::Store::open(Some(&data))?;
    log::info!(
        "{} accounts, season {}",
        store.state.accounts.len(),
        store.state.season
    );
    let api = api::Api::new(store, port, name);
    std::thread::spawn(move || {
        if let Err(e) = udp::serve(port) {
            log::error!("udp: {e}");
        }
    });
    let handler: http::Handler = {
        let api: Arc<api::Api> = api;
        Arc::new(move |req| api.handle(req))
    };
    http::serve(port, handler)
}
