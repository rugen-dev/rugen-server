//! End to end on loopback: a real `rugen-server` (HTTP + UDP relay) and two
//! client "machines", each with its own content library holding different
//! fighters. Pick → instant verdict → (BLOCKED re-pick) → confirm → upload
//! what the server lacks → download what we lack into the net cache →
//! ready → relay ticket → rollback match through the relay, in sync.

use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rugen_content::Library;
use rugen_net::online::{MatchupView, OnlineClient, ReadyReport, Transfer, VerdictKind};
use rugen_net::{Netplay, Options, RelaySocket};
use rugen_sim::Buttons;

use crate::api::{Api, ApiConfig};
use crate::relay::Relay;
use crate::store::Store;

const ENGINE: &str = "rugen e2e";

/// The rugen-engine checkout holding `reference/` and `chars/`:
/// `RUGEN_ENGINE_DIR`, else a sibling `../rugen-engine` (or `../rugen`).
fn engine_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("RUGEN_ENGINE_DIR") {
        return dir.into();
    }
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    ["../rugen-engine", "../rugen"]
        .iter()
        .map(|d| here.join(d))
        .find(|d| d.join("reference").is_dir())
        .unwrap_or_else(|| here.join("../rugen-engine"))
}

fn reference() -> Option<PathBuf> {
    let root = engine_dir().join("reference/mugen-1.1b1");
    root.join("chars/kfm/kfm.def").exists().then_some(root)
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for e in std::fs::read_dir(src).unwrap().flatten() {
        let to = dst.join(e.file_name());
        if e.path().is_dir() {
            copy_dir(&e.path(), &to);
        } else {
            std::fs::copy(e.path(), &to).unwrap();
        }
    }
}

/// A server on 127.0.0.1 (HTTP on a runtime thread, UDP relay thread).
struct Server {
    url: String,
    udp: SocketAddr,
    api: Arc<Api>,
    _rt: tokio::runtime::Runtime,
}

fn server(data: &Path) -> Server {
    server_with(data, None)
}

/// `turn`: Cloudflare TURN config (a mock); the UDP relay is still bound
/// but not advertised then (like a tunnel-only server: WebSocket relay).
fn server_with(data: &Path, turn: Option<crate::turn::TurnConfig>) -> Server {
    let tunnel = turn.is_some();
    let relay = Arc::new(Relay::default());
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    let udp = socket.local_addr().unwrap();
    relay.set_udp(socket.clone());
    let r = relay.clone();
    std::thread::spawn(move || crate::udp::serve(socket, r));
    let api = Api::new(
        Store::open(Some(data)).unwrap(),
        ApiConfig {
            name: "e2e".into(),
            udp_public: (!tunnel).then(|| udp.to_string()),
            data: Some(data.to_path_buf()),
            turn,
            ..Default::default()
        },
        relay,
    );
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let a = api.clone();
    rt.spawn(async move { crate::http::serve(listener, a, std::future::pending()).await });
    Server {
        url: format!("http://{addr}"),
        udp,
        api,
        _rt: rt,
    }
}

/// A player's machine: a content library in its own folder.
fn machine(root: &Path, reference: &Path) -> Library {
    std::fs::create_dir_all(root.join("chars")).unwrap();
    std::fs::create_dir_all(root.join("stages")).unwrap();
    copy_dir(&reference.join("data"), &root.join("data"));
    Library::discover(Some(root))
}

fn decl(lib: &Library, id: &str, stage: bool) -> rugen_net::online::FighterDecl {
    let (dir, m) = if stage {
        let e = lib
            .stages()
            .into_iter()
            .find(|e| e.id.eq_ignore_ascii_case(id))
            .unwrap();
        lib.prepare_stage(&e).unwrap()
    } else {
        lib.prepare_char(&lib.find_char(id).unwrap()).unwrap()
    };
    lib.declare(&dir, &m).unwrap()
}

fn poll_until(
    c: &OnlineClient,
    id: u64,
    secs: u64,
    mut done: impl FnMut(&MatchupView) -> bool,
) -> MatchupView {
    let t = Instant::now();
    loop {
        let v = c.matchup(id).unwrap();
        if done(&v) || v.phase == "failed" || t.elapsed() > Duration::from_secs(secs) {
            return v;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// After both accepted: upload ours, download theirs, report ready, wait
/// for the ticket. Returns (view, p1 def, p2 def, stage def, upload / download bytes).
fn sync(
    c: &OnlineClient,
    lib: &Library,
    id: u64,
    mine: &[&rugen_net::online::FighterDecl],
) -> (MatchupView, [PathBuf; 3], [u64; 2]) {
    let mut moved = [0u64; 2];
    for d in mine {
        let (dir, m) = lib.find_fingerprint(&d.fingerprint).unwrap();
        let pkg = lib.package(&dir, &m).unwrap();
        let t = Transfer::new();
        let st = c.upload_package(&d.fingerprint, &pkg, &t).unwrap();
        assert!(st.complete);
        moved[0] += t.done.load(std::sync::atomic::Ordering::Relaxed);
    }
    // everything known and on the server (verified) → fetch what we lack
    let v = poll_until(c, id, 120, |v| {
        v.fingerprints().iter().all(Option::is_some) && v.missing.is_empty()
    });
    assert_eq!(v.phase, "sync", "{}", v.error);
    let mut defs = Vec::new();
    for (i, fp) in v.fingerprints().into_iter().enumerate() {
        let fp = fp.unwrap().to_string();
        if lib.find_fingerprint(&fp).is_none() {
            let card = if i < 2 { &v.fighters[i] } else { &v.stage };
            let size = card.as_ref().unwrap().decl.size;
            let part = lib
                .cache_dir()
                .join("net/partial")
                .join(format!("{fp}.part"));
            let t = Transfer::new();
            c.download_package(&fp, size, &part, &t).unwrap();
            moved[1] += size;
            lib.install_package(&part, &fp, 1 << 30).unwrap();
            let _ = std::fs::remove_file(&part);
        }
        defs.push(lib.def_for_fingerprint(&fp).unwrap());
    }
    let fp = |i: usize| v.fingerprints()[i].unwrap().to_string();
    c.ready(
        id,
        &ReadyReport {
            p1: fp(0),
            p2: fp(1),
            stage: fp(2),
            engine: ENGINE.into(),
            rules: v.rules.clone(),
        },
    )
    .unwrap();
    let v = poll_until(c, id, 60, |v| v.ticket.is_some());
    assert_eq!(v.phase, "started", "{}", v.error);
    let [a, b, s]: [PathBuf; 3] = defs.try_into().unwrap();
    (v, [a, b, s], moved)
}

/// Both sides play `frames` frames through the relay; returns their input logs.
fn play(
    udp: SocketAddr,
    data: &Path,
    sides: [(MatchupView, [PathBuf; 3]); 2],
    frames: u32,
) -> [(u32, Vec<u8>, u64); 2] {
    let handles: Vec<_> = sides
        .into_iter()
        .map(|(view, defs)| {
            let data = data.to_path_buf();
            std::thread::spawn(move || {
                let spec = rugen_sim::headless::MatchSpec {
                    p1: &defs[0],
                    p2: &defs[1],
                    stage: Some(&defs[2]),
                    data_dir: &data,
                    motif: &data,
                    zoom: (0.6, 1.25),
                    movement: Default::default(),
                    round_time: None,
                    ai: [0, 0],
                };
                let mut w = rugen_sim::headless::build_world(&spec).unwrap();
                let ticket = view.ticket.unwrap();
                let slot = ticket.slot as usize;
                let mut sock =
                    RelaySocket::connect_udp(&ticket, &udp.to_string(), Duration::from_secs(3))
                        .unwrap();
                sock.wait_for(0b11, Duration::from_secs(10), &mut |_| {})
                    .unwrap();
                let mut net =
                    Netplay::relay(sock, slot, ticket.spectators, &Options::default()).unwrap();
                let mut seed: u32 = 0x1234_5678 ^ slot as u32;
                let start = Instant::now();
                while w.frame < frames + 40 && start.elapsed() < Duration::from_secs(90) {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    let b = Buttons::from_bits((seed & 0x7ff) as u16);
                    net.poll();
                    net.advance(&mut w, [b, b]).expect("no desync");
                    std::thread::sleep(Duration::from_millis(3));
                }
                let end = Instant::now() + Duration::from_millis(600);
                while Instant::now() < end {
                    net.poll();
                    let _ = net.advance(&mut w, [Buttons::default(); 2]);
                    std::thread::sleep(Duration::from_millis(3));
                }
                (w.frame, net.input_log_bytes(), w.checksum())
            })
        })
        .collect();
    let mut out = handles.into_iter().map(|h| h.join().unwrap());
    [out.next().unwrap(), out.next().unwrap()]
}

#[test]
fn bring_your_own_character_blocked_then_synced_relay_match() {
    let Some(reference) = reference() else {
        eprintln!("reference tree missing; skipping");
        return;
    };
    let tmp = crate::testkit::tmp("e2e");
    let srv = server(&tmp.join("server"));
    // machine A: Kung Fu Man and a stage
    let lib_a = machine(&tmp.join("a"), &reference);
    copy_dir(&reference.join("chars/kfm"), &tmp.join("a/chars/kfm"));
    copy_dir(&reference.join("stages"), &tmp.join("a/stages/stage0"));
    std::fs::remove_file(tmp.join("a/stages/stage0/kfm.def")).unwrap();
    std::fs::remove_file(tmp.join("a/stages/stage0/stage0-720.def")).unwrap();
    // machine B: a cheated KFM (regenerates in state -2) and a tuned one A does not have
    let lib_b = machine(&tmp.join("b"), &reference);
    copy_dir(&reference.join("chars/kfm"), &tmp.join("b/chars/kfm_cheat"));
    let cns = tmp.join("b/chars/kfm_cheat/kfm.cns");
    let mut text = std::fs::read_to_string(&cns).unwrap();
    text.push_str("\n[Statedef -2]\n[State -2, regen]\ntype = LifeAdd\ntrigger1 = Life < LifeMax\nvalue = 3\n");
    std::fs::write(&cns, text).unwrap();
    std::fs::rename(
        tmp.join("b/chars/kfm_cheat/kfm.def"),
        tmp.join("b/chars/kfm_cheat/kfm_cheat.def"),
    )
    .unwrap();
    copy_dir(&reference.join("chars/kfm"), &tmp.join("b/chars/kfm_tuned"));
    let cns = tmp.join("b/chars/kfm_tuned/kfm.cns");
    let text = std::fs::read_to_string(&cns)
        .unwrap()
        .replacen("[Data]", "; tuned by B\n[Data]", 1);
    std::fs::write(&cns, text).unwrap();
    std::fs::rename(
        tmp.join("b/chars/kfm_tuned/kfm.def"),
        tmp.join("b/chars/kfm_tuned/kfm_tuned.def"),
    )
    .unwrap();

    let mut a = OnlineClient::new(&srv.url, None);
    let mut b = OnlineClient::new(&srv.url, None);
    let (ida, idb) = (a.register().unwrap().id, b.register().unwrap().id);
    let room = a
        .create_room("", &rugen_net::online::RoomOptions::default())
        .unwrap();
    let joined = b.join_room(&room.code, "", "", false).unwrap();
    assert!(joined.ticket.is_none());
    let id = joined.matchup.unwrap().id;

    // picks: the verdict is instant
    let kfm = decl(&lib_a, "kfm", false);
    let stage = decl(&lib_a, "stage0", true);
    let t = Instant::now();
    a.pick(id, Some(&kfm), Some(&stage)).unwrap();
    let cheat = decl(&lib_b, "kfm_cheat", false);
    let v = b.pick(id, Some(&cheat), None).unwrap();
    let verdict = v.verdict.clone().unwrap();
    eprintln!(
        "verdict in {:?}: {:?} {:?}",
        t.elapsed(),
        verdict.kind,
        verdict.reasons
    );
    assert_eq!(verdict.kind, VerdictKind::Blocked);
    assert!(verdict.reasons[0].contains("regenerates"), "{verdict:?}");
    assert!(a.accept(id, true).is_err(), "BLOCKED can never be accepted");
    // B brings a fair fighter instead
    let tuned = decl(&lib_b, "kfm_tuned", false);
    assert_ne!(tuned.fingerprint, kfm.fingerprint);
    let v = b.pick(id, Some(&tuned), None).unwrap();
    assert_eq!(v.verdict.as_ref().unwrap().kind, VerdictKind::Fair, "{v:?}");
    // A sees B's card
    let va = a.matchup(id).unwrap();
    let card = va.fighters[1].as_ref().unwrap();
    assert_eq!(card.decl.name, "Kung Fu Man");
    assert!(card.decl.portrait.is_some(), "card portrait travels");
    a.accept(id, false).unwrap();
    b.accept(id, false).unwrap();

    // sync in parallel on both machines
    let (ca, cb) = (a.clone(), b.clone());
    let (la, lb) = (lib_a.clone(), lib_b.clone());
    let (k2, s2, t2) = (kfm.clone(), stage.clone(), tuned.clone());
    let ha = std::thread::spawn(move || sync(&ca, &la, id, &[&k2, &s2]));
    let hb = std::thread::spawn(move || sync(&cb, &lb, id, &[&t2]));
    let (va, defs_a, moved_a) = ha.join().unwrap();
    let (vb, defs_b, moved_b) = hb.join().unwrap();
    eprintln!("A uploaded {} B, downloaded {} B", moved_a[0], moved_a[1]);
    eprintln!("B uploaded {} B, downloaded {} B", moved_b[0], moved_b[1]);
    assert!(moved_a[1] > 0 && moved_b[1] > 0, "both downloaded");
    // downloads landed in the net cache, never in chars/
    assert!(defs_a[1].starts_with(tmp.join("a/cache/net/chars")));
    assert!(defs_b[0].starts_with(tmp.join("b/cache/net/chars")));
    assert!(defs_b[2].starts_with(tmp.join("b/cache/net/stages")));
    assert_eq!(std::fs::read_dir(tmp.join("b/chars")).unwrap().count(), 2);
    assert_eq!(
        va.ticket.as_ref().unwrap().session,
        vb.ticket.as_ref().unwrap().session
    );
    // same fingerprints of every file on both machines
    for i in 0..3 {
        assert_eq!(va.fingerprints()[i], vb.fingerprints()[i]);
    }

    // the relay match itself, desync detection on
    let data = tmp.join("a/data");
    let [(fa, la_log, _), (fb, lb_log, _)] =
        play(srv.udp, &data, [(va.clone(), defs_a), (vb, defs_b)], 300);
    assert!(fa >= 300 && fb >= 300, "frames {fa} / {fb}");
    let n = 280 * 4;
    assert_eq!(la_log[..n], lb_log[..n], "input streams diverged");

    // results (unranked room): accepted, community ratings of both fingerprints move
    let ev = |log: &Vec<u8>| rugen_net::online::Evidence {
        frames: 0,
        checksum: None,
        inputs: log.clone(),
        ..Default::default()
    };
    a.report(id, ida, &ev(&la_log)).unwrap();
    let ack = b.report(id, ida, &ev(&lb_log)).unwrap();
    assert!(!ack.disputed);
    let r = a.char_rating(&kfm.fingerprint).unwrap().unwrap();
    assert_eq!((r.games, r.wins), (1, 1));
    let _ = (idb, &srv.api);
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Naruto vs Sasuke (the real RAR characters in the engine's `chars/`, ~80 MB each):
/// fingerprints, profiles, verdict, upload, download and a synced relay
/// match. Slow (packaging); run with `cargo test --release -- --ignored`.
#[test]
#[ignore]
fn naruto_vs_sasuke_real_characters() {
    let Some(reference) = reference() else {
        return;
    };
    let chars = engine_dir().join("chars");
    let (naruto, sasuke) = (
        chars.join("G6_Naruto.rar"),
        chars.join("G6_Sasuke_Rinnegan.rar"),
    );
    if !naruto.exists() || !sasuke.exists() {
        eprintln!("chars/G6_*.rar missing; skipping");
        return;
    }
    let tmp = crate::testkit::tmp("e2e-naruto");
    let srv = server(&tmp.join("server"));
    let lib_a = machine(&tmp.join("a"), &reference);
    let lib_b = machine(&tmp.join("b"), &reference);
    std::fs::copy(&naruto, tmp.join("a/chars/G6_Naruto.rar")).unwrap();
    std::fs::copy(&sasuke, tmp.join("b/chars/G6_Sasuke_Rinnegan.rar")).unwrap();
    copy_dir(&reference.join("stages"), &tmp.join("a/stages/stage0"));
    std::fs::remove_file(tmp.join("a/stages/stage0/kfm.def")).unwrap();
    std::fs::remove_file(tmp.join("a/stages/stage0/stage0-720.def")).unwrap();
    let t = Instant::now();
    let n = decl(&lib_a, "G6_Naruto", false);
    let s = decl(&lib_b, "G6_Sasuke_Rinnegan", false);
    let st = decl(&lib_a, "stage0", true);
    eprintln!("prepare + fingerprint + profile: {:?}", t.elapsed());
    let mut a = OnlineClient::new(&srv.url, None);
    let mut b = OnlineClient::new(&srv.url, None);
    a.register().unwrap();
    b.register().unwrap();
    let room = a
        .create_room("", &rugen_net::online::RoomOptions::default())
        .unwrap();
    let id = b
        .join_room(&room.code, "", "", false)
        .unwrap()
        .matchup
        .unwrap()
        .id;
    let t = Instant::now();
    a.pick(id, Some(&n), Some(&st)).unwrap();
    let v = b.pick(id, Some(&s), None).unwrap();
    let verdict = v.verdict.clone().unwrap();
    eprintln!(
        "verdict in {:?}: {:?} ratio {:.2} {:?}",
        t.elapsed(),
        verdict.kind,
        verdict.ratio,
        verdict.reasons
    );
    for (who, c) in [("naruto", &n), ("sasuke", &s)] {
        let p = c.profile.as_ref().unwrap();
        eprintln!(
            "{who}: {} power {} flags {:?}",
            rugen_fair::short(&c.fingerprint),
            p.power_score,
            p.flags.iter().map(|f| &f.code).collect::<Vec<_>>()
        );
    }
    assert_ne!(verdict.kind, VerdictKind::Blocked);
    let unbalanced = verdict.kind == VerdictKind::Unbalanced;
    a.accept(id, unbalanced).unwrap();
    b.accept(id, unbalanced).unwrap();
    let t = Instant::now();
    let (ca, cb) = (a.clone(), b.clone());
    let (la, lb) = (lib_a.clone(), lib_b.clone());
    let (n2, st2, s2) = (n.clone(), st.clone(), s.clone());
    let ha = std::thread::spawn(move || sync(&ca, &la, id, &[&n2, &st2]));
    let hb = std::thread::spawn(move || sync(&cb, &lb, id, &[&s2]));
    let (va, defs_a, ma) = ha.join().unwrap();
    let (vb, defs_b, mb) = hb.join().unwrap();
    eprintln!(
        "sync in {:?}: A up {} MB down {} MB, B up {} MB down {} MB",
        t.elapsed(),
        ma[0] >> 20,
        ma[1] >> 20,
        mb[0] >> 20,
        mb[1] >> 20
    );
    let data = tmp.join("a/data");
    let [(fa, la_log, _), (fb, lb_log, _)] =
        play(srv.udp, &data, [(va, defs_a), (vb, defs_b)], 300);
    assert!(fa >= 300 && fb >= 300, "frames {fa} / {fb}");
    assert_eq!(la_log[..280 * 4], lb_log[..280 * 4]);
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---- TURN through a tunnel-only server

fn rtt_summary(v: &[u32]) -> String {
    if v.is_empty() {
        return "no samples".into();
    }
    let ms: Vec<f64> = v.iter().map(|&u| u as f64 / 1000.0).collect();
    let jitter =
        ms.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (ms.len().max(2) - 1) as f64;
    let mut s = ms.clone();
    s.sort_by(f64::total_cmp);
    let q = |f: f64| s[((s.len() - 1) as f64 * f) as usize];
    format!(
        "n={} median {:.3} ms, p95 {:.3} ms, jitter {:.3} ms",
        s.len(),
        q(0.5),
        q(0.95),
        jitter
    )
}

/// Collect round trips to the peer, then keep answering its pings until
/// both sides are done.
fn measure(sock: &mut RelaySocket, peer: u8, done: &std::sync::atomic::AtomicUsize) -> Vec<u32> {
    use std::sync::atomic::Ordering;
    let got = sock.peer_rtt_samples(peer, 100, Duration::from_secs(15));
    done.fetch_add(1, Ordering::SeqCst);
    let t = Instant::now();
    while done.load(Ordering::SeqCst) % 2 != 0 && t.elapsed() < Duration::from_secs(20) {
        let _ = sock.peer_rtt_samples(peer, 1, Duration::from_millis(5));
    }
    got
}

struct TurnSide {
    frames: u32,
    log: Vec<u8>,
    checks: Vec<(u32, u64)>,
    turn: Option<rugen_net::turn::TurnStats>,
    ws: Vec<u32>,
    turn_rtts: Vec<u32>,
    transport: &'static str,
}

/// Tunnel-only server (no UDP relay advertised) with Cloudflare TURN
/// switched on against a mock API that hands out a local coturn: tickets
/// list `turn` first, the clients signal over the `/relay` WebSocket, play
/// a rollback match over TURN, report RLE inputs + checksums, and the
/// server revokes both credentials. Prints WebSocket relay vs TURN round
/// trips. Needs `RUGEN_TEST_TURN` (see rugen-net's tests/turn_relay.rs).
#[test]
fn turn_match_through_a_tunnel_only_server() {
    let (Some(reference), Ok(turn_host)) = (reference(), std::env::var("RUGEN_TEST_TURN")) else {
        eprintln!("RUGEN_TEST_TURN or the reference tree missing; skipping");
        return;
    };
    let user = std::env::var("RUGEN_TEST_TURN_USER").unwrap_or_else(|_| "u".into());
    let pass = std::env::var("RUGEN_TEST_TURN_PASS").unwrap_or_else(|_| "p".into());
    let cf = crate::turn::tests::mock_cf_with(
        0,
        Some((vec![format!("turn:{turn_host}?transport=udp")], user, pass)),
    );
    let tmp = crate::testkit::tmp("e2e-turn");
    let srv = server_with(
        &tmp.join("server"),
        Some(crate::turn::tests::config(&cf.url, &[])),
    );
    let lib_a = machine(&tmp.join("a"), &reference);
    copy_dir(&reference.join("chars/kfm"), &tmp.join("a/chars/kfm"));
    copy_dir(&reference.join("stages"), &tmp.join("a/stages/stage0"));
    std::fs::remove_file(tmp.join("a/stages/stage0/kfm.def")).unwrap();
    std::fs::remove_file(tmp.join("a/stages/stage0/stage0-720.def")).unwrap();
    let lib_b = machine(&tmp.join("b"), &reference);
    copy_dir(&reference.join("chars/kfm"), &tmp.join("b/chars/kfm"));

    let mut a = OnlineClient::new(&srv.url, None);
    let mut b = OnlineClient::new(&srv.url, None);
    let ida = a.register().unwrap().id;
    b.register().unwrap();
    let room = a
        .create_room("", &rugen_net::online::RoomOptions::default())
        .unwrap();
    let id = b
        .join_room(&room.code, "", "", false)
        .unwrap()
        .matchup
        .unwrap()
        .id;
    let kfm = decl(&lib_a, "kfm", false);
    let stage = decl(&lib_a, "stage0", true);
    a.pick(id, Some(&kfm), Some(&stage)).unwrap();
    b.pick(id, Some(&decl(&lib_b, "kfm", false)), None).unwrap();
    a.accept(id, false).unwrap();
    b.accept(id, false).unwrap();
    let (ca, cb) = (a.clone(), b.clone());
    let (la, lb) = (lib_a.clone(), lib_b.clone());
    let (k2, s2) = (kfm.clone(), stage.clone());
    let ha = std::thread::spawn(move || sync(&ca, &la, id, &[&k2, &s2]));
    let hb = std::thread::spawn(move || sync(&cb, &lb, id, &[]));
    let (va, defs_a, _) = ha.join().unwrap();
    let (vb, defs_b, _) = hb.join().unwrap();
    for v in [&va, &vb] {
        let t = v.ticket.as_ref().unwrap();
        let kinds: Vec<&str> = t.transports.iter().map(|t| t.kind.as_str()).collect();
        assert_eq!(kinds, ["turn", "ws"], "TURN first, no UDP on a tunnel");
        assert!(t.udp.is_none());
    }
    assert_ne!(
        va.ticket.as_ref().unwrap().turn().unwrap().expires,
        0,
        "credentials expire"
    );

    let data = tmp.join("a/data");
    let frames = 600u32;
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sides: Vec<_> = [(va, defs_a), (vb, defs_b)]
        .into_iter()
        .map(|(view, defs)| {
            let (data, url, done) = (data.clone(), srv.url.clone(), done.clone());
            std::thread::spawn(move || {
                let spec = rugen_sim::headless::MatchSpec {
                    p1: &defs[0],
                    p2: &defs[1],
                    stage: Some(&defs[2]),
                    data_dir: &data,
                    motif: &data,
                    zoom: (0.6, 1.25),
                    movement: Default::default(),
                    round_time: None,
                    ai: [0, 0],
                };
                let mut w = rugen_sim::headless::build_world(&spec).unwrap();
                let ticket = view.ticket.unwrap();
                let slot = ticket.slot as usize;
                let peer = 1 - ticket.slot;
                let base = rugen_net::online::base_url(&url);
                // 1. the WebSocket relay alone (TURN stripped) for reference
                let mut plain = ticket.clone();
                plain.transports.retain(|t| t.kind != "turn");
                let mut s0 =
                    RelaySocket::connect(&plain, &base, Duration::ZERO, &mut |_| {}).unwrap();
                assert_eq!(s0.transport_name(), "WebSocket");
                s0.wait_for(0b11, Duration::from_secs(10), &mut |_| {})
                    .unwrap();
                let ws = measure(&mut s0, peer, &done);
                drop(s0);
                // 2. the real ticket: signalling over the WebSocket, match over TURN
                let mut s1 =
                    RelaySocket::connect(&ticket, &base, Duration::ZERO, &mut |_| {}).unwrap();
                s1.wait_for(0b11, Duration::from_secs(10), &mut |_| {})
                    .unwrap();
                assert!(s1.settle_turn(Duration::from_secs(5)), "TURN path");
                let transport = s1.transport_name();
                let turn_rtts = measure(&mut s1, peer, &done);
                let meter = s1.turn_meter();
                let mut net =
                    Netplay::relay(s1, slot, ticket.spectators, &Options::default()).unwrap();
                let mut seed: u32 = 0x5EED ^ slot as u32;
                let mut held = Buttons::default();
                let tick = Duration::from_micros(16_667);
                let mut next = Instant::now();
                let start = Instant::now();
                while w.frame < frames + 40 && start.elapsed() < Duration::from_secs(90) {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    if seed % 8 == 0 {
                        held = Buttons::from_bits(((seed >> 8) & 0x7ff) as u16);
                    }
                    net.poll();
                    net.advance(&mut w, [held, held]).expect("no desync");
                    next += tick;
                    if let Some(d) = next.checked_duration_since(Instant::now()) {
                        std::thread::sleep(d);
                    }
                }
                let end = Instant::now() + Duration::from_millis(600);
                while Instant::now() < end {
                    net.poll();
                    let _ = net.advance(&mut w, [Buttons::default(); 2]);
                    std::thread::sleep(Duration::from_millis(8));
                }
                TurnSide {
                    frames: w.frame,
                    log: net.input_log_bytes(),
                    checks: net.checksum_log().to_vec(),
                    turn: meter.map(|m| *m.lock().unwrap()),
                    ws,
                    turn_rtts,
                    transport,
                }
            })
        })
        .collect();
    let mut sides = sides.into_iter().map(|h| h.join().unwrap());
    let (sa, sb) = (sides.next().unwrap(), sides.next().unwrap());
    assert!(sa.frames >= frames && sb.frames >= frames);
    assert_eq!(sa.transport, "TURN/UDP");
    let n = (frames as usize - 20) * 4;
    assert_eq!(sa.log[..n], sb.log[..n], "input streams diverged");
    assert!(sa.checks.len() >= 9, "periodic checksums recorded");
    eprintln!("WebSocket relay: {}", rtt_summary(&sa.ws));
    eprintln!("TURN (coturn):   {}", rtt_summary(&sa.turn_rtts));
    let st = sa.turn.unwrap();
    eprintln!(
        "TURN bytes A: rx {} tx {} ({} / {} datagrams)",
        st.rx_wire, st.tx_wire, st.rx_packets, st.tx_packets
    );

    // reports: RLE inputs + checksums + TURN bytes; agreement settles them
    let ev = |s: &TurnSide| rugen_net::online::Evidence {
        frames: 0,
        checksum: None,
        inputs: s.log.clone(),
        checksums: s.checks.clone(),
        compact: true,
        turn_bytes: s.turn.map(|t| (t.rx_wire, t.tx_wire)),
        ending: None,
    };
    a.report(id, ida, &ev(&sa)).unwrap();
    let ack = b.report(id, ida, &ev(&sb)).unwrap();
    assert!(!ack.disputed);
    let t = Instant::now();
    while cf.revoked.lock().unwrap().len() < 2 && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        cf.revoked.lock().unwrap().len(),
        2,
        "both credentials revoked"
    );
    let health = a.info().unwrap();
    assert_eq!(health.name, "e2e");
    let st = srv.api.turn.as_ref().unwrap().status(&srv.api.store_lock());
    assert_eq!(st["matches"], 1);
    eprintln!("turn status: {st}");
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Named accounts over real HTTP with the game's own client: create on one
/// device, log out, log in on a second device, same account and rating;
/// an older device's anonymous account is claimed and keeps its key.
#[test]
fn named_account_moves_between_devices() {
    let tmp = crate::testkit::tmp("e2e-accounts");
    let srv = server(&tmp.join("server"));
    assert!(OnlineClient::new(&srv.url, None).info().unwrap().accounts);
    // device 1: create, then a rating to recognise
    let mut one = OnlineClient::new(&srv.url, None);
    let s = one.create_account("Axel", "simple").unwrap();
    assert_eq!(one.key.as_deref(), Some(s.key.as_str()));
    assert!(s.profile.verified);
    let opponent = OnlineClient::new(&srv.url, None).register().unwrap();
    {
        let mut st = srv.api.store_lock();
        let m = st.new_match([s.id, opponent.id], true, "{}").unwrap();
        let w = crate::store::ReportData {
            winner: s.id,
            ..Default::default()
        };
        st.report(s.id, m, &w).unwrap();
        st.report(opponent.id, m, &w).unwrap();
    }
    let rating = one.account().unwrap().profile.rating;
    assert_eq!(rating, 1216);
    one.logout(false).unwrap();
    assert!(one.account().is_err(), "logged out");
    // device 2: a fresh client logs in
    let mut two = OnlineClient::new(&srv.url, None);
    let wrong = two.login("axel", "simplE").unwrap_err().to_string();
    assert!(wrong.contains("WRONG USERNAME OR PASSWORD"), "{wrong}");
    let l = two.login("axel", "simple").unwrap();
    assert_eq!((l.id, l.username.as_str()), (s.id, "Axel"));
    let info = two.account().unwrap();
    assert_eq!(info.profile.rating, rating);
    assert_eq!(info.sessions, 1);
    // the leaderboard shows the badge
    let board = two.leaderboard().unwrap();
    assert!(board.rows.iter().any(|r| r.name == "Axel" && r.verified));
    // change password on device 2: device 3 (logged in before) is logged out
    let mut three = OnlineClient::new(&srv.url, None);
    three.login("AXEL", "simple").unwrap();
    two.change_password("simple", "better-one").unwrap();
    assert!(three.account().is_err());
    assert!(two.account().is_ok());
    two.logout(true).unwrap();
    assert!(two.account().is_err());
    // an older device: anonymous account, then claimed
    let mut old = OnlineClient::new(&srv.url, None);
    let anon = old.register().unwrap();
    assert!(!old.account().unwrap().named());
    let c = old.claim("OldTimer", "simple").unwrap();
    assert_eq!((c.id, c.key.as_str()), (anon.id, anon.key.as_str()));
    assert_eq!(old.account().unwrap().username, "OldTimer");
    let _ = std::fs::remove_dir_all(&tmp);
}
