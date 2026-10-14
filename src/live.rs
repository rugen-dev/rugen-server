//! The input log of every live match, fanned out to viewers.
//!
//! Each player of a match sends its confirmed inputs on its relay session
//! ([`rugen_proto::relay::STREAM`]); the server keeps a copy and serves it
//! to viewers over HTTP as [`rugen_proto::stream::Chunk`]s, so watching
//! never costs a player any bandwidth and a late viewer gets the backlog
//! from frame 0.
//!
//! Each player is trusted for its own input only: frame `f` of the merged
//! stream is P1's half from P1's upload and P2's half from P2's, so it is
//! complete once both sent it. When the match ends, a side that stopped
//! early (it fled or dropped) has its tail filled from the other upload.
//!
//! Bounded memory: a match keeps at most [`MAX_FRAMES`] frames, all logs
//! together at most `RUGEN_LIVE_MB` (64 MB); past either limit uploads are
//! acknowledged but not kept (the match itself is unaffected). A log is
//! dropped [`KEEP_ENDED`] after its match ended (late viewers, sharing from
//! the result screen) unless it is shared ([`crate::store`] keeps those).
//!
//! Fan-out is pull and batched: a viewer asks `GET /v1/live/{id}?from=N`
//! about every 0.4 s (the game) and gets every frame since `N` in one
//! response, so a viewer costs ~2.5 small responses a second, never one
//! message per frame. At most `RUGEN_LIVE_VIEWERS` (500) viewers per match:
//! one more is refused with [`FULL`] (a viewer keeps its seat while it
//! keeps asking).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rugen_proto::stream::{Chunk, LiveMatch, MAX_FRAMES, MatchHeader};

/// How long a finished match's log stays for late viewers and sharing.
pub const KEEP_ENDED: Duration = Duration::from_secs(15 * 60);
/// Frames one viewer request returns at most (5 minutes).
pub const MAX_CHUNK_FRAMES: usize = 60 * 60 * 5;
/// A viewer counts as watching for this long after its last request.
const VIEWER_SECS: u64 = 10;
/// Viewers per match unless `RUGEN_LIVE_VIEWERS` says.
pub const DEFAULT_VIEWERS: usize = 500;
/// What a viewer past the cap is told.
pub const FULL: &str = "this match is full: too many people are watching it, try another one";

/// Why a viewer gets no chunk.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// No such live match, or a private room's for an outsider.
    Missing,
    /// [`Live::max_viewers`] are watching already.
    Full,
}

struct Log {
    header: MatchHeader,
    session: u32,
    /// Each player's own upload (both halves; only its own half is used
    /// while the match runs).
    up: [Vec<[u16; 2]>; 2],
    ended: Option<Instant>,
    /// Listed in `GET /v1/live` (queue matches and public rooms).
    public: bool,
    room: Option<String>,
    /// Accounts that may watch a private room's match (its members).
    members: Vec<u64>,
    viewers: HashMap<u64, Instant>,
}

impl Log {
    fn bytes(&self) -> usize {
        (self.up[0].len() + self.up[1].len()) * 4
    }

    /// Frames of the merged stream.
    fn len(&self) -> usize {
        let (a, b) = (self.up[0].len(), self.up[1].len());
        if self.ended.is_some() {
            a.max(b)
        } else {
            a.min(b)
        }
    }

    fn frame(&self, i: usize) -> [u16; 2] {
        let (a, b) = (self.up[0].get(i), self.up[1].get(i));
        match (a, b) {
            (Some(a), Some(b)) => [a[0], b[1]],
            (Some(x), None) | (None, Some(x)) => *x,
            (None, None) => [0, 0],
        }
    }
}

#[derive(Default)]
struct Inner {
    logs: HashMap<u64, Log>,
    /// Relay session → match id.
    sessions: HashMap<u32, u64>,
    bytes: usize,
}

pub struct Live {
    inner: Mutex<Inner>,
    budget: usize,
    /// Viewers per match at most (`RUGEN_LIVE_VIEWERS`).
    pub max_viewers: usize,
}

impl Default for Live {
    fn default() -> Self {
        Self::new(64 << 20)
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Live {
    /// Logs of all matches together keep at most `budget` bytes.
    pub fn new(budget: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            budget,
            max_viewers: DEFAULT_VIEWERS,
        }
    }

    /// `RUGEN_LIVE_MB` (default 64), `RUGEN_LIVE_VIEWERS` (500).
    pub fn from_env() -> Self {
        let num = |k: &str| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.trim().parse::<usize>().ok())
        };
        let mut l = Self::new(num("RUGEN_LIVE_MB").unwrap_or(64) << 20);
        l.max_viewers = num("RUGEN_LIVE_VIEWERS")
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_VIEWERS);
        l
    }

    /// A match started on relay session `session`.
    pub fn start(
        &self,
        session: u32,
        header: MatchHeader,
        public: bool,
        room: Option<String>,
        members: Vec<u64>,
    ) {
        let mut g = lock(&self.inner);
        let id = header.match_id;
        if let Some(old) = g.logs.remove(&id) {
            g.bytes -= old.bytes();
            g.sessions.remove(&old.session);
        }
        g.sessions.insert(session, id);
        g.logs.insert(
            id,
            Log {
                header,
                session,
                up: [Vec::new(), Vec::new()],
                ended: None,
                public,
                room,
                members,
                viewers: HashMap::new(),
            },
        );
    }

    /// A player's upload: frames from `from`. Returns how many frames of
    /// this player's stream the server holds (what the player resumes
    /// from); `None` when the session has no log.
    pub fn upload(&self, session: u32, slot: u8, from: u32, frames: &[[u16; 2]]) -> Option<u32> {
        if slot > 1 {
            return None;
        }
        let mut g = lock(&self.inner);
        let id = *g.sessions.get(&session)?;
        let room = self.budget.saturating_sub(g.bytes);
        let log = g.logs.get_mut(&id)?;
        if log.ended.is_some() {
            return Some(log.up[slot as usize].len() as u32);
        }
        let up = &mut log.up[slot as usize];
        let held = up.len();
        let from = from as usize;
        let end = from + frames.len();
        if from > held || end <= held {
            // a gap (lost datagram: the player resends from `held`) or old news
            return Some(held as u32);
        }
        let fresh = &frames[held - from..];
        let room_frames = (room / 4).min(MAX_FRAMES.saturating_sub(held));
        let keep = fresh.len().min(room_frames);
        up.extend_from_slice(&fresh[..keep]);
        g.bytes += keep * 4;
        // past a limit: acknowledged, not kept (the player stops resending)
        Some(if keep < fresh.len() {
            end as u32
        } else {
            (held + keep) as u32
        })
    }

    /// The relay session closed or expired: its match is over.
    pub fn end_session(&self, session: u32) {
        let mut g = lock(&self.inner);
        if let Some(id) = g.sessions.remove(&session)
            && let Some(log) = g.logs.get_mut(&id)
        {
            log.ended.get_or_insert_with(Instant::now);
        }
    }

    /// Up to `max` frames from `from` (the header too when `from` is 0);
    /// `viewer` counts as watching. `None`: no such live match, or not
    /// allowed (a private room's match for an outsider).
    pub fn chunk(&self, match_id: u64, from: u32, max: usize, viewer: u64) -> Option<Chunk> {
        self.chunk_for(match_id, from, max, viewer).ok()
    }

    /// [`Self::chunk`] saying why there is none.
    pub fn chunk_for(
        &self,
        match_id: u64,
        from: u32,
        max: usize,
        viewer: u64,
    ) -> Result<Chunk, Refused> {
        let cap = self.max_viewers;
        let mut g = lock(&self.inner);
        let log = g.logs.get_mut(&match_id).ok_or(Refused::Missing)?;
        if !log.public && !log.members.contains(&viewer) {
            return Err(Refused::Missing);
        }
        if !log.viewers.contains_key(&viewer)
            || log.viewers[&viewer].elapsed().as_secs() >= VIEWER_SECS
        {
            log.viewers
                .retain(|_, t| t.elapsed().as_secs() < VIEWER_SECS);
            if log.viewers.len() >= cap {
                return Err(Refused::Full);
            }
        }
        log.viewers.insert(viewer, Instant::now());
        let total = log.len();
        let from = (from as usize).min(total);
        let to = (from + max.min(MAX_CHUNK_FRAMES)).min(total);
        Ok(Chunk {
            header: (from == 0).then(|| log.header.clone()),
            ended: log.ended.is_some(),
            total: total as u32,
            from: from as u32,
            inputs: (from..to).map(|i| log.frame(i)).collect(),
        })
    }

    /// Whether `account` may watch `match_id` (it is live, or ended recently).
    pub fn may_watch(&self, match_id: u64, account: u64) -> bool {
        lock(&self.inner)
            .logs
            .get(&match_id)
            .is_some_and(|l| l.public || l.members.contains(&account))
    }

    /// Public live matches, newest first.
    pub fn list(&self) -> Vec<LiveMatch> {
        let g = lock(&self.inner);
        let mut v: Vec<(u64, LiveMatch)> = g
            .logs
            .values()
            .filter(|l| l.public && l.ended.is_none())
            .map(|l| {
                let h = &l.header;
                (
                    h.created,
                    LiveMatch {
                        match_id: h.match_id,
                        players: [h.players[0].name.clone(), h.players[1].name.clone()],
                        fighters: [h.fighters[0].name.clone(), h.fighters[1].name.clone()],
                        stage: h.stage.name.clone(),
                        ranked: h.ranked,
                        frames: l.len() as u32,
                        room: l.room.clone(),
                        viewers: l
                            .viewers
                            .values()
                            .filter(|t| t.elapsed().as_secs() < VIEWER_SECS)
                            .count() as u32,
                    },
                )
            })
            .collect();
        v.sort_by_key(|(t, _)| std::cmp::Reverse(*t));
        v.into_iter().map(|(_, m)| m).take(100).collect()
    }

    /// Viewers of a match right now.
    #[cfg(test)]
    pub fn viewers(&self, match_id: u64) -> u32 {
        lock(&self.inner).logs.get(&match_id).map_or(0, |l| {
            l.viewers
                .values()
                .filter(|t| t.elapsed().as_secs() < VIEWER_SECS)
                .count() as u32
        })
    }

    /// A finished match's header and whole stream (sharing); `None` while
    /// it runs or when the server kept no log.
    pub fn finished(&self, match_id: u64) -> Option<(MatchHeader, Vec<[u16; 2]>)> {
        let g = lock(&self.inner);
        let l = g.logs.get(&match_id).filter(|l| l.ended.is_some())?;
        Some((l.header.clone(), (0..l.len()).map(|i| l.frame(i)).collect()))
    }

    /// The match is being fought (its log is not finished yet).
    pub fn running(&self, match_id: u64) -> bool {
        lock(&self.inner)
            .logs
            .get(&match_id)
            .is_some_and(|l| l.ended.is_none())
    }

    /// `account` opened a kept match that has this fingerprint (viewers
    /// may download its package, nobody else).
    pub fn watches_content(&self, fp: &str, account: u64) -> bool {
        lock(&self.inner).logs.values().any(|l| {
            l.viewers.contains_key(&account)
                && (l.header.fighters.iter().any(|f| f.fingerprint == fp)
                    || l.header.stage.fingerprint == fp)
        })
    }

    /// Drop logs of matches that ended more than [`KEEP_ENDED`] ago.
    pub fn sweep(&self) -> usize {
        let mut g = lock(&self.inner);
        let gone: Vec<u64> = g
            .logs
            .iter()
            .filter(|(_, l)| l.ended.is_some_and(|t| t.elapsed() >= KEEP_ENDED))
            .map(|(id, _)| *id)
            .collect();
        for id in &gone {
            if let Some(l) = g.logs.remove(id) {
                g.bytes -= l.bytes();
                g.sessions.remove(&l.session);
            }
        }
        gone.len()
    }

    /// (live logs, bytes held) for `/admin/stats`.
    pub fn usage(&self) -> (usize, usize) {
        let g = lock(&self.inner);
        (g.logs.len(), g.bytes)
    }

    #[cfg(test)]
    fn age(&self, match_id: u64, secs: u64) {
        let mut g = lock(&self.inner);
        if let Some(l) = g.logs.get_mut(&match_id) {
            l.ended = Some(Instant::now() - Duration::from_secs(secs));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rugen_proto::stream::StreamContent;

    fn header(id: u64) -> MatchHeader {
        MatchHeader {
            match_id: id,
            created: id,
            fighters: [
                StreamContent {
                    fingerprint: "a".repeat(64),
                    name: "Naruto".into(),
                    size: 1,
                },
                StreamContent::default(),
            ],
            ..Default::default()
        }
    }

    fn frames(n: usize, tag: u16) -> Vec<[u16; 2]> {
        (0..n).map(|i| [i as u16 | tag, i as u16 | tag]).collect()
    }

    #[test]
    fn each_player_feeds_its_own_half() {
        let live = Live::default();
        live.start(9, header(1), true, None, vec![]);
        assert_eq!(live.upload(9, 0, 0, &frames(10, 0x100)), Some(10));
        // nothing complete until P2 sent its frames
        assert_eq!(live.chunk(1, 0, 100, 5).unwrap().total, 0);
        assert_eq!(live.upload(9, 1, 0, &frames(6, 0x200)), Some(6));
        let c = live.chunk(1, 0, 100, 5).unwrap();
        assert_eq!((c.total, c.from, c.inputs.len()), (6, 0, 6));
        assert!(c.header.is_some() && !c.ended);
        // P1's half from P1, P2's from P2
        assert_eq!(c.inputs[3], [3 | 0x100, 3 | 0x200]);
        // resends and overlaps are fine, gaps are refused
        assert_eq!(live.upload(9, 1, 4, &frames(8, 0x200)[4..]), Some(8));
        assert_eq!(live.upload(9, 1, 20, &frames(2, 0x200)), Some(8));
        assert_eq!(
            live.upload(9, 7, 0, &frames(2, 0)),
            None,
            "spectator slots never feed"
        );
        assert_eq!(live.upload(5, 0, 0, &frames(2, 0)), None, "unknown session");
        // a later chunk has no header
        let c = live.chunk(1, 4, 100, 5).unwrap();
        assert_eq!((c.from, c.total, c.inputs.len()), (4, 8, 4));
        assert!(c.header.is_none());
        assert_eq!(live.viewers(1), 1);
        assert_eq!(live.list()[0].viewers, 1);
        // the end: P1's longer upload fills the tail
        live.end_session(9);
        let c = live.chunk(1, 0, 100, 5).unwrap();
        assert!(c.ended);
        assert_eq!(c.total, 10);
        assert_eq!(c.inputs[9], [9 | 0x100, 9 | 0x100]);
        assert!(live.list().is_empty(), "ended matches are not listed");
        let (h, all) = live.finished(1).unwrap();
        assert_eq!((h.match_id, all.len()), (1, 10));
        assert!(live.watches_content(&"a".repeat(64), 5));
        assert!(!live.watches_content(&"a".repeat(64), 6), "never opened it");
    }

    #[test]
    fn viewers_past_the_cap_are_told_the_match_is_full() {
        let mut live = Live::default();
        assert_eq!(live.max_viewers, 500);
        live.max_viewers = 3;
        live.start(7, header(1), true, None, vec![]);
        for v in 1..=3 {
            assert!(live.chunk_for(1, 0, 10, v).is_ok());
        }
        assert_eq!(live.chunk_for(1, 0, 10, 4).unwrap_err(), Refused::Full);
        // the seated keep watching
        assert!(live.chunk_for(1, 0, 10, 2).is_ok());
        assert_eq!(live.viewers(1), 3);
        // a viewer that stopped asking frees its seat
        lock(&live.inner)
            .logs
            .get_mut(&1)
            .unwrap()
            .viewers
            .insert(3, Instant::now() - Duration::from_secs(VIEWER_SECS + 1));
        assert!(live.chunk_for(1, 0, 10, 4).is_ok());
        assert_eq!(live.chunk_for(9, 0, 10, 4).unwrap_err(), Refused::Missing);
    }

    #[test]
    fn private_rooms_and_bounded_memory() {
        let live = Live::new(400); // 100 frames of one side
        live.start(1, header(1), false, Some("ROOM1".into()), vec![10, 11]);
        assert!(live.chunk(1, 0, 10, 99).is_none(), "an outsider");
        assert!(live.chunk(1, 0, 10, 10).is_some());
        assert!(!live.may_watch(1, 99) && live.may_watch(1, 11));
        assert!(live.list().is_empty(), "private matches are not listed");
        // past the budget: acknowledged, not kept
        assert_eq!(live.upload(1, 0, 0, &frames(150, 0)), Some(150));
        assert_eq!(live.usage(), (1, 400));
        assert!(live.finished(1).is_none(), "still running");
        // the per-match cap
        let big = Live::default();
        big.start(2, header(2), true, None, vec![]);
        let lots = frames(MAX_FRAMES + 50, 0);
        assert_eq!(big.upload(2, 0, 0, &lots), Some(lots.len() as u32));
        assert_eq!(big.usage().1, MAX_FRAMES * 4);
        // logs go some time after their match ended
        live.end_session(1);
        assert_eq!(live.sweep(), 0);
        live.age(1, KEEP_ENDED.as_secs());
        assert_eq!(live.sweep(), 1);
        assert_eq!(live.usage(), (0, 0));
    }
}
