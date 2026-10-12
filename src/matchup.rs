//! The matchup phase of a match (rooms and the queue alike):
//!
//! ```text
//! pick     each player declares a fighter (fingerprint + profile + card),
//!          P1 also the stage; the verdict is computed at once
//! confirm  both see the opponent's card and accept (BLOCKED: re-pick;
//!          ranked needs FAIR; casual UNBALANCED needs an explicit accept)
//! sync     packages the server lacks are uploaded and verified, each
//!          client downloads what it lacks, then reports ready with the
//!          fingerprints, rules and game version it will play with
//! started  everything agreed: the relay session exists, tickets go out
//! failed   a client lied (profile / fingerprint), left, or timed out
//! ```

use std::time::Instant;

use rugen_fair::verdict::{Thresholds, verdict};
use rugen_proto::{
    CharRating, FairnessProfile, FighterCard, FighterDecl, MatchupView, ReadyReport, Rules,
    Verdict, VerdictKind,
};

use crate::store::{PackageRow, Store};

/// Accounts by relay slot and their tokens once the match runs.
#[derive(Clone, Debug)]
pub struct Running {
    pub match_id: u64,
    pub session: u32,
    /// Accounts by relay slot (P1, P2, spectators).
    pub slots: Vec<u64>,
    pub tokens: Vec<[u8; 16]>,
}

pub struct Matchup {
    pub id: u64,
    pub ranked: bool,
    pub rules: Rules,
    pub players: [u64; 2],
    pub spectators: Vec<u64>,
    pub room: Option<String>,
    pub mirror: bool,
    pub picks: [Option<FighterDecl>; 2],
    pub stage: Option<FighterDecl>,
    pub verdict: Option<Verdict>,
    pub accepted: [bool; 2],
    pub ready: [Option<ReadyReport>; 2],
    pub failed: Option<String>,
    pub started: Option<Running>,
    pub created: Instant,
    pub touched: Instant,
}

impl Matchup {
    pub fn new(
        id: u64,
        players: [u64; 2],
        ranked: bool,
        rules: Rules,
        room: Option<String>,
    ) -> Self {
        Self {
            id,
            ranked,
            mirror: rules.chars == "mirror",
            rules,
            players,
            spectators: Vec::new(),
            room,
            picks: [None, None],
            stage: None,
            verdict: None,
            accepted: [false, false],
            ready: [None, None],
            failed: None,
            started: None,
            created: Instant::now(),
            touched: Instant::now(),
        }
    }

    /// 0 / 1 for the players, None for anybody else.
    pub fn side_of(&self, account: u64) -> Option<usize> {
        self.players.iter().position(|&p| p == account)
    }

    pub fn involves(&self, account: u64) -> bool {
        self.side_of(account).is_some() || self.spectators.contains(&account)
    }

    /// Fighter of side `i` (P2 plays P1's under the mirror rule).
    pub fn fighter(&self, i: usize) -> Option<&FighterDecl> {
        if i == 1 && self.mirror {
            self.picks[0].as_ref()
        } else {
            self.picks[i].as_ref()
        }
    }

    /// P1, P2 and stage fingerprints once all are known.
    pub fn fingerprints(&self) -> Option<[String; 3]> {
        Some([
            self.fighter(0)?.fingerprint.clone(),
            self.fighter(1)?.fingerprint.clone(),
            self.stage.as_ref()?.fingerprint.clone(),
        ])
    }

    /// Every fingerprint declared so far.
    pub fn declared(&self) -> Vec<&str> {
        self.picks
            .iter()
            .chain(std::iter::once(&self.stage))
            .flatten()
            .map(|d| d.fingerprint.as_str())
            .collect()
    }

    /// Who declared `fp` (players), for blame.
    pub fn declarers(&self, fp: &str) -> Vec<usize> {
        let mut out = Vec::new();
        for i in 0..2 {
            if self.picks[i].as_ref().is_some_and(|d| d.fingerprint == fp) {
                out.push(i);
            }
        }
        if self.stage.as_ref().is_some_and(|d| d.fingerprint == fp) && !out.contains(&0) {
            out.push(0);
        }
        out
    }

    pub fn phase(&self) -> &'static str {
        if self.failed.is_some() {
            "failed"
        } else if self.started.is_some() {
            "started"
        } else if self.fingerprints().is_none()
            || self
                .verdict
                .as_ref()
                .is_none_or(|v| v.kind == VerdictKind::Blocked)
        {
            "pick"
        } else if !(self.accepted[0] && self.accepted[1]) {
            "confirm"
        } else {
            "sync"
        }
    }

    /// Any change of picks resets confirmations and readiness.
    pub fn reset_progress(&mut self) {
        self.accepted = [false, false];
        self.ready = [None, None];
    }

    pub fn fail(&mut self, why: String) {
        if self.failed.is_none() && self.started.is_none() {
            log::warn!("matchup {}: {why}", self.id);
            self.failed = Some(why);
        }
    }

    /// The profile used for side `i`: the server's (from the verified
    /// package) when it has one, else the declared one.
    fn profile(&self, i: usize, store: &Store) -> Option<FairnessProfile> {
        let d = self.fighter(i)?;
        let verified = store
            .package(&d.fingerprint)
            .ok()
            .flatten()
            .and_then(|p| p.profile);
        let mut p = verified.or_else(|| d.profile.clone())?;
        // the client's verify verdict only ever counts against itself
        if let Some(v) = d.profile.as_ref().and_then(|p| p.verify.clone()) {
            p.verify = Some(v);
        }
        Some(p)
    }

    pub fn recompute_verdict(&mut self, store: &Store, t: &Thresholds) {
        let (Some(a), Some(b)) = (self.profile(0, store), self.profile(1, store)) else {
            self.verdict = None;
            return;
        };
        let rating = |i: usize| {
            self.fighter(i)
                .and_then(|d| store.char_rating(&d.fingerprint).ok().flatten())
        };
        let (ra, rb) = (rating(0), rating(1));
        let name = |i: usize| {
            self.fighter(i)
                .map(|d| d.name.to_uppercase())
                .unwrap_or_default()
        };
        let (na, nb) = (name(0), name(1));
        let v = verdict([&a, &b], [ra.as_ref(), rb.as_ref()], [&na, &nb], t);
        if self.verdict.as_ref() != Some(&v) {
            self.accepted = [false, false];
        }
        self.verdict = Some(v);
    }

    /// Accept the verdict (`unbalanced_ok` = the player explicitly agreed
    /// to an unbalanced fight). Err = why it is refused.
    pub fn accept(&mut self, side: usize, unbalanced_ok: bool) -> Result<(), String> {
        let Some(v) = &self.verdict else {
            return Err("both fighters are not picked yet".into());
        };
        match v.kind {
            VerdictKind::Blocked => {
                return Err("this matchup is blocked: pick another fighter".into());
            }
            VerdictKind::Unbalanced if self.ranked => {
                return Err("ranked matches must be fair: pick another fighter".into());
            }
            VerdictKind::Unbalanced if !unbalanced_ok => {
                return Err("unbalanced: accept it explicitly or pick another fighter".into());
            }
            _ => {}
        }
        self.accepted[side] = true;
        Ok(())
    }

    /// Fingerprints the server does not hold yet.
    pub fn missing(&self, has: &dyn Fn(&str) -> bool) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for fp in self.declared() {
            if !has(fp) && !out.iter().any(|o| o == fp) {
                out.push(fp.to_string());
            }
        }
        out
    }

    /// Both ready reports agree with each other and with the matchup.
    pub fn ready_agreed(&self) -> Result<bool, String> {
        let (Some(a), Some(b)) = (&self.ready[0], &self.ready[1]) else {
            return Ok(false);
        };
        let Some([p1, p2, st]) = self.fingerprints() else {
            return Ok(false);
        };
        for (who, r) in [("P1", a), ("P2", b)] {
            if r.p1 != p1 || r.p2 != p2 || r.stage != st {
                return Err(format!("{who} is ready with different files"));
            }
            if r.rules != self.rules {
                return Err(format!("{who} is ready with different rules"));
            }
        }
        if a.engine != b.engine {
            return Err(format!(
                "game versions differ ({} / {})",
                a.engine, b.engine
            ));
        }
        Ok(true)
    }

    pub fn view(
        &self,
        me: u64,
        store: &Store,
        has: &dyn Fn(&str) -> bool,
        ticket: Option<rugen_proto::SessionTicket>,
    ) -> MatchupView {
        let card = |d: Option<&FighterDecl>| -> Option<FighterCard> {
            let d = d?;
            let row: Option<PackageRow> = store.package(&d.fingerprint).ok().flatten();
            let rating: Option<CharRating> = if d.kind == "char" {
                store.char_rating(&d.fingerprint).ok().flatten()
            } else {
                None
            };
            let mut decl = d.clone();
            if let Some(r) = &row {
                // the server's view of the content wins over the declaration
                if r.profile.is_some() {
                    decl.profile = r.profile.clone().map(|mut p| {
                        p.verify = d.profile.as_ref().and_then(|x| x.verify.clone());
                        p
                    });
                }
                decl.size = r.size;
            }
            Some(FighterCard {
                decl,
                rating,
                verified: row.is_some(),
            })
        };
        MatchupView {
            id: self.id,
            ranked: self.ranked,
            rules: self.rules.clone(),
            side: self.side_of(me).map_or(3, |s| s as u8 + 1),
            phase: self.phase().into(),
            fighters: [card(self.fighter(0)), card(self.fighter(1))],
            stage: card(self.stage.as_ref()),
            verdict: self.verdict.clone(),
            accepted: self.accepted,
            ready: [self.ready[0].is_some(), self.ready[1].is_some()],
            missing: self.missing(has),
            error: self.failed.clone().unwrap_or_default(),
            mirror: self.mirror,
            ticket,
        }
    }
}

/// Server-side sanity checks of a declaration.
pub fn check_decl(d: &FighterDecl, kind: &str, max_pkg: u64) -> Result<FighterDecl, String> {
    if !rugen_proto::is_fingerprint(&d.fingerprint) {
        return Err("bad fingerprint".into());
    }
    if d.kind != kind {
        return Err(format!("expected a {kind}"));
    }
    if d.size > max_pkg {
        return Err(format!(
            "{} is {} MB, this server accepts up to {} MB",
            d.name,
            d.size >> 20,
            max_pkg >> 20
        ));
    }
    if kind == "char" && d.profile.is_none() {
        return Err("a fighter needs its fairness profile".into());
    }
    if d.portrait
        .as_ref()
        .is_some_and(|p| p.len() > rugen_proto::MAX_PORTRAIT_B64)
    {
        return Err("card portrait too large".into());
    }
    let clip = |s: &str, n: usize| {
        s.chars()
            .filter(|c| !c.is_control())
            .take(n)
            .collect::<String>()
    };
    let mut out = d.clone();
    out.name = clip(&d.name, 48);
    out.author = clip(&d.author, 48);
    out.id = clip(&d.id, 64);
    out.def = clip(&d.def, 128);
    if let Some(p) = out.profile.as_mut() {
        p.reasons.truncate(32);
        p.flags.truncate(64);
    }
    Ok(out)
}
