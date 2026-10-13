//! Server-side re-simulation of disputed matches (`--features resim`).
//!
//! The stored packages of both fighters and the stage (content files,
//! verified again) are loaded in place and the confirmed input stream is
//! replayed through
//! the deterministic simulation (`rugen-sim`, no GPU / audio), built by the
//! same [`rugen_sim::headless::build_world`] the game uses. The engine's
//! `data/` (fightfx, fight.def) must be available: `RUGEN_RESIM_DATA`
//! (and optionally `RUGEN_RESIM_MOTIF`, default the same directory).

use std::path::PathBuf;

use crate::packages::Packages;

#[derive(Clone, Debug)]
#[cfg_attr(not(feature = "resim"), allow(dead_code))]
pub struct ResimConfig {
    pub data: PathBuf,
    pub motif: PathBuf,
}

impl ResimConfig {
    /// `RUGEN_RESIM_DATA` / `RUGEN_RESIM_MOTIF`; `None` when unset or the
    /// server was built without the `resim` feature.
    pub fn from_env() -> Option<Self> {
        let data = std::env::var("RUGEN_RESIM_DATA")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(PathBuf::from)?;
        if !cfg!(feature = "resim") {
            log::warn!(
                "RUGEN_RESIM_DATA is set but this server was built without --features resim"
            );
            return None;
        }
        let motif = std::env::var("RUGEN_RESIM_MOTIF")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map_or_else(|| data.clone(), PathBuf::from);
        Some(Self { data, motif })
    }
}

/// What the replay produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub frames: u32,
    pub checksum: u64,
    /// Winning side (0 / 1).
    pub winner: Option<usize>,
    pub match_over: bool,
}

/// Replay `inputs` of a match set up by `setup` (JSON with `p1_fp`,
/// `p2_fp`, `stage_fp`, `rules`), stopping at `stop_frame` when given.
#[cfg(feature = "resim")]
pub fn replay(
    packages: &Packages,
    cfg: &ResimConfig,
    setup: &str,
    inputs: &[u8],
    stop_frame: Option<u32>,
) -> Result<Outcome, String> {
    let v: serde_json::Value = serde_json::from_str(setup).map_err(|e| e.to_string())?;
    let fp = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .filter(|s| rugen_proto::is_fingerprint(s))
            .map(str::to_string)
            .ok_or_else(|| format!("setup has no {k}"))
    };
    let (f1, f2, fs) = (fp("p1_fp")?, fp("p2_fp")?, fp("stage_fp")?);
    {
        let mut defs = Vec::new();
        for f in [&f1, &f2, &fs] {
            if !packages.has(f) {
                return Err(format!("package {} expired", rugen_fair::short(f)));
            }
            // simulated by this engine, a 0.5 match could settle wrongly
            if packages.is_legacy(f) {
                return Err("an API 4 (rugen 0.5) match: not re-simulated".into());
            }
            let u = packages.verified(f).map_err(|e| e.to_string())?;
            if u.fingerprint != *f {
                return Err(format!("package {} changed", rugen_fair::short(f)));
            }
            defs.push(u.def_path());
        }
        let arena = v
            .get("rules")
            .and_then(|r| r.get("mode"))
            .and_then(|m| m.as_str())
            == Some("arena");
        let spec = rugen_sim::headless::MatchSpec {
            p1: &defs[0],
            p2: &defs[1],
            stage: Some(&defs[2]),
            data_dir: &cfg.data,
            motif: &cfg.motif,
            zoom: (0.6, 1.25),
            movement: rugen_sim::world::Movement {
                air_jumps: i32::from(arena),
                air_dash: arena,
                fast_fall: arena,
            },
            round_time: None,
            ai: [0, 0],
        };
        let mut world = rugen_sim::headless::build_world(&spec).map_err(|e| e.to_string())?;
        let r = rugen_sim::headless::replay(&mut world, inputs, stop_frame);
        Ok(Outcome {
            frames: r.frames,
            checksum: r.checksum,
            winner: r.winner,
            match_over: r.match_over,
        })
    }
}

#[cfg(not(feature = "resim"))]
pub fn replay(
    _packages: &Packages,
    _cfg: &ResimConfig,
    _setup: &str,
    _inputs: &[u8],
    _stop_frame: Option<u32>,
) -> Result<Outcome, String> {
    Err("this server was built without --features resim".into())
}
