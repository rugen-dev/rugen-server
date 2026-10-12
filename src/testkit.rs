//! Test content: tiny characters / stages, their packages and declarations.

use std::path::{Path, PathBuf};

use rugen_proto::FighterDecl;

pub fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rugen-relay-{tag}-{}", crate::store::random_hex(4)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A minimal character whose cns gets `extra` appended.
pub fn tiny_char(dir: &Path, name: &str, extra: &str) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let w = |n: &str, t: &str| std::fs::write(dir.join(n), t).unwrap();
    w(
        "c.def",
        &format!(
            "[Info]\nname = \"{name}\"\nauthor = \"test\"\n[Files]\ncmd = c.cmd\ncns = c.cns\nsprite = c.sff\nanim = c.air\nstcommon = common1.cns\n"
        ),
    );
    w("c.cmd", "[Statedef -1]\n");
    w(
        "c.cns",
        &format!(
            "[Data]\nlife = 1000\nattack = 100\ndefence = 100\n[Statedef 200]\nmovetype = A\n[State 200, h]\ntype = HitDef\ntrigger1 = 1\ndamage = 40\nguardflag = MA\n{extra}"
        ),
    );
    w("c.sff", &format!("sprites of {name}"));
    w("c.air", "[Begin Action 0]\n0,0, 0,0, 10\n");
    w("common1.cns", "[Statedef 0]\n");
    dir.join("c.def")
}

pub fn tiny_stage(dir: &Path) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("s.def"),
        "[Info]\nname = \"Dojo\"\n[BGdef]\nspr = s.sff\n",
    )
    .unwrap();
    std::fs::write(dir.join("s.sff"), "stage sprites").unwrap();
    dir.join("s.def")
}

/// Declaration + package bytes of the content at `def`.
pub fn declare(def: &Path, kind: rugen_fair::Kind) -> (FighterDecl, Vec<u8>) {
    let files = rugen_fair::files::content_files(kind, def, None).unwrap();
    let fp = rugen_fair::fingerprint(&files).unwrap();
    let mut pkg = Vec::new();
    rugen_fair::package::write(&files, &fp, &mut pkg).unwrap();
    let profile = match kind {
        rugen_fair::Kind::Char => Some(rugen_fair::profile::analyze(&files).unwrap()),
        rugen_fair::Kind::Stage => None,
    };
    let d = FighterDecl {
        fingerprint: fp,
        kind: kind.as_str().into(),
        id: "t".into(),
        name: rugen_formats::def::Def::open(def)
            .ok()
            .and_then(|d| {
                d.section("info")
                    .and_then(|i| i.str("name").map(str::to_string))
            })
            .unwrap_or_default(),
        author: "test".into(),
        def: files.def.clone(),
        size: pkg.len() as u64,
        profile,
        portrait: None,
    };
    (d, pkg)
}
