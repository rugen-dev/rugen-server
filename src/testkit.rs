//! Test content: tiny characters / stages, their packages (`.rgc` / `.rgs`
//! files) and declarations.

use std::path::{Path, PathBuf};

use rugen_proto::FighterDecl;

pub fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "rugen-server-{tag}-{}",
        crate::store::random_hex(4)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A one-sprite SFF whose pixels depend on `name`.
pub fn tiny_sff(name: &str) -> Vec<u8> {
    let mut sff = rugen_formats::sff::Sff {
        version: Some(rugen_formats::sff::Version::V2 { patch: 1 }),
        ..Default::default()
    };
    let mut pal = vec![[0u8; 4]; 256];
    for (i, c) in pal.iter_mut().enumerate().skip(1) {
        *c = [i as u8, 255 - i as u8, 7, 255];
    }
    let p = sff.push_palette((1, 1), pal);
    let px: Vec<u8> = name.bytes().chain([1, 2, 3]).collect();
    sff.push_indexed((0, 0), px.len() as u16, 1, [0, 0], p, px);
    sff.write_exact()
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
    std::fs::write(dir.join("c.sff"), tiny_sff(name)).unwrap();
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
    std::fs::write(dir.join("s.sff"), tiny_sff("stage")).unwrap();
    dir.join("s.def")
}

/// The content file (`.rgc` / `.rgs`) of the content at `def`, as uploaded.
pub fn package(def: &Path, kind: rugen_fair::Kind) -> Vec<u8> {
    let dir = def.parent().unwrap();
    let out = dir.with_extension(rugen_fair::package::ext(kind));
    let src = rugen_content::convert::Source {
        root: dir.to_path_buf(),
        def: def.file_name().unwrap().to_string_lossy().to_string(),
        kind: match kind {
            rugen_fair::Kind::Char => rugen_formats::rgc::Kind::Char,
            rugen_fair::Kind::Stage => rugen_formats::rgc::Kind::Stage,
        },
        name: "test".into(),
    };
    rugen_content::convert::convert(&src, &out, dir, None).unwrap();
    let bytes = std::fs::read(&out).unwrap();
    let _ = std::fs::remove_file(&out);
    bytes
}

/// Declaration + package bytes of the content at `def`.
pub fn declare(def: &Path, kind: rugen_fair::Kind) -> (FighterDecl, Vec<u8>) {
    let files = rugen_fair::files::content_files(kind, def, None).unwrap();
    let fp = rugen_fair::fingerprint(&files).unwrap();
    let pkg = package(def, kind);
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
