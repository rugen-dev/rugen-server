//! Two client generations on one server.
//!
//! API 5 (rugen 0.6) moved fighters to `.rgc` / `.rgs` content files and
//! `rugen-fp-2` fingerprints; API 4 (rugen 0.5) clients upload RGPK
//! packages fingerprinted with `rugen-fp-1` ([`crate::legacy`]). Nothing
//! else of the lobby protocol changed, so one server serves both:
//!
//! * API 5 clients send `X-Rugen-Api: 5` on every request; API 4 clients
//!   send nothing new, so a request without the header is API 4.
//! * `/health` advertises `api` (the newest API served) and `api_min` (the
//!   oldest). 0.5 clients never look at `api`, so they keep connecting.
//! * Players of different APIs can never share fighters (neither can read
//!   the other's packages, and their fingerprints differ for the same
//!   character), so they never meet: the queue pairs equal APIs only, a
//!   room remembers its host's API and refuses players and spectators of
//!   the other one with a message saying who must update, uploads are
//!   verified in the format of the uploader's API and downloads refuse a
//!   package of the other generation.
//! * The lobby lists every public room with an additive `api` field; for
//!   API 4 clients (which do not know that field) rooms of the newer API
//!   carry a `[0.6]` name prefix and come last.

/// The newest API served.
pub const API: u32 = rugen_proto::API_VERSION;
/// The oldest API served: rugen 0.5 (RGPK packages, `rugen-fp-1`).
pub const LEGACY_API: u32 = 4;
/// Request header carrying the client's API (absent: [`LEGACY_API`]).
pub const API_HEADER: &str = "x-rugen-api";

const _: () = assert!(API == LEGACY_API + 1, "map the new API in release()");

/// The API of a request from its [`API_HEADER`] value. Absent or garbage is
/// an API 4 client (they send nothing); newer than [`API`] is served as
/// [`API`] (such a client decides itself whether this server is enough).
pub fn api_of(header: Option<&str>) -> u32 {
    header
        .and_then(|h| h.trim().parse::<u32>().ok())
        .map_or(LEGACY_API, |v| v.clamp(LEGACY_API, API))
}

/// Whether requests of `api` use RGPK packages and `rugen-fp-1`.
pub fn is_legacy(api: u32) -> bool {
    api <= LEGACY_API
}

/// The game release players know an API by.
pub fn release(api: u32) -> &'static str {
    if is_legacy(api) { "0.5" } else { "0.6" }
}

/// Why a player of `mine` cannot join a room hosted on `host`.
pub fn room_refusal(mine: u32, host: u32) -> String {
    if host < mine {
        format!(
            "THIS ROOM'S HOST RUNS AN OLDER RUGEN ({}). BOTH PLAYERS NEED THE SAME VERSION.",
            release(host)
        )
    } else {
        format!(
            "THIS ROOM'S HOST RUNS A NEWER RUGEN ({}). UPDATE YOUR GAME TO JOIN.",
            release(host)
        )
    }
}

/// Why a package of the other generation cannot go to a client of `mine`.
pub fn package_refusal(mine: u32) -> String {
    if is_legacy(mine) {
        "THIS FIGHTER COMES FROM A NEWER RUGEN (0.6). UPDATE YOUR GAME.".into()
    } else {
        "THIS FIGHTER COMES FROM AN OLDER RUGEN (0.5). BOTH PLAYERS NEED THE SAME VERSION.".into()
    }
}

/// The lobby name of a room of `room` shown to a client of `viewer` that
/// cannot read the additive `api` field.
pub fn listed_name(name: &str, room: u32, viewer: u32) -> String {
    if is_legacy(viewer) && room != viewer {
        format!("[{}] {name}", release(room))
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_parsing_defaults_to_api_4() {
        assert_eq!(api_of(None), 4);
        assert_eq!(api_of(Some("")), 4);
        assert_eq!(api_of(Some("junk")), 4);
        assert_eq!(api_of(Some("3")), 4);
        assert_eq!(api_of(Some(" 5 ")), 5);
        assert_eq!(api_of(Some("9")), API);
        assert!(is_legacy(4) && !is_legacy(5));
    }

    #[test]
    fn messages_say_who_must_update() {
        assert_eq!(
            room_refusal(5, 4),
            "THIS ROOM'S HOST RUNS AN OLDER RUGEN (0.5). BOTH PLAYERS NEED THE SAME VERSION."
        );
        assert!(room_refusal(4, 5).contains("NEWER RUGEN (0.6)"));
        assert!(room_refusal(4, 5).contains("UPDATE YOUR GAME"));
        assert_eq!(listed_name("DOJO", 5, 4), "[0.6] DOJO");
        assert_eq!(listed_name("DOJO", 4, 4), "DOJO");
        assert_eq!(listed_name("DOJO", 4, 5), "DOJO");
    }
}
