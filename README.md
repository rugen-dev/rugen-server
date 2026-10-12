# rugen-server

The self-hostable online hub for [rugen](https://github.com/rugen-dev/rugen-engine),
the M.U.G.E.N engine rewritten in Rust. One small binary (≈5 MB image,
SQLite inside):

- anonymous accounts, a lobby with public and private rooms (optional
  Argon2id room passwords), spectators, rematch
- quick match and ranked (Elo K=32, 90-day seasons, leaderboard)
- the **match relay**: every datagram goes player → server → player over UDP
  (WebSocket fallback), so players never learn each other's IP address
- **bring your own character**: instant FAIR / UNBALANCED / BLOCKED
  matchup verdicts, verified temporary packages so both players fight with
  byte-identical files
- ranked result verification, stored replays, optional re-simulation of
  disputed matches (`--features resim`)
- **official vs community servers**: the official server (`play.rugen.dev`,
  holder of the official Ed25519 key) is the global ranking and publishes a
  signed truth feed (cheat blocklist + character ratings) that every
  community server pulls and enforces; verdicts and results are signed

Docs: <https://rugen.dev> ·
deployment guide: [`deploy/README.md`](deploy/README.md)

## Run

```sh
docker compose -f deploy/docker-compose.yml up -d
```

or from source:

```sh
cargo build --release
RUGEN_DATA=/var/lib/rugen RUGEN_NAME="my server" ./target/release/rugen-server
```

HTTP + WebSocket on 8080 (put HTTPS in front), UDP relay on 7001. Players
connect from the game's ONLINE menu by entering the server address.

## Develop

The protocol, fairness rules and simulation are shared with the game and
come from [rugen-engine](https://github.com/rugen-dev/rugen-engine) as git
dependencies. To work against a local engine checkout, add an untracked
`.cargo/config.toml`:

```toml
[patch."https://github.com/rugen-dev/rugen-engine"]
rugen-proto   = { path = "../rugen-engine/crates/proto" }
rugen-fair    = { path = "../rugen-engine/crates/fair" }
rugen-formats = { path = "../rugen-engine/crates/formats" }
rugen-cns     = { path = "../rugen-engine/crates/cns" }
rugen-sim     = { path = "../rugen-engine/crates/sim" }
rugen-net     = { path = "../rugen-engine/crates/net" }
rugen-content = { path = "../rugen-engine/crates/content" }
```

The end-to-end tests use the engine checkout's `reference/` tree (KFM) and
skip when it is missing; point `RUGEN_ENGINE_DIR` at it if it is not a
sibling `../rugen-engine`.

Commits follow Conventional Commits: `type(scope): subject`.

## License

MIT OR Apache-2.0.
