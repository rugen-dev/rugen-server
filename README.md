# rugen-server

The self-hostable online hub for [rugen](https://github.com/rugen-dev/rugen-engine),
the M.U.G.E.N engine rewritten in Rust: accounts, rooms, quick match, ranked
and the match relay. One small binary with SQLite inside.

**Docs: [rugen.dev/server](https://rugen.dev/server/overview/)** · official
server: `play.rugen.dev`

## Features

- **Accounts**: optional username and password (Argon2id), several devices.
- **Lobby**: public and private rooms, spectators, rematch, tournament
  brackets of 8 or 16 players (seeded by rating, matches called by the server).
- **Quick match and ranked**: Elo, 90-day seasons (final standings and tier
  badges kept), leaderboards.
- **Match relay**: UDP with a WebSocket fallback; players never see each
  other's IP. Optional Cloudflare TURN inside the free tier.
- **Bring your own character**: matchup verdicts and verified temporary
  packages, so both players fight with identical files.
- **Fair ranked**: result checks, stored replays, re-simulation of disputed
  matches.
- **Official and community servers**: the official server signs a truth feed
  (cheat blocklist, character ratings) that community servers enforce.
- **Backups**: daily, to any S3-compatible bucket.

## Capacity

Measured on the production host with the built-in self-benchmark. The
container was capped at **1 CPU and 768 MB**, and the load generator ran
inside the same container, so these numbers are a floor.

| Players online | CPU | Memory | Errors |
|---|---|---|---|
| 500 | 37 % | 228 MB | 0 |
| 1,000 | 66 % | 408 MB | 0 |
| 1,250 | 79 % | 530 MB | 0 |

Every simulated player keeps a presence WebSocket, polls its room or queue,
plays matches and reports results; part of them relay their match traffic
through the server (about 10,000 packets/s at 1,250 players).

- **1 CPU / 768 MB**: about 2,000 players online at once; memory runs out
  first.
- **2 CPU / 1.5 GB**: the compose defaults; roughly twice that.

Method, raw numbers and how to benchmark your own host:
[`docs/performance.md`](docs/performance.md).

## Deploy

Both compose files cap the container at 2 CPU / 1.5 GB by default
(`RUGEN_CPUS`, `RUGEN_MEM`), with low priority under contention. They run
as plain `docker compose` or as a Dokploy "Compose" app.

**Public server**: [`deploy/docker-compose.yml`](deploy/docker-compose.yml)
publishes 8080/tcp (HTTP and WebSocket; put HTTPS in front) and 7001/udp
(the relay's fast path).

```sh
git clone https://github.com/rugen-dev/rugen-server
cd rugen-server/deploy
cp .env.example .env    # optional: name, MOTD, public URL
docker compose up -d
```

**Behind a Cloudflare Tunnel**:
[`deploy/docker-compose.tunnel.yml`](deploy/docker-compose.tunnel.yml) opens
no ports at all; the tunnel is the only way in and matches relay over the
WebSocket. It builds the image from this repository on the host, so no
registry is needed. This is how `play.rugen.dev` runs.

```sh
docker compose -f deploy/docker-compose.tunnel.yml up -d
```

Players connect from the game's ONLINE menu by entering the server address.
Configuration, official server keys, TURN, backups and operations:
[rugen.dev/server](https://rugen.dev/server/overview/) and
[`deploy/README.md`](deploy/README.md).

## Build from source

```sh
cargo build --release --features resim
RUGEN_DATA=/var/lib/rugen RUGEN_NAME="my server" ./target/release/rugen-server
```

The protocol, fairness rules and simulation come from
[rugen-engine](https://github.com/rugen-dev/rugen-engine) as git dependencies.
To build against a local engine checkout, add an untracked
`.cargo/config.toml` with a `[patch."https://github.com/rugen-dev/rugen-engine"]`
section pointing at its `crates/`.

Commits follow Conventional Commits: `type(scope): subject`.

## License

MIT OR Apache-2.0.
