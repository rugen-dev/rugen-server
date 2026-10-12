# Hosting a rugen server

`rugen-server` is one small Rust binary (≈5 MB image, SQLite inside) that
gives rugen players a place to meet:

- accounts (nickname + server-issued key, no passwords), profiles
- a **lobby**: public rooms, private rooms (code only), optional room
  passwords, rules (rounds, timer, classic / arena, free pick / mirror),
  spectator seats, host kick, rematch
- **quick match** and **ranked** (Elo K=32, 90-day seasons, leaderboard)
- the **match relay**: every match datagram goes player → server → player,
  so players never learn each other's IP address
- ranked result verification and stored ranked replays

`deploy/docker-compose.yml` runs only `rugen-server` and publishes its two
ports. HTTPS in front is your choice: Dokploy's domains (Traefik), any
reverse proxy, or the optional Cloudflare Tunnel add-on in
`deploy/cloudflared/` (a separate compose).

| Port      | What                                              | Notes |
|-----------|---------------------------------------------------|-------|
| 8080/tcp  | HTTP API, `/ws` lobby presence, `/relay` fallback | put HTTPS in front |
| 7001/udp  | match relay, fast path                            | open it in the firewall |

Without 7001/udp reachable, clients fall back to the WebSocket relay on
8080 after a 1.5 s UDP probe (works everywhere, a bit slower). Host ports
can be changed with `RUGEN_HTTP_PORT` / `RUGEN_UDP_PORT`.

## 1. Dokploy

1. **Create Project → Create Service → Compose**. Source: this Git
   repository, compose path `deploy/docker-compose.yml` (or paste the file
   in the *Raw* editor).
2. **Environment** tab (optional): paste `deploy/.env.example` and set
   `RUGEN_PUBLIC_URL`, `RUGEN_NAME`, `RUGEN_MOTD`. Dokploy writes `.env` next
   to the compose file; without it the defaults are used.
3. **Domains** tab: add `rugen.example.com` → service `rugen-server`, port
   `8080`, HTTPS on (WebSocket upgrades pass through Traefik). Skip this if
   you use the Cloudflare Tunnel add-on instead.
4. Open **7001/udp** in the VPS firewall / security group.
5. **Deploy**. Logs show `http + websocket on 0.0.0.0:8080` and
   `udp relay advertised as ...`; `https://rugen.example.com/health` answers
   with the server name, version and players online.

## 2. Optional: Cloudflare Tunnel (separate compose)

1. Cloudflare dashboard → **Zero Trust → Networks → Tunnels → Create a
   tunnel** → *Cloudflared*. Copy the token after `--token` (`eyJ...`).
2. **Public hostname**: `rugen.example.com` → service `HTTP`, URL
   `rugen-server:8080`.
3. In Dokploy create a **second** Compose service with compose path
   `deploy/cloudflared/docker-compose.yml`, set `CF_TUNNEL_TOKEN` in its
   Environment tab and deploy it after the server (it joins the server's
   `rugen` network; no ports needed).
4. For the UDP fast path add a **DNS-only** (grey cloud) record such as
   `udp.example.com` → the server's public IP and set
   `RUGEN_UDP_PUBLIC=udp.example.com:7001` on the server (a proxied name
   cannot carry UDP). With the tunnel you may also drop the `8080` port
   mapping from the server compose.

The image is pulled from `ghcr.io/diary-axel-rakotoarivao/rugen-server:latest`
(published by `.github/workflows/server-image.yml` on `v*` tags). To build
on the server instead, uncomment the `build:` block in the compose file
(and drop `image:` or point `RUGEN_IMAGE` at a local tag).

## 3. Players

In the game: **ONLINE → ADD SERVER** → `https://rugen.example.com`, or in
`rugen.toml`:

```toml
[net]
server = "https://rugen.example.com"     # default server
servers = ["https://friends.example.org", "203.0.113.5:8080"]   # favourites
input_delay = "auto"                      # or a fixed number of frames
good_connections_only = false
websocket_only = false                    # skip the UDP probe
```

Command line (two machines, or two terminals for testing):

```sh
rugen play kfm --server https://rugen.example.com --room new        # prints ROOM CODE
rugen play G6_Naruto --server https://rugen.example.com --room ABCDE   # joins, brings Naruto
rugen play kfm --server https://rugen.example.com --room ABCDE --spectate
```

Each command line player brings the character it names, goes through the
matchup screen on its own (confirms unless BLOCKED, prints the verdict),
syncs the files, fights and quits; `--shot out.png` saves a picture of the
matchup screen instead.

## Bring your own character

Players do not need the same characters installed. Every match (rooms,
quick match, ranked) starts with a **matchup**:

1. Each player picks a fighter from their own `chars/` (P1 also the stage).
   The client sends its **fingerprint** (sha256 of the gameplay files) and
   **fairness profile** (static analysis of the CNS: life, attack, damage,
   supers, projectiles, invulnerability windows, cheat flags, a power score
   where Kung Fu Man ≈ 100) plus a small card portrait.
2. The server answers at once:
   - **BLOCKED**: a cheat-level flag on either side (life / power regen in
     state -2, permanent invulnerability, setting the opponent's life or
     state, custom-state kills, pause loops, round stalling, extreme
     constants…) or a character that fails `rugen verify`. Never playable;
     that player changes fighter.
   - **UNBALANCED**: power-score ratio above `RUGEN_FAIR_RATIO` (1.6), or
     life / attack / defence twice the other's, or (once both have
     `RUGEN_FAIR_MIN_GAMES` verified games) a community rating gap above
     `RUGEN_FAIR_COMMUNITY_GAP`. Ranked refuses it; casual rooms and quick
     match play it only when **both** players accept it explicitly.
   - **FAIR** otherwise (a small community gap also clears a score-only
     UNBALANCED: real matches showed the fight is even).
3. Both see the other's card and the verdict and confirm (or change fighter;
   any change resets confirmations, and so does a verdict that changes once
   the server has checked the files).
4. From pick time each client uploads its optimised package (zstd, only the
   files the character uses) **if the server does not already hold that
   fingerprint**, resumably, in 2 MB chunks. The server unpacks it into
   scratch space, recomputes fingerprint and profile, and fails the match
   (and flags the account) when they differ from what the client claimed.
5. Each client downloads what it lacks into `cache/net/` (never into
   `chars/`), reports ready with the fingerprints, rules and game version,
   and the server hands out the relay tickets once both agree.

Packages are **temporary caches**: they expire `RUGEN_PKG_TTL` after their
last use, the oldest go first above `RUGEN_PKG_MAX_TOTAL`, and only packages
of stored ranked replays are kept longer (`RUGEN_PKG_REPLAY_TTL`). Uploads
are only accepted for a fighter the account declared in a live matchup,
capped per package and per hour (account and IP). Every verified result
moves a **community Elo per fingerprint**, shown on the cards.

**Legal note.** Characters are third-party content. The server stores
uploaded packages only to pass them between the two players of a match and
deletes them on expiry; it does not list or publish them. As the operator
you are responsible for what your server hosts: set the caps and TTL to
what you are willing to keep, remove content on request (delete
`packages/<fingerprint>.rgpk` from the data volume; the server drops its
record on the next sweep), and
do not run a public server if you cannot answer takedown requests.

### Re-simulating disputed matches

Built with `--features resim` (`cargo build --release -p rugen-relay
--features resim`, or `docker build --build-arg FEATURES=resim ...`) and
given the engine data (`RUGEN_RESIM_DATA=/path/to/data`, the folder with
`common1.cns` / `fight.def`), the server re-plays a disputed match from
both input streams with the stored packages, headless, and settles the
result when one report matches the simulation.

LAN / direct-IP matches (`--net ip:port`, HOST / JOIN DIRECT MATCH) still
work without any server; there the players type each other's address on
purpose.

## Environment variables

| Variable           | Default            | Meaning |
|--------------------|--------------------|---------|
| `RUGEN_PUBLIC_URL` | –                  | public https URL; logged, and its host is the UDP fallback host |
| `RUGEN_NAME`       | `rugen server`     | name in the server list |
| `RUGEN_MOTD`       | empty              | message of the day |
| `RUGEN_BIND`       | `0.0.0.0:8080`     | HTTP / WebSocket listener |
| `RUGEN_UDP_BIND`   | `0.0.0.0:7001`     | UDP relay listener, `off` to disable |
| `RUGEN_UDP_PUBLIC` | public URL host + port | `host:port` clients send UDP to (must not be Cloudflare-proxied) |
| `RUGEN_DATA`       | `/data`            | directory of `rugen.db` |
| `RUST_LOG`         | `info`             | `error` … `debug` |
| `RUGEN_PKG_TTL`    | `24h`              | a package expires this long after its last use (`90m`, `2d`, seconds) |
| `RUGEN_PKG_MAX_TOTAL` | `5GB`           | all packages together; least recently used evicted above it |
| `RUGEN_PKG_MAX`    | `150MB`            | largest single package accepted |
| `RUGEN_PKG_RATE_ACCOUNT` | `1GB`        | upload bytes per account per hour |
| `RUGEN_PKG_RATE_IP` | `2GB`             | upload bytes per client IP per hour |
| `RUGEN_PKG_REPLAY_TTL` | `720`          | hours the packages of a stored ranked replay are kept |
| `RUGEN_FAIR_RATIO` | `1.6`              | power-score ratio above which a matchup is UNBALANCED |
| `RUGEN_FAIR_COMMUNITY_GAP` | `200`      | community rating gap that is UNBALANCED |
| `RUGEN_FAIR_MIN_GAMES` | `10`           | verified games before a character's community rating counts |
| `RUGEN_RESIM_DATA` | –                  | engine `data/` for re-simulating disputed matches (`--features resim`) |
| `RUGEN_RESIM_MOTIF` | `RUGEN_RESIM_DATA` | motif for re-simulation |
| `RUGEN_IMAGE`      | GHCR `latest`      | image tag used by the compose file |
| `RUGEN_HTTP_PORT`  | `8080`             | host port for HTTP (compose only) |
| `RUGEN_UDP_PORT`   | `7001`             | host port for the UDP relay (compose only) |
| `CF_TUNNEL_TOKEN`  | –                  | tunnel token, `deploy/cloudflared/` only |

## Backups

All state is one SQLite database (WAL mode) in the `rugen-data` volume.
Character packages live next to it in `packages/`; they are caches and need
no backup (size the volume for `RUGEN_PKG_MAX_TOTAL`).

```sh
# consistent online copy, from inside the container (no sqlite3 needed)
docker compose exec rugen-server /rugen-server --backup /data/backup.db
docker compose cp rugen-server:/data/backup.db ./rugen-$(date +%F).db

# or with sqlite3 on the host, against the volume directory
sqlite3 /var/lib/docker/volumes/rugen_rugen-data/_data/rugen.db ".backup rugen.db.bak"
```

Restore: stop the stack, copy the file over `rugen.db` in the volume
(delete `rugen.db-wal` / `rugen.db-shm`), start again. Schema migrations
are embedded and applied on start; a `state.json` from the old JSON store
is imported once automatically.

## Updating

Dokploy: **Redeploy** (pulls the new `latest`), or pin `RUGEN_IMAGE` to a
version tag and change it. Plain Docker:

```sh
docker compose pull && docker compose up -d
```

Releases: pushing a `v*` tag builds and pushes the image (amd64; run the
workflow manually with *arm64* ticked for ARM servers).

## Without a proxy

The compose already publishes 8080 and 7001/udp: give players
`http://your-ip:8080` and set `RUGEN_UDP_PUBLIC=your-ip:7001`. Any reverse
proxy with TLS works too; it must pass WebSocket upgrades for `/ws` and
`/relay`.

## Security notes

- **IP addresses are never shared.** Match traffic is relayed by the
  server; no API or WebSocket payload contains a client address (tests
  assert it). Client IPs are used only for rate limiting and are not
  logged at `info`.
- Relay datagrams are authenticated per session and slot with a random
  128-bit token handed out over HTTPS only to that player; a slot may move
  between UDP and WebSocket without trusting source addresses. Spectators
  can only talk to the host.
- Room passwords are hashed with Argon2id (per-room salt) and checked in
  constant time; nothing stores or returns them in clear.
- Rate limits: 120 HTTP requests / 10 s per IP, 600 relay datagrams / s per
  slot, 2000 UDP datagrams / s per source IP, bounded rooms, sessions and
  queue sizes. The container runs as non-root on a read-only root fs with
  all capabilities dropped.
- Accounts are anonymous: the key in the player's `profile.json` *is* the
  account. Keep backups of the database if rankings matter.

## Netcode

What the client does to keep online play feeling local:

- **Rollback** (ggrs) with prediction up to 8 frames; only inputs travel.
- **Adaptive input delay**: before the match, both clients measure the
  round trip to each other *through the relay* and pick
  `ceil(rtt / 2 / 16.7 ms) - 1` frames, clamped to 0-3 (0-1 on a LAN or
  in the same city, 2-3 across a continent). `[net] input_delay = n`
  forces a value; OPTIONS → ONLINE cycles AUTO / 0-8.
- **Time sync**: ggrs frame-advantage hints make the player who runs ahead
  pause a frame or two (a brief slowdown instead of large rollbacks).
- **Rollback-safe audio / effects**: sounds and announcer calls are keyed
  by (frame, event); re-simulated frames never replay or cut a sound,
  events revealed by a rollback play once, round calls (FIGHT, KO …) are
  deduplicated across a window.
- **Connection quality**: 1-4 bars and the ping in the corner of the
  match, a *CONNECTION UNSTABLE* warning on interruptions, large frame
  advantage or deep rollbacks; rooms and the queue show the estimated ping.
- **Ping-aware matchmaking**: the server measures each player's round trip
  on the lobby WebSocket; quick match / ranked pair the lowest combined
  ping first with a window widening 60 → 120 → 200 ms → any after 30 s
  (ranked also widens the Elo window). *Good connections only* caps it.
- **Shared settings**: both sides of an online match simulate with the
  same game settings (room round time / mode), whatever their local
  options say.
- **Result verification**: both clients report winner, last frame, world
  checksum and the confirmed input stream; disagreement marks the match
  *disputed* (no rating change). Ranked input streams are stored as
  replays (latest 2000). With `--features resim` the server re-simulates
  disputed matches headless and settles them (see above).
- **Same files on both sides**: the matchup syncs both fighters and the
  stage by fingerprint before the relay session exists, and both clients
  confirm the fingerprints, rules and game version they will run.
- **Spectators** join a room before the match starts and receive the host's
  confirmed inputs through the relay (ggrs spectator session).
