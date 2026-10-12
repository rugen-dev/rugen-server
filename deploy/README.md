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

This folder runs it with Docker Compose next to a Cloudflare Tunnel, which
is exactly what a Dokploy "Compose" app wants.

```
                 HTTPS (lobby, /ws presence, /relay WebSocket)
 players ──► Cloudflare edge ──► cloudflared ──► rugen-server:8080
    │                                                 ▲
    └──────────── UDP 7001 (match relay fast path) ───┘  (published port)
```

| Port      | What                                              | Through the tunnel? |
|-----------|---------------------------------------------------|---------------------|
| 8080/tcp  | HTTP API, `/ws` lobby presence, `/relay` fallback | yes (keep it private) |
| 7001/udp  | match relay, fast path                            | **no**: publish it   |

The tunnel only carries HTTP/WebSocket. Opening 7001/udp gives the lowest
latency; without it every client automatically falls back to the WebSocket
relay through the tunnel after a 1.5 s UDP probe (works everywhere, a bit
slower).

## 1. Cloudflare Tunnel

1. Cloudflare dashboard → **Zero Trust → Networks → Tunnels → Create a
   tunnel** → *Cloudflared* → name it `rugen`.
2. On the "Install connector" page pick *Docker* and copy the token after
   `--token` (a long `eyJ...` string). That is `CF_TUNNEL_TOKEN`.
3. **Public hostname** tab → add `rugen.example.com` → service type `HTTP`,
   URL `rugen-server:8080` (the compose service name; both containers share
   the `rugen` network). WebSockets are on by default.
4. Optional, for the UDP fast path: add a **DNS-only** (grey cloud) `A`
   record, e.g. `udp.example.com` → your server's public IP, and set
   `RUGEN_UDP_PUBLIC=udp.example.com:7001`. (A proxied, orange-cloud name
   cannot carry UDP.)

## 2. Dokploy

1. **Create Project → Create Service → Compose**. Source: this Git
   repository, compose path `deploy/docker-compose.yml` (or paste the file
   in the *Raw* editor).
2. **Environment** tab: paste `deploy/.env.example` and fill in at least
   `CF_TUNNEL_TOKEN` and `RUGEN_PUBLIC_URL`. Dokploy writes them to `.env`
   next to the compose file, which `env_file: .env` reads.
3. No domain needs to be configured in Dokploy (the tunnel is the ingress).
   If you prefer Dokploy's Traefik instead of the tunnel, remove the
   `cloudflared` service and add a domain pointing at `rugen-server:8080`.
4. Open **7001/udp** in the VPS firewall / security group (the compose file
   already publishes it).
5. **Deploy**. Logs should show `http + websocket on 0.0.0.0:8080` and
   `udp relay advertised as ...`; `https://rugen.example.com/health` answers
   with the server name, version and players online.

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
rugen play kfm --server https://rugen.example.com --room ABCDE      # joins
rugen play kfm --server https://rugen.example.com --room ABCDE --spectate
```

LAN / direct-IP matches (`--net ip:port`, HOST / JOIN DIRECT MATCH) still
work without any server; there the players type each other's address on
purpose.

## Environment variables

| Variable           | Default            | Meaning |
|--------------------|--------------------|---------|
| `CF_TUNNEL_TOKEN`  | –                  | cloudflared connector token (compose only) |
| `RUGEN_PUBLIC_URL` | –                  | public https URL; logged, and its host is the UDP fallback host |
| `RUGEN_NAME`       | `rugen server`     | name in the server list |
| `RUGEN_MOTD`       | empty              | message of the day |
| `RUGEN_BIND`       | `0.0.0.0:8080`     | HTTP / WebSocket listener |
| `RUGEN_UDP_BIND`   | `0.0.0.0:7001`     | UDP relay listener, `off` to disable |
| `RUGEN_UDP_PUBLIC` | public URL host + port | `host:port` clients send UDP to (must not be Cloudflare-proxied) |
| `RUGEN_DATA`       | `/data`            | directory of `rugen.db` |
| `RUST_LOG`         | `info`             | `error` … `debug` |
| `RUGEN_IMAGE`      | GHCR `latest`      | image tag used by the compose file |

## Backups

All state is one SQLite database (WAL mode) in the `rugen-data` volume.

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

## Without Cloudflare

Delete the `cloudflared` service, publish `8080:8080` as well, and give
players `http://your-ip:8080` (or put any reverse proxy with TLS in front;
it must pass WebSocket upgrades for `/ws` and `/relay`). Set
`RUGEN_UDP_PUBLIC=your-ip:7001`.

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
  replays (latest 2000). Re-simulating disputed matches on the server is
  possible later (the simulation crate has no GPU dependency) but not done.
- **Spectators** join a room before the match starts and receive the host's
  confirmed inputs through the relay (ggrs spectator session).
