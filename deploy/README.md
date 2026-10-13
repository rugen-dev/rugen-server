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
- **official or community**: the server holding the official signing key is
  *the* official server (global ranking, global cheat blocklist); every
  other server is a community server that pulls and enforces the official
  blocklist (see [Official server](#official-server))

`deploy/docker-compose.yml` runs only `rugen-server` and publishes its two
ports. HTTPS in front is your choice: Dokploy's domains (Traefik), any
reverse proxy, or the optional Cloudflare Tunnel add-on in
`deploy/cloudflared/` (a separate compose).

| Port      | What                                              | Notes |
|-----------|---------------------------------------------------|-------|
| 8080/tcp  | HTTP API, `/ws` lobby presence, `/relay` fallback | put HTTPS in front |
| 7001/udp  | match relay, fast path                            | open it in the firewall |

Without 7001/udp reachable, clients fall back to the WebSocket relay on
8080 after a 1.5 s UDP probe (works everywhere, a bit slower). With
`RUGEN_UDP_PUBLIC=off` the server binds and advertises no UDP relay at all
and clients use the WebSocket at once. Host ports can be changed with
`RUGEN_HTTP_PORT` / `RUGEN_UDP_PORT`.

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

### Tunnel-only (no open ports)

If a Cloudflare Tunnel (or Zero Trust) is the only way in, use
`deploy/docker-compose.tunnel.yml` as the compose path instead. It publishes
no ports, turns the UDP relay off (`RUGEN_UDP_BIND=off`,
`RUGEN_UDP_PUBLIC=off`: nothing bound, nothing advertised; matches use the
WebSocket relay through the tunnel with no UDP probe delay), joins
`dokploy-network` so a cloudflared container there reaches it as
`http://rugen-server:8080`, and builds the image on the host from this
repository, so no registry login is needed. Set the Watch Paths to
`deploy/**`, `src/**`, `Cargo.toml` and `Cargo.lock` to redeploy on server
changes. This is the profile of the official server below.

### Official server

The official server (`https://play.rugen.dev`, the address baked into the
game) is **never exposed directly**: no `ports:`, no UDP, no DNS record
pointing at the VPS. Everything goes through the Cloudflare Tunnel, which
cannot carry raw UDP from players, so it runs WebSocket-relay only
(sockets use `TCP_NODELAY`; relayed frames are sent one by one, unbatched).

1. Compose path `deploy/docker-compose.tunnel.yml` (above). It already has
   no port mappings and sets `RUGEN_UDP_BIND=off` / `RUGEN_UDP_PUBLIC=off`.
2. The cloudflared add-on is **required** (tunnel container on
   `dokploy-network`). Public hostname: `play.rugen.dev` → service `HTTP`,
   URL `http://rugen-server:8080`; WebSockets enabled (Network settings),
   no caching for this hostname.
3. Environment tab:
   - `RUGEN_SIGNING_KEY` = the **seed** from `rugen-server --gen-key`
     (secret; it is what makes this server official),
   - `RUGEN_ADMIN_TOKEN` = a long random string (moderation API),
   - `RUGEN_PUBLIC_URL=https://play.rugen.dev`, `RUGEN_NAME=rugen official`,
     `RUGEN_MOTD=...`.
4. Deploy. The log must say `OFFICIAL server: signing key xxxx:xxxx:...`;
   `https://play.rugen.dev/health` shows `"official":true`, a `key` equal to
   the public key baked into the game, and `"transports":[{"kind":"ws",...}]`
   with no UDP entry.

Community hosts are free to keep the UDP fast path (section 2, step 4).

On a host shared with other apps it stays out of the way: at most
`RUGEN_CPUS` (1.0) CPUs and `RUGEN_MEM` (768m) of memory, a quarter of the
default CPU weight and a low disk-I/O weight (so other containers win under
contention), first in line for the OOM killer, 3 × 10 MB of logs, and
character packages capped at 2 GB on disk and 500 MB/h per account. The one
heavy moment is the Rust build on each deploy (a few CPU-minutes); to avoid it,
pull the prebuilt GHCR image instead (registry login in Dokploy) or deploy
less often (Trigger Type: manual).

## 2. Optional: Cloudflare Tunnel (separate compose)

1. Cloudflare dashboard → **Zero Trust → Networks → Tunnels → Create a
   tunnel** → *Cloudflared*. Copy the token after `--token` (`eyJ...`).
2. **Public hostname**: `rugen.example.com` → service `HTTP`, URL
   `rugen-server:8080`.
3. In Dokploy create a **second** Compose service with compose path
   `deploy/cloudflared/docker-compose.yml`, set `CF_TUNNEL_TOKEN` in its
   Environment tab and deploy it after the server (it joins the server's
   `rugen` network; no ports needed).
4. Community servers only: for the UDP fast path add a **DNS-only** (grey
   cloud) record such as `udp.example.com` → the server's public IP and set
   `RUGEN_UDP_PUBLIC=udp.example.com:7001` on the server (a proxied name
   cannot carry UDP). With the tunnel you may also drop the `8080` port
   mapping from the server compose. (The official server stays
   tunnel-only, see above.)

The image is pulled from `ghcr.io/rugen-dev/rugen-server:latest`
(published by `.github/workflows/server-image.yml` on `v*` tags). To build
on the server instead, uncomment the `build:` block in the compose file
(and drop `image:` or point `RUGEN_IMAGE` at a local tag).

## 2b. Optional: Cloudflare Realtime TURN (real UDP behind a tunnel)

Behind a Cloudflare Tunnel (no open ports) matches use the WebSocket relay,
which works everywhere but rides TCP through the tunnel twice. With
**Cloudflare Realtime TURN** the server hands each player a short-lived TURN
credential and the two clients relay their match datagrams through
Cloudflare's anycast TURN servers over **UDP** instead (TCP / TLS 443 when UDP
is blocked). The server still signals and verifies, but never sees the match
packets, and nobody learns an IP address: each player only learns the other's
*relayed* address, which belongs to Cloudflare. If TURN does not work for a
player the match silently stays on the server relay (the clients wait at most
1.5 s for it).

### Set it up

1. Cloudflare dashboard → **Realtime** (formerly *Calls*) → **TURN Server**
   → **Create** (name it e.g. `rugen`). Copy the **Turn Token ID** and the
   **API Token** shown once.
2. Dokploy → your rugen-server compose → **Environment** tab, add:

   ```env
   RUGEN_CF_TURN_KEY_ID=<Turn Token ID>
   RUGEN_CF_TURN_TOKEN=<API Token>
   ```

   and **Redeploy**. The log shows `turn: Cloudflare TURN on (key abc123…),
   2026-10: 0.00 of 500 GB used`; `/health` gains a `turn` object (month,
   `used_gb`, `cap_gb`, `issuing`, `ranked_only`, `matches`).
3. Optional, recommended: let the server cross-check its own count with
   Cloudflare's analytics. **My Profile → API Tokens → Create Token →
   Custom**, permission *Account → Account Analytics → Read* for your account,
   then add `RUGEN_CF_ACCOUNT_ID=<account id>` (dashboard URL / overview
   sidebar) and `RUGEN_CF_ANALYTICS_TOKEN=<that token>`. Every 15 minutes the
   server reads this month's TURN bytes for its key and counts whichever is
   higher, its estimate or Cloudflare's number.

The secrets are only read from the environment and never logged. Nothing else
changes: no ports, the tunnel stays the only way in (the TURN traffic goes
from the players to Cloudflare, not to your server).

### Never pay: the budget

Cloudflare bills Realtime (SFU + TURN together) by **egress, $0.05 per GB,
with the first 1,000 GB each month free**
([pricing](https://developers.cloudflare.com/realtime/pricing/)). The server
keeps TURN far below that with a hard monthly cap, tracked per **UTC calendar
month** in SQLite (survives restarts):

- Each credential **reserves** `ttl × RUGEN_TURN_RATE_ESTIMATE × 2 directions
  × RUGEN_TURN_SAFETY` bytes when it is handed out (both directions are
  counted although Cloudflare only bills egress). The TTL is the longest the
  match can last with its rules (every round to the time limit + 25 s,
  infinite rounds count as 4 min, + 90 s), at most `RUGEN_TURN_TTL_MAX`; a
  rematch gets fresh credentials.
- When the credential ends (the player reported the result, the relay
  session closed, or the TTL passed) the reservation is **settled** to
  `max(bytes the client reported × safety, a quarter of the reservation)`.
  Clients report their TURN byte counters in relay keep-alives and in the
  result.
- `used = max(estimate, client reports, Cloudflare analytics)`. At
  `RUGEN_TURN_SOFT_PERCENT` (80 %) of `RUGEN_TURN_BUDGET_GB` only ranked
  matches still get TURN (and a warning is logged); at the cap no credential
  is issued until the month rolls over, so matches use the WebSocket relay.
- Per credential: one per player per match, never for spectators, revoked at
  Cloudflare as soon as it is no longer needed, and revoked early if its
  reported traffic passes `ttl × rate × 8` (a ceiling far above a real match).
  Cloudflare itself stops a credential at its TTL.
- Per account / per client IP: at most `RUGEN_TURN_MAX_MATCHES_PER_HOUR` /
  `_PER_DAY` (12 / 60) and `..._HOUR_IP` / `..._DAY_IP` (24 / 120) TURN
  matches.

The math with the defaults (500 GB cap = half the free tier, rules 2 rounds
to win / 99 s, so ttl = 3 × 124 + 90 = 462 s):

| | per player | per match (2 players) |
|---|---|---|
| reserved at start: 462 s × 8,000 B/s × 2 × 2.0 | 14.8 MB | 29.6 MB |
| settled floor (a quarter) | 3.7 MB | 7.4 MB |
| measured real traffic, 99-second match, both directions | ≈ 0.7 MB | ≈ 1.4 MB |

So the cap is reached after at most 500 GB / 29.6 MB ≈ **16,900 matches in
flight**, and after about 500 GB / 7.4 MB ≈ **67,500 settled matches** a month
— while those matches really move only ≈ 95 GB through Cloudflare. Even a
month where every one of those matches never reported back stays at 500 GB,
half the free 1,000 GB. Raising `RUGEN_TURN_BUDGET_GB` above 1000 logs a
warning; keep it at or below 1000 and the free tier cannot be exceeded by
rugen (other Realtime / SFU use on the same account shares the allowance).

## 3. Players

The official server is built into the game and always listed first. A
community server is added with **ONLINE → ADD SERVER** →
`https://rugen.example.com` (REMOVE SERVER takes it out again), or in
`rugen.toml`:

```toml
[net]
server = "https://rugen.example.com"     # default selection ("" = the official server)
servers = ["https://rugen.example.com", "203.0.113.5:8080"]   # community servers
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
4. From pick time each client uploads its content file (the character's
   `.rgc` or the stage's `.rgs`: sprites pixel-exact, sounds as Opus,
   about 20 MB for a big character) **if the server does not already hold
   that fingerprint**, resumably, in 2 MB chunks. The server opens it in
   place (nothing is unpacked), recomputes fingerprint and profile from its
   content, and fails the match (and flags the account) when they differ
   from what the client claimed. Fingerprints (`rugen-fp-2`) hash the
   gameplay text, the palettes and the decoded sprites, not the sounds or
   the container, so the same character has the same fingerprint on every
   machine.
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
`packages/<fingerprint>.rgc` (stages: `.rgs`, rugen 0.5 packages: `.rgpk`)
from the data volume; the server drops its record on the next sweep), and
do not run a public server if you cannot answer takedown requests.

### Re-simulating disputed matches

Built with `--features resim` (`cargo build --release
--features resim`, or `docker build --build-arg FEATURES=resim ...`) and
given the engine data (`RUGEN_RESIM_DATA=/path/to/data`, the folder with
`common1.cns` / `fight.def`), the server re-plays a disputed match from
both input streams with the stored packages, headless, and settles the
result when one report matches the simulation. Matches between two rugen
0.5 players (RGPK packages, see below) are not re-simulated: this engine
is not theirs, so a disputed one settles as an unresolved dispute.

### rugen 0.5 and 0.6 players on one server

Since rugen 0.6 (lobby API 5) fighters travel as `.rgc` / `.rgs` with
`rugen-fp-2` fingerprints; rugen 0.5 (API 4) uploads RGPK packages with
`rugen-fp-1` fingerprints. This server serves both, so updating the server
never locks 0.5 players out:

- 0.6 clients send `X-Rugen-Api: 5` on every request; a request without
  it is a 0.5 client. `/health` says `api: 5` and `api_min: 4` (0.5
  clients ignore `api`; 0.6 clients refuse servers that serve API 4 only).
- Players of different versions can never share fighters, so they never
  meet: the queue pairs equal versions only; a room keeps its host's
  version and refuses players and spectators of the other one
  (`THIS ROOM'S HOST RUNS AN OLDER RUGEN (0.5). BOTH PLAYERS NEED THE SAME
  VERSION.` / `... A NEWER RUGEN (0.6). UPDATE YOUR GAME TO JOIN.`). The
  lobby lists every public room with its `api`; 0.5 clients see rooms of
  0.6 hosts last, named `[0.6] ...`.
- Uploads are verified in the uploader's format (0.5: unpacked into
  scratch space, `rugen-fp-1`; 0.6: opened in place, `rugen-fp-2`) and a
  package is only handed to a client of its own generation.
- Accounts, ratings, seasons, results, TURN and signatures are shared.
  Character ratings and the blocklist stay keyed by fingerprint, and the
  two generations fingerprint the same character differently: a block of
  a 0.5 fingerprint does not cover its `.rgc`. Block it again by the 0.6
  fingerprint (the official feed simply carries both kinds; each client
  only ever matches its own).

LAN / direct-IP matches (`--net ip:port`, HOST / JOIN DIRECT MATCH) still
work without any server; there the players type each other's address on
purpose.

## Official server

### Official or community

Every server signs with an Ed25519 key:

1. `RUGEN_SIGNING_KEY`: the 32-byte seed, 64 hex digits (or base64),
2. else `RUGEN_SIGNING_KEY_FILE`: a file holding it (Docker secrets),
3. else `<data>/signing.key`, generated on first start (mode 0600).

A server whose public key equals the **official public key** (baked into
the engine at build time, `RUGEN_OFFICIAL_KEY` overrides it here) is the
official server; every other server is a community server. Players' games
only call a server OFFICIAL after it signed a random nonce with that key, so
a community server can never pass as the official one.

Generate the official key pair once:

```sh
rugen-server --gen-key
# private: the official server only (secret env / file, never commit)
RUGEN_SIGNING_KEY=5f0c...
# public: bake into game builds and pass to community servers if needed
RUGEN_OFFICIAL_KEY=9a41...
```

The seed goes into the official server's secret environment; the public key
becomes the `RUGEN_OFFICIAL_KEY` repository variable of the engine (release
builds bake it in, see the engine's BUILDING.md). Until then everything uses
a development key whose seed is public: fine for testing, worthless for
trust. A server started with it logs a warning.

### Truth feed

`GET /v1/truth` returns this server's signed feed:

```json
{"purpose":"truth","key":"<public key hex>","sig":"<signature hex>",
 "payload":"{\"blocked\":[{\"fingerprint\":\"b960...\",\"reason\":\"...\",\"since\":1791830134,\"source\":\"admin\"}],\"expires_at\":...,\"issued_at\":...,\"ratings\":[{\"fingerprint\":\"...\",\"games\":40,\"rating\":1520,\"wins\":22}],\"sequence\":1791830134,\"server\":\"rugen official\",\"v\":1}"}
```

- `payload` is the statement as **canonical JSON** (keys sorted by bytes,
  no whitespace, integers only, serde_json string escaping); the Ed25519
  signature covers `rugen-signed-v1\n<purpose>\n<payload>`. Verifiers check
  the signature over the received bytes and that the payload is canonical.
- `issued_at` / `expires_at`: a feed is valid for 3 days (at most 7 are ever
  accepted); `sequence` grows with every blocklist change (at least the
  Unix time of the change) and nobody accepts a lower one than they hold.
- Only the official server's feed counts. **Community servers** pull it from
  `RUGEN_OFFICIAL_URL` (default `https://play.rugen.dev`, `off` disables)
  every `RUGEN_OFFICIAL_PULL` seconds, verify it against the official key,
  keep it in `<data>/official_truth.json`, mirror it at
  `GET /v1/truth/official`, and enforce it: a blocked fingerprint makes the
  matchup **BLOCKED** with the reason `blocked by the official server (...)`.
  Their own blocklist applies on top (`blocked by this server`). Official
  community ratings refine verdicts when they rest on more games.
- Games download the feed from the official server (or a community mirror),
  cache it, and mark blocked fighters in their roster and matchup cards.

### Signed verdicts and results

Matchup views carry `signed` (a `verdict` statement: match id, ranked,
fingerprints, verdict, reasons) and settled results carry `signed` (a
`result` statement: match id, account, players, winner, rating, delta,
season). `GET /match/{id}/result?key=` returns the signed result to the
player who reported first. `GET /v1/identity?nonce=<hex>` signs a client's
challenge. Games show OFFICIAL stamps only for the official key, community
servers with their key fingerprint, and reject forged signatures.

### Moderation

With `RUGEN_ADMIN_TOKEN` set:

```sh
curl -X POST https://play.rugen.dev/v1/admin/block \
  -d '{"token":"...","fingerprint":"<64 hex>","reason":"infinite regen"}'
curl -X POST https://play.rugen.dev/v1/admin/unblock \
  -d '{"token":"...","fingerprint":"<64 hex>"}'
curl 'https://play.rugen.dev/v1/admin/blocklist?token=...'
```

or on the host, against the same database (also while the server runs):

```sh
docker exec rugen-server /rugen-server --data /data --block <fp> --reason "infinite regen"
docker exec rugen-server /rugen-server --data /data --unblock <fp>
docker exec rugen-server /rugen-server --data /data --blocklist
```

Live matchups are judged again at once.

**Password resets.** Named accounts have no e-mail, so the operator is the
only way back in for a player who lost their password:

```sh
curl -X POST https://play.rugen.dev/v1/admin/reset_password \
  -d '{"token":"...","username":"axel"}'        # → {"username","password"}
docker exec rugen-server /rugen-server --data /data --reset-password axel
```

Both set a random temporary password, log the account out on every device
and print the password once (it is never logged). Hand it over privately
and have the player change it from PROFILE → CHANGE PASSWORD. Check who is
asking first: the username is public.

Automatic entries (`source: auto`):

- the server's own analysis of an uploaded package finds a block-level
  cheat (`RUGEN_AUTO_BLOCK_ANALYSIS`, on),
- `RUGEN_AUTO_BLOCK_LIARS` (3) different players were caught declaring a
  false fairness profile for the same fingerprint,
- the fingerprint took part in `RUGEN_AUTO_BLOCK_DESYNCS` (10) matches with
  a reported desync.

Unblocking keeps the fingerprint as *cleared*: automatic rules never block
it again (the operator still can). Restoring an older database backup
lowers the feed sequence; the next blocklist change publishes a newer one
again (it is at least the current Unix time).

## Environment variables

| Variable           | Default            | Meaning |
|--------------------|--------------------|---------|
| `RUGEN_PUBLIC_URL` | –                  | public https URL; logged, and its host is the UDP fallback host |
| `RUGEN_NAME`       | `rugen server`     | name in the server list |
| `RUGEN_MOTD`       | empty              | message of the day |
| `RUGEN_BIND`       | `0.0.0.0:8080`     | HTTP / WebSocket listener |
| `RUGEN_UDP_BIND`   | `0.0.0.0:7001`     | UDP relay listener, `off` to disable |
| `RUGEN_UDP_PUBLIC` | public URL host + port | `host:port` clients send UDP to (must not be Cloudflare-proxied); `off` = no UDP relay at all |
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
| `RUGEN_SIGNING_KEY` | generated `signing.key` | this server's Ed25519 seed; the official key makes it official (secret) |
| `RUGEN_SIGNING_KEY_FILE` | – | file holding the seed instead |
| `RUGEN_OFFICIAL_KEY` | baked into the build | public key whose signatures / feed are official |
| `RUGEN_OFFICIAL_URL` | `https://play.rugen.dev` | where community servers pull the official feed, `off` disables |
| `RUGEN_OFFICIAL_PULL` | `900` | seconds between feed pulls |
| `RUGEN_ADMIN_TOKEN` | – | enables `/v1/admin/*` |
| `RUGEN_AUTO_BLOCK_LIARS` | `3` | players lying about a fingerprint before it is blocked (0 = off) |
| `RUGEN_AUTO_BLOCK_DESYNCS` | `10` | desynced matches before a fingerprint is blocked (0 = off) |
| `RUGEN_AUTO_BLOCK_ANALYSIS` | `on` | block fingerprints the server's analysis flags as cheats |
| `RUGEN_IMAGE`      | GHCR `latest`      | image tag used by the compose file |
| `RUGEN_HTTP_PORT`  | `8080`             | host port for HTTP (compose only) |
| `RUGEN_UDP_PORT`   | `7001`             | host port for the UDP relay (compose only) |
| `CF_TUNNEL_TOKEN`  | –                  | tunnel token, `deploy/cloudflared/` only |
| `RUGEN_CF_TURN_KEY_ID` | –              | Cloudflare Realtime TURN key id (TURN is off without it) |
| `RUGEN_CF_TURN_TOKEN` | –               | that key's API token (secret) |
| `RUGEN_CF_ACCOUNT_ID` | –               | optional: account id for the usage cross-check |
| `RUGEN_CF_ANALYTICS_TOKEN` | –          | optional: API token with *Account Analytics: Read* |
| `RUGEN_TURN_BUDGET_GB` | `500`          | hard monthly TURN cap (decimal GB; free tier is 1000) |
| `RUGEN_TURN_SOFT_PERCENT` | `80`        | above this share of the cap only ranked matches get TURN |
| `RUGEN_TURN_MAX_MATCHES_PER_HOUR` / `_PER_DAY` | `12` / `60` | TURN matches per account |
| `RUGEN_TURN_MAX_MATCHES_PER_HOUR_IP` / `_PER_DAY_IP` | `24` / `120` | TURN matches per client IP |
| `RUGEN_TURN_RATE_ESTIMATE` | `8000`     | budgeted bytes / s per player and direction (measured ≈ 3,500) |
| `RUGEN_TURN_SAFETY` | `2.0`             | factor on estimates and client reports |
| `RUGEN_TURN_TTL_MAX` | `1800`           | longest credential in seconds |
| `RUGEN_WORKERS`    | CPU quota / cores  | async worker threads; default = the container's CPU quota (cgroup `cpu.max`, i.e. `cpus:`), else the cores; at least 2 |
| `RUGEN_RATE_ACCOUNT` | `120`            | API calls per account (its key) per 10 s |
| `RUGEN_RATE_IP`    | `2000`             | API calls per client IP per 10 s, all accounts together (abuse ceiling; mobile carriers put many players behind one IP) |
| `RUGEN_RATE_ANON`  | `300`              | calls without a key per client IP per 10 s |
| `RUGEN_RATE_REGISTER` | `30`            | registrations, logins and other `POST /v1/account/*` calls per client IP per minute |
| `RUGEN_RATE_RELAY` | `300`              | `/relay` WebSocket upgrades per client IP per 10 s (not charged to the API budgets) |
| `RUGEN_HIGH_PING_MS` | `200`            | queue pairs estimated above this round trip are flagged `high_ping` |
| `RUGEN_RATE_ADMIN` | `30`               | `/v1/admin/*` calls per client IP per minute |
| `RUGEN_BACKUP_S3`  | –                  | S3-compatible bucket for daily backups, `s3://KEY:SECRET@HOST/BUCKET[/prefix][?region=…]` (secret; see Backups) |
| `RUGEN_BACKUP_RETENTION_DAYS` | `7`     | days backups are kept (any whole number ≥ 1; the newest is always kept) |
| `RUGEN_BACKUP_INCLUDE` | –              | extras in backups: `packages`, `signing-key` (comma-separated) |

## Backups

All state is one SQLite database (WAL mode) in the `rugen-data` volume.
Character packages live next to it in `packages/`; they are caches that
players upload again on demand.

### Off-site: any S3-compatible bucket (daily, automatic)

Create a bucket and an API key that can **read, write, list and delete
objects in that bucket only**, then set one variable (Dokploy: Environment
tab, it is a secret):

```sh
# Cloudflare R2 (free tier: 10 GB, no egress fees)
RUGEN_BACKUP_S3=s3://ACCESS_KEY_ID:SECRET_ACCESS_KEY@<accountid>.r2.cloudflarestorage.com/rugen-backups?region=auto
# AWS S3
RUGEN_BACKUP_S3=s3://AKIA...:SECRET@s3.eu-west-1.amazonaws.com/rugen-backups?region=eu-west-1
# MinIO on the LAN, plain HTTP, with a key prefix
RUGEN_BACKUP_S3=s3+http://minio:minio-secret@minio.lan:9000/rugen/play-rugen-dev
```

Backblaze B2 (`s3.<region>.backblazeb2.com`) and Wasabi
(`s3.<region>.wasabisys.com`) work the same way. Path-style addressing is
used; add `style=virtual` (`?region=x&style=virtual`) for stores that only
take `bucket.host`. **Percent-encode** `/ + @ : ? %` in the key or secret
(`/` → `%2F`, `+` → `%2B`).

- One backup a day at **03:00 UTC**. After a restart (every deploy), the
  bucket is listed: if the newest backup is older than 24 h one runs 5
  minutes after boot, otherwise the next 03:00 is waited for. Never more
  than one automatic backup a day; a failed one is retried once an hour later.
- `RUGEN_BACKUP_RETENTION_DAYS` (7): after each backup, backups older than
  this are deleted; the newest one always stays. Only objects named
  `rugen-backup-*` (and `packages/`) under the prefix are ever touched.
- What a backup is: a consistent snapshot of `rugen.db` (`VACUUM INTO`
  on a second connection: the server keeps serving), zstd-compressed and
  streamed up, plus a manifest with sha256 sums, sizes and the schema
  version:
  `<prefix>/rugen-backup-YYYYMMDDTHHMMSSZ-<version>.db.zst` + `.json`.
- Not included unless asked for with `RUGEN_BACKUP_INCLUDE`:
  - `packages`: uploaded incrementally to `<prefix>/packages/` (a package
    already in the bucket is not sent again); can be gigabytes.
  - `signing-key`: `<data>/signing.key`, the generated key of a community
    server. **Risk:** anyone who can read the bucket can then sign as your
    server. The official key normally comes from `RUGEN_SIGNING_KEY` and is
    never in the data directory: keep it in your secret store instead.
- Invalid settings are logged at start (credentials redacted) and shown on
  `/health`; the server runs without backups.
- Light by design: one copy buffer of memory for any size, streaming zstd
  level 3, no extra process.

Admin API (with `RUGEN_ADMIN_TOKEN`, as `Authorization: Bearer <token>`,
`?token=` or `{"token": …}`):

```sh
curl -X POST -H "Authorization: Bearer $TOKEN" https://play.example.com/v1/admin/backup        # 202 {job}; 409 running; 429 (1 per 10 min)
curl -H "Authorization: Bearer $TOKEN" https://play.example.com/v1/admin/backups               # key, time, size of each backup
curl -H "Authorization: Bearer $TOKEN" https://play.example.com/v1/admin/backup/status
```

`GET /health` carries a `backup` object without endpoint, bucket or keys:
`configured`, `status` (`off` / `misconfigured` / `ok` / `failing`),
`provider` (`r2` / `aws` / `other`), `retention_days`, `last_success`,
`last_error`, `last_size_bytes`, `next_at`, `running`.

One-off from the shell: `rugen-server --backup-now`.

### Restore

The server must be **stopped** (Dokploy: Stop). Then, on the host, run the
image once against the volume (enter the URL without leaving it in the shell
history):

```sh
read -rs RUGEN_BACKUP_S3 && export RUGEN_BACKUP_S3
docker run --rm -e RUGEN_BACKUP_S3 -v rugen_rugen-data:/data rugen-server:local --restore latest
# or a given backup: --restore rugen-backup-20261013T030000Z-0.6.0  (a name or key from GET /v1/admin/backups)
```

It downloads the backup, checks the sha256 sums from the manifest and
SQLite's integrity check, then swaps it in: the old database stays as
`rugen.db.<time>.bak` (with its `-wal` / `-shm`). A backed-up signing key
and packages are restored too (the old key is kept as `.bak`). Start the
server again; schema migrations of newer versions apply on start.

### Local copy

```sh
# consistent online copy, from inside the container (no sqlite3 needed)
docker compose exec rugen-server /rugen-server --backup /data/backup.db
docker compose cp rugen-server:/data/backup.db ./rugen-$(date +%F).db
```

Restore by hand: stop the stack, copy the file over `rugen.db` in the
volume (delete `rugen.db-wal` / `rugen.db-shm`), start again. A
`state.json` from the old JSON store is imported once automatically.

## Updating

Dokploy: **Redeploy** (pulls the new `latest`), or pin `RUGEN_IMAGE` to a
version tag and change it. Plain Docker:

```sh
docker compose pull && docker compose up -d
```

Releases: pushing a `v*` tag builds and pushes the image (amd64; run the
workflow manually with *arm64* ticked for ARM servers).

Packages already on the data volume keep working across an update: the
RGPK packages of rugen 0.5 players (`packages/*.rgpk`) are still served to
0.5 clients, new 0.6 uploads land next to them as `.rgc` / `.rgs`.

## Without a proxy

The compose already publishes 8080 and 7001/udp: give players
`http://your-ip:8080` and set `RUGEN_UDP_PUBLIC=your-ip:7001`. Any reverse
proxy with TLS works too; it must pass WebSocket upgrades for `/ws` and
`/relay`.

## Security notes

- **IP addresses are never shared.** Match traffic is relayed by the
  server (or by Cloudflare TURN, where each player only learns the other's
  Cloudflare relayed address); no API or WebSocket payload contains a client
  address (tests assert it). Client IPs are used only for rate limiting and are not
  logged at `info`.
- Relay datagrams are authenticated per session and slot with a random
  128-bit token handed out over HTTPS only to that player; a slot may move
  between UDP and WebSocket without trusting source addresses. Spectators
  can only talk to the host.
- Room passwords are hashed with Argon2id (per-room salt) and checked in
  constant time; nothing stores or returns them in clear.
- Rate limits: 120 API calls / 10 s per account, with a 2000 / 10 s ceiling
  per IP (players behind carrier NAT share addresses), 300 / 10 s per IP for
  calls without a key, 30 registrations / min per IP, 300 `/relay` upgrades /
  10 s per IP, 600 relay datagrams / s per slot, 2000 UDP datagrams / s per
  source IP, bounded rooms, sessions, queue sizes and per-connection relay
  queues (256 frames; overflow is dropped like lost UDP and counted in
  `/health` → `relay.queue_drops`). The container runs as non-root on a read-only root fs with
  all capabilities dropped.
- Accounts: rugen 0.6 players create a **named account** (unique username,
  3-16 letters / digits / `_` / `-`, case-insensitive; reserved names like
  `admin`, `rugen`, `official` refused) with a password of 6-128
  characters. Passwords are hashed with Argon2id (19 MiB, 2 passes, 1
  lane, per-hash salt; ≈ 22 ms on one core, at most two hashes at once),
  only ever travel inside the HTTPS body and are never logged. Failed
  logins: 5 free tries per username and 20 per IP, then a lockout of 30 s
  doubling with every failure (15 min at most); every refusal reads
  `WRONG USERNAME OR PASSWORD`. Logging in returns an account key like
  before (stored as a SHA-256 hash, up to 10 devices per account); changing
  the password or LOG OUT EVERYWHERE revokes the others. Anonymous accounts
  (rugen 0.5 players, and 0.6 players who have not claimed theirs yet) still
  work: their key in `profile.json` *is* the account, and they can claim it
  (pick a username + password) without losing id, rating or history.
  Usernames carry a `verified` flag in every profile so the game shows a
  badge; free-form names of anonymous accounts can never equal a username.
  Keep backups of the database if rankings matter.

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
  on the lobby WebSocket; quick match / ranked take the lowest estimated
  ping pairs of the whole queue first with a window widening
  80 → 150 → 250 ms → any after 30 s (ranked also widens the Elo window).
  *Good connections only* caps it. Pairs estimated above
  `RUGEN_HIGH_PING_MS` (200) carry `high_ping: true` so the client shows
  the ping on the confirm screen, where both players accept anyway.
- **Shared settings**: both sides of an online match simulate with the
  same game settings (room round time / mode), whatever their local
  options say.
- **Result verification**: both clients report winner, last frame, world
  checksum, a world checksum every 60 frames and the confirmed input stream
  (run-length encoded for TURN-capable servers); disagreement on the frames
  both confirmed marks the match *disputed* (no rating change). This does
  not need the server to see the match traffic, so it covers TURN matches. Ranked input streams are stored as
  replays (latest 2000). With `--features resim` the server re-simulates
  disputed matches headless and settles them (see above).
- **Same files on both sides**: the matchup syncs both fighters and the
  stage by fingerprint before the relay session exists, and both clients
  confirm the fingerprints, rules and game version they will run.
- **Spectators** join a room before the match starts and receive the host's
  confirmed inputs through the relay (ggrs spectator session).
- **Transports**: tickets list the relay transports in order of preference
  (`udp` when the server has a public UDP relay, then the `ws` `/relay`
  WebSocket; unknown kinds are skipped by clients, so new ones can be added
  without breaking older games). Both ends of the WebSocket relay disable
  Nagle (`TCP_NODELAY`): on loopback two frames each way per round went
  from an 82 ms median to 0.5 ms.
