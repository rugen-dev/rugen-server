# Performance

## Method

`examples/loadgen.rs` (clients in `src/loadgen.rs`) simulates N rugen 0.6
clients at the real client's rates: register (2 % named / Argon2id),
profile, presence WebSocket, `GET /rooms` every 5 s; then 60 % queue
(1 s polls → matchup polls at 400 ms → a 20–40 s match → both report),
25 % host a room (1 s polls, 25 % public), 15 % idle. 30 % of matches send
60 packets/s per player over the UDP relay; 10 % of ranked matches are
disputed with 3600 frames of inputs (re-simulated, `--features resim`).
Every client has its own `CF-Connecting-IP` and its own 127.x.y.z UDP
address, so per-IP limits apply as in production.

The server ran like production: `systemd-run --user -p CPUQuota=100%
-p MemoryMax=768M -p TasksMax=256`, pinned to one physical core, fresh
data directory; the load generator on other cores. Steps of N clients
(20 s ramp, 40 s measured); a step breaks the server when errors exceed
1 % or p99 (all HTTP calls) exceeds 500 ms. Laptop (Ryzen 5 5500U) shared
with other builds: p99 near the knee varies x3–x10 between runs, so every
configuration ran 2–3 times, interleaved.

## Production host (self-benchmark, 1 CPU / 768 MB)

`play.rugen.dev`, Docker capped at `cpus: 1.0`, `mem_limit: 768m`,
`pids_limit: 256`; `POST /admin/bench` with steps 250 → 1500, 30 s hold.
The load generator shares the container, so this is a floor.

| clients | req/s | p50 ms | p99 ms | errors | CPU % | RSS MB | threads | relay pkt/s |
|---|---|---|---|---|---|---|---|---|
| 250 | 116 | 0.5 | 1.9 | 0 | 22 | 137 | 18 | 1,976 |
| 500 | 233 | 0.6 | 1.8 | 0 | 37 | 228 | 19 | 4,037 |
| 750 | 328 | 0.6 | 2.1 | 0 | 52 | 314 | 20 | 6,662 |
| 1000 | 431 | 0.7 | 2.5 | 0 | 66 | 408 | 20 | 8,892 |
| 1250 | 541 | 0.8 | 4.8 | 0 | 79 | 530 | 30 | 10,140 |

The run stopped before 1500 on the memory guard (projected 636 MB of the
614 MB allowed), not on latency or errors.

## Laptop results (one CPU, static musl build like the release image)

| | clients held | req/s | p99 ms | CPU % | RSS MB | threads | broke at |
|---|---|---|---|---|---|---|---|
| before (5912fa6) | 1000 | 412–418 | 163–393 | 78–80 | 203–208 | 38–39 | 1250 (p99 1.3 s) |
| after, without mimalloc | 1000 | 412–417 | 272–395 | 80–85 | 208–209 | 39 | 1250 (p99 0.8–0.9 s) |
| after (with mimalloc) | **1250** | 521–524 | 408–473 | 95–98 | 367–396 | 38–39 | 1500 (p99 2.1 s) |

No errors and no crash at any step: the limit is the CPU quota. At 1000
clients the CPU goes to request handling (HTTP, JSON, `expire_rooms` on
every room call, allocations), the kernel (sockets), re-simulations
(~15–25 %, now one thread at nice 10) and SQLite (~11 %). The store
changes (prepared statements, pragmas, read pool, group commit) removed
the global store lock and cut contention but SQLite was never the
bottleneck, so they barely move the knee; mimalloc does, on musl. Threads
stay at ~40 whatever the load (budget in `src/main.rs`).

Further levers, not done: cache verified packages across re-simulation
replays (sha256 + zstd per replay), expire rooms on a timer instead of on
every room call, look up only the 100 listed hosts in `GET /rooms`.

## Self-benchmark on the production host

The laptop is not the server. With `RUGEN_BENCH=1` and
`RUGEN_ADMIN_TOKEN` set, the server can benchmark itself where it runs:

```sh
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -d '{"steps":[250,500,1000,1500,2000],"hold_secs":30,"ramp_secs":10}' \
  https://your.server/admin/bench          # 202 {"id": ...}; 409 while one runs
curl -H "Authorization: Bearer $TOKEN" https://your.server/admin/bench   # status + per-step table
curl -H "Authorization: Bearer $TOKEN" https://your.server/admin/stats   # live numbers
```

A run starts a second, throw-away server inside the process (fresh store
in `RUGEN_BENCH_DIR`, default the system temp dir, never the data
directory; random 127.0.0.1 ports; no backups, official feed, TURN or
re-simulation) and loads it with the clients above, using a synthetic
fighter so matches and relay traffic happen. The load generator shares
the container's CPU quota and memory: the numbers are a lower bound.
Limits: one run at a time, 5000 clients per step, 5 minutes per run,
abort when p99 > 2 s or errors > 5 %, and never past 80 % of the
container's memory limit (a step that would need more is not started:
an OOM kill would take the real server down); the temp directory is
removed however the run ends. The bench instance has no rate limits (its
clients all come from this process); the real server's are unchanged.
Each row has the errors by kind (`e_net` / `e_5xx` / `e_429` / `e_4xx`),
a few `error_samples` and `relay_fail`.

Open files: Docker 25+ starts containers with a soft limit of 1024 open
files, about 500 players' sockets (the first production bench aborted at
500 clients on it: connections and `/proc` reads failed). The server
raises its soft limit to the hard one at startup (logged as `open files:
limit …`); `/admin/stats` shows `open_files` / `max_open_files`. A read-only container needs a writable
`RUGEN_BENCH_DIR` (e.g. `tmpfs: /tmp` in compose). Run it off-peak: it
competes with real players for the same CPU.

`GET /admin/stats` (admin token; no `RUGEN_BENCH` needed): uptime,
threads, RSS, CPU %, req/s and relay pkt/s over the last ~10 s, WebSockets,
relay sessions, store write queue, re-simulation queue.
