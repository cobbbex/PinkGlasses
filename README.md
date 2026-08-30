# Attack Surface Monitor

A self-hosted web application that discovers and continuously monitors the external attack
surface of one organization — domains, DNS, hosts, open ports, services, technologies, TLS
and findings. DNSDumpster-style discovery output; Shodan-style drill-down. Scanning runs on
a fleet of workers you own, including VPS boxes you enroll from the UI.

Design docs: [`architecture.md`](architecture.md) · [`worker-pipeline.md`](worker-pipeline.md)
· build plan: [`TODO.md`](TODO.md)

## Architecture at a glance

```
Browser ── HTTPS ──▶ api ─────┐
                              ├─▶ PostgreSQL (source of truth)
Workers ── WSS/HTTPS ─▶ gateway┘         │
   (your VPS boxes)     scheduler ◀───────┘  advances runs, reaps leases, diffs
```

- **api** — user-facing REST + SSE surface, serves the SPA.
- **gateway** — the only internet-facing service; terminates worker control channels, leases
  tasks, ingests **confined** results, presigns artifact uploads.
- **scheduler** — leader-elected loop: advances the stage machine, reaps expired leases,
  runs the differ, sweeps for stale workers / expiring certs.
- **worker** — one box carrying the whole toolchain; connects outbound only.

## Scan pipeline (per run, across many targets)

```
subdomains → dns resolve → [coalesce: dedupe IPs] → port scan → service probe
                                                         ├─ tech detect
                                                         ├─ screenshot
                                                         └─ directory brute
```

Tools per stage (ProjectDiscovery where it fits; the worker falls back to pure-Go
implementations when a binary is absent, so it works before you install anything):

| Stage | Primary tool | Fallback |
|---|---|---|
| Subdomains | subfinder, alterx, dnsx | stdlib resolver |
| Ports & services | naabu → **nmap -sV** | Go connect-scan (+ nmap when present) |
| Tech & versions | httpx `-tech-detect`, nuclei | header/body fingerprint |
| Screenshots | httpx `-screenshot` | (needs `browser` capability) |
| Directory brute | katana → ffuf/feroxbuster | built-in common-path probe |

## Run it (docker-compose)

```bash
cp .env.example .env
docker compose up --build -d      # postgres, minio, migrate, api, gateway, scheduler, worker
# UI:            http://localhost:8080
# gateway:       http://localhost:8090   (the only service you expose in production)
# MinIO console: http://localhost:9001   (minioadmin / minioadmin)
```

The bundled local worker enrols itself, is auto-approved, and appears under
**Workers → Local workers**. Add a scope, add a target, then start a scan from **Runs**.

## Stop it

```bash
docker compose down          # stop everything, KEEP scan data
docker compose down -v       # stop everything and DELETE the database + artifacts
```

`down` removes the containers but keeps the `pgdata` and `miniodata` volumes, so your
scopes, inventory and scan history survive. Add `-v` only when you want a clean slate —
it is irreversible.

Other useful forms:

```bash
docker compose stop                  # pause without removing containers (resume: start)
docker compose start                 # resume after `stop`
docker compose restart api           # restart one service
docker compose down --rmi local      # also delete the images this project built
docker compose ps                    # what is currently running
docker compose logs -f api worker    # follow logs
```

Local worker containers created from the UI are managed by the `provisioner`, not by
compose, so `docker compose down` leaves them running. Scale them to 0 in
**Workers → Add local worker** first, or remove them directly:

```bash
docker rm -f $(docker ps -aq --filter label=asm.managed=true)
```

### Workers: local or external

**Both kinds do the same job — scanning your external targets.** Internal (RFC1918)
ranges are out of scope for this product entirely and are skipped for every worker.
Kind decides only where the traffic comes from and how the worker enrols.

| | Local | External (VPS) |
|---|---|---|
| What it scans | Your external targets | Your external targets |
| Traffic leaves from | Your corporate IP | The provider's IP |
| Setup | Free, already running | A box you rent and enrol |
| Enrolment | Self-enrols, auto-approved | Installer + manual approval |

Local workers alone are a complete scanning system — the stack scans your perimeter as
soon as it is up. Add VPS workers for **egress diversity** (not every packet leaving one
corporate IP) and a **true outside-in view**: your own egress filtering and firewall
policy quietly shape what a local worker sees, so a local worker can report a service as
reachable when in fact only you can reach it.

**Add local workers** — click **Workers → Add local worker**, pick a count, apply. The
`provisioner` service creates the containers; they self-enrol over the internal network
and are auto-approved.

The button is served by an isolated `provisioner` sidecar — the **only** container with
the Docker socket. The socket is root-equivalent on the host, so it is deliberately kept
out of the `api`, which is internet-adjacent and holds your whole attack-surface map. The
provisioner speaks a fixed vocabulary (list / scale labelled worker containers) and cannot
run arbitrary Docker commands.

Prefer not to mount the socket at all? Delete the `provisioner` service from
`docker-compose.yml` — the UI then shows this command instead:

```bash
docker compose up -d --scale worker=3
```

### Managing workers

Each worker row in **Workers** offers these actions. The `i` buttons on the *Status* and
*Actions* column headers show the same summary in the UI.

| Action | Use it when |
|---|---|
| **approve** | A newly enrolled worker should start taking scan tasks. VPS workers need this; local ones are approved automatically. |
| **drain** | Planned wind-down — decommission, reboot or patch a worker. |
| **quarantine** | The worker may be compromised and must be cut off now. |
| **resume** | Return a draining or stale worker to active. |
| **remove** | Delete it from the fleet. A local worker's container is destroyed first. |

**drain vs. quarantine** — they take a worker out of service for opposite reasons, and the
difference matters:

- **drain is planned and graceful.** New leases stop, but tasks already running are allowed
  to finish and report their results. Use it to retire a VPS or reboot a host without
  breaking a scan in flight; **resume** puts it back. Without drain your only option is
  killing the worker mid-task and waiting for its lease to expire before another worker
  retries the work.
- **quarantine is unplanned and defensive.** It blocks new leases *and* refuses the control
  channel outright. Crucially it **keeps the worker record and its history**, which is the
  whole difference from removing it: every observation stores the `worker_id` that produced
  it, so after a quarantine you can find and re-verify exactly what that worker contributed
  instead of distrusting the entire inventory.

Quarantine is also applied **automatically**: if a worker reports observations for assets
outside the target it was assigned, the gateway quarantines it on the spot. Workers parse
hostile content from the internet, so one turning malicious must not be able to poison the
inventory with fabricated assets (`architecture.md` §10.3).

| | drain | quarantine |
|---|---|---|
| Reason | Routine maintenance | Suspected compromise |
| Tasks in flight | Allowed to finish | Should be cut off |
| Trust in its data | Unchanged | Suspect — re-verify what it reported |
| Triggered by | You | You, or automatically on a confinement violation |

### Add your own VPS as a worker

1. In the UI, **Workers → Add VPS worker** → copy the one-line install command.
2. Paste it on the VPS (it needs Docker). The worker connects **outbound only** — no inbound
   ports, works behind NAT.
3. Approve the new worker in **Workers**.

The install token is single-use and expires in 1 hour; the worker's long-lived credential is
minted on enrollment and never leaves the box. See `scripts/install.sh`.

## Develop

Backend (Go 1.23):

```bash
make build            # builds api, gateway, scheduler, worker, migrate into ./bin
make migrate          # apply DB migrations (needs ASM_DATABASE_URL)
./bin/api             # :8080
./bin/gateway         # :8090
./bin/scheduler
go test ./... && go vet ./...
```

Frontend (Node 20):

```bash
cd web
npm install
npm run dev           # :5173, proxies /api to :8080
npm run build         # emits web/dist, served by the api binary
```

## Passive discovery API keys

Passive enumeration finds subdomains without sending a single packet to the target, and
it gets substantially better with API keys. Copy `.env.example` to `.env` and fill in
whichever you have — **every one is optional**, and blanks are skipped:

```
DNSDUMPSTER_API_KEY=      SHODAN_API_KEY=          CENSYS_API_ID= / _SECRET=
SECURITYTRAILS_API_KEY=   VIRUSTOTAL_API_KEY=      NETLAS_API_KEY=
ZOOMEYE_API_KEY=          QUAKE_API_KEY=           FOFA_EMAIL= / FOFA_API_KEY=
HUNTER_API_KEY=           BINARYEDGE_API_KEY=      LEAKIX_API_KEY=
WHOISXMLAPI_API_KEY=      BEVIGIL_API_KEY=         INTELX_HOST= / INTELX_API_KEY=
CHAOS_API_KEY=            GITHUB_TOKEN=
```

Compose passes them to the worker, which renders subfinder's `provider-config.yaml` from
them at startup. Keys live only in `.env` (git-ignored) and on the worker — they are never
stored in the database or shown in the UI.

> Wiring these into subfinder is TODO 13.0.4 — the variables are defined and delivered to
> the worker, but nothing reads them yet.

## Safety & authorization

This tool sends packets to real infrastructure. Read `architecture.md` §10 first.

- A target is **passive-only** unless it carries an explicit **active** authorization record.
- CDN / shared-hosting IPs are excluded from port scanning by default.
- RFC1918 / loopback targets are always rejected — this tool scans the external
  perimeter only, which is also what closes the scanner-as-SSRF hole.
- Enrolled workers are **semi-trusted**: they only ever see their current job's targets, and
  the gateway rejects (and quarantines a worker for) any observation outside that set.
- Your VPS provider may suspend accounts over unsolicited scanning — set per-worker rate caps
  and keep an abuse-contact note. Never expose the UI to the internet; put an
  identity-aware proxy in front.

## Layout

```
cmd/         api · gateway · scheduler · worker · migrate
internal/    domain · store · scanproto · scopeguard · planner · dispatch · ingest · diff
             search · notify · obj · audit · httpapi · agentapi · scanner (the pipeline)
migrations/  goose SQL
web/         Vite + React + TS SPA
deploy/      worker Dockerfile
```

## Status

First working cut. The Go control plane and worker build and vet clean; the SPA type-checks
and builds. Deliberately deferred (see `architecture.md` §14): multi-tenancy, ClickHouse
analytics, SSH-push provisioning, worker auto-update, cloud-inventory connectors. The worker
prefers real tools when installed and falls back to Go implementations otherwise, so the
`naabu`/`nmap`/`nuclei`/etc. libraries can be swapped in behind the `scanner` package without
touching the rest of the system.
