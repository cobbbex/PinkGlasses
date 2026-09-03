<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/brand/lockup-dark-1880.png">
    <img src="assets/brand/lockup-light-1880.png" alt="PinkGlasses — external attack surface, continuously watched." width="620">
  </picture>
</p>

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
subdomains ─┬─────────────────┐
            └─ dns bruteforce ┴→ dns resolve ─→ [new addresses, deduped]
                                                  → port scan (batched, 64/task)
                                                         → service probe
                                                              ├─ tech detect
                                                              ├─ screenshot
                                                              └─ directory brute
```

Tools per stage (ProjectDiscovery where it fits; the worker falls back to pure-Go
implementations when a binary is absent, so it works before you install anything):

| Stage | Primary tool | Fallback |
|---|---|---|
| Subdomains | subfinder | stdlib resolver |
| DNS bruteforce | shuffledns + massdns | skipped |
| Resolution & enrichment | dnsx, Team Cymru | stdlib resolver |
| Ports & services | **nmap -sV** alone at top-100; naabu → nmap when wider | Go connect-scan |
| Tech & versions | httpx `-tech-detect`, nuclei | header/body fingerprint |
| Screenshots | httpx `-screenshot` | (needs `browser` capability) |
| Directory brute | katana, urlfinder → gobuster/ffuf | built-in common-path probe |

**DNS bruteforce is a separate task per wordlist**, so several lists spread across
workers instead of grinding through one after another. See
[Wordlists and resolvers](#wordlists-and-resolvers).

**Port scanning is batched and incremental.** Resolution feeds addresses forward as
they appear rather than waiting for every name to resolve, and each port-scan task
carries a pool of up to 64 addresses handed to nmap on stdin (`-iL -`). Both halves
matter:

- *Incremental* — a slow wordlist no longer holds back scanning of the hosts already
  found. Addresses are deduplicated as they arrive, so a shared IP behind twenty
  names is still scanned once.
- *Batched* — nmap is built to scan host groups. One address per task makes
  `--min-hostgroup` and `--min-rate` meaningless and pays process startup per host;
  a real pool makes the rate limits mean what they say.

**Only authorized targets are port-scanned.** The planner resolves each address back
to the scope target that produced it and drops the ones whose target is passive-only,
so a name discovered under passive authorization can be enumerated and resolved but
never has a packet sent to it. The scheduler log says so explicitly when it happens.

**Every resolved address carries its network provenance** — reverse DNS, AS
number, AS name and the announcing prefix. dnsx supplies PTR; the ASN details
come from Team Cymru's DNS interface, which needs no extra binary and no API key.
Enrichment runs once per unique address, not once per name.

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

A good first target is `scanme.nmap.org`, which Nmap's authors publish for exactly this
purpose. Add it as an **active** target (port scanning is refused otherwise) and a
standard run walks the whole pipeline in about a minute, ending with 22/tcp and 80/tcp
open on `45.33.32.156`.

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

## The Hosts view

Names and the machines they point at are one question in practice, so there is a
single **Hosts** page rather than separate Domains and Hosts pages. Each row is a
discovered name with the address it resolves to and that address's provenance:

| Subdomain | Address | Reverse DNS | ASN | AS name | AS range | Services |
|---|---|---|---|---|---|---|

**Names that no longer resolve are hidden by default.** Passive sources record
every name a domain has ever used — certificate transparency and passive DNS
archives go back years — and for a long-lived domain that is tens of thousands of
names, almost none of them current. They are still recorded, the count of what is
hidden is shown, and a checkbox brings them back. They are evidence of past
infrastructure, not present attack surface.

A Map toggle renders the same data as a force-directed asset graph.

**Clicking a row opens that address's own page** at `/host/<id>`, in a new tab — the
Shodan host page for your own inventory. It carries the enrichment, every name that
resolves there, each open port with what answered on it (banner, product and version,
HTTP title and status, response headers, fingerprinted technologies) and the findings
raised against the host or its services. It is a real URL, so it can be bookmarked and
shared, and it needs no company selected to open.

Services with a screenshot offer a **Screenshot** button — on the host page per service,
and in the Hosts list per row — which opens the captured page image.

**Mine / All companies.** The company picker can narrow the list to the companies
you created. "You" is whatever `X-Forwarded-User` says, or `local` — so this tidies
a shared list, it does not protect anything. Real accounts are Phase 17; until then
anyone who can reach the API can list every company by not asking for the filter.

## Wordlists and resolvers

**Wordlists** in the UI manages every list a scan needs: the subdomain wordlists
shuffledns brute-forces, the resolver lists it queries through, and the directory
wordlists gobuster brute-forces web services with. All three are the same kind of
object — a line-oriented file — so they share one registry, under three tabs.

Five lists ship as built-ins and download themselves on first boot:

| List | Kind | Size |
|---|---|---|
| assetnote `best-dns-wordlist` | subdomain | ~9.5M entries |
| assetnote `httparchive_subdomains` | subdomain | ~3.2M entries |
| SecLists `common.txt` | directory | ~4.7k entries |
| SecLists `raft-medium-directories` | directory | ~30k entries |
| trickest public resolvers | resolvers | ~12.7k entries |

Until a download finishes the entry shows as `pending` and scans skip it; a download that
fails shows the reason and is retried on every sweep, so a network blip heals itself
rather than disabling the list permanently.

**Files live in object storage, not in the worker image.** A worker downloads each
list once and caches it on disk by content hash, so the same list is never fetched
twice — and editing a list changes its hash, which is what makes workers pick up
the new version rather than serving the old one from cache.

You can **upload** your own list, mark which lists are **used by default**, and
**edit** entries in place. Editing is capped at 4 MB: resolver lists are kilobytes,
but the assetnote wordlists are hundreds of megabytes and are replaced by upload
instead.

Resolver entries are validated on save — each must be an IP, optionally with a
port — and bad lines are reported with their line numbers. A malformed resolver
otherwise degrades every brute force that uses the list with no visible error.

Every list marked default for the subdomain kind becomes **its own dns_brute task**,
so lists run in parallel across workers.

Directory search works the other way round: it uses **one** list per run, so marking
several `dir` lists default picks the first by name and the dispatch log says which. The
size of that list is the main thing deciding how loud a scan is — it is the only stage
that fires thousands of requests at a single host. A run with no `dir` list falls back to
the small list baked into the worker image.

## Watching a scan

The **Runs** table gives each run a line: when it started, what it is scanning, how far
along it is, and its status. The target cell names the first few targets and counts the
rest; the progress bar counts failed tasks as finished — the run has dealt with them —
but marks them separately, because a full bar should not hide whether everything worked.
A run's task total climbs while it is running: the planner adds stages as it discovers
work, so 5/9 can become 5/12 without anything being wrong.

Expanding a run shows, refreshed every few seconds:

- **Pipeline** — a chip per stage with done/total, a dot while work is in flight,
  and a count of failures
- **Workers on this scan** — each worker, how many tasks it is running and has
  finished, and which stages it is on
- **Activity** — running tasks first, then recently finished: stage, target,
  which worker, status, retries and elapsed time

The same story appears in the worker log:

```
tool finished  tool=subfinder args="-silent -json -d example.com -max-time 3"
               results=24948 took=1.949s ok=true
passive enumeration  domain=example.com candidates=24949
               by_source="map[seed:1 subfinder:24948]"
dns_brute finished   wordlist="best-dns-wordlist" resolvers="trickest" found=37
address enrichment   addresses=4 with_asn=4 with_ptr=0
queued port scans    addresses=2 tasks=1
tool finished  tool=nmap args="-Pn --open --min-hostgroup 64 --min-rate 10000 ...
               --top-ports 100 -sV -oG - -iL -" results=4 took=8.936s ok=true
port scan      hosts=2 with_open_ports=1 open=2 scanner=nmap ports="--top-ports 100"
```

`addresses=2 tasks=1` is the batching: both addresses went to nmap as one host group.
A tool that exits cleanly but produces nothing while writing to stderr is reported as a
failure too — naabu rejecting a flag and exiting 0 looked exactly like "found nothing"
until that check existed.

`by_source` is worth watching: it distinguishes a dead API key or a rate-limited
provider from a domain that genuinely has few names.

Set `ASM_LOG_LEVEL` to `debug` for the individual findings behind those summaries —
every candidate name, port with its product, discovered path, and each tool's
command line before it runs:

```bash
ASM_LOG_LEVEL=debug docker compose up -d worker
```

`info` (the default) is every tool invocation and stage summary; `warn` and `error`
narrow it further.

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
  perimeter only, which is also what closes the scanner-as-SSRF hole. The check runs
  twice: once on the target itself, and once on every address discovery resolves, since
  a name under an authorized target can still point at 127.0.0.1 or a cloud metadata
  address. `ASM_ALLOW_PRIVATE_TARGETS=true` lifts it for a local test target such as
  `tools/cookielab`, and must not be set on anything reachable by anyone else.
- **Cookie names are recorded; cookie values are not.** A name like `webvpn` or
  `BIGipServer...` identifies the appliance behind a port and is searchable with
  `cookie:webvpn*`; the value is a session token, so `Set-Cookie` is dropped from the
  stored headers rather than kept.
- Enrolled workers are **semi-trusted**: they only ever see their current job's targets, and
  the gateway rejects (and quarantines a worker for) any observation outside that set.
- Your VPS provider may suspend accounts over unsolicited scanning — set per-worker rate caps
  and keep an abuse-contact note. Never expose the UI to the internet; put an
  identity-aware proxy in front.

## Layout

```
cmd/         api · gateway · scheduler · worker · provisioner · migrate
internal/    domain · store · scanproto · scopeguard · planner · dispatch · ingest · diff
             search · notify · obj · audit · httpapi · agentapi · provisioner
             scanparams (the settable scan knobs) · wordlists (registry seeding)
             scanner (the pipeline)
migrations/  goose SQL
web/         Vite + React + TS SPA
deploy/      worker Dockerfile
```

## Status

Working end to end, verified against `scanme.nmap.org`: passive enumeration and DNS
brute-forcing, resolution with ASN and reverse-DNS enrichment, batched port and service
scanning, technology detection, screenshots, and directory brute-forcing — every stage
confirmed by what it stored, not just by the tool running. A scan of that host records
`OpenSSH 6.6.1p1` on 22, `Apache 2.4.7` with `Apache HTTP Server 2.4.7` and `Ubuntu` on
80, a page screenshot, and the paths its crawl and brute force found.

Supporting that: a wordlist registry for all three list kinds that workers fetch and
cache, per-worker scan visibility that survives a worker being replaced, and a per-address
page for drilling into any of it. The Go control plane and worker build and vet clean, the
test suite passes, and the SPA type-checks and builds.

The worker prefers real tools when installed and falls back to Go implementations
otherwise, so a tool can be swapped or removed behind the `scanner` package without
touching the rest of the system.

**The recurring failure mode in this project is a stage doing its work and the results
evaporating downstream**, which looks exactly like a clean "found nothing". Three checks
exist to make that visible, and each was added after it had already happened: every tool
invocation is logged with its result count and duration; a tool that exits 0 while
producing nothing and writing to stderr is reported as a failure; and a batch of results
the gateway refuses is logged by both the worker that sent it and the gateway that
rejected it, with the reason.

Deliberately deferred (see `architecture.md` §14): multi-tenancy, ClickHouse analytics,
SSH-push provisioning, worker auto-update, cloud-inventory connectors.

Known rough edges:

- Results held by a worker that is stopped mid-task are lost. The agent logs
  "spooling would retry", but no spool exists yet.
- Provisioner-created workers are not rebuilt by `docker compose up --build`, so they keep
  running an older image until removed and recreated.
- A rebuilt worker registers under a new container hostname, so the fleet list accumulates
  a `stale` row per rebuild. Harmless, but it needs a sweep by age to stay tidy.
- Wordlist downloads use the resolver a container was started with. If that resolver
  disappears — a VPN dropping is the usual cause — fetches fail until the service is
  recreated (`docker compose up -d --force-recreate scheduler`), at which point they
  retry themselves.
- Configuration keeps the `ASM_` environment-variable prefix and the `asm` database role
  from before the project was renamed, so existing `.env` files and volumes keep working.
  The compose volumes are pinned to their original `scan_tool_*` names for the same
  reason — renaming them would orphan the database.
