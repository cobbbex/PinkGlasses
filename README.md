<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/brand/lockup-dark-1880.png">
    <img src="assets/brand/lockup-light-1880.png" alt="PinkGlasses — external attack surface, continuously watched." width="620">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/cobbbex/PinkGlasses/actions/workflows/ci.yml"><img src="https://github.com/cobbbex/PinkGlasses/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

A self-hosted web application that discovers and continuously monitors the external attack
surface of one organization — domains, DNS, hosts, open ports, services, technologies, TLS
and findings. DNSDumpster-style discovery output; Shodan-style drill-down. Scanning runs on
a fleet of workers you own, including VPS boxes you enroll from the UI.

<p align="center">
  <img src="assets/screenshots/hosts.png"
       alt="The Hosts view: every name and address discovered for one company, enriched with reverse DNS, ASN, AS name and announced prefix."
       width="900">
</p>
<p align="center">
  <sub>The Hosts view — every name and address found for one company, with reverse DNS,
  ASN and announced prefix. Non-resolving names are folded away by default; here 24,947
  of them.</sub>
</p>

Design docs: [Architecture](wiki/Architecture.md) · [Worker pipeline](wiki/Worker-Pipeline.md) · [wiki](wiki/Home.md)
· API reference: [`wiki/API.md`](wiki/API.md) · OpenAPI: [`docs/openapi.yaml`](docs/openapi.yaml)
· build plan: [`TODO.md`](TODO.md)

## Architecture at a glance

```
 Browser ──HTTPS──▶ api ──────────────────────────┐
                    │ SSE ◀── LISTEN/NOTIFY ◀──────┤
                                                   ▼
 VPS workers ──WSS──▶ gateway ──ingest──▶ PostgreSQL ◀──▶ scheduler
   (optional exit)      │                (source of truth)    │ starts runs (button or schedule),
                        │ presigned                            │ advances the stage machine,
                        ▼ uploads                              │ diffs, alerts, sweeps
                      MinIO ◀── screenshots, wordlists         │
                                                               ▼
 standing local worker ──WSS──▶ gateway                  provisioner ── the only holder of
   (passive stages only)                                      │           the Docker socket
                                                              ▼ per active run
                                                    ┌──────────────────────┐
                                                    │ vpn-gateway (tunnel) │
                                                    │  └ run workers ×N    │──WSS──▶ gateway
                                                    │    share its network │
                                                    └──────────────────────┘
                                                      built at start, destroyed at the end
```

- **api** — the REST + SSE surface and the SPA. Writes go to PostgreSQL; changes made by
  any process reach open browsers through Postgres `LISTEN/NOTIFY`, so the api never has
  to be told what the scheduler or gateway did.
- **gateway** — the only internet-facing service. Terminates every worker's control
  channel, hands out task leases, ingests **confined** results (nothing a worker sends is
  trusted as markup or as an instruction), and presigns artifact uploads to MinIO.
- **scheduler** — the leader-elected loop. Starts runs a person or a schedule asked for,
  advances the stage machine, asks the provisioner for a run's fleet and tears it down,
  reaps expired leases, runs the differ and alert digests, sweeps stale workers and
  zombie runs.
- **provisioner** — a sidecar that alone holds the Docker socket, deliberately kept out of
  the api and the scheduler. It speaks a fixed vocabulary — build, list, remove labelled
  containers — so a bug in the api cannot become root on the host.
- **workers** — the same agent in three places. The **standing local worker** ships with
  the stack and runs only the passive stages (discovery, resolution, enrichment), which
  talk to public sources and never to the target. An **active run gets its own fleet**: a
  VPN gateway holding the tunnel plus N workers in its network namespace, built when the
  run starts and destroyed when it ends, so everything sent at the target leaves through
  the VPN. **VPS workers** you enrol are the alternative exit, leaving from their own
  addresses. Nothing active ever leaves from the control plane's own address.
- **PostgreSQL** is the source of truth; **MinIO** holds screenshots, wordlists and raw
  artifacts. **migrate** runs the schema forward once at start, and every other service
  waits for it.

The full design is in the wiki: [Architecture](wiki/Architecture.md) for the components
and their contracts, [Worker pipeline](wiki/Worker-Pipeline.md) for the tools each stage
runs, [Where scans run from](wiki/VPN-Scanning.md) for the exits and fleets, and
[Workers and containers](wiki/Workers-and-Containers.md) for a step-by-step picture of a
scan going through the VPN.

## Scan pipeline (per run, across many targets)

```
subdomains ─┬─────────────────┐
            └─ dns bruteforce ┴→ dns resolve ─→ [new addresses, deduped]
                                                  → port scan (batched, 64/task)
                                                         → service probe
                                                              ├─ tech detect
                                                              ├─ screenshot
                                                              ├─ directory brute
                                                              └─ vulnerability check
```

Tools per stage (ProjectDiscovery where it fits; the worker falls back to pure-Go
implementations when a binary is absent, so it works before you install anything):

| Stage | Primary tool | Fallback |
|---|---|---|
| Subdomains | subfinder | stdlib resolver |
| DNS bruteforce | shuffledns + massdns | skipped |
| Resolution & enrichment | dnsx, Team Cymru; a wildcard probe per apex | stdlib resolver |
| Ports & services | **nmap -sV** alone at top-100; naabu → nmap when wider | Go connect-scan |
| Tech & versions | httpx `-tech-detect`, cookie names | header/body fingerprint |
| Screenshots | httpx `-screenshot` | (needs `browser` capability) |
| Directory brute | katana, urlfinder → gobuster/ffuf | built-in common-path probe |
| Vulnerabilities | nuclei, default templates, severity low and up | skipped |

The directory stage is two tools behind one switch each. **Directory brute force** is the
wordlist; **Web crawling** is katana. With only the brute force off the stage still runs,
quietly, and reports the paths the crawl found. With both off no `dir_brute` task is
planned and the stage does not appear on the run. **Vulnerability checks** off likewise
plans no `vuln_check` task.

**Web stages ask for each site by name.** One address often serves many names, and a
server answers a request that carries no name with its default block — for nginx that
is typically a bare 403. So once the probe has found a live port, the planner makes one
target per name that resolves to that address, each carrying the name as SNI and Host
header, and tech detection, screenshots, the directory stage and the vulnerability check run
per name. What each name serves is stored under that name: the Hosts table shows the
screenshot of the row's own name, and a host page lists *Sites on this port* with each
name's status, title, cookies and headers. An address nothing resolves to is probed as
itself. *Virtual hosts per address* under Customize scanning caps the fan-out (default
20, shortest names first) so a wildcard-ish address with hundreds of names does not
multiply the loudest stages by hundreds.

**Every live web endpoint gets a nuclei pass.** Once the service probe has found what
answers HTTP on a host, `vuln_check` runs nuclei against each endpoint with its default
template set, at severity *low* and above by default — *Minimum severity* under
Customize scanning changes that per run, and `nuclei_enabled` turns the stage off. Each
match becomes a finding of kind `nuclei:<template-id>` with the template's severity and
the matched URL, so it shows on the Findings page and the host page with the same dot
history as every other finding. nuclei fetches its templates on a worker's first run;
to pin a revision or ship your own set, point `ASM_NUCLEI_TEMPLATES` at a directory
inside the worker container and it is passed as `-t`. That reaches the standing worker
service; the workers a run builds for itself start from the worker image and fetch the
default templates on first use, which is part of why the first nuclei task of a fleet
takes minutes.

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
**Workers → Local workers**. Add a company, add a group of targets on the **Dashboard**,
then **Runs → + New scan** and tick which groups the scan covers.

A good first target is `scanme.nmap.org`, which Nmap's authors publish for exactly this
purpose. Add it as an **active** target (port scanning is refused otherwise) and a
standard run walks the whole pipeline in about a minute, ending with 22/tcp and 80/tcp
open on `45.33.32.156`.

### Signing in

The first boot creates one administrator, **`admin`**, with a password it
generates and prints **once**, in the api log:

```
docker compose logs api | grep "default administrator"
  WARN created the default administrator account — this password is printed ONCE … username=admin password=Xk3…
```

Copy it, sign in, and change it under **password** at the foot of the sidebar —
the UI carries a banner until you do, and the api says so at every start. The
password appears nowhere else and is never printed again.

To choose it yourself instead, set this before first boot:

```bash
ASM_DEFAULT_ADMIN_PASSWORD=$(openssl rand -base64 24)
```

Or set it to `-` to create no account at all, in which case the first visit asks
you to create an administrator.

The account is only ever created on an empty database, so deleting or renaming
it is permanent — as is losing the password. If you lock yourself out,
`go run ./tools/pwhash 'new password'` prints a hash you can write straight into
`app_user.password_hash`.

## Run it from the published images

Every push to `main` publishes two images to the GitHub Container Registry, listed under
the repository's **Packages**: `ghcr.io/cobbbex/pinkglasses` (the control plane — api,
gateway, scheduler, provisioner and migrate are one image, chosen by entrypoint) and
`ghcr.io/cobbbex/pinkglasses-worker` (the scanning agent with its tools). A tag `v1.2.3`
also publishes `1.2.3`, `1.2` and `1`; every push publishes `sha-<short>`.

To run without building anything, add the override file:

```bash
docker compose -f docker-compose.yml -f docker-compose.ghcr.yml pull
docker compose -f docker-compose.yml -f docker-compose.ghcr.yml up -d
```

`PINKGLASSES_IMAGE_TAG` in `.env` pins a version (default `latest`). The override also
points the provisioner at the published worker image, so a run's own workers come from it
too. The first publish creates each package **private**; to let others pull without a
token, open the package on GitHub → *Package settings* → *Change visibility* → Public,
once per image. The packages link to this repository through the image source label.

## Upgrade it

```bash
git pull && docker compose up --build -d        # built locally
docker compose -f docker-compose.yml -f docker-compose.ghcr.yml pull && \
docker compose -f docker-compose.yml -f docker-compose.ghcr.yml up -d   # published images
```

`migrate` runs first and applies any new schema; the standing worker reconnects on its
own. The web page tells browsers to revalidate the app shell on every load, so an open tab
picks up the new build on its next reload — no hard refresh needed. (Builds before
2026-09-18 sent no cache headers; a browser that last loaded one of those may keep its old
copy until you reload with the cache bypassed, `Ctrl+Shift+R`, once.)

**Workers**, **Wordlists** and **Accounts** belong to the install, not to a company, and
show before any company exists — so a fresh deployment can be checked from those pages
before anything is added.

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

A run's own workers and VPN gateway are created by the `provisioner`, not by compose,
and are destroyed when the run ends. `docker compose down` while a run is going leaves
them until the scheduler comes back and sweeps them; to remove them by hand:

```bash
docker rm -f $(docker ps -aq --filter label=asm.managed=true)
```

### Workers: local or external

Every worker is the same agent; what differs is where it runs and what it is for.

| | Local | External (VPS) |
|---|---|---|
| Where it runs | A container beside the control plane | A box you rent and enrol |
| What it does | Passive stages on the standing worker; active stages on a run's own fleet behind a VPN | Active stages, as a run's chosen remote exit |
| Traffic leaves from | Third-party APIs from your address (passive); the VPN's address (active) | The provider's IP |
| How it appears | Automatically: the standing worker enrols itself, a run's fleet is built and destroyed with the run | Installer + manual approval under **Workers → Add VPS worker** |

Nothing local is created by hand. The `worker` service in docker-compose is the standing
worker: it runs the passive stages (subfinder, DNS brute force, resolution, enrichment)
and never touches a target. When you start an active scan from local workers, the
scheduler asks the `provisioner` for a VPN gateway and a fleet of workers sized from the
run's targets — one, plus one per CIDR /24-equivalent or per five targets, at most four —
unless you set a number under Customize scanning; they scan through the tunnel and are
removed when the run ends. Every run's workers share one tunnel and one target, so more
of them adds noise and RAM, not speed, which is why the count is not a decision the
dialog asks you to make. The
standing local pool is never offered as an exit, so no active scan can leave from this
host's own address.

The `provisioner` is an isolated sidecar — the **only** container with the Docker
socket. The socket is root-equivalent on the host, so it is deliberately kept out of the
`api`, which is internet-adjacent and holds your whole attack-surface map, and out of the
`scheduler`, which merely asks for fleets. The provisioner speaks a fixed vocabulary
(build, list and remove labelled containers) and cannot run arbitrary Docker commands.
Without it, scanning from local workers is refused with that reason, and remote workers
remain the way to scan.

If passive discovery ever queues behind a busy standing worker — many companies scanning
at once, or very large brute-force lists — add capacity with compose; each extra replica
enrols itself:

```bash
docker compose up -d --scale worker=3
```

**Run fleets on the Workers page.** While an active scan runs from local workers, the
Workers page shows its fleet under *Run fleets*: the VPN gateway with the tunnel's state,
the VPN configuration it uses and the exit address the target sees, and the workers beside
it by name. The gateway never enrols — it only holds the tunnel — so it is not a worker and
this is the one place it appears; its workers also show under *Local workers* while the run
lasts. Fleets that ended in the last day stay listed as *destroyed*, with the address they
had, so what a run did with its containers can be read after the fact.

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
inventory with fabricated assets ([Architecture](wiki/Architecture.md) §10.4).

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

## Accounts and access

A fresh install starts with one account, `admin`, whose password is generated at
first boot and printed once in the api log — see [Signing in](#signing-in). Change
it on first sign-in; the UI nags until you do. Every endpoint
requires a signed-in session or an API token.

### Roles

Three, and each adds to the one below it:

| Role | Can |
|---|---|
| **viewer** | Read everything — inventory, findings, runs, search. Change nothing. |
| **operator** | Also add companies and targets, edit wordlists and alerts, and **start scans**. |
| **admin** | Also manage accounts and API tokens, enrol and scale workers, and add VPN configurations. |

Starting a scan is what separates viewer from operator, because a scan sends
packets at somebody's infrastructure. Adding a VPN configuration or enrolling a
worker is admin, because both hand out credentials.

Manage accounts under **Accounts** in the sidebar (administrators only). You can
change a username there; history stays attached to the account rather than to the
name, so renaming loses nothing (if an identity proxy is in front, change what it
sends to match). Disabling an account is reversible and keeps its history;
removing one is not. Either takes
effect immediately — changing a role, disabling an account or setting a new
password signs that person out everywhere on their next request.

The last enabled administrator cannot be demoted, disabled or deleted. Promote
someone else first; otherwise the only way back in is `psql`.

### API tokens

For scripts and CI, so automating something does not mean sharing a password.
Create one under **Accounts → API tokens**, then:

```bash
curl -H "Authorization: Bearer pgt_…" http://localhost:8080/api/v1/scopes
```

The secret is shown **once**, at creation — only a hash is stored, so it cannot
be retrieved later. Lose it and you revoke it and make another. A token may be
narrower than the person who created it, never wider: an admin can mint a
read-only token for a dashboard, and a viewer cannot mint an admin token.
Revoking one, or disabling its owner, stops it working immediately.

### Passwords

Minimum 12 characters, and that is the only rule — length is worth more than
punctuation, and composition rules mostly produce `Password1!`. They are stored
as argon2id.

Sign-in is rate limited to 10 attempts per 15 minutes, counted per username *and*
per source address. An unknown username takes the same time and gives the same
answer as a wrong password, so the login form does not tell you who has an
account.

### Putting an identity proxy in front

If you already run oauth2-proxy, Authelia or Cloudflare Access, the app can take
its word for who you are — but only if the proxy proves it is the proxy:

```bash
ASM_TRUSTED_PROXY_SECRET=$(openssl rand -base64 32)   # on the api
```

Then have the proxy send `X-Forwarded-User: <username>` **and**
`X-Proxy-Secret: <that value>`. The account still has to exist here, with a role;
the proxy says *who*, PinkGlasses says *what they may do*. Create the account
under Accounts with no password — it will only ever sign in through the proxy.

Leave the variable unset and header authentication is off. `X-Forwarded-User` on
its own is refused and logged, because it is just a request header: before this
existed, anything that could reach the API could set it and be anyone.

## Where scans run from

Every scan has two kinds of work, and they leave your network by different doors.

**Passive stages** — subdomain discovery, DNS, enrichment — talk to third-party
sources with your API keys and never send a packet at the target. They always
run on the standing local workers. Set `ASM_PASSIVE_PROXY` (http or socks5) to
put one hop in front of them; DNS stages speak UDP and cannot use it.

**Active stages** — port scan through vulnerability check — send traffic at the
target, so the launch dialog asks where they should leave from. Two choices:

| Exit | What runs the scan | Leaves from |
|---|---|---|
| **Local workers behind a VPN** | containers created for this run, sharing a gateway container's network namespace | the VPN's address |
| **Remote workers** | a pool of workers you enrolled — a VPS | those workers' addresses |

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/diagrams/scan-fork-dark.svg">
  <img src="assets/diagrams/scan-fork.svg" alt="One run's tasks fork by stage class: passive stages to the standing local pool, active stages to the run's exit pool; a worker leases a task only when the pools match." width="960">
</picture>

There is deliberately no "from this host". **Local requires a VPN configuration**;
a company with none cannot start a local active scan, and the dialog says so. A
**passive** scan needs no exit at all.

```
vpn gateway ──── tun0, default route ──── the internet
     ▲
     └── network namespace shared by ──── run worker 0, run worker 1, …
                                          (nmap, chromium, nuclei, gobuster)
```

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/diagrams/scan-exits-dark.svg">
  <img src="assets/diagrams/scan-exits.svg" alt="The two exits side by side: local is a gateway container holding the tunnel with the run's workers sharing its network namespace; remote is an existing pool of enrolled workers." width="960">
</picture>

Three things follow from that shape, and they are the reasons for it:

- **The workers never hold `NET_ADMIN` or `/dev/net/tun`.** The container running
  scanners over hostile output is the one most likely to be exploited; it should
  hold the least. Sharing a namespace gives it the tunnel's routing and none of
  its capability.
- **A worker cannot exist outside the tunnel.** Workers start only after the
  gateway is healthy, and it is healthy only once its public address has actually
  changed. If the tunnel never comes up, the run fails with the gateway's own
  error rather than quietly scanning from your address.
- **No other worker can take the run's active work.** Routing is per task and the
  lease is strict: a run's active tasks are leased only by its own fleet or its
  chosen remote pool, and a fleet worker cannot pick up anyone else's.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/diagrams/scan-timeline-dark.svg">
  <img src="assets/diagrams/scan-timeline.svg" alt="Timeline of a local run: passive stages start at once on the standing pool while the fleet is requested, built, runs the active stages, and is torn down." width="960">
</picture>

Up to 8 workers per local run; at most 3 runs hold their own containers at once
(`ASM_MAX_RUN_FLEETS`). A run over that limit waits — its discovery runs meanwhile
— and starts when a slot frees. The run view says why it is waiting.

### If a VPN does not come up

The run fails with the gateway's own output:

| Message | Cause |
|---|---|
| `the VPN gateway did not report a working tunnel within 90s` | Endpoint unreachable, or wrong credentials |
| `…stopped before its tunnel came up: …` | openvpn's or wg's own error — read it literally |
| `the VPN configuration could not be decrypted` | `ASM_SECRET_KEY` differs from the one it was stored under |
| `the provisioner is unreachable` | Provisioner settings missing on the **scheduler** |
| `this run's own workers stopped reporting for 2m0s` | The tunnel dropped mid-scan |

A WireGuard config whose `AllowedIPs` carries no default route is rejected at
upload. Config bodies are sealed with AES-256-GCM at rest, never returned by any
endpoint, never logged.

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

**Deleting a company.** An administrator can delete the selected company from the company
picker (*Delete <name>…* at the foot of the list). The dialog counts what goes — target
groups and entries, the whole inventory of names, hosts and services with its history, every
run with its tasks and observations, screenshots, findings, schedules, VPN configurations and
alert channels — asks for the name to be typed back, and refuses while a run of the company
is still going. Workers, wordlists and accounts are not the company's and stay.

**Mine / All companies.** The company picker can narrow the list to the companies
you created. "You" is whatever `X-Forwarded-User` says, or `local` — so this tidies
a shared list, it does not protect anything. Real accounts are Phase 17; until then
anyone who can reach the API can list every company by not asking for the filter.


**Seen.** The last column is when that name was last seen resolving to that
address, with the time; hover it for when the pair was first seen. It is the
pair's timestamps, not the name's or the address's alone — a name that moves
between two addresses shows a different date on each row.

**History, per address.** Open a host and each name resolving to it carries a
row of dots, one per completed run that resolved the name: filled where it
pointed at this address, hollow where it pointed elsewhere. Hover a dot for the
date. Under a name that has pointed at other addresses, `also →` lists them, so
a move is visible from either side. Each open port carries the same strip, one
dot per run that port-scanned the address: filled where the port was open,
hollow where the scan ran and did not find it — which is how a port that closed
and came back shows the gap that *first seen / last seen* alone cannot.

Resolution history starts at migration 00023 and port history at 00016; runs
before those looked but left no per-run record, and are left out rather than
read as "did not find".

## Search

The Dashboard's **Services** number is a shortcut here: it opens Search with `product:*`
already run, so the summary below shows every service the company exposes, by product,
port and technology, in one click.

**Search** is a Shodan-style query bar over the inventory of one company, or with
**Global search** over every company at once. Terms are `field:value` joined with
`AND` / `OR`; free text searches banners, titles and products. Fields: `port`, `proto`,
`ip`, `domain`, `site` (the virtual host a row is about), `country`, `cloud`, `asn`,
`product`, `version`, `tech`, `cookie`, `status`, `title`, `cert.expires`, `new`,
`severity` and, globally, `company`. Numeric fields take `>=` and friends.

`*` is a wildcard anywhere in a value: `product:nginx*`, `title:*login*`. `field:*` means
the field has a value, so `product:*` is every port whose product is known. A bare `*`
matches everything, which is how to read the whole inventory.

**Results are one row per site.** A port that serves several names is listed once per
name, with the *Site* column saying which one the row is about, because a shared address
answers differently per name; a row marked *by address* is what the port serves when
asked with no name. Above the rows, a **summary** says what the query matched in
aggregate — how many services across how many sites, and the products, ports,
technologies, titles and HTTP statuses behind them, each with a count. Click any value to
narrow the query by it: `*` → click *nginx* → click *443* is a three-click answer to "which
nginx ports do we expose on 443, and what do they say".

## Finding history

Scanning the same host again does not overwrite what the last scan knew. Every run
that *could* have seen a finding — one that executed the stage which produces its
kind against that host — records whether it did, and a finding's presence is
computed from that record rather than set by hand:

- **active** — the latest run that looked for it found it;
- **gone since \<date\>** — a later run looked and did not find it.

Each row on the **Findings** page says where it was found: the **Host** it was observed
under (or *by address* when the request carried no name), the **IP**, which opens the
host page, and for a discovered path the **Status** it answered with — that, rather than
a presence badge, is what a path is about; a finding that has gone says so in the same
cell. Every finding that is a URL has an **Open** link, and every column sorts. The
Search table sorts the same way.

The Findings page and each host page show this as a **dot-strip**: one dot per run,
oldest on the left, filled when that run observed the finding and hollow when it
looked and did not. Hovering a dot shows the date and time of that run and the
severity it reported, so a gap or a severity change is readable in place. "Seen
7/8" beside it is the same thing as a number.

Presence is judged only against runs that actually looked. A passive scan never
probes for paths, so a path it did not report has not gone anywhere; without that
rule every passive scan would mark the whole inventory as vanished.

The differ records `finding_gone` and `finding_returned` alongside `new_finding`.
The one worth an alert is `finding_returned` — a new finding is noise until triaged,
but something that was gone and is back is a regression.

## Alerts

**Alerts** is where a company's changes get sent. Add a channel — a Slack incoming
webhook or any URL that accepts JSON — and tick which changes it should hear about:
finding returned, new finding, finding gone, new open port, new subdomain, plus a
minimum severity that applies to findings. When a scan finishes, one digest per
channel goes out listing the changes it asked for, regressions first, capped so a
first scan of a big domain is a count rather than four thousand lines.

Every attempt is recorded under **Recent deliveries** with its outcome. A destination
returning 404 for a month is a row that says so, not a silence you discover when
someone asks why nobody heard about the open RDP port. **Send test** posts a sample
digest so a destination can be checked before anything real changes.

A Slack webhook URL is a bearer token; the API returns it masked and never logs it.

## Wordlists and resolvers

**Wordlists** in the UI manages every list a scan needs: the subdomain wordlists
shuffledns brute-forces, the resolver lists it queries through, and the directory
wordlists gobuster brute-forces web services with. All three are the same kind of
object — a line-oriented file — so they share one registry, under three tabs.

Five lists ship as built-ins and are ready seconds after first boot:

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

**The shipped lists come with the deployment.** They are fetched once when the
control-plane image is built and carried inside it, gzip-compressed; at first start the
scheduler loads them from there into object storage in seconds, with no internet needed
at runtime, and they appear under **Wordlists** as ready for every user of the install.
A list the image lacks falls back to its source URL.

**Files live in object storage, not in the worker image, and no scan downloads one.** When the standing
worker starts it asks the gateway for every ready list and caches each on disk by
content hash, in a volume that a run's own workers mount too — so by the time anyone
scans, every list is already on disk, and a worker behind a VPN or on a VPS never has
to reach the object store: it asks the gateway, which it can reach by definition, and
only for a list it does not already have. Editing a list changes its hash, which is
what makes workers pick up the new version rather than serving the old one from cache.

You can **upload** your own list, mark which lists are **used by default**, and
**edit** entries in place. Editing is capped at 4 MB: resolver lists are kilobytes,
but the assetnote wordlists are hundreds of megabytes and are replaced by upload
instead.

Resolver entries are validated on save — each must be an IP, optionally with a
port — and bad lines are reported with their line numbers. A malformed resolver
otherwise degrades every brute force that uses the list with no visible error.

Every list marked default for the subdomain kind becomes **its own dns_brute task**,
so lists run in parallel across workers.

Directory brute force works the other way round: it uses **one** list per run, so marking
several `dir` lists default picks the first by name and the dispatch log says which. The
size of that list is the main thing deciding how loud a scan is — it is the only stage
that fires thousands of requests at a single host. A run with no `dir` list falls back to
the small list baked into the worker image.

## Scheduled scans

**Targets come in groups, and the Dashboard owns them.** *+ Add targets* takes a name and a
list of domains, IPs or CIDRs one per line, with optional tags and the active-scanning
authorization, and makes one entry of it: a group. The Dashboard lists groups; expand one
to see its entries. *Edit* is the same form and changes the group as one thing — rename it,
change its list (entries taken off it are removed, new lines added), its tags, tick or
untick the authorization for every entry, recorded with your name and the time. *Remove*
drops the group and its entries. What earlier scans discovered under them stays in the
inventory whatever you change. The same entry may sit in several groups; a scan covers it
once, and it counts as authorized if any of its groups authorizes it (and as excluded if
any excludes it). Anything added through the plain targets API without a group becomes a
group of its own, named after itself.

**Runs → + New scan → When.** The same dialog starts a scan now, once at a time
you pick, or on a repeat — and whatever it runs carries the targets, profile, exit
and customized settings chosen in that dialog. *What to scan* lists the company's
target groups with a checkbox each, all on by default — nothing about the groups is
edited here; that is the Dashboard. A schedule remembers the groups it was given and
expands them when each run starts, so editing a group later changes what its scheduled
runs cover; one left at "every group" also picks up groups added later. *Now* is a run. *Once* is a single
run started for you at that time (overnight, after a maintenance window). *Repeat*
offers hourly, daily, weekly, every 30 or 90 days, yearly, or a custom number of
hours, with the first run within a minute or at a time you set.

Scheduled scans are listed under the runs table, where they are paused, resumed
and removed. Four behaviours are worth knowing:

- **A schedule starts a run through the same code the button does**, so it is
  refused for exactly the same reasons — VPN configuration removed, pool emptied,
  no targets. The refusal is shown in the schedule's row as *did not start*, with
  the sentence, and a repeating schedule tries again next cadence. A broken
  schedule is visible, not silent.
- **A company with a run still going is skipped, never stacked.** The slot is
  re-checked five minutes later; a slow run is not treated as a broken schedule.
- **The cadence does not drift.** The next time is computed from the planned
  time, not from when the run actually started. Yearly is a plain 365 days.
- **A one-off does its job and stops.** Once it has started its run it disables
  itself and shows *ran*; the row stays as the record of what was asked for.

Runs a schedule started carry a **scheduled** label in the run list. History —
finding, resolution and port dots, the differ, alert digests — is what recurring
scans are for: it only accumulates if scans recur.

## Watching a scan

The **Runs** table gives each run a line: when it started, what it is scanning, how far
along it is, and its status. The target cell names the first few targets and counts the
rest; the progress bar counts failed tasks as finished — the run has dealt with them —
but marks them separately, because a full bar should not hide whether everything worked.
A run's task total climbs while it is running: the planner adds stages as it discovers
work, so 5/9 can become 5/12 without anything being wrong.

**Stop, pause, resume, rerun.** Each row offers what fits its state. *Pause* holds a
running scan: no further task is handed to any worker, the tasks already in flight finish
and report, and the run's own workers and VPN gateway stay up so *Resume* continues at
once. *Stop* ends it; unfinished tasks are cancelled and the run's containers come down.
A finished, failed or stopped run offers *Delete*, which removes it with everything it
recorded — tasks, per-host observations, screenshots, and the history dots it contributed;
hosts and findings other runs also saw stay. A run still going must be stopped first. It
also offers *Rerun*: a new run with the same profile,
settings, wordlists and exit, through the same checks as a fresh start — so a rerun whose
VPN configuration has since been removed is refused with that reason rather than started
from somewhere else. A paused run still counts as "going" for a schedule, which skips its
slot rather than stacking a second run.

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

### If a run does not move

A run that says *running* while its progress bar stays put is waiting for a worker,
not for a tool. Expand it: **Activity** shows every task in flight with its worker
and elapsed time, so an empty running list with pending tasks means nobody has leased
them. The scheduler says why, once tasks have waited two minutes:

```bash
docker compose logs -f scheduler
  WARN tasks pending with no active worker able to lease them run=… stage=port_scan
       tasks=6 pool=none waiting_since=…
```

`pool=none` means the tasks were planned without an exit and no worker will ever match
them (a bug, fixed 2026-09-19 — a rerun clears it). A pool id with no worker in it means
the run's own fleet never came up or died: `docker ps --filter label=asm.managed=true`
lists the run's containers, `docker logs <container>` shows a worker enrolling, its
control channel coming up, and the wordlists it cached, or the VPN gateway waiting for
its tunnel. A fleet worker that logs `control channel up` and then nothing is healthy
and idle — the problem is upstream of it. The scheduler's own log covers the rest:
`run fleet up` when the containers are ready, `reaped expired leases` when a worker died
mid-task, and `advance` errors when planning failed.

The same picture from the database, for a run id:

```bash
docker compose exec postgres psql -U asm -d asm -c \
  "select stage, status, pool_id, worker_name, attempts, left(error,80)
     from scan_task where run_id='<run id>' order by created_at"
```

## MCP server

An AI client — Claude Code, Claude Desktop, anything that speaks the Model Context
Protocol — can do what the web UI does through the built-in MCP server: read the
inventory and findings, manage target groups, start, watch, pause, stop and rerun
scans, keep schedules. It is a thin adapter over the HTTP API, authenticated with a
PinkGlasses API token, so every rule the UI obeys applies unchanged and every action is
audited under that account; a viewer token gives a read-only server. Destructive tools
require `confirm: true`; credentials (workers, VPN bodies, accounts, tokens) are not
exposed. Run it over stdio from the published image, or as the `mcp` compose profile
over HTTP. See the wiki page [MCP server](wiki/MCP.md).

## Develop

**The wiki is mirrored from `wiki/`.** The pages under `wiki/` are the GitHub wiki: `Home.md`
is its front page and links are by page name. A workflow copies the directory to the wiki
on every push to `main` that touches it — after the wiki has been created once in the
browser (repository → *Wiki* → *Create the first page*), since GitHub only makes the wiki
repository exist then. Edit the pages here, not in the wiki, or the next sync overwrites
the change.

**CI runs the same checks on every push and pull request** (`.github/workflows/ci.yml`):
gofmt, `go vet`, `go test -race` including the drift tests, the OpenAPI document against
the router, the SPA build, the control-plane image build and the compose file; the worker
image builds on pushes to `main`. Run them locally before pushing:

```bash
gofmt -l . && go vet ./... && go test -race -short ./...
go run ./tools/openapi | diff -u docs/openapi.yaml -
(cd web && npm ci && npm run build)
docker compose config -q && docker build .
```

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

Where to get each key, in the order of `.env.example`, is on the wiki page
[Passive discovery sources](wiki/Passive-Sources.md).

Passive enumeration finds subdomains without sending a single packet at the
target, and it gets substantially better with API keys. `.env.example` lists
**every source subfinder accepts a credential for** — 40 of them, grouped by what
they are. Copy it to `.env` and paste in whichever you have; every one is
optional and blanks are skipped.

```
# Certificate transparency and DNS history
CERTSPOTTER_API_KEY=   DNSDB_API_KEY=       DNSDUMPSTER_API_KEY=  DNSREPO_API_KEY=
MERKLEMAP_API_KEY=     SECURITYTRAILS_API_KEY=  WHOISXMLAPI_API_KEY=

# Internet-wide scan indexes
CENSYS_API_ID= / _SECRET=   FOFA_EMAIL= / FOFA_API_KEY=   FULLHUNT_API_KEY=
NETLAS_API_KEY=   ONYPHE_API_KEY=   QUAKE_API_KEY=   SHODAN_API_KEY=   ZOOMEYE_API_KEY=

# Threat intelligence and reputation
ALIENVAULT_API_KEY=  LEAKIX_API_KEY=  THREATBOOK_API_KEY=  URLSCAN_API_KEY=
VIRUSTOTAL_API_KEY=

# Recon platforms and aggregators
BEVIGIL_API_KEY=  BUFFEROVER_API_KEY=  BUILTWITH_API_KEY=  C99_API_KEY=
CHAOS_API_KEY=  CHINAZ_API_KEY=  DIGITALYAMA_API_KEY=  DOMAINSPROJECT_API_KEY=
DRIFTNET_API_KEY=  HACKERTARGET_API_KEY=  INTELX_HOST= / INTELX_API_KEY=
PROFUNDIS_API_KEY=  PUGRECON_API_KEY=  RECONEER_API_KEY=  REDHUNTLABS_API_KEY=
ROBTEX_API_KEY=  RSECLOUD_API_KEY=  SUBMD_API_KEY=  WINDVANE_API_KEY=

# Code search
GITHUB_TOKEN=
```

Twelve more sources need no key at all and are always used: `anubis`,
`commoncrawl`, `crtsh`, `digitorus`, `hudsonrock`, `rapiddns`, `scanmalware`,
`shodanct`, `sitedossier`, `thc`, `threatcrowd`, `waybackarchive`.

**Paste the value and nothing else.** A `.env` file has no inline comments, so
`SHODAN_API_KEY=abc123  # my key` sets the key to `abc123  # my key` and the
provider rejects it.

Three sources take two parts, which the worker joins the way subfinder expects —
Censys as `ID:SECRET`, FOFA as `EMAIL:KEY`, IntelX as `HOST:KEY`. Set both halves
or neither; half a credential is skipped and said so in the log.

Compose passes them to the worker, which renders subfinder's
`provider-config.yaml` at startup and logs which sources came up configured:

```
passive sources configured  count=3  sources="[censys github shodan]"
```

Keys live only in `.env` (git-ignored) and in the worker's environment. They are
never stored in the database, never shown in the UI, and never written to a log —
the config file is mode 0600 and only source *names* are logged.

These calls go to the providers, never to the target, so their exit is not a scan
concern — but it is still this host's address at forty APIs. `ASM_PASSIVE_PROXY`
(http or socks5) puts one hop in front of subfinder; DNS stages cannot use it.

If you upgrade subfinder and it renames or drops a source, the worker says so at
startup instead of ignoring your key. That check exists because it had already
happened: `zoomeye` had become `zoomeyeapi`, and `hunter` and `binaryedge` were
gone, so three keys were being written into a config subfinder read straight
past.

## Safety & authorization

This tool sends packets to real infrastructure. Read [Architecture](wiki/Architecture.md) §10 first.

- A target is **passive-only** unless it carries an explicit **active** authorization record.
- CDN / shared-hosting IPs are excluded from port scanning by default.
- RFC1918 / loopback targets are always rejected — this tool scans the external
  perimeter only, which is also what closes the scanner-as-SSRF hole. The check runs
  twice: once on the target itself, and once on every address discovery resolves, since
  a name under an authorized target can still point at 127.0.0.1 or a cloud metadata
  address. `ASM_ALLOW_PRIVATE_TARGETS=true` lifts it for a test target you run yourself on
  a private network, and must not be set on anything reachable by anyone else.
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
scanning, technology detection, screenshots, directory brute-forcing and the nuclei
vulnerability check — every stage confirmed by what it stored, not just by the tool
running. A scan of that host records
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

Deliberately deferred (see [Architecture](wiki/Architecture.md) §14): multi-tenancy, ClickHouse analytics,
SSH-push provisioning, worker auto-update, cloud-inventory connectors.

Known rough edges:

- Provisioner-created workers are not rebuilt by `docker compose up --build`, so they keep
  running an older image until removed and recreated.
- Wordlist downloads use the resolver a container was started with. If that resolver
  disappears — a VPN dropping is the usual cause — fetches fail until the service is
  recreated (`docker compose up -d --force-recreate scheduler`), at which point they
  retry themselves.
- Configuration keeps the `ASM_` environment-variable prefix and the `asm` database role
  from before the project was renamed, so existing `.env` files and volumes keep working.
  The compose volumes are pinned to their original `scan_tool_*` names for the same
  reason — renaming them would orphan the database.
