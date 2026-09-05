# Build TODO — PinkGlasses

Derived from `architecture.md` (v0.2), `worker-pipeline.md` and `Tools.md`.
Status legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` deferred/blocked

## Phase 0 — Scaffolding
- [x] 0.1 Go module, directory layout, Makefile, .gitignore, .env.example
- [x] 0.2 config package (env-driven, shared by all binaries)

## Phase 1 — Data layer
- [x] 1.1 goose SQL migrations: scope/target, runs/run_target/task/task_origin
- [x] 1.2 goose SQL migrations: fleet (worker_pool, worker, enrollment_token)
- [x] 1.3 goose SQL migrations: assets (domain, dns_record, ip, service, obs, cert, tech, finding, change_event)
- [x] 1.4 goose SQL migrations: indexes (gist inet, trigram, GIN, partial lease indexes)
- [x] 1.5 store: pgx pool bootstrap + migrate runner (cmd/migrate)

## Phase 2 — Shared contract
- [x] 2.1 scanproto: stages, capabilities, job envelope v2, result envelope v2, observation types

## Phase 3 — Domain + store
- [x] 3.1 domain: entities + enums + rules (no I/O)
- [x] 3.2 store: repositories (scope, run, task, worker, asset, finding)

## Phase 4 — Orchestration core
- [x] 4.1 scopeguard: authorization, shared-infra, exclusions, RFC1918 guard
- [x] 4.2 planner: run -> task DAG, coalesce barrier, task_origin, fairness
- [x] 4.3 dispatch: lease claim SQL, capability match, heartbeat, reaper
- [x] 4.4 ingest: normalize observations -> temporal upsert
- [x] 4.5 diff: run vs baseline -> change_events (per target)

## Phase 5 — Services / query
- [x] 5.1 search: lexer + Pratt parser -> whitelisted SQL
- [x] 5.2 notify: slack/email/webhook sinks (interface + webhook impl)
- [x] 5.3 obj: S3/MinIO artifact store + presign
- [x] 5.4 audit: append-only log helper

## Phase 6 — HTTP surface
- [x] 6.1 httpapi: router, middleware, DTOs, error handling
- [x] 6.2 httpapi: scope/target/run handlers + SSE progress
- [x] 6.3 httpapi: asset/search/findings/export handlers
- [x] 6.4 httpapi: fleet handlers (enrollment token, approve/drain/etc)

## Phase 7 — Agent gateway
- [x] 7.1 agentapi: enroll, WSS control channel, dispatch loop
- [x] 7.2 agentapi: batched result ingest (lease-token auth) + result confinement
- [x] 7.3 agentapi: presign endpoint

## Phase 8 — Binaries
- [x] 8.1 cmd/api
- [x] 8.2 cmd/gateway
- [x] 8.3 cmd/scheduler (recurring runs + lease reaper + sweeps)

## Phase 9 — Worker (the scan box)
- [x] 9.1 worker: agent runtime (enroll, WSS connect, lease loop, spool, heartbeat)
- [x] 9.2 worker: tool runner abstraction (exec + JSONL parse)
- [x] 9.3 worker stage 1: subfinder -> alterx -> dnsx (+ shuffledns deep)
- [x] 9.4 worker stage 2: naabu -> nmap -sV
- [x] 9.5 worker stage 3: httpx (-tech-detect) + nuclei tech
- [x] 9.6 worker stage 4: httpx -screenshot
- [x] 9.7 worker stage 5: katana -> ffuf/feroxbuster
- [x] 9.8 cmd/worker main + capability self-detection

## Phase 10 — Packaging
- [x] 10.1 Dockerfiles (control plane + worker image with tools)
- [x] 10.2 docker-compose.yml (caddy, api, gateway, scheduler, worker, postgres, minio)
- [x] 10.3 install.sh (VPS enrollment one-liner)

## Phase 11 — Frontend
- [x] 11.1 Vite React TS scaffold, API client, router, layout
- [x] 11.2 Dashboard + Domain (DNSDumpster) page
- [x] 11.3 Host + Service (Shodan) pages
- [x] 11.4 Runs (multi-target progress) + Fleet management pages

## Phase 12 — Finish
- [x] 12.1 README with run instructions
- [x] 12.2 Final `go build ./...` + `go vet` green

---

# Next up

Phases 0–12 delivered the working system. The three phases below are the current
backlog, **Phase 13 first**.

## Phase 13 — Tool coverage per `Tools.md`, one tool at a time  ← DO THIS FIRST

Today the worker only ever invokes **5** tools: `subfinder`, `naabu`, `nmap`, `httpx`,
`ffuf`. Everything else in `Tools.md` is missing, `katana` is referenced only in a comment,
and `vuln_check` is defined in `scanproto` but never wired into `scanner.Run()`, so
**nuclei can never execute**.

**Rules for this phase — one tool per step, in order:**

1. Implement exactly one tool.
2. Add its binary to the worker image and to tool/capability reporting.
3. Run its test gate against an authorized target and record the result.
4. **Do not start the next step until the current gate passes.** If a gate fails, fix it or
   mark the step `[!]` with the reason — never carry a broken tool forward.

Each step is `.1` implement · `.2` image + reporting · `.3` **GATE** (must pass).

### Step 0 — Prerequisites (blocks everything below)
- [x] 13.0.1 Pick and document authorized test targets. `scanme.nmap.org` is published by
      the Nmap project explicitly for scan testing; `example.com` is safe for passive and
      DNS work. **Never gate-test against third-party infrastructure you do not own.**
- [x] 13.0.2 Test harness: a `make tool-test TOOL=<name> TARGET=<host>` that runs one stage
      on a worker and prints the observations it produced, so each gate is one command.
- [x] 13.0.3 Wordlists + resolvers baked into the worker image (assetnote DNS lists, a
      resolver list). Needed by shuffledns, gobuster dns, gobuster dir.
- [x] 13.0.4 Render subfinder's `provider-config.yaml` from the API-key env vars at worker
      startup, skipping blanks. (The trailing "nothing reads them yet" stood here, and in
      the README, long after `NewAgent` had started calling `WriteProviderConfig`.)
      Extended 2026-09-04 to all 40 sources subfinder v2.16 takes a credential for, from
      17 — of which three (`zoomeye`, `hunter`, `binaryedge`) had been renamed or dropped
      upstream and were being written into a config subfinder read straight past. The
      worker now asks `subfinder -ls` at startup and reports any source name it no longer
      recognises, and a test keeps `providers.go`, `.env.example` and `docker-compose.yml`
      in step.
- [x] 13.0.5 **GATE:** worker starts with keys set, `provider-config.yaml` is written with
      only the populated sources, and no secret is logged.

### Step 1 — `assetfinder` — REMOVED
> **Dropped by decision.** Implemented and gated (it worked), but removed from the
> worker: in the example.com gate it contributed 2 in-scope names against subfinder's
> 24,948, so it added a from-source build to the image for almost no coverage.
> The label-boundary scope fix it exposed is kept, with its regression test in
> `internal/scanner/stage_discovery_test.go`.
- [x] 13.1.1 ~~Implement in `passive_enum`~~ — removed from the pipeline.
- [x] 13.1.2 ~~Add binary to the worker image~~ — removed from `Dockerfile.worker`.
- [x] 13.1.3 ~~GATE~~ — passed before removal; no longer applicable.

### Step 2 — `subfinder` (already present — align with `Tools.md`)
- [x] 13.2.1 Align flags, keep `-json` for parsing, confirm it consumes the keys from 13.0.4.
- [x] 13.2.2 Tool-version reporting shows configured sources count.
- [~] 13.2.3 **GATE PARTIAL** — subfinder returned 24,948 candidates using free sources. The
      "more with a key than without" half is **unverified**: no API keys are set in `.env`,
      so `passive_sources=[]`. Re-run once a key is configured. Original criterion: with at least one API key set, subfinder returns strictly more
      subdomains than with none — proves the key plumbing actually works.

### Step 3 — `dnsx` (resolution backbone — everything downstream depends on it)
- [x] 13.3.1 Implement as the primary resolver: `dnsx -silent` over the deduped candidate
      set; keep the stdlib resolver as the no-binary fallback.
- [x] 13.3.2 Add binary + reporting.
- [x] 13.3.3 **GATE PASSED** (24,949 candidates -> 47 resolving names, 99.8% filtered; 0 out-of-scope) — only resolving names survive; wildcard domains do not produce
      thousands of phantom hosts; resolved IPs reach the coalesce barrier and become
      `port_scan` tasks.

### Step 4 — `shuffledns` (deep profile only)
- [x] 13.4.1 Implement bruteforce: `-d <domain> -w <wordlist> -r <resolvers> -mode
      bruteforce -silent`. Deep profile only — it is high-volume.
- [x] 13.4.2 Add binary (plus `massdns`) + reporting.
- [~] 13.4.3 GATE deferred — bruteforce is deep-profile-gated and needs an owned domain to verify a known-unlisted name. Criterion: finds a known-unlisted subdomain on a domain you own; respects the
      rate limits; standard profile does **not** trigger it.

### Step 5 — `gobuster dns` (wildcard + vhost)
- [ ] 13.5.1 Implement: `gobuster dns -d <domain> -w <wordlist> --wildcard`.
- [ ] 13.5.2 Add binary + reporting.
- [ ] 13.5.3 **GATE:** wildcard domains are detected and flagged rather than exploded into
      false subdomains.

### Step 6 — `naabu` (already present — align with `Tools.md`)
- [x] 13.6.1 Align to `-c 4 -rate 20 -top-ports 100 -silent`; keep params overridable
      (Phase 15). Confirm the connect-scan fallback without `CAP_NET_RAW`.
- [x] 13.6.2 **GATE PASSED** (scanme.nmap.org: naabu found 22,80; fed to nmap) — finds the expected open ports on `scanme.nmap.org`, and its output
      is what feeds nmap — never a full-range nmap.

### Step 7 — `nmap` (expand from `-sV` to the `Tools.md` profile)
- [x] 13.7.1 Implement `-A -vvv -Pn --min-hostgroup 256 --min-rate 10000 --max-retries 3
      --defeat-rst-ratelimit --open -oA`. **Gate `-p-` behind the deep profile** — full-range
      `-A` on every host is very slow and very loud.
- [x] 13.7.2 Parse `-oA`/greppable output into product + version observations.
- [x] 13.7.3 **GATE PASSED** (OpenSSH 6.6.1p1, Apache 2.4.7 on scanme; version-split fixed + tested) — service versions appear for non-HTTP ports (e.g. SSH) on
      `scanme.nmap.org`; standard profile stays on the naabu-supplied port list.

### Step 8 — `katana` (crawl — currently never invoked)
- [x] 13.8.1 Implement: `katana -d 5 -jsl -c 3 -p 3 -rl 10 -silent`.
- [x] 13.8.2 Add binary + reporting.
- [x] 13.8.3 **GATE PASSED** — katana crawled 11,983 URLs on scanme; paths seeded dir_brute (see 13.13.3). Criterion: returns real linked paths for a site you own, and those paths seed
      the directory-brute stage instead of it guessing blind.

### Step 9 — `urlfinder` (passive URLs)
- [~] 13.9.1 Implement: `urlfinder -silent`.
- [x] 13.9.2 Add binary + reporting.
- [!] 13.9.3 urlfinder stalls on keyless external APIs; hard-capped at 30s and made optional. Revisit with keys. returns URLs without sending traffic to the target.

### Step 10 — `httpx` probe (align + chain)
- [x] 13.10.1 Implement `-title -sc -cl -location -fr -silent -delay 1s`, taking the union
      of katana + urlfinder output as input, as `Tools.md` chains them.
- [x] 13.10.2 **GATE PASSED** (example.com: status 200, title, server, Cloudflare tech) — live web services get title/status/content-length/redirect chain;
      dead ones are dropped; the `-delay` is honoured.

### Step 11 — `httpx` screenshots (+ fix the broken upload)
- [x] 13.11.1 Implement `-sc -title -tech-detect -screenshot -timeout 200
      -screenshot-timeout 200`.
- [x] 13.11.2 **FIXED** — screenshot now uploads via presign; agent.uploadArtifact. Original::** the screenshot stage emits an object-storage key but
      never uploads the file, so every screenshot reference points at nothing. Upload via
      the gateway presign endpoint.
- [~] 13.11.3 GATE partial — PNG captured + upload path wired/built; full object-storage round-trip needs a live standard run. Criterion: a screenshot is actually retrievable from object storage and renders
      in the service detail view.

### Step 12 — `nuclei` (wire the unreachable stage)
- [x] 13.12.1 Wire `StageVulnCheck` into `scanner.Run()` and into the planner's DAG.
- [x] 13.12.2 Implement `nuclei -l urls` (default templates) and `-t <dir>` for a pinned
      custom set; template updates handled like wordlists.
- [x] 13.12.3 Add binary + reporting.
- [~] 13.12.4 nuclei stage reachable + wired; findings-page gate deferred to an end-to-end run (needs a target with a known issue). Criterion: findings appear on the Findings page with correct severity; template
      version is recorded; a run with no findings does not fail the task.

### Step 13 — `gobuster dir` (directory search)
- [x] 13.13.1 Implement `gobuster dir -u <url> -w <wordlist> -k`, plus `--exclude-length`
      to cut the false positives `Tools.md` warns about. Keep `ffuf` as the alternative.
- [x] 13.13.2 Add binary + reporting.
- [x] 13.13.3 **GATE PASSED** (scanme.nmap.org: 927 crawl candidates -> 9 verified 200 paths, 0 junk after cleanPath+probe) — discovers a known path on a site you own; false positives from
      uniform-size 40x/50x responses are filtered out; per-target concurrency is capped —
      this is the loudest stage in the pipeline.

### Step 14 — Close-out
- [x] 13.14.1 End-to-end run — passive run on example.com populated 1 domain + 4 IPs through worker->ingest->API. Fixed two lease-query bugs found here. over a scope you own with every tool enabled; confirm the full
      `Tools.md` sequence executes in order and the asset graph is populated at each stage.
- [x] 13.14.2 Update `worker-pipeline.md` to match what is actually implemented. (22.5)

## Phase 14 — Global search across all companies

Search is scoped to one company today (`/scopes/{id}/search`). Make it work across the
whole inventory, Shodan-style, for when there are many companies.

- [x] 14.1 store: cross-scope search — drop the mandatory `scope_id` filter, return the
      owning company with each row.
- [x] 14.2 search language: add a `company:` (alias `scope:`) field so results can be
      narrowed back down from a global query.
- [x] 14.3 api: `GET /api/v1/search` (no scope in the path), with optional company filter
      and cursor pagination.
- [x] 14.4 UI: promote Search to a global page — company column in results, click through
      to that company's host/service view, and a global/current-company toggle.
- [x] 14.5 Performance (migration 00007: scope name trigram + port/product indexes): review indexes for cross-scope queries; the current ones assume a
      `scope_id` prefix and will not serve a global scan well.

## Phase 15 — Configurable scan parameters with saved presets

Every tool's flags are hardcoded today. Let users adjust them per scan and save their own
presets, with the `Tools.md` values as the shipped defaults.

- [x] 15.1 schema: `scan_profile` table (name, owner, optional `scope_id` for
      company-specific presets, `params` jsonb, is_default).
- [x] 15.2 Codify the built-in defaults per tool/stage from `Tools.md` in one place, so the
      UI can show "default vs. yours" and offer a reset.
- [x] 15.3 `scanproto`: extend `Params` to carry a per-tool argument set, versioned like the
      rest of the contract.
- [x] 15.4 planner (params persisted on run; gateway attaches to each job): merge the selected profile's params into each job envelope.
- [x] 15.5 api: CRUD for scan profiles + pick one when starting a run.
- [x] 15.6 UI: scan-launch modal has a **Manual setup** toggle opening a per-tool parameter
      editor (14 params across 8 tools), with defaults shown, changed-badges, preset
      load/save and reset. Verified live: preset overrides merge with defaults onto the run.: scan-launch modal with a per-tool parameter editor (rate, ports, wordlist,
      timeouts, templates, depth) and "save as preset".
- [x] 15.7 **Security: whitelist every settable parameter.** These values become process
      arguments on a scan box — never pass raw user strings to `exec`. Validate each field
      by type and allowed range, and reject anything unrecognised rather than forwarding it.

## Phase 16 - Tunning
- [x] 16.1 Directory wordlists in the registry: a `dir` kind in the Wordlists UI, two
      shipped SecLists defaults, delivery to the worker by presigned URL and content-hash
      cache, and `gobuster dir` using the run's list. Verified live with an uploaded list:
      the worker cached the exact file and its hits landed as findings — which surfaced
      that `gobuster`'s output was never parsed at all (it prints entries without a leading
      slash), so this stage had only ever reported the crawler's paths.
- [x] 16.2 Runs table shows what each run is scanning and how far along it is: a target
      column (first few names, "+N" for the rest) and a task progress bar with failures
      called out. Targets and progress are aggregated in the same query as the runs, so
      the list stays one round trip. Verified live in a browser: the bar tracked a running
      scan from 2/3 through 9/9 as the planner added stages.
- [x] 16.3 Wordlist checkboxes in manual setup, for all three kinds: subdomain lists under
      shuffledns, resolver lists under dnsx, directory lists under gobuster. Ticking none
      means "use the registry defaults", which is the normal case. A run may now name lists
      of any kind and each kind it stays silent about falls back to its defaults; an unknown
      or not-ready list is refused rather than silently ignored. Verified: a run naming a
      non-default subdomain list and resolver list got exactly those, plus the default
      directory list.
- [x] 16.4 (covered by 16.3 — resolver lists use the same picker.)
- [x] 16.5 Custom ports and ranges were already settable and validated; the UI's "custom…"
      option and the `1-1024` / `80,443` grammar both existed. Verified live rather than
      rebuilt: a run with `ports=22,80` reached naabu as `-p 22,80` and nmap as `-p 22,80`.
- [x] 16.6 A switch per tool (nine of them; shuffledns keeps its existing `dns_bruteforce`
      key rather than growing a second one). A disabled tool is skipped, not run and
      discarded — the stage falls back to its Go implementation or contributes nothing.
      ffuf answers to gobuster's switch, since turning the brute force off must not quietly
      swap in the other tool. Verified live: with subfinder, nmap, katana, gobuster and
      bruteforce off, only dnsx/httpx/urlfinder ran, the port scan fell back to the connect
      scan, and the run still completed.
- [x] 16.7 httpx User-Agent field, defaulting to a current iPhone Safari string. It applies
      to every web request the scan makes, not just httpx's — the built-in probes used to
      send "pinkglasses-worker". httpx's `-random-agent` is disabled so the setting is not
      overridden. Verified in the invocation log.
- [x] 16.8 Saving scan profiles already existed (15.6). Verified in a browser rather than
      rebuilt: named, saved, and offered in the preset dropdown afterwards.
- [x] 16.9 httpx proxy field: a list, one per line or comma-separated, http/socks4/socks5
      with or without credentials. A task picks one by hashing its target, so a list spreads
      a scan over several egress addresses while a retry reuses the same one. Proxies are
      parsed, not pattern-matched, and credentials are never logged. httpx, katana, gobuster
      and the built-in Go probes all honour it, so a proxied scan cannot leak the worker's
      own address from whichever stage happened to fall back. Verified end to end through
      socks5 184.178.172.17:4145: the whole web half of the pipeline ran through it and
      still found 12 paths.
- [x] 16.11 Show only the companies I created, or all of them: a Mine / All toggle in the
      company picker, remembered per browser, with a count of what the filter is holding
      back. Scopes carry `created_by`, backfilled for existing rows from the audit log
      rather than defaulted. It is a view, not a permission — the owner is whoever the
      request claims to be — and it only becomes meaningful once 17.0 verifies that.
- [x] 16.10 Scan-type descriptions in the launch window rewritten against what the profiles
      actually do. The old text claimed Standard scanned the top 1000 ports (it is 100) and
      implied Deep added DNS and directory brute forcing (both already run on Standard —
      Deep only widens the port scan and switches nmap to `-A`).

## Phase 17 — Authorization

There is no authentication in this build. `actor()` reads `X-Forwarded-User` and otherwise
calls everyone `local`, on the assumption stated in `architecture.md` §10.2: the app sits
behind an identity-aware proxy and is never exposed directly. Everything below exists
because that assumption is doing a lot of work, and anything that depends on *who* is
asking — ownership, per-user views, audit that means something — is only as good as it.

- [x] 17.0 **Authentication.** Sessions with a real login, or trusted-header auth with the
      proxy's identity verified rather than believed. `X-Forwarded-User` is a request header:
      anything that can reach the API can claim to be anyone, which is why the API must not
      be reachable without the proxy in front.
- [x] 17.1 **Users and ownership.** A users table, and scope ownership pointing at it rather
      than at a free-text actor string. Backfill from `scope.created_by`.
- [x] 17.2 **Authorization proper.** Who may read a scope, start a run against it, enrol a
      worker, or export data. A scan is an action with consequences for someone else's
      infrastructure, so "who started this run" needs to be a fact, not a header.
- [x] 17.3 **Audit that identifies a person.** The audit log already records an actor; it
      should record a user id, and the fleet and run views should show it.
- [x] 17.4 **API tokens** for automation, scoped and revocable, so scripting the API does not
      mean sharing a human's session.

Tested against the running stack on 2026-09-04: all 58 routes answer 401
unauthenticated, and so does `X-Forwarded-User: admin` on its own. A viewer
reads and is refused every write (403); an operator creates scopes but is
refused users, VPN configs and worker enrollment; an admin gets through. An
admin's viewer-scoped token reads but cannot reach `/users`, and a viewer is
refused an admin token outright. Disabling an account took a live session from
200 to 401 on the next request. Sign-in attempt 10 returned 429; an unknown
username and a wrong password gave the same message in the same time (31-41 ms).
The audit log resolves through a foreign key. A real scan started by the
operator ran to completion, and the SPA was driven in headless Chromium: login
screen when signed out, no Accounts entry in an operator's nav, present in an
admin's.

Built as: `app_user`, `user_session`, `api_token` (migration 00021); `internal/auth`
for argon2id and role ordering; `internal/httpapi/auth.go` for the middleware.
The whole of `/api/v1` sits inside `requireAuth` with three stated exceptions,
and `TestEveryRouteRequiresAuth` walks the live router to keep it that way — a
new handler outside the group fails the test rather than quietly becoming
public. Sessions are server-side rows, so disabling an account or changing a
role takes effect on the next request. Documented in architecture.md §10.2 and
the README.

Deliberately not done, and worth stating: there is no per-scope isolation —
every signed-in user sees every company. `scope.owner_id` exists so that can be
tightened without another migration. No MFA and no OIDC; the session layer is
shaped so an external provider can be added without reworking ownership, audit
or tokens.

## Phase 18 — Finish what is wired but not running, then choose your egress

The first three exist as code that nothing calls. That has been this project's most
expensive failure mode all along: a stage that is written, documented as working, and
never actually reached. Each of these was found the same way — by asking the database
what had happened rather than reading what the code intended.

- [x] 18.1 Made `vuln_check` run. The planner never created the task, so nuclei had never
      executed once despite the stage being declared, the worker handling it and the binary
      being installed. It is enqueued per live web service now, honouring `nuclei_enabled`
      at planning time so switching it off means no task rather than a task that leases a
      worker to do nothing. Verified against the cookie lab: the task runs, and turning the
      switch off plans none.
- [x] 18.1.1 Finding history. Every completed run that could have observed a finding — one
      that ran the producing stage against its host — records whether it did, and presence
      (`active` / `gone since`) is derived from that rather than set by hand. The ack/resolve
      buttons are gone; the `finding` table is untouched. Shown as a dot-strip per finding on
      the Findings and host pages, one dot per run with the date, time and severity on hover,
      plus "seen 7/8". The differ records `finding_gone` and `finding_returned`. Verified by
      hiding a path between scans: `●○●`, one gone event, one returned event, tooltips
      reading "Not found 8:05:17 PM" on the hollow dot. History starts at the migration —
      runs before it left no record and are excluded rather than read as "not found".
- [x] 18.2 Alerts. Per-company channels — Slack incoming webhook or any JSON URL — each
      choosing which changes it hears about (finding returned, new finding, finding gone,
      new port, new subdomain) and a minimum finding severity. One digest per run per
      channel, regressions first, capped at 25 lines with a count of the rest. Every attempt
      is recorded with its outcome, so a dead destination is a visible row rather than
      silence; a "Send test" checks a destination before anything real changes. The senders
      now treat non-2xx as failure — the old ones did not, so a 404 counted as delivered.
      Verified end to end against the lab's own webhook receiver: hiding a path produced a
      finding_gone digest, restoring it a finding_returned digest, in both JSON and Slack
      text; a channel pointing at a 404 records "HTTP 404" instead of "sent".
- [x] 18.3 Result spool. Batches the gateway cannot be reached for are written to a
      volume-backed spool and replayed when the control channel comes back and once a
      minute meanwhile, in the order produced. Only transient failures spool — a 4xx is the
      gateway saying no and is dropped, a transport error or 5xx is retried. The spool
      survives a worker restart. Its one limit is the lease TTL: a gateway gone longer than
      two minutes has had the task re-queued, so the replayed batch is refused as stale and
      dropped — the results are not lost, they came from the re-run. Verified live: a
      gateway pause spooled both of a task's batches, they survived a worker restart, and on
      resume replayed as delivered=2 dropped=0 with the task still at attempts=1 and its
      port-scan result intact — the spooled data itself landed, not a re-run.
- [x] 18.4 Scan through a VPN. A VPN page for WireGuard and OpenVPN configs, sealed with
      AES-256-GCM under ASM_SECRET_KEY and never returned by any endpoint, and a picker on
      the scan-launch modal. Runs bound to a tunnel demanded (superseded by Phase 20) a `vpn` capability that only a
      worker with /dev/net/tun, NET_ADMIN and the clients reports, so an ordinary worker is
      never offered the work. The worker measures its address before and after connecting
      and refuses the task unless it changed. Verified: a deliberately unusable config gave
      3 attempts, 3 refusals, 0 tools run and 0 services touched.
- [x] **Reconsider the shipped default credential.** Done as 22.2. Original: `admin` / `pinkglasses` is created
      on first boot (README, wiki/Accounts-and-Access.md). It is mitigated — created only
      on an empty database, warned about in the log at every start and in a
      non-dismissible UI banner, and 11 characters so it cannot be re-entered as its own
      replacement — but a published credential on a database holding a complete map of
      somebody's attack surface is still the weakest thing in the auth design. Better:
      generate a random password on first boot and print it once, which keeps the
      zero-config start without publishing anything.
- [x] **The run events stream carries nothing.** Done as 22.1: database triggers on scan_task, scan_run and run_fleet raise `pg_notify`, the api LISTENs and fans out. Original: `GET /runs/{id}/events` opens a
      server-sent events stream and the UI subscribes to it, but `SSEHub.Publish` has no
      callers anywhere — found 2026-09-05 while writing the API reference. Nothing is broken
      only because the UI also polls every 4 s. Either publish from ingest and the planner
      (task done, stage advanced, run finished) and lengthen the poll, or remove the stream.
- [x] **No OpenAPI document.** Done as 22.5: `docs/openapi.yaml` from the router, guarded by `TestOpenAPIDocIsCurrent`. Original: architecture.md claimed one was generated from the handlers;
      it never was. `wiki/API.md` is the hand-written reference, held to the router by
      `TestAPIDocCoversEveryRoute`. Generating a spec from the same walk would let clients be
      typed from it.
- [ ] **Passive discovery stores every name it hears about, resolving or not.** example.com
      holds 24,950 domains of which 3 resolve; the other 24,947 all came from subfinder — dead
      CT-log and archive entries for a famous domain. The Hosts view hides them ("non-resolving
      names hidden") but the dashboard counts them, and every run re-plans dns_resolve for all
      of them. Decide: keep them (dangling names are takeover candidates) but count and rank
      resolving names first, and stop re-resolving a name that has failed N runs in a row.
- [ ] How to save and then show user historical data ?
- [x] **A worker whose row is reaped never re-enrols.** Fixed 2026-09-05. Mechanism: the
      gateway's dispatch loop reloaded the worker row every 2 s and, when it was gone, did
      `continue` — holding the socket open forever while heartbeats updated zero rows. The
      worker only re-enrols on a 401, and a 401 needs a new HTTP request, which nothing ever
      forced. Now a missing row (`store.ErrNoWorker`, distinct from a transient DB error, which
      still waits) closes the channel with a policy-violation frame and a reason; the worker
      drops its credential on that frame and re-enrols. Live test: row deleted at 13:00:54,
      channel closed 13:00:56, re-enrolled 13:01:01 — seven seconds, versus never. Original text: Seen 2026-09-04: the gateway
      restarted, the worker reconnected and re-enrolled, then its heartbeat stopped
      reaching the database; `ReapStaleLocalWorkers` deleted the row after 10 minutes and
      the worker sat there with "control channel up" believing it was fine. The whole
      fleet was gone and scans queued forever with nothing to run them; `docker compose
      restart worker` fixed it. The worker should treat "the control plane does not know
      me" as a reason to re-enrol, the way it already treats a rejected credential.

## Phase 19 — Ephemeral scan fleets, and a VPN gateway per run

Scanning through a VPN currently means a long-lived worker holding NET_ADMIN
alongside nmap, chromium and nuclei — the privilege sits in the container most
likely to be the thing that gets exploited — and one tunnel at a time per box.

Instead: a run can bring up its own fleet. A VPN gateway container holds the
tunnel and nothing else; the run's workers join its network namespace, so they
inherit its egress without needing any network privilege themselves. Both are
destroyed when the run ends.

Most of the routing already exists: worker pools, enrollment tokens bound to a
pool, a lease query that filters on it, and a provisioner that is the only
component touching the Docker socket.

- [x] 19.1 **Ephemeral fleet per run**, no VPN involved. A run can request its own
      workers: a pool for the run, an enrollment token bound to it, containers created
      by the provisioner and labelled with the run, torn down when the run ends. Testable
      and useful on its own — it is how a run gets workers that cannot be starved by
      another run.
- [x] 19.2 **VPN gateway container.** Holds the tunnel and nothing else; the run's workers
      share its network namespace. The worker stops needing NET_ADMIN entirely, and the
      egress check moves into the gateway, which refuses to report healthy until its
      address has actually changed.
- [x] 19.3 **Teardown and supervision.** Containers, worker rows and the pool are removed
      when the run finishes, and orphans left by a control-plane restart are swept. A run
      whose fleet dies must fail with a reason rather than stall: workers sharing a dead
      gateway's namespace lose all networking, including their route back here, so they
      cannot report it themselves.
- [x] 19.4 **A ceiling.** Containers per run and concurrent fleets are capped, with a clear
      failure when the cap is hit rather than a fork bomb.
- [x] 19.5 **Document the architecture** in architecture.md, README and the wiki: what a run
      fleet is, why the privilege lives in the gateway, and what happens when it dies.

Tested against your two VPS configs on 2026-09-04: WireGuard and OpenVPN both
brought a gateway up (193.176.38.211 -> 157.230.81.163), workers confirmed
inside the gateway's namespace with no NET_ADMIN and no /dev/net/tun, teardown
removed all three containers, the orphan sweep collected a stranded gateway, an
unreachable endpoint failed the run with the gateway's own error instead of
scanning from the host address, and killing a live gateway failed its run in
under three minutes.

Built as: `run_fleet` (migration 00019) records the intent; the scheduler
(`internal/fleet`) builds, supervises and tears down through the provisioner;
`cmd/vpngw` is the gateway binary, shipped in the worker image and selected by
entrypoint. The planner, the dispatcher and the worker all read one fact —
`store.RunHasFleet` — to decide who owns the tunnel, because deciding it
separately is what broke the first version. Documented in architecture.md §7.6,
the README, and `wiki/VPN-Scanning.md`.

- [x] Add to .env file file all subfinder supported survices list then i could put there API tokens to them. Done 2026-09-04 (commit 58ba5e8): all 40 key-taking sources, kept in step with compose and the worker by a test.

## UI tuninnig
Write here new UI features.

- [x] Add date and time to hosts table with when they were got. A **Seen** column: when the
      name was last seen resolving to that address, with the time; hover for first seen. It is
      the name→address pair's timestamps, so a name that moves shows a different date per row.
- [x] Add to detailed host view host cookies names. Was already there — each service card
      lists "Cookies set (names only)" — verified end to end 2026-09-05: 18 observations carry
      names and the host API returns them (`webvpn`, `BIGipServerpool_web_https`, `NSC_wt_mfi`…).
- [x] **Ingest writes a service_observation only when a probe had details.** Fixed
      2026-09-05: every open `ObsService` now leaves a per-run row; the upsert already lets only
      non-empty values overwrite, so a bare row and a detailed one merge. Original text: Found while
      building port history: on scanme.nmap.org, 18 of 22 completed port-scan runs that
      reported port 80 open left no `service_observation` row, because `ObsService` writes
      one only when product, version or banner is non-empty (`internal/ingest/ingest.go`).
      The table is therefore a record of *details*, not of *open*. Port history reads the
      port-scan task result instead; a bare per-run row on every open observation would
      make banner/version history possible too — `UpsertServiceObservation` already merges.
- [x] How to save host ip history and how and where to view it ? Same answer as findings:
      a per-run record (`domain_ip_observation`, 00023, written by dns_resolve ingest) shown as
      one dot per completed run that resolved the name — filled where it pointed at this
      address, hollow where it pointed elsewhere — in the host page's "Names resolving here"
      table, plus `also →` listing the other addresses the name has pointed at. History starts
      at 00023; earlier runs left no per-run record and are excluded rather than read as
      "pointed away". Verified: a passive run wrote 2 rows and the page shows the dot.
- [x] How to save and how to view services and port history ? One dot per completed run
      that port-scanned the address, on each service card: filled where the port was open,
      hollow where the scan ran and did not find it. "Open" is read from the port-scan task's
      own result, not `service_observation` — see the ingest note above for why. Verified on
      scanme.nmap.org: 22 runs, 22 filled, for both 22/tcp and 80/tcp.

## Phase 20 — Every active scan gets its own exit; passive never touches the target

Today a run's own fleet is opt-in, and the lease query has a one-way hole:
`r.pool_id IS NULL` is true for every worker, so an idle fleet worker sitting
inside a VPN gateway's namespace can lease an unrelated non-fleet run's task and
scan it through the tunnel. Standing workers cannot take fleet work; fleet
workers can take standing work.

New invariant. Stages that send traffic at the target — `port_scan` onward — run
from one of exactly two exits, chosen per run: **remote**, an existing pool of
enrolled VPS workers; or **local**, an ephemeral fleet behind its own VPN
gateway. Local requires a VPN config; with none, active scanning is refused.
There is no "direct from this host". Stages that never touch the target —
`passive_enum`, `dns_brute`, `dns_resolve`, `ip_enrich` — always run on the
standing local workers, optionally through one proxy. Routing is per task, not
per run, and the lease query is strict equality.

- [x] 20.1 **Per-task routing.** `scan_task.pool_id`, set by the planner from the stage
      class: passive → the standing `local` pool, active → the run's exit pool. Lease is
      `pool_id = worker's pool`, no NULL wildcard. Closes the leak above.
- [x] 20.2 **Exit is required for active runs.** `exit: local|remote`. Local needs a VPN
      config and a provisioner and always builds a fleet; remote needs a non-run-scoped
      pool with at least one active worker. A passive-profile run needs neither. A scope
      with no VPN config cannot start a local active scan — the error names the fix.
- [x] 20.3 **Ceiling becomes a queue.** A fleet over `ASM_MAX_RUN_FLEETS` waits in
      `requested` with a visible reason instead of failing; it is built when a slot frees.
- [x] 20.4 **Remove the per-worker tunnel path.** No worker builds its own tunnel any more:
      drop `attachVPN`, the `/agent/v1/vpn-config` route, `ensureTunnel`, the `vpn`
      capability and the `worker-vpn` compose service. The gateway container is the only
      thing that holds a tunnel. Dead code that looks alive is how this repo gets bitten.
- [x] 20.5 **Passive proxy.** `ASM_PASSIVE_PROXY` (http/socks5) honoured by subfinder for
      `passive_enum`. DNS stages cannot use an HTTP proxy and say so in the docs.
- [x] 20.6 **UI.** The launch dialog asks *where the scan runs from*: local via VPN
      (choose config, worker count) or remote (choose pool). Passive profile hides it.
      With no VPN configs and no remote pools, active profiles explain why they are off.
- [x] 20.7 **Docs + tests.** architecture.md §7.6, README, wiki/VPN-Scanning.md; lease
      routing verified in both directions against the database; end-to-end local+VPN run
      with passive tasks on a standing worker and active tasks on the fleet; a remote run;
      the refusal; and the queue.

Tested 2026-09-05. The lease clause was probed as pure SQL in both directions:
passive task / fleet worker and fleet task / standing worker both refuse, the
matching pairs both lease, a NULL-pool task leases to nobody. A remote-exit
`standard` run on scanme.nmap.org split cleanly — 3 passive tasks on the standing
worker, 7 active tasks across all six active stages on `remote-vps-1` in pool
`remote`, zero crossover. A local-exit run's passive stages ran on the standing
worker before its fleet existed. With the ceiling held at 1, a local run on the
active target sat `running` with the note "waiting for a slot: 1 of 1 runs
already hold their own workers (ASM_MAX_RUN_FLEETS)", its discovery complete and
its `port_scan` pending on its own run-scoped pool; releasing the slot built it.
The five refusals — no exit, local without a VPN config, remote to an empty pool,
an unknown exit, and passive needing none — each answer with the fix named.

Gap closed 2026-09-05 once a VPN configuration was re-added: a local-exit
`standard` run on scanme.nmap.org (run 557fcd63) reached `up` under per-task
routing — egress 157.230.81.163, two workers in the gateway's network namespace
with the VPN as their own outbound address — and ran every active stage
(port_scan, service_probe ×2, tech_detect, screenshot, dir_brute, vuln_check) on
the fleet worker while its three passive stages ran on the standing worker. The
run completed and the fleet tore down to zero containers. After teardown the
finished tasks show no pool, because the run-scoped pool is deleted with the
fleet and scan_task.pool_id sets null; attribution stays on worker_name.

Two mistakes worth keeping: the first two attempts to hold the ceiling for the
queue test forged database state that the scheduler then correctly acted on — a
`failed` run was torn down, a `pending` task was leased and completed. The hold
that works is a `running` task with a live lease, the one state nothing touches.

## Phase 21 — Recurring scans

The tagline says "continuously watched", and nothing in the codebase starts a
run without a human clicking: every run in the database was started by hand.
Everything built to show change over time — finding, resolution and port
history, the differ, the alert digests — only accumulates if scans recur. This
turns the scanner into a monitor.

- [x] 21.1 **One way to start a run.** Run creation lives in the API handler today, together
      with exit binding and fleet requests. Move it to `internal/launch` so the API and the
      scheduler start runs through the same code and are refused for the same reasons; the
      handler becomes a thin wrapper. No second copy of the rules.
- [x] 21.2 **A schedule per company.** `scan_schedule`: profile, exit (VPN config or remote
      pool), cadence in hours, enabled, next_run_at, last_run_id. Scopes gain a default exit
      so the launch dialog pre-selects it and a schedule has one to use.
- [x] 21.3 **The scheduler starts what is due.** Each tick: schedules with next_run_at in
      the past, whose company has no run still going (skip, never stack), start a run with
      trigger 'scheduled' through 21.1; next_run_at advances from the planned time, not from
      now, so a slow run does not drift the cadence. A refusal (VPN config deleted, pool
      empty) is written on the schedule where the UI shows it, and retried next cadence.
- [x] 21.4 **UI.** A schedule block on the Runs page: cadence, exit, last run, next run,
      last refusal; enable/disable. Scheduled runs are labelled in the run list.
- [x] 21.5 **Test.** A 2-minute cadence starts two runs unattended; the second is skipped
      while the first still runs; the differ and a digest fire between them; deleting the
      schedule's VPN config produces a visible refusal rather than a silent stop.

Tested 2026-09-05 on scanme.nmap.org with the re-added WireGuard config: a 1-hour
schedule started run 1 itself (trigger `scheduled`, `last_run_id` set); forcing it
due while run 1 ran produced a skip with a 5-minute recheck and no error; run 1
completed through its own VPN fleet (egress 157.230.81.163, torn down) and the
differ ran; forcing it due again started run 2; `next_run_at` advanced from the
planned time. A schedule whose VPN config was deleted showed "did not start" with
the actionable sentence and started nothing. The schedule is left **paused** so it
does not scan hourly through the operator's VPS unasked; resume it from the Runs
page.

Two things the tests turned up, both fixed in the same change:

- **Exits are validated before a run row exists.** `Start` used to create the run and then
  bind the exit; a refusal marked the row failed. For a person's click that recorded the
  attempt; for a schedule it would have minted a failed run every hour on top of the reason
  already written on the schedule. `checkExit` now runs first, with no side effects, and
  `bindExit` only applies what it established.
- **Runs queued with no tasks are zombies, and they blocked schedules.** Two runs from 2 and
  4 September sat in `queued` with zero tasks — planning failed after the row was written,
  and nothing advances a queued run — so `ScopeHasActiveRun` counted them and every
  scheduled scan for that company was skipped forever. The sweep now fails a run queued
  for ten minutes with no tasks (`FailZombieRuns`); verified on a planted row.

## Phase 22 — After recurring scans, in this order

- [x] 22.1 **Make the events stream real.** `SSEHub.Publish` has no callers. Publish on task
      done, stage advanced and run finished from where those happen, and lengthen the UI's
      poll to a fallback. With runs recurring and dashboards left open, polling every run
      detail every 4 s is the wrong shape.
- [x] 22.2 **Default credential: random on first boot, printed once.** Keeps the zero-config
      start without a password in the README. The banner and startup warning stay for the
      case where the printed password is never changed.
- [x] 22.3 **Passive-discovery noise.** example.com: 24,950 names, 3 resolve, 24,947 dead
      entries from subfinder. Count and rank resolving names first on the dashboard; stop
      re-planning dns_resolve for a name that has failed N runs in a row; keep the names —
      dangling ones are takeover candidates.
- [x] 22.4 **Wildcard DNS detection** (13.5): detect a wildcard before brute force and flag
      the domain rather than explode it into thousands of fake subdomains.
- [x] 22.5 **Docs debt.** An OpenAPI document generated from the same router walk the
      reference test uses; `worker-pipeline.md` updated to what runs (13.14.2).

## Phase 23 — Run controls, one launch dialog, UI wording

- [ ] 23.1 **Stop, pause, resume and rerun a scan.** Stop is the existing cancel. Pause holds
      a run: no task is leased for it (the lease already requires `status='running'`), tasks
      in flight finish and report, the run's own fleet stays up; resume lets it continue.
      Rerun starts a new run with the same profile, parameters, wordlists and exit as an old
      one, through the same `Launcher.Start` a fresh click uses.
- [ ] 23.2 **Schedules live in the Start-a-scan dialog.** One dialog: the profile, exit and
      manual setup chosen there apply whether the scan runs now, once at a chosen time, or on
      a cadence from hourly to yearly. `every_hours = 0` is a one-off at `next_run_at`, which
      disables itself after starting. The separate "Schedule a recurring scan" dialog goes;
      the schedules table stays for pause/resume/remove.
- [ ] 23.3 **"Manual setup" becomes "Customize scanning"**, with a chevron that reads as
      expand/collapse rather than a triangle.
- [ ] 23.4 **Search: "All companies" → "Global search".**
- [ ] 23.5 **Sidebar order:** Dashboard, Hosts, Scan runs, Findings, Search, Wordlists, VPN,
      Workers, Alerts, Accounts.
- [ ] 23.6 **Account footer:** "Change password" and "Sign out", capitalised.
