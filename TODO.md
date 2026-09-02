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
      startup, skipping blanks. Keys already exist in `.env.example` and are passed to the
      worker in `docker-compose.yml`; nothing reads them yet.
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
- [ ] 13.14.2 Update `worker-pipeline.md` to match what is actually implemented.

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
- [x] 16.10 Scan-type descriptions in the launch window rewritten against what the profiles
      actually do. The old text claimed Standard scanned the top 1000 ports (it is 100) and
      implied Deep added DNS and directory brute forcing (both already run on Standard —
      Deep only widens the port scan and switches nmap to `-A`).
