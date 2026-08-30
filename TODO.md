# Build TODO — Attack Surface Monitor

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
- [ ] 13.0.1 Pick and document authorized test targets. `scanme.nmap.org` is published by
      the Nmap project explicitly for scan testing; `example.com` is safe for passive and
      DNS work. **Never gate-test against third-party infrastructure you do not own.**
- [ ] 13.0.2 Test harness: a `make tool-test TOOL=<name> TARGET=<host>` that runs one stage
      on a worker and prints the observations it produced, so each gate is one command.
- [ ] 13.0.3 Wordlists + resolvers baked into the worker image (assetnote DNS lists, a
      resolver list). Needed by shuffledns, gobuster dns, gobuster dir.
- [ ] 13.0.4 Render subfinder's `provider-config.yaml` from the API-key env vars at worker
      startup, skipping blanks. Keys already exist in `.env.example` and are passed to the
      worker in `docker-compose.yml`; nothing reads them yet.
- [ ] 13.0.5 **GATE:** worker starts with keys set, `provider-config.yaml` is written with
      only the populated sources, and no secret is logged.

### Step 1 — `assetfinder` (passive, no keys, safest first)
- [ ] 13.1.1 Implement in `passive_enum`: `assetfinder <domain>`, merge into the candidate set.
- [ ] 13.1.2 Add binary to the worker image + tool reporting.
- [ ] 13.1.3 **GATE:** returns subdomains for `example.com`; results appear as `subdomain`
      observations attributed to source `assetfinder`; absent binary degrades cleanly.

### Step 2 — `subfinder` (already present — align with `Tools.md`)
- [ ] 13.2.1 Align flags, keep `-json` for parsing, confirm it consumes the keys from 13.0.4.
- [ ] 13.2.2 Tool-version reporting shows configured sources count.
- [ ] 13.2.3 **GATE:** with at least one API key set, subfinder returns strictly more
      subdomains than with none — proves the key plumbing actually works.

### Step 3 — `dnsx` (resolution backbone — everything downstream depends on it)
- [ ] 13.3.1 Implement as the primary resolver: `dnsx -silent` over the deduped candidate
      set; keep the stdlib resolver as the no-binary fallback.
- [ ] 13.3.2 Add binary + reporting.
- [ ] 13.3.3 **GATE:** only resolving names survive; wildcard domains do not produce
      thousands of phantom hosts; resolved IPs reach the coalesce barrier and become
      `port_scan` tasks.

### Step 4 — `shuffledns` (deep profile only)
- [ ] 13.4.1 Implement bruteforce: `-d <domain> -w <wordlist> -r <resolvers> -mode
      bruteforce -silent`. Deep profile only — it is high-volume.
- [ ] 13.4.2 Add binary (plus `massdns`) + reporting.
- [ ] 13.4.3 **GATE:** finds a known-unlisted subdomain on a domain you own; respects the
      rate limits; standard profile does **not** trigger it.

### Step 5 — `gobuster dns` (wildcard + vhost)
- [ ] 13.5.1 Implement: `gobuster dns -d <domain> -w <wordlist> --wildcard`.
- [ ] 13.5.2 Add binary + reporting.
- [ ] 13.5.3 **GATE:** wildcard domains are detected and flagged rather than exploded into
      false subdomains.

### Step 6 — `naabu` (already present — align with `Tools.md`)
- [ ] 13.6.1 Align to `-c 4 -rate 20 -top-ports 100 -silent`; keep params overridable
      (Phase 15). Confirm the connect-scan fallback without `CAP_NET_RAW`.
- [ ] 13.6.2 **GATE:** finds the expected open ports on `scanme.nmap.org`, and its output
      is what feeds nmap — never a full-range nmap.

### Step 7 — `nmap` (expand from `-sV` to the `Tools.md` profile)
- [ ] 13.7.1 Implement `-A -vvv -Pn --min-hostgroup 256 --min-rate 10000 --max-retries 3
      --defeat-rst-ratelimit --open -oA`. **Gate `-p-` behind the deep profile** — full-range
      `-A` on every host is very slow and very loud.
- [ ] 13.7.2 Parse `-oA`/greppable output into product + version observations.
- [ ] 13.7.3 **GATE:** service versions appear for non-HTTP ports (e.g. SSH) on
      `scanme.nmap.org`; standard profile stays on the naabu-supplied port list.

### Step 8 — `katana` (crawl — currently never invoked)
- [ ] 13.8.1 Implement: `katana -d 5 -jsl -c 3 -p 3 -rl 10 -silent`.
- [ ] 13.8.2 Add binary + reporting.
- [ ] 13.8.3 **GATE:** returns real linked paths for a site you own, and those paths seed
      the directory-brute stage instead of it guessing blind.

### Step 9 — `urlfinder` (passive URLs)
- [ ] 13.9.1 Implement: `urlfinder -silent`.
- [ ] 13.9.2 Add binary + reporting.
- [ ] 13.9.3 **GATE:** returns URLs without sending traffic to the target.

### Step 10 — `httpx` probe (align + chain)
- [ ] 13.10.1 Implement `-title -sc -cl -location -fr -silent -delay 1s`, taking the union
      of katana + urlfinder output as input, as `Tools.md` chains them.
- [ ] 13.10.2 **GATE:** live web services get title/status/content-length/redirect chain;
      dead ones are dropped; the `-delay` is honoured.

### Step 11 — `httpx` screenshots (+ fix the broken upload)
- [ ] 13.11.1 Implement `-sc -title -tech-detect -screenshot -timeout 200
      -screenshot-timeout 200`.
- [ ] 13.11.2 **Fix the existing bug:** the screenshot stage emits an object-storage key but
      never uploads the file, so every screenshot reference points at nothing. Upload via
      the gateway presign endpoint.
- [ ] 13.11.3 **GATE:** a screenshot is actually retrievable from object storage and renders
      in the service detail view.

### Step 12 — `nuclei` (wire the unreachable stage)
- [ ] 13.12.1 Wire `StageVulnCheck` into `scanner.Run()` and into the planner's DAG.
- [ ] 13.12.2 Implement `nuclei -l urls` (default templates) and `-t <dir>` for a pinned
      custom set; template updates handled like wordlists.
- [ ] 13.12.3 Add binary + reporting.
- [ ] 13.12.4 **GATE:** findings appear on the Findings page with correct severity; template
      version is recorded; a run with no findings does not fail the task.

### Step 13 — `gobuster dir` (directory search)
- [ ] 13.13.1 Implement `gobuster dir -u <url> -w <wordlist> -k`, plus `--exclude-length`
      to cut the false positives `Tools.md` warns about. Keep `ffuf` as the alternative.
- [ ] 13.13.2 Add binary + reporting.
- [ ] 13.13.3 **GATE:** discovers a known path on a site you own; false positives from
      uniform-size 40x/50x responses are filtered out; per-target concurrency is capped —
      this is the loudest stage in the pipeline.

### Step 14 — Close-out
- [ ] 13.14.1 End-to-end run over a scope you own with every tool enabled; confirm the full
      `Tools.md` sequence executes in order and the asset graph is populated at each stage.
- [ ] 13.14.2 Update `worker-pipeline.md` to match what is actually implemented.

## Phase 14 — Global search across all companies

Search is scoped to one company today (`/scopes/{id}/search`). Make it work across the
whole inventory, Shodan-style, for when there are many companies.

- [ ] 14.1 store: cross-scope search — drop the mandatory `scope_id` filter, return the
      owning company with each row.
- [ ] 14.2 search language: add a `company:` (alias `scope:`) field so results can be
      narrowed back down from a global query.
- [ ] 14.3 api: `GET /api/v1/search` (no scope in the path), with optional company filter
      and cursor pagination.
- [ ] 14.4 UI: promote Search to a global page — company column in results, click through
      to that company's host/service view, and a global/current-company toggle.
- [ ] 14.5 Performance: review indexes for cross-scope queries; the current ones assume a
      `scope_id` prefix and will not serve a global scan well.

## Phase 15 — Configurable scan parameters with saved presets

Every tool's flags are hardcoded today. Let users adjust them per scan and save their own
presets, with the `Tools.md` values as the shipped defaults.

- [ ] 15.1 schema: `scan_profile` table (name, owner, optional `scope_id` for
      company-specific presets, `params` jsonb, is_default).
- [ ] 15.2 Codify the built-in defaults per tool/stage from `Tools.md` in one place, so the
      UI can show "default vs. yours" and offer a reset.
- [ ] 15.3 `scanproto`: extend `Params` to carry a per-tool argument set, versioned like the
      rest of the contract.
- [ ] 15.4 planner: merge the selected profile's params into each job envelope.
- [ ] 15.5 api: CRUD for scan profiles + pick one when starting a run.
- [ ] 15.6 UI: scan-launch modal with a per-tool parameter editor (rate, ports, wordlist,
      timeouts, templates, depth) and "save as preset".
- [ ] 15.7 **Security: whitelist every settable parameter.** These values become process
      arguments on a scan box — never pass raw user strings to `exec`. Validate each field
      by type and allowed range, and reject anything unrecognised rather than forwarding it.
