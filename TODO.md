# Build TODO — Attack Surface Monitor

Derived from `architecture.md` (v0.2) and `worker-pipeline.md`.
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
