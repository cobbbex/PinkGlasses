# API

Everything the UI does, it does through this API, so anything on a page can be
scripted. Base path `/api/v1`, JSON in and out, same host as the UI.

This page lists every route the server actually registers. A test
(`TestAPIDocCoversEveryRoute`) walks the live router and fails the build if a
route is added without a line here, so the list below is not a sketch of intent
— it is what the binary serves.

## Authentication

Three ways in, checked in this order. Every route past the three public ones
refuses a request that carries none of them with `401`.

| How | Send | Notes |
|---|---|---|
| Session cookie | `pg_session` (set by `POST /auth/login`) | what the UI uses; `HttpOnly`, `SameSite=Lax`, 12 h sliding |
| API token | `Authorization: Bearer pgt_…` or `X-API-Token: pgt_…` | for scripts and CI; may be narrower than its owner, never wider |
| Trusted proxy | `X-Forwarded-User` **and** `X-Proxy-Secret` | only when `ASM_TRUSTED_PROXY_SECRET` is set; the header alone is refused and logged |

```bash
curl -H "Authorization: Bearer pgt_…" https://host/api/v1/scopes
```

### Roles

Three, ordered; each adds to the one below. The role a route needs is in its
table below.

| Role | Adds |
|---|---|
| **viewer** | read everything; create and revoke your own API tokens |
| **operator** | companies, targets, scan profiles, alerts, wordlists — and starting runs |
| **admin** | accounts, everyone's tokens, workers and enrollment, VPN configurations |

A route above your role answers `403` with the role it needs.

### Errors

Every error is `{"error": "<one sentence, written for a person>"}` with the
matching status. The sentence says what went wrong and, where there is one,
the fix — `scanning from local workers needs a VPN so the scan never leaves
from this host's own address, and this company has no VPN configuration yet:
add one under VPN, or scan from a remote pool`.

| Status | Meaning |
|---|---|
| 400 | the request is malformed or missing something |
| 401 | not signed in, or the credential is no longer valid |
| 403 | signed in, wrong role — or a disabled account |
| 404 | no such thing |
| 409 | conflicts with state: last administrator, username taken, empty pool |
| 429 | sign-in rate limit — 10 tries per 15 minutes, per username and per address |

List endpoints return every row up to a fixed cap (hosts: 500; others smaller
or unbounded — the inventories this tool holds are thousands, not millions).
There is no cursor pagination yet.

## Public

| Route | Purpose |
|---|---|
| `GET /auth/status` | `{setup_required, user?}` — whether the install still needs its first administrator, and who you are if signed in |
| `POST /auth/setup` | create the first administrator — `{username, display_name, password}`; refuses once any account exists |
| `POST /auth/login` | `{username, password}` → sets the session cookie, returns `{user}` |

## Signed in (any role)

| Route | Purpose |
|---|---|
| `POST /auth/logout` | end this session |
| `GET /auth/me` | `{user, via, using_default_password}` |
| `POST /auth/password` | `{current_password, new_password}` — signs your other sessions out |

## Companies and targets

A *scope* is one company: its own targets, inventory and authorization. Every
asset route is under a scope.

| Route | Role | Purpose |
|---|---|---|
| `GET /scopes` | viewer | all companies; `?mine=true` narrows to ones you created |
| `POST /scopes` | operator | `{name}` |
| `GET /scopes/{scopeID}/summary` | viewer | dashboard counters: domains, ips, services, open_findings |
| `GET /scopes/{scopeID}/targets` | viewer | `?tag=` filters |
| `POST /scopes/{scopeID}/targets` | operator | `{value}` or `{values:[…]}`, `kind` (domain, cidr, ip, asn — inferred if omitted), `tags`, `mode` (`passive_only` default, `active`, `exclude`), `authorize: true` to record active authorization |

## Runs

| Route | Role | Purpose |
|---|---|---|
| `GET /scan-params` | viewer | every tunable a run accepts, with type, range, default and help |
| `GET /scopes/{scopeID}/scan-profiles` | viewer | saved parameter presets |
| `POST /scopes/{scopeID}/scan-profiles` | operator | `{name, params, global, default}` |
| `GET /scopes/{scopeID}/runs` | viewer | runs with progress counters |
| `POST /scopes/{scopeID}/runs` | operator | start a run — body below |
| `GET /runs/{runID}` | viewer | `{run, progress, fleet?}` — `fleet` is present when the run has its own containers, and carries the reason if it is waiting or failed |
| `GET /runs/{runID}/targets` | viewer | per-target status, counters, skip reasons |
| `GET /runs/{runID}/activity` | viewer | `{tasks, stages, workers}` — what is running where, right now |
| `GET /runs/{runID}/diff` | viewer | change events this run produced: `{kind, asset_kind, asset_id, before, after, created_at}` |
| `GET /runs/{runID}/events` | viewer | server-sent events stream; see the note under *Known gaps* |
| `POST /runs/{runID}/cancel` | operator | |

**Starting a run:**

```json
{
  "profile": "standard",          // passive | standard | deep
  "all": true,                    // or "targets": ["example.com"], or "tag": "prod"
  "exit": "local",                // required unless profile is passive
  "vpn_config_id": "…",           // local: the tunnel this run leaves through
  "pool_id": "…",                 // remote: the pool of enrolled workers instead
  "worker_count": 2,              // local only, 1–8
  "profile_id": "…",              // a saved preset
  "params": {"httpx_user_agent": "…"},   // ad-hoc overrides
  "wordlist_ids": ["…"]           // explicit lists; empty means the registry defaults
}
```

Active stages send traffic at the target, so a run with any needs an **exit**:
`local` — an ephemeral fleet behind a VPN gateway, needs `vpn_config_id` and a
provisioner; or `remote` — an existing pool with at least one active worker,
needs `pool_id`. There is no "direct from this host". A `passive` run needs
neither. Refusals are `400` (nothing chosen, bad ids) or `409` (no VPN config in
this company, empty pool). See [Where scans run from](VPN-Scanning).

## Inventory and search

| Route | Role | Purpose |
|---|---|---|
| `GET /scopes/{scopeID}/domains` | viewer | `?q=` substring |
| `GET /scopes/{scopeID}/graph` | viewer | `{nodes, edges}` for the name→address map |
| `GET /scopes/{scopeID}/hosts` | viewer | addresses with ASN, PTR, country, cloud |
| `GET /scopes/{scopeID}/hostrows` | viewer | the Hosts table: one row per name→address pair, `?q=` and `?unresolved=true` to include names that resolve to nothing. Returns `{rows, unresolved_hidden}` |
| `GET /hosts/{ipID}` | viewer | everything about one address: `{host, names, services, findings}`. Each name carries `history` (one entry per run that resolved it) and `also_resolved_to`; each service carries `history` (one entry per run that port-scanned the address), the latest banner/HTTP/TLS, technologies, and cookie **names** |
| `GET /hosts/{ipID}/services` | viewer | open ports only |
| `GET /services/{serviceID}/screenshot` | viewer | `image/png`, the most recent capture |
| `GET /scopes/{scopeID}/search` | viewer | `?q=` in the query language, one company |
| `GET /search` | viewer | `?q=` across every company; `?scope=` narrows |

**Query language.** Terms are `field:value`, joined with `AND` / `OR`, free text
searches banners and titles. Fields: `port`, `proto`, `ip`, `domain`, `country`,
`cloud`, `asn`, `product`, `version`, `tech`, `cookie`, `status`, `title`,
`cert.expires`, `new`, `severity`, `company`/`scope`. Numeric fields take `>=`
and friends; `cookie:webvpn*` matches cookie names by prefix — names only,
never values.

## Findings and alerts

| Route | Role | Purpose |
|---|---|---|
| `GET /scopes/{scopeID}/findings` | viewer | with per-run `history`, `presence` (active/gone) and `gone_since` |
| `PATCH /findings/{findingID}` | operator | `{status}`: `open`, `acknowledged`, `resolved`, `accepted_risk` |
| `GET /scopes/{scopeID}/notifications` | viewer | `{channels, events}` — the second lists the event kinds a channel may subscribe to |
| `POST /scopes/{scopeID}/notifications` | operator | `{name, kind: slack\|webhook, url, events, min_severity}` |
| `PATCH /notifications/{channelID}` | operator | `{enabled}` |
| `DELETE /notifications/{channelID}` | operator | |
| `POST /notifications/{channelID}/test` | operator | sends a test digest → `{sent, error?}` |
| `GET /scopes/{scopeID}/notifications/deliveries` | viewer | every delivery attempt, with status and error |

Event kinds: `new_finding`, `finding_gone`, `finding_returned`, `new_port`,
`new_subdomain`. One digest per completed run per channel.

## Wordlists

| Route | Role | Purpose |
|---|---|---|
| `GET /wordlists` | viewer | `?kind=dns\|dir\|resolvers` |
| `POST /wordlists` | operator | multipart: `file`, `name` (defaults to the filename), `kind` (default `dns`) |
| `PATCH /wordlists/{wordlistID}` | operator | `{is_default}` |
| `GET /wordlists/{wordlistID}/content` | viewer | the list, up to 4 MB |
| `PUT /wordlists/{wordlistID}/content` | operator | `{content}` — resolver lists are validated line by line |
| `DELETE /wordlists/{wordlistID}` | operator | built-in lists refuse |

## Workers and pools

| Route | Role | Purpose |
|---|---|---|
| `GET /workers` | viewer | every worker: status, egress, load, tools, `run_scoped` for a run's own containers |
| `GET /pools` | viewer | pools a run may choose as its remote exit, with `active_workers` |
| `POST /workers/enrollment-tokens` | admin | `{kind: vps\|local, name, pool_id, ttl_mins, max_uses}` → for `vps`: `{token, install_command, expires_in}`; for `local`: the compose command |
| `GET /workers/provision` | admin | `{enabled, count}` — whether a provisioner is configured and how many standing workers it runs |
| `POST /workers/provision` | admin | `{count}` — scale the standing local workers |
| `POST /workers/{workerID}/{action}` | admin | `approve`, `drain`, `resume`, `quarantine` |
| `DELETE /workers/{workerID}` | admin | a local worker's container is removed first |

## VPN configurations

| Route | Role | Purpose |
|---|---|---|
| `GET /scopes/{scopeID}/vpn-configs` | viewer | name, kind, endpoint host, last egress — **never the body** |
| `POST /scopes/{scopeID}/vpn-configs` | admin | multipart `file` + `name`, or JSON `{name, config}`; kind (wireguard/openvpn) and endpoint are detected from the body; a WireGuard config without a default route is refused |
| `DELETE /vpn-configs/{vpnID}` | admin | |

Bodies are sealed with AES-256-GCM at rest and are returned by no endpoint.

## Accounts and tokens

| Route | Role | Purpose |
|---|---|---|
| `GET /users` | admin | |
| `POST /users` | admin | `{username, display_name, password, role}`; an empty password makes a proxy-only account |
| `PATCH /users/{userID}` | admin | any of `{username, display_name, role, disabled, password}`; role and disabled changes end that user's sessions; the last enabled administrator cannot be demoted or disabled |
| `DELETE /users/{userID}` | admin | not yourself; not the last administrator |
| `GET /tokens` | viewer | yours; an administrator sees everyone's |
| `POST /tokens` | viewer | `{name, role, ttl_days}` → `{token, secret}` — the only time the secret is returned; `role` may not exceed yours |
| `DELETE /tokens/{tokenID}` | viewer | revoke yours; an administrator, anyone's |

## Agent API — what workers speak

Served by the **gateway** binary (`:8090`), the one component meant to be
reachable from outside. Workers authenticate with the credential minted at
enrollment (`X-Worker-Id`, `X-Worker-Credential`); results carry a per-task
lease token.

| Route | Purpose |
|---|---|
| `GET /healthz` | |
| `GET /install.sh` | the one-line VPS install script |
| `POST /agent/v1/enroll` | `{token, hostname, name, capabilities, tools, agent_version}` → `{worker_id, credential}`; a `local` token redeemed from a public address is downgraded to `vps` and needs approval |
| `GET /agent/v1/connect` | WebSocket control channel. Server → worker envelopes: `job`, `cancel`, `heartbeat_ack`, `rotate_cred`. Worker → server: heartbeats `{worker_id, running_tasks, stopping, at}`. A worker whose row no longer exists is closed with a policy-violation frame and re-enrols |
| `POST /agent/v1/results` | a batch of observations for one task: `{schema, job_id, task_id, lease_token, seq, final, status, observations, errors}`. Observations for assets outside the task's target are refused and the worker quarantined |
| `POST /agent/v1/artifacts/presign` | a presigned upload URL for a screenshot or raw output |

A **job** is `{job_id, run_id, task_id, lease_token, stage, profile, targets,
params, constraints, ingest}`; `constraints.allow`/`deny` are the CIDRs the
worker may and must not touch, enforced on the worker as well as at ingest.

## Provisioner API — internal

Served by the **provisioner** (`:8091`), the only container holding the Docker
socket. Never exposed; every call carries `X-Provisioner-Token`.

| Route | Purpose |
|---|---|
| `GET /v1/workers` | standing worker containers |
| `POST /v1/scale` | `{count}` |
| `POST /v1/remove` | `{name}` |
| `POST /v1/fleet/create` | `{run_id, workers, enroll_token, vpn_kind?, vpn_config?}` → `{gateway, workers, egress_ip}`; builds the gateway first and starts workers only once it is healthy |
| `POST /v1/fleet/remove` | `{run_id}` |
| `GET /v1/fleet/orphans` | run ids that still have containers, for the sweep |

## Known gaps

- **`GET /runs/{runID}/events` streams nothing.** The endpoint and the hub
  exist, and the UI subscribes to it — but nothing in the codebase publishes to
  the hub, so no event is ever sent. The UI works because it also polls every
  four seconds; the stream is decoration. Recorded in TODO.
- **No OpenAPI document.** architecture.md once said one was generated from the
  handlers; it never was. This page is the reference, kept honest by the test
  that walks the router.
- **No cursor pagination, no export endpoint.** Both were in the original sketch
  and neither exists.
