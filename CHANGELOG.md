# Changelog

Each release says what changed and **what an upgrade needs**. Upgrading is always
`git pull && docker compose up --build -d` (or `pull` + `up -d` with the published
images); the notes say when anything more is involved. Migrations run on their own
at start. Open browser tabs notice a new version and offer a reload.

## v0.1.0 — 2026-09-24

The first tagged release: everything up to Phase 26's first items.

- Discovery (subfinder, DNS brute force, resolution), port scanning, service probing,
  technology detection from pages and response headers, screenshots, directory search
  and nuclei, per virtual host.
- Companies, target groups with active-scanning authorization, scan profiles, recurring
  and one-off schedules; pause, resume, stop, rerun; who started each run.
- Every active scan leaves through its own exit: a VPN gateway per run, or an enrolled
  pool of remote workers. VPN configurations belong to accounts.
- Hosts, Findings and Search with per-run history; Shodan-style search with facets.
- Accounts, roles, API tokens; a built-in MCP server at `/mcp` with a downloadable skill.
- Operations: a System page, scheduled backups, fleet failure evidence, lease hand-back
  after a worker reconnects, and resource limits so a scan cannot take the host down.

### Upgrade notes

- New services in `docker-compose.yml`: **backup** (writes to `./backups`). Review
  `ASM_BACKUP_*` in `.env.example`.
- New limits on worker containers (`ASM_WORKER_CPUS`, `ASM_WORKER_MEMORY`,
  `ASM_FLEET_WORKER_*`) and on DNS brute force (`ASM_BRUTE_PER_WORKER`): raise them in
  `.env` on a large host.
- Builds before this one sent no cache headers for the app shell; reload once with
  `Ctrl+Shift+R` after upgrading from one of them.
