# MCP server

PinkGlasses has an MCP server, so an AI client — Claude Code, Claude Desktop,
anything that speaks the Model Context Protocol — can do what the web UI does:
read the inventory and findings, manage target groups, start, watch, pause,
stop and rerun scans, and keep schedules.

## How it is built, and why

It is a **thin adapter over the HTTP API**, nothing more. The API already holds
every rule that matters — roles, target authorization, the exit a scan needs,
the refusals written for a person — so the MCP server reimplements none of
them and cannot drift from them. It **runs inside the api**, served at `/mcp`
on the web app's own address, where its calls reach the router in-process; the
same code is also a binary in the control-plane image (`/usr/local/bin/mcp`)
for a local client over stdio.

It **authenticates with a PinkGlasses API token** (`Accounts → API tokens`,
or `POST /tokens`). Two things follow: a *viewer* token gives a read-only MCP
server with no configuration, and every run started or group removed through
a model shows in the audit log under that token's account, like any other API
call.

Tools are **task-shaped, not route-shaped**: about two dozen, named the way a
person would ask (`search`, `get_host`, `start_scan`, `wait_for_run`), rather
than one per HTTP route. Results are compact JSON with ids, so calls chain.

Destructive tools — `remove_target_group`, `delete_run`, `remove_schedule` —
refuse unless called with `confirm: true`. `delete_company` exists only when
`ASM_MCP_ALLOW_DELETE_COMPANY=true` is set — on the api service in compose, or
on the stdio binary — and then also demands the company's exact name.

A scan started with a local exit names a VPN configuration, and that must be
one of the **token owner's own** (`list_vpn_configs` shows exactly those):
configurations belong to accounts, not companies, so a token sees the same
list in every company and never another account's.

**Not exposed**: worker enrolment and removal, VPN configuration bodies, alert
channel secrets, wordlist editing, API tokens and accounts. Those hand out
credentials, and a model has no business with them; the web UI and the API
remain for people. A test in `internal/mcpserver` walks the route table and
fails the build if a viewer or operator route is reachable through no tool or
resource and is not on that list with a reason.

## Tools

| Group | Tools |
|---|---|
| Orientation | `list_companies`, `company_summary` |
| Inventory | `search` (the query language, with facets), `list_hosts`, `get_host`, `list_findings`, `update_finding` |
| Targets | `list_target_groups`, `add_targets`, `edit_target_group`, `remove_target_group` |
| Scanning | `start_scan` (now, once at a time, or on a repeat), `list_runs`, `get_run`, `wait_for_run`, `run_diff`, `pause_run`, `resume_run`, `stop_run`, `rerun`, `delete_run`, `list_schedules`, `edit_schedule`, `remove_schedule`, `scan_parameters` |
| Infrastructure | `list_workers` (workers, pools, runs' own fleets), `list_vpn_configs` (the token owner's, names only, usable in any company), `list_wordlists`, `alerts` |

Resources for the read side: `pinkglasses://companies`,
`pinkglasses://companies/{id}/summary`, `pinkglasses://hosts/{id}`,
`pinkglasses://runs/{id}`, `pinkglasses://services/{id}/screenshot` (the
PNG), `pinkglasses://scan-parameters`. Prompts: `triage_changes`,
`explain_host`, `plan_scan`.

## Running it

**Over HTTP, from the running app** — the usual way. The api serves the MCP
server itself, at `/mcp` on the same address as the web app:
`http://<host>:8080/mcp`. There is nothing to enable and nothing else to
deploy; it is up whenever the web app is. Each request carries its own token as
`Authorization: Bearer pgt_…`; the server holds no credential of its own, and
a request without a token gets the API's own refusal. It is reachable wherever
the web app is — the same address, port and hostname, plus `/mcp` — so put TLS
in front before exposing it beyond the host, and if a reverse proxy sits in
front, forward `/mcp` with the `Authorization` header and without response
buffering, as for the run events stream.

```bash
claude mcp add --transport http pinkglasses http://localhost:8080/mcp \
  --header "Authorization: Bearer pgt_…"
```

Claude Desktop and other clients take the same URL and header in their MCP
servers configuration. In **Cursor**: Settings → MCP → *Add new global MCP
server* opens `~/.cursor/mcp.json` (or `.cursor/mcp.json` in a project — keep
it out of version control, it holds the token):

```json
{
  "mcpServers": {
    "pinkglasses": {
      "url": "http://localhost:8080/mcp",
      "headers": { "Authorization": "Bearer pgt_…" }
    }
  }
}
```

**Locally over stdio**, for a client that cannot speak HTTP or a laptop that
reaches the api through a tunnel of its own. The binary is in the published
image; the token is the only configuration:

```bash
claude mcp add pinkglasses -e ASM_API_URL=http://localhost:8080 -e ASM_MCP_TOKEN=pgt_… \
  -- docker run -i --rm --network host -e ASM_API_URL -e ASM_MCP_TOKEN \
     --entrypoint /usr/local/bin/mcp ghcr.io/cobbbex/pinkglasses:latest
```

Point `ASM_API_URL` at wherever the api answers. The same command in Cursor's
`mcp.json` is `"command": "docker"` with those arguments under `"args"`.

| Variable | Where | Meaning |
|---|---|---|
| `ASM_MCP_ALLOW_DELETE_COMPANY` | api service, or the binary | `true` adds the `delete_company` tool |
| `ASM_API_URL` | stdio binary | where the api answers (default `http://localhost:8080`) |
| `ASM_MCP_TOKEN` | stdio binary | the API token |

The binary's own `ASM_MCP_TRANSPORT=http` / `ASM_MCP_ADDR` mode still exists
for running it apart from the api; the api's `/mcp` is the same server and
needs none of that.

## A first conversation

*"Which companies can you see?"* → `list_companies`. *"What does lanet.ua
expose on 443?"* → `search` with `port:443 company:lanet.ua`, or with the
company id. *"Run a passive scan of it and tell me what changed."* →
`start_scan` with `profile: passive`, then `wait_for_run`, which returns the
diff. An active scan needs an exit; `start_scan` returns the API's sentence
saying so if none is possible, and `plan_scan` walks through what exists first.
