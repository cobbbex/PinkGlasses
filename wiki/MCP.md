# MCP server

PinkGlasses has an MCP server, so an AI client — Claude Code, Claude Desktop,
anything that speaks the Model Context Protocol — can do what the web UI does:
read the inventory and findings, manage target groups, start, watch, pause,
stop and rerun scans, and keep schedules.

## How it is built, and why

It is a **thin adapter over the HTTP API**, nothing more. The API already holds
every rule that matters — roles, target authorization, the exit a scan needs,
the refusals written for a person — so the MCP server reimplements none of
them and cannot drift from them. It is the sixth binary in the control-plane
image (`/usr/local/bin/mcp`).

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
the server is started with `ASM_MCP_ALLOW_DELETE_COMPANY=true`, and then also
demands the company's exact name.

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
| Infrastructure | `list_workers` (workers, pools, runs' own fleets), `list_vpn_configs` (names only), `list_wordlists`, `alerts` |

Resources for the read side: `pinkglasses://companies`,
`pinkglasses://companies/{id}/summary`, `pinkglasses://hosts/{id}`,
`pinkglasses://runs/{id}`, `pinkglasses://services/{id}/screenshot` (the
PNG), `pinkglasses://scan-parameters`. Prompts: `triage_changes`,
`explain_host`, `plan_scan`.

## Running it

**Locally over stdio** (Claude Code, Claude Desktop). The binary is in the
published image; the token is the only configuration:

```bash
claude mcp add pinkglasses -e ASM_API_URL=http://localhost:8080 -e ASM_MCP_TOKEN=pgt_… \
  -- docker run -i --rm --network host -e ASM_API_URL -e ASM_MCP_TOKEN \
     --entrypoint /usr/local/bin/mcp ghcr.io/cobbbex/pinkglasses:latest
```

Point `ASM_API_URL` at wherever the api answers. Claude Desktop takes the same
command in its MCP servers configuration.

**On the network over streamable HTTP**: the api serves it itself, at `/mcp`
on the same address as the web app — `http://<host>:8080/mcp`. There is
nothing to enable and nothing else to deploy; it is up whenever the web app
is, and requests reach the router in-process rather than over a second hop.
Each request carries its own token as `Authorization: Bearer pgt_…`; the
server holds no credential of its own, and a request without a token gets the
API's own refusal. Put TLS in front before exposing it beyond the host, as with
the api.

```bash
claude mcp add --transport http pinkglasses http://localhost:8080/mcp \
  --header "Authorization: Bearer pgt_…"
```

| Variable | Meaning |
|---|---|
| `ASM_MCP_ALLOW_DELETE_COMPANY` | On the api: `true` adds the `delete_company` tool |
| `ASM_API_URL` | stdio binary: where the api answers (default `http://localhost:8080`) |
| `ASM_MCP_TOKEN` | stdio binary: the API token |

The `mcp` binary's own `ASM_MCP_TRANSPORT=http` mode still exists for running
it apart from the api; the api's `/mcp` is the same server and needs none of
that.

## A first conversation

*"Which companies can you see?"* → `list_companies`. *"What does lanet.ua
expose on 443?"* → `search` with `port:443 company:lanet.ua`, or with the
company id. *"Run a passive scan of it and tell me what changed."* →
`start_scan` with `profile: passive`, then `wait_for_run`, which returns the
diff. An active scan needs an exit; `start_scan` returns the API's sentence
saying so if none is possible, and `plan_scan` walks through what exists first.
