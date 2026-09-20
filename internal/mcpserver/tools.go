package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Options tune what the server exposes.
type Options struct {
	// AllowDeleteCompany adds the delete_company tool. Off by default: it takes
	// a company's whole inventory and history with it.
	AllowDeleteCompany bool
}

// toolDef is one tool: its schema, the API routes it uses (for the coverage
// test), and the handler. Handlers receive decoded arguments and return any
// JSON-serialisable value; the server renders it as text.
type toolDef struct {
	Name        string
	Description string
	Schema      map[string]any
	ReadOnly    bool
	Destructive bool
	Routes      []string // "GET /scopes/{scopeID}/summary"
	Run         func(ctx context.Context, c *Client, a args) (any, error)
}

type args map[string]any

func (a args) str(k string) string {
	if v, ok := a[k].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}
func (a args) boolean(k string) bool { v, _ := a[k].(bool); return v }
func (a args) integer(k string, def int) int {
	switch v := a[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return def
}
func (a args) strs(k string) []string {
	raw, ok := a[k].([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, x := range raw {
		if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}
func (a args) has(k string) bool { _, ok := a[k]; return ok }
func (a args) strMap(k string) map[string]string {
	raw, ok := a[k].(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for kk, v := range raw {
		out[kk] = fmt.Sprint(v)
	}
	return out
}

// schema helpers
func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}
func str(desc string, enum ...string) map[string]any {
	m := map[string]any{"type": "string", "description": desc}
	if len(enum) > 0 {
		m["enum"] = enum
	}
	return m
}
func integer(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}
func boolean(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}
func strList(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}

var errConfirm = errors.New("this is destructive; call again with confirm: true to do it")

// Tools is the whole tool set, in the order a client lists them.
func Tools(o Options) []toolDef {
	t := []toolDef{
		// ---------------- orientation ----------------
		{
			Name: "list_companies", ReadOnly: true,
			Description: "List the companies (scopes) this token can see, with ids. Every other tool takes a company_id from here.",
			Schema:      obj(map[string]any{}),
			Routes:      []string{"GET /scopes"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				var out []map[string]any
				return out, c.get(ctx, "/scopes", &out)
			},
		},
		{
			Name: "company_summary", ReadOnly: true,
			Description: "Dashboard counters for a company: resolving names, hosts, services, open findings — and what it owns (target groups, runs, schedules) with whether a run is going.",
			Schema:      obj(map[string]any{"company_id": str("Company id")}, "company_id"),
			Routes:      []string{"GET /scopes/{scopeID}/summary", "GET /scopes/{scopeID}/footprint"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				id := a.str("company_id")
				var sum, fp map[string]any
				if err := c.get(ctx, "/scopes/"+id+"/summary", &sum); err != nil {
					return nil, err
				}
				if err := c.get(ctx, "/scopes/"+id+"/footprint", &fp); err != nil {
					return nil, err
				}
				return map[string]any{"summary": sum, "owns": fp}, nil
			},
		},
		// ---------------- inventory ----------------
		{
			Name: "search", ReadOnly: true,
			Description: "Search the inventory with the query language (port:443 product:nginx, title:*login*, cookie:webvpn*, cert.expires<30d, new:7d, severity>=high; * is a wildcard, field:* means the field has a value, a bare * is everything). Returns one row per service per site plus a summary by product, port, technology, title and status. Omit company_id to search every company.",
			Schema: obj(map[string]any{
				"query":      str("The query; use * for everything"),
				"company_id": str("Limit to one company; omit for all"),
			}, "query"),
			Routes: []string{"GET /scopes/{scopeID}/search", "GET /scopes/{scopeID}/search/facets", "GET /search", "GET /search/facets"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				qq := a.str("query")
				if qq == "" {
					qq = "*"
				}
				base := "/search"
				if id := a.str("company_id"); id != "" {
					base = "/scopes/" + id + "/search"
				}
				var rows []map[string]any
				var facets map[string]any
				if err := c.get(ctx, base+"?q="+q(qq), &rows); err != nil {
					return nil, err
				}
				if err := c.get(ctx, base+"/facets?q="+q(qq), &facets); err != nil {
					return nil, err
				}
				return map[string]any{"summary": facets, "rows": trim(rows, 200)}, nil
			},
		},
		{
			Name: "list_hosts", ReadOnly: true,
			Description: "The Hosts table of a company: one row per name→address pair with reverse DNS, ASN, service count and when it was last seen. Filter with a substring; include names that resolve to nothing with include_unresolved.",
			Schema: obj(map[string]any{
				"company_id":         str("Company id"),
				"filter":             str("Substring of a name, address or AS name"),
				"include_unresolved": boolean("Also list names that currently resolve to nothing"),
				"limit":              integer("Max rows, default 200"),
			}, "company_id"),
			Routes: []string{"GET /scopes/{scopeID}/hostrows", "GET /scopes/{scopeID}/hosts", "GET /scopes/{scopeID}/domains"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				var out struct {
					Rows             []map[string]any `json:"rows"`
					UnresolvedHidden int              `json:"unresolved_hidden"`
				}
				path := fmt.Sprintf("/scopes/%s/hostrows?q=%s&unresolved=%t", a.str("company_id"), q(a.str("filter")), a.boolean("include_unresolved"))
				if err := c.get(ctx, path, &out); err != nil {
					return nil, err
				}
				return map[string]any{"rows": trim(out.Rows, a.integer("limit", 200)), "unresolved_hidden": out.UnresolvedHidden, "total": len(out.Rows)}, nil
			},
		},
		{
			Name: "get_host", ReadOnly: true,
			Description: "Everything about one address (the host page): network, every name resolving to it with history, every open port with what answered — banner, version, the sites on it by name with title and status, cookie names, headers, TLS — and its findings and discovered paths. host_id is the ip_id from list_hosts or search.",
			Schema:      obj(map[string]any{"host_id": str("The address id (ip_id)")}, "host_id"),
			Routes:      []string{"GET /hosts/{ipID}", "GET /hosts/{ipID}/services"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				var out map[string]any
				return out, c.get(ctx, "/hosts/"+a.str("host_id"), &out)
			},
		},
		{
			Name: "list_findings", ReadOnly: true,
			Description: "A company's findings with per-run history and presence (active, or gone since a later run no longer saw it). Filter by severity and presence. Discovered paths are kind content_discovery; nuclei matches are kind nuclei:<template>.",
			Schema: obj(map[string]any{
				"company_id": str("Company id"),
				"severity":   str("Only this severity", "info", "low", "medium", "high", "critical"),
				"presence":   str("active or gone", "active", "gone"),
				"kind":       str("Only this kind, e.g. content_discovery or a nuclei:<template> id"),
				"limit":      integer("Max rows, default 200"),
			}, "company_id"),
			Routes: []string{"GET /scopes/{scopeID}/findings"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				var all []map[string]any
				if err := c.get(ctx, "/scopes/"+a.str("company_id")+"/findings", &all); err != nil {
					return nil, err
				}
				var out []map[string]any
				for _, f := range all {
					if s := a.str("severity"); s != "" && f["severity"] != s {
						continue
					}
					if p := a.str("presence"); p != "" && fmt.Sprint(f["presence"]) != p {
						continue
					}
					if k := a.str("kind"); k != "" && f["kind"] != k {
						continue
					}
					delete(f, "history") // the dots are a UI thing; seen_in/covered_runs say the same
					out = append(out, f)
				}
				return map[string]any{"findings": trim(out, a.integer("limit", 200)), "total": len(out)}, nil
			},
		},
		{
			Name:        "update_finding",
			Description: "Set a finding's status: open, acknowledged or resolved.",
			Schema:      obj(map[string]any{"finding_id": str("Finding id"), "status": str("New status", "open", "acknowledged", "resolved")}, "finding_id", "status"),
			Routes:      []string{"PATCH /findings/{findingID}"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				var out map[string]any
				return out, c.patch(ctx, "/findings/"+a.str("finding_id"), map[string]any{"status": a.str("status")}, &out)
			},
		},
		// ---------------- targets ----------------
		{
			Name: "list_target_groups", ReadOnly: true,
			Description: "A company's target groups — a name and its entries (domains, IPs, CIDRs) — and whether each is authorized for active scanning. A scan picks groups by id.",
			Schema:      obj(map[string]any{"company_id": str("Company id")}, "company_id"),
			Routes:      []string{"GET /scopes/{scopeID}/target-groups", "GET /scopes/{scopeID}/targets"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				var out []map[string]any
				return out, c.get(ctx, "/scopes/"+a.str("company_id")+"/target-groups", &out)
			},
		},
		{
			Name:        "add_targets",
			Description: "Add a group of targets to a company: a list of domains, IPs or CIDRs under one name (defaults to the first entry). authorize: true records that active scanning of these is permitted, under the token's account — only for infrastructure the caller is authorized to scan; without it they get passive discovery only.",
			Schema: obj(map[string]any{
				"company_id": str("Company id"),
				"values":     strList("Domains, IPs or CIDRs"),
				"name":       str("Group name; defaults to the first value"),
				"tags":       strList("Tags applied to every entry"),
				"authorize":  boolean("Record authorization for active scanning"),
			}, "company_id", "values"),
			Routes: []string{"POST /scopes/{scopeID}/target-groups", "POST /scopes/{scopeID}/targets"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				body := map[string]any{"values": a.strs("values"), "tags": a.strs("tags"), "authorize": a.boolean("authorize")}
				if n := a.str("name"); n != "" {
					body["name"] = n
				}
				var out map[string]any
				return out, c.post(ctx, "/scopes/"+a.str("company_id")+"/target-groups", body, &out)
			},
		},
		{
			Name:        "edit_target_group",
			Description: "Edit a target group as one thing: rename it, replace its list (entries not in values are removed, new ones added), set tags, or tick/untick active-scanning authorization for every entry. Omit a field to leave it.",
			Schema: obj(map[string]any{
				"company_id": str("Company id"),
				"group_id":   str("Group id"),
				"name":       str("New name"),
				"values":     strList("The full list the group should have"),
				"tags":       strList("Tags for every entry"),
				"authorize":  boolean("Authorization for every entry"),
			}, "company_id", "group_id"),
			Routes: []string{"PATCH /scopes/{scopeID}/target-groups/{groupID}", "PATCH /scopes/{scopeID}/targets/{targetID}"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				body := map[string]any{}
				if a.has("name") {
					body["name"] = a.str("name")
				}
				if a.has("values") {
					body["values"] = a.strs("values")
				}
				if a.has("tags") {
					body["tags"] = a.strs("tags")
				}
				if a.has("authorize") {
					body["authorize"] = a.boolean("authorize")
				}
				var out map[string]any
				return out, c.patch(ctx, "/scopes/"+a.str("company_id")+"/target-groups/"+a.str("group_id"), body, &out)
			},
		},
		{
			Name: "remove_target_group", Destructive: true,
			Description: "Remove a target group and its entries from a company; future scans stop covering them. What earlier scans found stays in the inventory. Requires confirm: true.",
			Schema:      obj(map[string]any{"company_id": str("Company id"), "group_id": str("Group id"), "confirm": boolean("Must be true")}, "company_id", "group_id"),
			Routes:      []string{"DELETE /scopes/{scopeID}/target-groups/{groupID}", "DELETE /scopes/{scopeID}/targets/{targetID}"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				if !a.boolean("confirm") {
					return nil, errConfirm
				}
				var out map[string]any
				return out, c.del(ctx, "/scopes/"+a.str("company_id")+"/target-groups/"+a.str("group_id"), &out)
			},
		},
		// ---------------- scanning ----------------
		{
			Name:        "start_scan",
			Description: "Start a scan now, once at a time, or on a repeat. profile: passive (public sources only, no packets at the target, needs no exit), standard, or deep. An active profile needs an exit: local (the run builds its own workers behind a VPN; needs vpn_config_id from list_vpn_configs) or remote (an enrolled pool; needs pool_id from list_workers). Targets default to every group; narrow with target_group_ids. when: now returns the run; once needs start_at; repeat takes every_hours (1..8784, e.g. 24, 168) and optional start_at, and returns the schedule. The API refuses with a sentence naming the fix when something is missing — return it as is.",
			Schema: obj(map[string]any{
				"company_id":       str("Company id"),
				"profile":          str("Scan profile", "passive", "standard", "deep"),
				"target_group_ids": strList("Groups to cover; omit for all"),
				"exit":             str("Where active stages leave from", "local", "remote"),
				"vpn_config_id":    str("For exit local: the VPN configuration"),
				"pool_id":          str("For exit remote: the pool of enrolled workers"),
				"worker_count":     integer("For exit local: 1–8 workers; omit for Auto"),
				"params":           map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "Per-tool overrides, keys from scan_parameters"},
				"when":             str("now, once or repeat; default now", "now", "once", "repeat"),
				"start_at":         str("RFC3339 time for once, or the first run of a repeat"),
				"every_hours":      integer("Cadence for repeat"),
			}, "company_id", "profile"),
			Routes: []string{"POST /scopes/{scopeID}/runs", "POST /scopes/{scopeID}/schedules"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				body := map[string]any{"profile": a.str("profile")}
				if g := a.strs("target_group_ids"); len(g) > 0 {
					body["target_group_ids"] = g
				}
				if e := a.str("exit"); e != "" {
					body["exit"] = e
				}
				if v := a.str("vpn_config_id"); v != "" {
					body["vpn_config_id"] = v
				}
				if v := a.str("pool_id"); v != "" {
					body["pool_id"] = v
				}
				if n := a.integer("worker_count", 0); n > 0 {
					body["worker_count"] = n
				}
				if p := a.strMap("params"); len(p) > 0 {
					body["params"] = p
				}
				when := a.str("when")
				if when == "" {
					when = "now"
				}
				id := a.str("company_id")
				switch when {
				case "now":
					if _, ok := body["target_group_ids"]; !ok {
						body["all"] = true
					}
					var out map[string]any
					return out, c.post(ctx, "/scopes/"+id+"/runs", body, &out)
				case "once":
					if a.str("start_at") == "" {
						return nil, errors.New("once needs start_at (RFC3339); to scan right now use when: now")
					}
					body["every_hours"] = 0
					body["start_at"] = a.str("start_at")
				case "repeat":
					h := a.integer("every_hours", 0)
					if h < 1 {
						return nil, errors.New("repeat needs every_hours, 1 to 8784")
					}
					body["every_hours"] = h
					if s := a.str("start_at"); s != "" {
						body["start_at"] = s
					}
				default:
					return nil, errors.New("when must be now, once or repeat")
				}
				var out map[string]any
				return out, c.post(ctx, "/scopes/"+id+"/schedules", body, &out)
			},
		},
		{
			Name: "list_runs", ReadOnly: true,
			Description: "A company's runs, newest first, with status, profile, progress counters and the targets covered.",
			Schema:      obj(map[string]any{"company_id": str("Company id"), "limit": integer("Max rows, default 50")}, "company_id"),
			Routes:      []string{"GET /scopes/{scopeID}/runs"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				var out []map[string]any
				if err := c.get(ctx, "/scopes/"+a.str("company_id")+"/runs", &out); err != nil {
					return nil, err
				}
				return trim(out, a.integer("limit", 50)), nil
			},
		},
		{
			Name: "get_run", ReadOnly: true,
			Description: "One run in full: status and progress, its own fleet if any (gateway state, exit address, or why it could not start), per-target progress, and what is running where right now.",
			Schema:      obj(map[string]any{"run_id": str("Run id")}, "run_id"),
			Routes:      []string{"GET /runs/{runID}", "GET /runs/{runID}/targets", "GET /runs/{runID}/activity", "GET /runs/{runID}/footprint"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				return runView(ctx, c, a.str("run_id"))
			},
		},
		{
			Name: "wait_for_run", ReadOnly: true,
			Description: "Block until a run finishes (completed, failed or stopped) or timeout_seconds pass (default 600, max 3600), then return its final state and, when it completed, what changed against the previous run.",
			Schema:      obj(map[string]any{"run_id": str("Run id"), "timeout_seconds": integer("How long to wait, default 600")}, "run_id"),
			Routes:      []string{"GET /runs/{runID}/diff"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				id := a.str("run_id")
				limit := time.Duration(min(max(a.integer("timeout_seconds", 600), 1), 3600)) * time.Second
				deadline := time.Now().Add(limit)
				for {
					var r struct {
						Run struct {
							Status string `json:"status"`
						} `json:"run"`
					}
					if err := c.get(ctx, "/runs/"+id, &r); err != nil {
						return nil, err
					}
					switch r.Run.Status {
					case "completed", "failed", "cancelled":
						view, err := runView(ctx, c, id)
						if err != nil {
							return nil, err
						}
						if r.Run.Status == "completed" {
							var diff []map[string]any
							if err := c.get(ctx, "/runs/"+id+"/diff", &diff); err == nil {
								view["changes"] = trim(diff, 200)
							}
						}
						return view, nil
					}
					if time.Now().After(deadline) {
						view, err := runView(ctx, c, id)
						if err != nil {
							return nil, err
						}
						view["timed_out"] = true
						return view, nil
					}
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(5 * time.Second):
					}
				}
			},
		},
		{
			Name: "run_diff", ReadOnly: true,
			Description: "What a completed run changed against the previous one: new, changed and gone assets and findings.",
			Schema:      obj(map[string]any{"run_id": str("Run id")}, "run_id"),
			Routes:      []string{"GET /runs/{runID}/diff"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				var out []map[string]any
				return out, c.get(ctx, "/runs/"+a.str("run_id")+"/diff", &out)
			},
		},
		{
			Name:        "pause_run",
			Description: "Hold a running run: nothing more is leased, tasks in flight finish, its own workers stay up.",
			Schema:      obj(map[string]any{"run_id": str("Run id")}, "run_id"),
			Routes:      []string{"POST /runs/{runID}/pause"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				var out map[string]any
				return out, c.post(ctx, "/runs/"+a.str("run_id")+"/pause", nil, &out)
			},
		},
		{
			Name:        "resume_run",
			Description: "Continue a paused run.",
			Schema:      obj(map[string]any{"run_id": str("Run id")}, "run_id"),
			Routes:      []string{"POST /runs/{runID}/resume"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				var out map[string]any
				return out, c.post(ctx, "/runs/"+a.str("run_id")+"/resume", nil, &out)
			},
		},
		{
			Name:        "stop_run",
			Description: "Stop a run: unfinished tasks are cancelled and its own workers are torn down.",
			Schema:      obj(map[string]any{"run_id": str("Run id")}, "run_id"),
			Routes:      []string{"POST /runs/{runID}/cancel"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				var out map[string]any
				return out, c.post(ctx, "/runs/"+a.str("run_id")+"/cancel", nil, &out)
			},
		},
		{
			Name:        "rerun",
			Description: "Start a new run with a finished run's targets, profile, settings, wordlists and exit.",
			Schema:      obj(map[string]any{"run_id": str("Run id")}, "run_id"),
			Routes:      []string{"POST /runs/{runID}/rerun"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				var out map[string]any
				return out, c.post(ctx, "/runs/"+a.str("run_id")+"/rerun", nil, &out)
			},
		},
		{
			Name: "delete_run", Destructive: true,
			Description: "Delete a finished run with everything it recorded — tasks, observations, screenshots, the history dots it contributed. Hosts and findings other runs saw stay. Requires confirm: true.",
			Schema:      obj(map[string]any{"run_id": str("Run id"), "confirm": boolean("Must be true")}, "run_id"),
			Routes:      []string{"DELETE /runs/{runID}"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				if !a.boolean("confirm") {
					return nil, errConfirm
				}
				var out map[string]any
				return out, c.del(ctx, "/runs/"+a.str("run_id"), &out)
			},
		},
		{
			Name: "list_schedules", ReadOnly: true,
			Description: "A company's scheduled scans: cadence (every_hours, 0 = one-off), next run, last run, target groups, and why the last attempt did not start if it did not.",
			Schema:      obj(map[string]any{"company_id": str("Company id")}, "company_id"),
			Routes:      []string{"GET /scopes/{scopeID}/schedules"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				var out []map[string]any
				return out, c.get(ctx, "/scopes/"+a.str("company_id")+"/schedules", &out)
			},
		},
		{
			Name:        "edit_schedule",
			Description: "Pause (enabled: false), resume, change the cadence, move the next run (start_at) or change the target groups of a schedule. Omit a field to leave it.",
			Schema: obj(map[string]any{
				"schedule_id":      str("Schedule id"),
				"enabled":          boolean("false pauses, true resumes"),
				"every_hours":      integer("New cadence, 1..8784"),
				"start_at":         str("RFC3339 time of the next run"),
				"target_group_ids": strList("Groups to cover; [] means all"),
			}, "schedule_id"),
			Routes: []string{"PATCH /schedules/{scheduleID}"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				body := map[string]any{}
				if a.has("enabled") {
					body["enabled"] = a.boolean("enabled")
				}
				if a.has("every_hours") {
					body["every_hours"] = a.integer("every_hours", 0)
				}
				if a.has("start_at") {
					body["start_at"] = a.str("start_at")
				}
				if a.has("target_group_ids") {
					body["target_group_ids"] = a.strs("target_group_ids")
				}
				var out map[string]any
				return out, c.patch(ctx, "/schedules/"+a.str("schedule_id"), body, &out)
			},
		},
		{
			Name: "remove_schedule", Destructive: true,
			Description: "Delete a scheduled scan. Requires confirm: true.",
			Schema:      obj(map[string]any{"schedule_id": str("Schedule id"), "confirm": boolean("Must be true")}, "schedule_id"),
			Routes:      []string{"DELETE /schedules/{scheduleID}"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				if !a.boolean("confirm") {
					return nil, errConfirm
				}
				var out map[string]any
				return out, c.del(ctx, "/schedules/"+a.str("schedule_id"), &out)
			},
		},
		{
			Name: "scan_parameters", ReadOnly: true,
			Description: "Every tunable a run accepts under params — key, tool, type, range, default and what it does — plus a company's saved presets.",
			Schema:      obj(map[string]any{"company_id": str("Company id, to include its saved presets")}),
			Routes:      []string{"GET /scan-params", "GET /scopes/{scopeID}/scan-profiles"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				var params any
				if err := c.get(ctx, "/scan-params", &params); err != nil {
					return nil, err
				}
				out := map[string]any{"parameters": params}
				if id := a.str("company_id"); id != "" {
					var presets any
					if err := c.get(ctx, "/scopes/"+id+"/scan-profiles", &presets); err == nil {
						out["presets"] = presets
					}
				}
				return out, nil
			},
		},
		// ---------------- infrastructure ----------------
		{
			Name: "list_workers", ReadOnly: true,
			Description: "Workers and where scans can run from: the standing local worker, enrolled VPS workers with their pools (a pool with active remote workers can be a scan's remote exit), and runs' own fleets — each VPN gateway with its tunnel state and exit address.",
			Schema:      obj(map[string]any{}),
			Routes:      []string{"GET /workers", "GET /pools", "GET /fleets"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				var workers, pools, fleets []map[string]any
				if err := c.get(ctx, "/workers", &workers); err != nil {
					return nil, err
				}
				if err := c.get(ctx, "/pools", &pools); err != nil {
					return nil, err
				}
				if err := c.get(ctx, "/fleets", &fleets); err != nil {
					return nil, err
				}
				return map[string]any{"workers": workers, "pools": pools, "run_fleets": fleets}, nil
			},
		},
		{
			Name: "list_vpn_configs", ReadOnly: true,
			Description: "The VPN configurations of the account this token belongs to, by name and kind (never their contents), with the exit address last measured. They are usable in any company. Pick one's id as vpn_config_id for a local scan.",
			Schema:      obj(map[string]any{}),
			Routes:      []string{"GET /vpn-configs"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				var out map[string]any
				return out, c.get(ctx, "/vpn-configs", &out)
			},
		},
		{
			Name: "list_wordlists", ReadOnly: true,
			Description: "The wordlists workers can use for DNS brute force, resolvers and directory search, with size, kind and whether each is ready.",
			Schema:      obj(map[string]any{}),
			Routes:      []string{"GET /wordlists"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				var out []map[string]any
				return out, c.get(ctx, "/wordlists", &out)
			},
		},
		{
			Name: "alerts", ReadOnly: true,
			Description: "A company's alert channels (Slack or webhook) and the recent digests delivered to them.",
			Schema:      obj(map[string]any{"company_id": str("Company id")}, "company_id"),
			Routes:      []string{"GET /scopes/{scopeID}/notifications", "GET /scopes/{scopeID}/notifications/deliveries"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				id := a.str("company_id")
				var ch, dl any
				if err := c.get(ctx, "/scopes/"+id+"/notifications", &ch); err != nil {
					return nil, err
				}
				if err := c.get(ctx, "/scopes/"+id+"/notifications/deliveries", &dl); err != nil {
					return nil, err
				}
				return map[string]any{"channels": ch, "deliveries": dl}, nil
			},
		},
	}
	if o.AllowDeleteCompany {
		t = append(t, toolDef{
			Name: "delete_company", Destructive: true,
			Description: "Delete a company with everything it owns — inventory, runs, findings, schedules, alert channels. Refused while a run of it is going. Admin only. Requires confirm: true and the company's exact name.",
			Schema:      obj(map[string]any{"company_id": str("Company id"), "name": str("The company's exact name, typed back"), "confirm": boolean("Must be true")}, "company_id", "name"),
			Routes:      []string{"DELETE /scopes/{scopeID}"},
			Run: func(ctx context.Context, c *Client, a args) (any, error) {
				if !a.boolean("confirm") {
					return nil, errConfirm
				}
				var fp map[string]any
				if err := c.get(ctx, "/scopes/"+a.str("company_id")+"/footprint", &fp); err != nil {
					return nil, err
				}
				if fmt.Sprint(fp["name"]) != a.str("name") {
					return nil, fmt.Errorf("name does not match: the company is %q", fp["name"])
				}
				var out map[string]any
				return out, c.del(ctx, "/scopes/"+a.str("company_id"), &out)
			},
		})
	}
	return t
}

// runView assembles what the run page shows.
func runView(ctx context.Context, c *Client, id string) (map[string]any, error) {
	var run map[string]any
	if err := c.get(ctx, "/runs/"+id, &run); err != nil {
		return nil, err
	}
	var targets []map[string]any
	_ = c.get(ctx, "/runs/"+id+"/targets", &targets)
	var activity map[string]any
	_ = c.get(ctx, "/runs/"+id+"/activity", &activity)
	run["targets"] = targets
	if activity != nil {
		run["stages"] = activity["stages"]
		run["workers"] = activity["workers"]
		if tasks, ok := activity["tasks"].([]any); ok {
			run["recent_tasks"] = tasks[:min(len(tasks), 30)]
		}
	}
	return run, nil
}

func trim[T any](rows []T, n int) []T {
	if n <= 0 || len(rows) <= n {
		return rows
	}
	return rows[:n]
}

// CoveredRoutes is every "METHOD /path" some tool or resource uses.
func CoveredRoutes() map[string]bool {
	out := map[string]bool{}
	for _, t := range Tools(Options{AllowDeleteCompany: true}) {
		for _, r := range t.Routes {
			out[r] = true
		}
	}
	for _, r := range resourceRoutes {
		out[r] = true
	}
	return out
}

// register adds every tool to a server, bound to one client.
func register(s *mcp.Server, c *Client, o Options) {
	for _, def := range Tools(o) {
		def := def
		readOnly, destructive := def.ReadOnly, def.Destructive
		s.AddTool(&mcp.Tool{
			Name:        def.Name,
			Description: def.Description,
			InputSchema: def.Schema,
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: readOnly, DestructiveHint: &destructive},
		}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var a args
			if raw := req.Params.Arguments; raw != nil {
				if err := json.Unmarshal(raw, &a); err != nil {
					return toolError("bad arguments: " + err.Error()), nil
				}
			}
			out, err := def.Run(ctx, c, a)
			if err != nil {
				return toolError(err.Error()), nil
			}
			b, _ := json.MarshalIndent(out, "", " ")
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil
		})
	}
}

func toolError(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: msg}}}
}

// names, for the coverage test's report
func toolNames() []string {
	var n []string
	for _, t := range Tools(Options{AllowDeleteCompany: true}) {
		n = append(n, t.Name)
	}
	sort.Strings(n)
	return n
}
