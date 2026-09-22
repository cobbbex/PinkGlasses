package mcpserver

import (
	"archive/zip"
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// The skill is a folder an AI client loads to know how to use this MCP server
// well: when to reach for which tool, how the scan model works (companies,
// target groups, authorization, exits), and the search query language. The
// tool reference is generated from the tool set, so it never drifts from what
// the server actually exposes.

// SkillFiles returns the skill's files by path inside the folder.
func SkillFiles(o Options) map[string]string {
	return map[string]string{
		"pinkglasses/SKILL.md":                           skillMD,
		"pinkglasses/reference/tools.md":                 toolsReference(o),
		"pinkglasses/reference/search-query-language.md": searchReference,
		"pinkglasses/reference/scanning.md":              scanningReference,
	}
}

// SkillZip is the skill as a zip archive, ready to unpack into a skills folder.
func SkillZip(o Options) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := SkillFiles(o)
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		w, err := zw.Create(p)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(files[p])); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// toolsReference renders every tool with its parameters, from the tool set.
func toolsReference(o Options) string {
	var b strings.Builder
	b.WriteString("# PinkGlasses MCP tools\n\n")
	b.WriteString("Generated from the server's tool set. Read-only tools change nothing; destructive ones refuse unless called with `confirm: true`.\n\n")
	for _, t := range Tools(o) {
		fmt.Fprintf(&b, "## %s\n\n", t.Name)
		tags := []string{}
		if t.ReadOnly {
			tags = append(tags, "read-only")
		}
		if t.Destructive {
			tags = append(tags, "destructive — needs confirm: true")
		}
		if len(tags) > 0 {
			fmt.Fprintf(&b, "*%s*\n\n", strings.Join(tags, "; "))
		}
		fmt.Fprintf(&b, "%s\n\n", t.Description)
		props, _ := t.Schema["properties"].(map[string]any)
		required := map[string]bool{}
		if req, ok := t.Schema["required"].([]string); ok {
			for _, r := range req {
				required[r] = true
			}
		}
		if len(props) == 0 {
			b.WriteString("No parameters.\n\n")
			continue
		}
		names := make([]string, 0, len(props))
		for n := range props {
			names = append(names, n)
		}
		sort.Strings(names)
		b.WriteString("| Parameter | Type | Required | Meaning |\n|---|---|---|---|\n")
		for _, n := range names {
			p, _ := props[n].(map[string]any)
			typ, _ := p["type"].(string)
			if enum, ok := p["enum"].([]string); ok && len(enum) > 0 {
				typ += " (" + strings.Join(enum, " | ") + ")"
			}
			desc, _ := p["description"].(string)
			req := ""
			if required[n] {
				req = "yes"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", n, typ, req, strings.ReplaceAll(desc, "|", "\\|"))
		}
		b.WriteString("\n")
	}
	return b.String()
}

const skillMD = `---
name: pinkglasses
description: Work with a PinkGlasses external attack surface scanner through its MCP server — read a company's inventory and findings, search it Shodan-style, triage what changed, and plan, start and watch scans. Use when the user asks about their attack surface, hosts, services, findings, or wants a scan run, and a PinkGlasses MCP server is connected.
---

# PinkGlasses

PinkGlasses watches the external attack surface of one or more **companies**:
their domains, names, hosts, open ports, services, technologies, TLS
certificates and findings, collected by scans that run on workers the
operator owns. This skill is for using its MCP server well. The tool
reference is in ` + "`reference/tools.md`" + `, the search syntax in
` + "`reference/search-query-language.md`" + `, and how scanning works in
` + "`reference/scanning.md`" + `.

## Orient first

Every tool takes a ` + "`company_id`" + `. Start with ` + "`list_companies`" + `; keep the
id and use it for the rest of the conversation. ` + "`company_summary`" + ` gives the
counters and whether a run is going right now.

## Reading

- To answer "what do we expose" questions, use ` + "`search`" + ` with the query
  language: ` + "`port:443 product:nginx`" + `, ` + "`tech:WordPress`" + `, ` + "`title:*login*`" + `,
  ` + "`cert.expires<30d`" + `, ` + "`new:7d`" + `. It returns one row per service per site
  plus facets (products, ports, technologies, titles, statuses), so answer
  from the facets when the user wants a summary and from the rows when they
  want the list.
- ` + "`list_hosts`" + ` is the names-and-addresses table; ` + "`get_host`" + ` is everything
  about one address: names, services with banners, headers, technologies,
  cookies (names only), screenshots and findings.
- ` + "`list_findings`" + ` carries per-run history and a presence ("active" or
  "gone"); a discovered path's evidence has its path, host and HTTP status.
- ` + "`run_diff`" + ` says what a run changed against the previous one. For
  "what's new" or "what changed", prefer it over re-reading everything.

## Scanning

Read ` + "`reference/scanning.md`" + ` before starting anything. In short:

1. A **passive** profile touches only public sources and needs nothing else.
2. An **active** profile (standard, deep) sends packets at the targets. It
   needs (a) targets marked as authorized for active scanning, and (b) an
   **exit**: ` + "`local`" + ` with a ` + "`vpn_config_id`" + ` from ` + "`list_vpn_configs`" + ` (the
   token owner's own tunnels), or ` + "`remote`" + ` with a ` + "`pool_id`" + ` from
   ` + "`list_workers`" + ` that has an active remote worker.
3. The server refuses with a sentence naming the fix when something is
   missing. Return that sentence to the user as it is; do not guess around it.
4. ` + "`start_scan`" + ` returns the run; ` + "`wait_for_run`" + ` blocks until it ends and
   returns the diff. Use ` + "`get_run`" + ` for progress: each stage says what it
   found (names, addresses, open ports, web endpoints) and, for discovery,
   by source.

Never add targets or authorize active scanning on your own initiative: that is
a statement about who owns the infrastructure, and only the user can make it.
Ask, then use ` + "`add_targets`" + ` / ` + "`edit_target_group`" + ` with what they said.

## Destructive tools

` + "`remove_target_group`" + `, ` + "`delete_run`" + `, ` + "`remove_schedule`" + ` and (when enabled)
` + "`delete_company`" + ` refuse unless called with ` + "`confirm: true`" + `. Call them only
after the user has clearly asked for that exact thing, and say what was
removed afterwards.

## Answering well

- Lead with the answer: counts, the notable items, then the list.
- Name hosts by their name where one exists, by address otherwise.
- Quote the API's own refusal sentences verbatim; they were written for
  the user and say what to fix.
- Findings and paths are evidence, not verdicts: say what was observed and
  when it was last seen.
`

const searchReference = `# Search query language

` + "`search`" + ` takes a Shodan-style query. Terms are ANDed; ` + "`OR`" + ` and parentheses
work. A value with spaces is quoted: ` + "`title:\"403 Forbidden\"`" + `.

| Term | Matches |
|---|---|
| ` + "`*`" + ` | everything (list the inventory, read the facets) |
| ` + "`port:443`" + `, ` + "`port>1024`" + ` | service port |
| ` + "`product:nginx`" + `, ` + "`product:*`" + ` | product name from banners / headers; ` + "`*`" + ` means any product known |
| ` + "`version:1.24*`" + ` | product version |
| ` + "`tech:WordPress`" + `, ` + "`tech:*`" + ` | detected technology (also from response headers) |
| ` + "`title:*login*`" + ` | HTTP title, substring unless wildcards are given |
| ` + "`status:403`" + `, ` + "`status>=500`" + ` | HTTP status |
| ` + "`cookie:webvpn*`" + ` | cookie **names** (Cisco ASA WebVPN, BIGipServer* for F5, NSC_* for Citrix) |
| ` + "`cert.expires<30d`" + ` | TLS certificate expiry |
| ` + "`new:7d`" + ` | services first seen in the last 7 days |
| ` + "`severity>=high`" + ` | services with findings at or above that severity |
| ` + "`country:DE`" + `, ` + "`asn:13335`" + ` | where the address is announced from |
| ` + "`company:acme`" + ` | only without a company_id: the company's name |
| bare words | free text over banner, title and product |

` + "`*`" + ` inside a value is a wildcard; ` + "`field:*`" + ` means the field has a value.
Results are one row per service per site (a port serving several names is
listed once per name), with facets by product, port, technology, title and
status.
`

const scanningReference = `# How scanning works

## The model

- A **company** (scope) owns **target groups** of domains, IPs and CIDRs.
  Each entry has a mode: ` + "`active`" + ` (may be port-scanned and probed),
  ` + "`passive_only`" + ` (discovery only), or ` + "`exclude`" + `. Active scanning is an
  authorization recorded with who granted it and when.
- A **run** executes a **profile**: ` + "`passive`" + ` (subdomain discovery from
  public sources, DNS resolution, enrichment — no packets at the target),
  ` + "`standard`" + ` (adds port scan, service probe, technology detection,
  screenshots, directory search, vulnerability checks), ` + "`deep`" + ` (same
  stages, wider port scan).
- Passive stages run on the standing workers. Active stages run from an
  **exit**: ` + "`local`" + ` builds the run its own workers behind a VPN gateway
  (needs one of the token owner's ` + "`vpn_config_id`" + `s), ` + "`remote`" + ` uses a pool
  of enrolled workers (` + "`pool_id`" + `). There is no "from this host".
- **Scan settings** (` + "`scan_parameters`" + `) switch tools on and off — subfinder,
  DNS brute force, katana crawling, gobuster brute force, nuclei — and tune
  them. Turning gobuster and katana both off plans no directory stage;
  nuclei off plans no vulnerability stage.

## Starting a run

Call ` + "`plan_scan`" + ` (a prompt) or do by hand: ` + "`list_target_groups`" + ` to see
what is authorized, ` + "`list_vpn_configs`" + ` and ` + "`list_workers`" + ` for an exit, then
` + "`start_scan`" + ` with ` + "`profile`" + `, optional ` + "`target_group_ids`" + `, and for an
active profile ` + "`exit`" + ` plus ` + "`vpn_config_id`" + ` or ` + "`pool_id`" + `. ` + "`when`" + ` is
` + "`now`" + `, ` + "`once`" + ` (with ` + "`start_at`" + `) or ` + "`repeat`" + ` (with ` + "`every_hours`" + `), the
last two returning a schedule.

## Following a run

` + "`get_run`" + ` shows the pipeline: per stage, done/total and what was found —
names for discovery and brute force (and by source), addresses for
resolution, open ports, web endpoints. ` + "`wait_for_run`" + ` blocks until the run
ends and returns the diff. ` + "`pause_run`" + `, ` + "`resume_run`" + `, ` + "`stop_run`" + ` and
` + "`rerun`" + ` do what they say; a rerun goes through the same checks as a fresh
start.

A run that fails carries the reason in its record: the VPN not coming up, a
lease expiring, workers that stopped reporting. Show it to the user.
`
