package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Version is stamped into the server's implementation info.
var Version = "0.1.0"

// NewServer builds an MCP server bound to one API client. Every tool, resource
// and prompt goes through that client, so the token's role decides what works.
func NewServer(c *Client, o Options) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{
		Name: "pinkglasses", Title: "PinkGlasses", Version: Version,
		Description: "External attack-surface scanner: inventory, findings, scans and schedules of the companies this token can see.",
	}, &mcp.ServerOptions{
		Instructions: instructions,
	})
	register(s, c, o)
	registerResources(s, c)
	registerPrompts(s)
	return s
}

const instructions = `PinkGlasses watches companies' external attack surface. Start with list_companies to get ids.
Read with search (the query language; * is everything), list_hosts, get_host, list_findings.
Targets are named groups (list_target_groups); a scan picks groups. start_scan runs now, once at a time, or on a repeat;
a passive profile needs nothing else, an active one (standard, deep) needs an exit: local with a vpn_config_id
(list_vpn_configs) or remote with a pool_id (list_workers). Use wait_for_run to block until a run ends and see what changed.
Refusals from the API say what to fix — pass them on as they are. Destructive tools require confirm: true.`

// ---------------- resources ----------------

// resourceRoutes are the API routes the resources read, for the coverage test.
var resourceRoutes = []string{
	"GET /scopes", "GET /scopes/{scopeID}/summary", "GET /hosts/{ipID}", "GET /runs/{runID}",
	"GET /services/{serviceID}/screenshot", "GET /scan-params",
}

func registerResources(s *mcp.Server, c *Client) {
	jsonText := func(uri string, v any) *mcp.ReadResourceResult {
		b, _ := json.MarshalIndent(v, "", " ")
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: "application/json", Text: string(b)}}}
	}
	s.AddResource(&mcp.Resource{
		URI: "pinkglasses://companies", Name: "companies", MIMEType: "application/json",
		Description: "The companies this token can see, with ids.",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		var out any
		if err := c.get(ctx, "/scopes", &out); err != nil {
			return nil, err
		}
		return jsonText(req.Params.URI, out), nil
	})
	s.AddResource(&mcp.Resource{
		URI: "pinkglasses://scan-parameters", Name: "scan-parameters", MIMEType: "application/json",
		Description: "Every tunable a run accepts under params.",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		var out any
		if err := c.get(ctx, "/scan-params", &out); err != nil {
			return nil, err
		}
		return jsonText(req.Params.URI, out), nil
	})
	s.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: "pinkglasses://companies/{id}/summary", Name: "company-summary", MIMEType: "application/json",
		Description: "Dashboard counters of one company.",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		id := between(req.Params.URI, "pinkglasses://companies/", "/summary")
		var out any
		if err := c.get(ctx, "/scopes/"+id+"/summary", &out); err != nil {
			return nil, err
		}
		return jsonText(req.Params.URI, out), nil
	})
	s.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: "pinkglasses://hosts/{id}", Name: "host", MIMEType: "application/json",
		Description: "Everything about one address: names, ports, sites, findings.",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		id := strings.TrimPrefix(req.Params.URI, "pinkglasses://hosts/")
		var out any
		if err := c.get(ctx, "/hosts/"+id, &out); err != nil {
			return nil, err
		}
		return jsonText(req.Params.URI, out), nil
	})
	s.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: "pinkglasses://runs/{id}", Name: "run", MIMEType: "application/json",
		Description: "One run: status, progress, fleet, targets, activity.",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		id := strings.TrimPrefix(req.Params.URI, "pinkglasses://runs/")
		out, err := runView(ctx, c, id)
		if err != nil {
			return nil, err
		}
		return jsonText(req.Params.URI, out), nil
	})
	s.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: "pinkglasses://services/{id}/screenshot{?host}", Name: "screenshot", MIMEType: "image/png",
		Description: "The most recent screenshot of a service; ?host= picks one site's.",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		rest := strings.TrimPrefix(req.Params.URI, "pinkglasses://services/")
		id, query, _ := strings.Cut(rest, "/screenshot")
		data, ct, err := c.getBytes(ctx, "/services/"+id+"/screenshot"+query)
		if err != nil {
			return nil, err
		}
		if ct == "" {
			ct = "image/png"
		}
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, MIMEType: ct, Blob: data}}}, nil
	})
}

func between(s, prefix, suffix string) string {
	s = strings.TrimPrefix(s, prefix)
	if i := strings.Index(s, suffix); i >= 0 {
		s = s[:i]
	}
	return s
}

// ---------------- prompts ----------------

func registerPrompts(s *mcp.Server) {
	user := func(text string) *mcp.GetPromptResult {
		return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: text}}}}
	}
	s.AddPrompt(&mcp.Prompt{
		Name: "triage_changes", Description: "What changed for a company since its previous scan, ordered by what deserves attention.",
		Arguments: []*mcp.PromptArgument{{Name: "company_id", Description: "Company id", Required: true}},
	}, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		id := req.Params.Arguments["company_id"]
		return user(fmt.Sprintf(`For company %s: call list_runs and take the latest completed run, then run_diff on it and list_findings with presence active.
Report, in this order: new hosts or ports exposed; findings that returned after being gone; new findings by severity; what disappeared.
For each item name the host and port, and say whether it was seen by name or by address. Keep it to what a person should act on today.`, id)), nil
	})
	s.AddPrompt(&mcp.Prompt{
		Name: "explain_host", Description: "Explain one host: what it is, what it serves, and what is worth looking at.",
		Arguments: []*mcp.PromptArgument{{Name: "host_id", Description: "The address id (ip_id)", Required: true}},
	}, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		id := req.Params.Arguments["host_id"]
		return user(fmt.Sprintf(`Call get_host for %s. Explain in plain terms: whose address this is (ASN), which names point at it and since when,
each open port and what answers on it — per site by name, since a shared address answers differently per name — and the findings and discovered paths.
End with the two or three things a security engineer would look at first, and why.`, id)), nil
	})
	s.AddPrompt(&mcp.Prompt{
		Name: "plan_scan", Description: "Prepare a scan of a company: check what exists, what is authorized, and which exit to use, then propose the start_scan call.",
		Arguments: []*mcp.PromptArgument{{Name: "company_id", Description: "Company id", Required: true}},
	}, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		id := req.Params.Arguments["company_id"]
		return user(fmt.Sprintf(`For company %s: call list_target_groups, list_vpn_configs and list_workers.
Say which groups are authorized for active scanning and which are passive only. If no VPN config and no remote pool with an active worker exists,
say that only a passive scan is possible and what to add. Otherwise propose one start_scan call with profile, groups and exit filled in,
and ask before running it.`, id)), nil
	})
}
