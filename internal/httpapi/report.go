package httpapi

import (
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// scopeReport renders one company's attack surface as a self-contained page:
// what it exposes now, and what changed over a period. It is HTML rather than
// JSON because its reader is a person — often one who does not use the app —
// and HTML prints to PDF from any browser without a PDF library here. No
// scripts and no external requests, so it can be saved and mailed on.
func (s *Server) scopeReport(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 365 {
			days = n
		}
	}
	ctx := r.Context()
	scope, err := s.st.GetScope(ctx, scopeID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "company not found")
		return
	}
	now := time.Now().UTC()
	from := now.AddDate(0, 0, -days)

	sum, _ := s.st.Summary(ctx, scopeID)
	findings, _ := s.st.ListFindings(ctx, scopeID, "", "")
	hosts, _ := s.st.HostRows(ctx, scopeID, "", 2000, false)
	changes, _ := s.st.ScopeChangeEvents(ctx, scopeID, from, now)

	// Findings by severity, worst first, and the ones still present.
	sevRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	type findingRow struct {
		Severity, Kind, Title, Where, LastSeen string
	}
	bySev := map[string]int{}
	var open []findingRow
	for _, f := range findings {
		if f.Presence == "gone" {
			continue
		}
		sev := string(f.Severity)
		bySev[sev]++
		where := f.IP
		if where == "" {
			where = "—"
		} else if f.Port > 0 {
			where += ":" + strconv.Itoa(f.Port)
		}
		open = append(open, findingRow{sev, f.Kind, f.Title, where, f.LastSeen.UTC().Format("2006-01-02")})
	}
	sort.SliceStable(open, func(i, j int) bool {
		return sevRank[open[i].Severity] < sevRank[open[j].Severity]
	})
	// Informational findings are the bulk (every discovered path); the report
	// counts them above but lists only what someone would act on.
	var listed []findingRow
	for _, f := range open {
		if f.Severity != "info" {
			listed = append(listed, f)
		}
	}
	infoOpen := len(open) - len(listed)
	if len(listed) > 200 {
		listed = listed[:200]
	}

	// One line per name→address pair, and the services on each address.
	type hostRow struct {
		Name, Addr, Org string
		Services        int
	}
	var hrows []hostRow
	for _, h := range hosts.Rows {
		addr, org := "did not resolve", ""
		if h.Addr != nil {
			addr = *h.Addr
		}
		if h.ASOrg != nil {
			org = *h.ASOrg
		}
		hrows = append(hrows, hostRow{h.Name, addr, org, h.Services})
	}
	if len(hrows) > 500 {
		hrows = hrows[:500]
	}

	// What changed in the period, grouped by what it was.
	changeLabel := map[string]string{
		"new_subdomain":    "New names",
		"new_port":         "Newly open ports",
		"new_finding":      "New findings",
		"finding_returned": "Findings that came back",
		"finding_gone":     "Findings no longer seen",
	}
	order := []string{"finding_returned", "new_finding", "new_port", "new_subdomain", "finding_gone"}
	type changeGroup struct {
		Label string
		Items []string
		More  int
	}
	grouped := map[string][]string{}
	infoChanges := 0
	for _, c := range changes {
		src := c.After
		if c.Kind == "finding_gone" {
			src = c.Before
		}
		var line string
		switch c.Kind {
		case "new_subdomain":
			line, _ = src["name"].(string)
		case "new_port":
			ip, _ := src["ip"].(string)
			port, _ := src["port"].(float64)
			line = ip + ":" + strconv.Itoa(int(port))
		default:
			sev, _ := src["severity"].(string)
			// Informational findings are the discovered paths: hundreds of
			// them on any site with a crawlable tree. They are inventory, not
			// news, and listing them buries everything a reader came for.
			if sev == "info" {
				infoChanges++
				continue
			}
			line, _ = src["title"].(string)
			if sev != "" {
				line = sev + " — " + line
			}
		}
		if line != "" {
			grouped[c.Kind] = append(grouped[c.Kind], line)
		}
	}
	var groups []changeGroup
	for _, k := range order {
		items := grouped[k]
		if len(items) == 0 {
			continue
		}
		g := changeGroup{Label: changeLabel[k]}
		if len(items) > 50 {
			g.More = len(items) - 50
			items = items[:50]
		}
		g.Items = items
		groups = append(groups, g)
	}

	data := map[string]any{
		"Company":  scope.Name,
		"Now":      now.Format("2006-01-02 15:04 UTC"),
		"From":     from.Format("2006-01-02"),
		"Days":     days,
		"Summary":  sum,
		"BySev":    bySev,
		"SevOrder": []string{"critical", "high", "medium", "low", "info"},
		"Findings": listed,
		"InfoOpen": infoOpen,
		"MoreF":    0,
		"Hosts":    hrows,
		"MoreH":    len(hosts.Rows) - len(hrows),
		"Groups":   groups,
		"Info":     infoChanges,
		"Quiet":    len(groups) == 0 && infoChanges == 0,
	}
	// The app's policy allows no inline styles, and this document is one
	// file with its stylesheet inside it. Give this response its own, which
	// is stricter than the app's: the sheet is allowed by nonce and nothing
	// else is allowed at all — no scripts, no requests off the page.
	nonce := randToken(16)
	data["Nonce"] = nonce
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'nonce-"+nonce+"'; img-src 'self' data:; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := reportTmpl.Execute(w, data); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
	}
}

// reportTmpl is deliberately plain: system fonts, no scripts, no external
// requests, and print rules so "Print → Save as PDF" gives a clean document.
var reportTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"add": func(a, b int) int { return a + b },
}).Parse(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>{{.Company}} — attack surface report</title>
<style nonce="{{.Nonce}}">
 :root { color-scheme: light; }
 body { font: 14px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        color: #14181f; background: #fff; margin: 0 auto; padding: 32px; max-width: 900px; }
 h1 { font-size: 24px; margin: 0 0 4px; }
 h2 { font-size: 16px; margin: 28px 0 8px; border-bottom: 1px solid #dfe3e8; padding-bottom: 4px; }
 .sub { color: #5b6470; margin-bottom: 20px; }
 table { border-collapse: collapse; width: 100%; font-size: 13px; }
 th, td { text-align: left; padding: 5px 8px; border-bottom: 1px solid #eceff2; vertical-align: top; }
 th { color: #5b6470; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .4px; }
 .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
 .tiles { display: flex; flex-wrap: wrap; gap: 10px; margin: 12px 0 4px; }
 .tile { border: 1px solid #dfe3e8; border-radius: 8px; padding: 10px 14px; min-width: 110px; }
 .tile .n { font-size: 22px; font-weight: 650; }
 .tile .l { color: #5b6470; font-size: 11px; text-transform: uppercase; letter-spacing: .4px; }
 .sev { font-weight: 600; }
 .sev-critical { color: #a4123f; } .sev-high { color: #c2410c; }
 .sev-medium  { color: #a16207; } .sev-low  { color: #3f6212; } .sev-info { color: #5b6470; }
 ul { margin: 6px 0 0; padding-left: 20px; } li { margin: 1px 0; }
 .muted { color: #5b6470; }
 footer { margin-top: 36px; color: #5b6470; font-size: 12px; border-top: 1px solid #dfe3e8; padding-top: 10px; }
 @media print { body { padding: 0; max-width: none; } h2 { break-after: avoid; } tr { break-inside: avoid; } }
</style>
</head><body>
<h1>{{.Company}}</h1>
<div class="sub">External attack surface, as of {{.Now}}. Changes cover the last {{.Days}} days (since {{.From}}).</div>

<h2>What is exposed</h2>
<div class="tiles">
  <div class="tile"><div class="l">Resolving names</div><div class="n">{{.Summary.DomainsResolving}}</div></div>
  <div class="tile"><div class="l">Hosts</div><div class="n">{{.Summary.IPs}}</div></div>
  <div class="tile"><div class="l">Services</div><div class="n">{{.Summary.Services}}</div></div>
</div>
<table>
  <tr><th>Severity</th>{{range .SevOrder}}<th>{{.}}</th>{{end}}</tr>
  <tr><td class="muted">Findings still present</td>{{range .SevOrder}}<td class="sev sev-{{.}}">{{with index $.BySev .}}{{.}}{{else}}0{{end}}</td>{{end}}</tr>
</table>

<h2>What changed</h2>
{{if .Quiet}}<p class="muted">Nothing changed in this period.</p>{{end}}
{{range .Groups}}
  <p><strong>{{.Label}}</strong> ({{len .Items}}{{if .More}} shown of {{add (len .Items) .More}}{{end}})</p>
  <ul>{{range .Items}}<li class="mono">{{.}}</li>{{end}}</ul>
{{end}}
{{if .Info}}<p class="muted">{{.Info}} informational finding{{if ne .Info 1}}s{{end}} also changed — discovered paths, listed in the app rather than here.</p>{{end}}

<h2>Findings</h2>
{{if .Findings}}
<table>
  <tr><th>Severity</th><th>Where</th><th>Finding</th><th>Last seen</th></tr>
  {{range .Findings}}<tr>
    <td class="sev sev-{{.Severity}}">{{.Severity}}</td>
    <td class="mono">{{.Where}}</td>
    <td>{{.Title}}</td>
    <td class="muted">{{.LastSeen}}</td>
  </tr>{{end}}
</table>
{{else}}<p class="muted">Nothing above informational is currently present.</p>{{end}}
{{if .InfoOpen}}<p class="muted">{{.InfoOpen}} informational finding{{if ne .InfoOpen 1}}s are{{else}} is{{end}} also present — discovered paths, in the app.</p>{{end}}

<h2>Names and hosts</h2>
{{if .Hosts}}
<table>
  <tr><th>Name</th><th>Address</th><th>Network</th><th>Services</th></tr>
  {{range .Hosts}}<tr>
    <td class="mono">{{.Name}}</td><td class="mono">{{.Addr}}</td>
    <td class="muted">{{.Org}}</td><td>{{.Services}}</td>
  </tr>{{end}}
</table>
{{if .MoreH}}<p class="muted">and {{.MoreH}} more, in the app.</p>{{end}}
{{else}}<p class="muted">Nothing discovered yet.</p>{{end}}

<footer>Generated by PinkGlasses. Findings are what a scan observed and when it last saw them, not a judgement of risk.</footer>
</body></html>
`))
