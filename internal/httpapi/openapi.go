package httpapi

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// OpenAPI renders an OpenAPI 3.1 document for the routes: methods, paths,
// the role each needs, how to authenticate, and the error contract. Summaries
// come from wiki/API.md, whose tables already describe every route in a
// sentence. Request and response bodies are not typed here — that would need
// reflection over handlers that decode ad hoc structs — so this is a
// paths-and-auth spec, and says so.
//
// Emitted by hand rather than through a YAML library: the shape is small and
// fixed, and a dependency for it would be the larger cost.
func OpenAPI(routes []RouteInfo, purposes map[string]string) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	w("openapi: 3.1.0\n")
	w("info:\n  title: PinkGlasses API\n  version: \"1\"\n")
	w("  description: |\n    Every route the server registers, generated from the router (go run ./tools/openapi).\n")
	w("    Paths, methods, roles and authentication are exact; request and response bodies are\n")
	w("    described in wiki/API.md rather than typed here. Errors are {\"error\": \"<sentence>\"}.\n")
	w("servers:\n  - url: /\n")
	w("components:\n  securitySchemes:\n")
	w("    session:\n      type: apiKey\n      in: cookie\n      name: pg_session\n")
	w("    token:\n      type: http\n      scheme: bearer\n      description: An API token, pgt_… — may be narrower than its owner, never wider.\n")
	w("    proxy:\n      type: apiKey\n      in: header\n      name: X-Forwarded-User\n      description: Honoured only alongside X-Proxy-Secret when ASM_TRUSTED_PROXY_SECRET is set.\n")
	w("  responses:\n")
	for _, code := range []string{"400", "401", "403", "404", "409"} {
		desc := map[string]string{
			"400": "malformed or missing input", "401": "not signed in, or the credential is no longer valid",
			"403": "signed in, but the route needs a higher role", "404": "no such thing",
			"409": "conflicts with state — last administrator, username taken, empty pool",
		}[code]
		w("    e%s:\n      description: %s\n      content:\n        application/json:\n          schema:\n            type: object\n            properties:\n              error: {type: string}\n", code, desc)
	}

	// Group by path, preserving registration order of first appearance.
	byPath := map[string][]RouteInfo{}
	var order []string
	for _, r := range routes {
		if _, ok := byPath[r.Path]; !ok {
			order = append(order, r.Path)
		}
		byPath[r.Path] = append(byPath[r.Path], r)
	}
	w("paths:\n")
	for _, path := range order {
		w("  %s:\n", path)
		rs := byPath[path]
		sort.Slice(rs, func(i, j int) bool { return rs[i].Method < rs[j].Method })
		for _, r := range rs {
			w("    %s:\n", strings.ToLower(r.Method))
			w("      operationId: %s\n", opID(r))
			if p := purposes[r.Method+" "+strings.TrimPrefix(r.Path, "/api/v1")]; p != "" {
				w("      summary: %s\n", yamlString(p))
			}
			w("      x-required-role: %s\n", r.Role)
			if params := pathParams(path); len(params) > 0 {
				w("      parameters:\n")
				for _, name := range params {
					w("        - {name: %s, in: path, required: true, schema: {type: string}}\n", name)
				}
			}
			switch r.Role {
			case RolePublic:
				w("      security: []\n")
			default:
				w("      security:\n        - session: []\n        - token: []\n        - proxy: []\n")
			}
			w("      responses:\n        \"200\": {description: ok}\n")
			if r.Method == "POST" {
				w("        \"201\": {description: created}\n")
			}
			w("        \"400\": {$ref: \"#/components/responses/e400\"}\n")
			if r.Role != RolePublic {
				w("        \"401\": {$ref: \"#/components/responses/e401\"}\n")
			}
			if r.Role != RolePublic && r.Role != RoleAnySignedIn {
				w("        \"403\": {$ref: \"#/components/responses/e403\"}\n")
			}
			w("        \"404\": {$ref: \"#/components/responses/e404\"}\n        \"409\": {$ref: \"#/components/responses/e409\"}\n")
		}
	}
	return b.String()
}

var paramRe = regexp.MustCompile(`\{([^}]+)\}`)

func pathParams(path string) []string {
	var out []string
	for _, m := range paramRe.FindAllStringSubmatch(path, -1) {
		out = append(out, m[1])
	}
	return out
}

func opID(r RouteInfo) string {
	p := strings.TrimPrefix(r.Path, "/api/v1")
	p = paramRe.ReplaceAllStringFunc(p, func(s string) string { return "By" + strings.Title(strings.Trim(s, "{}")) })
	parts := strings.FieldsFunc(p, func(c rune) bool { return c == '/' || c == '-' })
	for i := range parts {
		parts[i] = strings.Title(parts[i])
	}
	return strings.ToLower(r.Method) + strings.Join(parts, "")
}

func yamlString(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return "\"" + s + "\""
}

// PurposesFromDoc reads wiki/API.md's route tables and returns the purpose
// sentence per "METHOD /path". The tables are the hand-written reference; the
// spec borrows their words rather than repeating them.
func PurposesFromDoc(md string) map[string]string {
	out := map[string]string{}
	row := regexp.MustCompile("(?m)^\\|\\s*`(GET|POST|PUT|PATCH|DELETE) (/[^`]*)`\\s*\\|(.*)$")
	for _, m := range row.FindAllStringSubmatch(md, -1) {
		cells := strings.Split(m[3], "|")
		// Two-column tables: purpose is the first cell; three-column: role then purpose.
		purpose := strings.TrimSpace(cells[len(cells)-2])
		purpose = strings.ReplaceAll(purpose, "\\|", "|")
		purpose = regexp.MustCompile("`([^`]*)`").ReplaceAllString(purpose, "$1")
		purpose = strings.ReplaceAll(purpose, "**", "")
		if len(purpose) > 300 {
			purpose = purpose[:297] + "…"
		}
		out[m[1]+" "+m[2]] = purpose
	}
	return out
}
