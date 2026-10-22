package fingerprint

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Banner is one HTTP response a search engine recorded: Shodan, Censys and
// FOFA have already asked these hosts for their front page, so the rules can
// be measured against thousands of real deployments without sending anything.
type Banner struct {
	Source   string // "shodan", "censys", "fofa"
	Addr     string // "ip:port", for reading a report; never fetched
	Response Response
}

// ReadBanners reads an export in any of the formats the engines produce —
// JSON lines, one JSON array, an API response object, optionally gzipped —
// and returns the HTTP responses it holds. fofaFields names the columns of a
// FOFA API response whose rows are arrays (the `fields` the query asked for).
func ReadBanners(r io.Reader, fofaFields []string) ([]Banner, error) {
	br := bufio.NewReader(r)
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		br = bufio.NewReader(gz)
	}
	data, err := io.ReadAll(br)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}

	var records []any
	switch data[0] {
	case '[':
		if err := json.Unmarshal(data, &records); err != nil {
			return nil, fmt.Errorf("json array: %w", err)
		}
	default:
		// One document, or one per line. A single API response is one
		// document holding the records; JSON lines are many.
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		for dec.More() {
			var v any
			if err := dec.Decode(&v); err != nil {
				return nil, fmt.Errorf("record %d: %w", len(records)+1, err)
			}
			records = append(records, v)
		}
	}

	var out []Banner
	for _, rec := range records {
		out = append(out, fromRecord(rec, fofaFields)...)
	}
	return out, nil
}

// fromRecord recognises a record by its shape.
func fromRecord(rec any, fofaFields []string) []Banner {
	m, ok := rec.(map[string]any)
	if !ok {
		return nil
	}
	switch {
	case m["matches"] != nil: // Shodan search API response
		return fromList(m["matches"], fofaFields)
	case m["results"] != nil: // FOFA API response
		return fromFOFAResults(m["results"], fofaFields)
	case m["result"] != nil: // Censys v2 search response {"result":{"hits":[…]}}
		if res, ok := m["result"].(map[string]any); ok {
			if hits := res["hits"]; hits != nil {
				return fromList(hits, fofaFields)
			}
			return fromRecord(res, fofaFields)
		}
	case m["ip_str"] != nil && m["data"] != nil:
		if b, ok := fromShodan(m); ok {
			return []Banner{b}
		}
	case m["services"] != nil:
		return fromCensysHost(m)
	case m["header"] != nil || m["banner"] != nil || m["body"] != nil:
		if b, ok := fromFOFAObject(m); ok {
			return []Banner{b}
		}
	}
	// Censys Platform wraps a host as {"resource": {...}} or {"host_v1": {"resource": {...}}}.
	for _, k := range []string{"resource", "host_v1", "host"} {
		if inner, ok := m[k].(map[string]any); ok {
			return fromRecord(inner, fofaFields)
		}
	}
	return nil
}

func fromList(v any, fofaFields []string) []Banner {
	list, _ := v.([]any)
	var out []Banner
	for _, rec := range list {
		out = append(out, fromRecord(rec, fofaFields)...)
	}
	return out
}

// --- Shodan ---
//
// A Shodan banner keeps the raw response head in "data" and the parsed page
// under "http": status, title, html, location.

func fromShodan(m map[string]any) (Banner, bool) {
	h, _ := m["http"].(map[string]any)
	if h == nil {
		return Banner{}, false // not an HTTP banner
	}
	r := parseHead(str(m["data"]))
	if s := num(h["status"]); s != 0 {
		r.Status = s
	}
	r.Title = str(h["title"])
	r.Body = str(h["html"])
	if loc := str(h["location"]); loc != "" && r.Headers.Get("Location") == "" && loc != "/" {
		r.Headers.Set("Location", loc)
	}
	if ssl, ok := m["ssl"].(map[string]any); ok {
		if cert, ok := ssl["cert"].(map[string]any); ok {
			if subj, ok := cert["subject"].(map[string]any); ok {
				r.CertSubject = "CN=" + str(subj["CN"])
			}
		}
	}
	return Banner{Source: "shodan", Addr: str(m["ip_str"]) + ":" + strconv.Itoa(num(m["port"])), Response: r}, true
}

// --- Censys ---
//
// Censys Search v2 keeps each service's response under
// services[].http.response with headers as name -> [values] (dashes written
// as underscores); the Censys Platform keeps it under
// services[].endpoints[].http with headers as name -> {"headers": [values]}.

func fromCensysHost(m map[string]any) []Banner {
	ip := str(m["ip"])
	services, _ := m["services"].([]any)
	var out []Banner
	for _, s := range services {
		svc, _ := s.(map[string]any)
		if svc == nil {
			continue
		}
		port := num(svc["port"])
		var https []map[string]any
		if h, ok := svc["http"].(map[string]any); ok {
			https = append(https, h)
		}
		if eps, ok := svc["endpoints"].([]any); ok {
			for _, e := range eps {
				if em, ok := e.(map[string]any); ok {
					if h, ok := em["http"].(map[string]any); ok {
						https = append(https, h)
					}
				}
			}
		}
		for _, h := range https {
			resp := h
			if inner, ok := h["response"].(map[string]any); ok {
				resp = inner
			}
			r := Response{Headers: http.Header{}}
			if req, ok := h["request"].(map[string]any); ok {
				r.Path = pathOf(str(req["uri"]))
			} else if u := str(h["uri"]); u != "" {
				r.Path = pathOf(u)
			}
			r.Status = num(resp["status_code"])
			r.Body = str(resp["body"])
			r.Title = str(resp["html_title"])
			if r.Title == "" {
				r.Title = Title(r.Body)
			}
			if hs, ok := resp["headers"].(map[string]any); ok {
				for k, v := range hs {
					name := http.CanonicalHeaderKey(strings.ReplaceAll(k, "_", "-"))
					for _, val := range headerValues(v) {
						if name == "Set-Cookie" {
							r.Cookies = append(r.Cookies, cookieNames(val)...)
							continue
						}
						r.Headers.Add(name, val)
					}
				}
			}
			out = append(out, Banner{Source: "censys", Addr: ip + ":" + strconv.Itoa(port), Response: r})
		}
	}
	return out
}

func headerValues(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, headerValues(e)...)
		}
		return out
	case map[string]any:
		return headerValues(x["headers"])
	}
	return nil
}

// --- FOFA ---
//
// FOFA returns the fields a query asked for: as arrays in API order, or as
// objects from tools that name them. "header" (and "banner") is the raw
// response head; "body" needs a membership that includes it.

func fromFOFAResults(v any, fields []string) []Banner {
	rows, _ := v.([]any)
	var out []Banner
	for _, row := range rows {
		switch x := row.(type) {
		case []any:
			obj := map[string]any{}
			for i, f := range fields {
				if i < len(x) {
					obj[strings.TrimSpace(f)] = x[i]
				}
			}
			if b, ok := fromFOFAObject(obj); ok {
				out = append(out, b)
			}
		case map[string]any:
			if b, ok := fromFOFAObject(x); ok {
				out = append(out, b)
			}
		}
	}
	return out
}

func fromFOFAObject(m map[string]any) (Banner, bool) {
	head := str(m["header"])
	if head == "" {
		head = str(m["banner"])
	}
	if head == "" && str(m["body"]) == "" {
		return Banner{}, false
	}
	r := parseHead(head)
	r.Body = str(m["body"])
	r.Title = str(m["title"])
	if r.Title == "" {
		r.Title = Title(r.Body)
	}
	if s := str(m["server"]); s != "" && r.Headers.Get("Server") == "" {
		r.Headers.Set("Server", s)
	}
	addr := str(m["ip"]) + ":" + str(m["port"])
	return Banner{Source: "fofa", Addr: addr, Response: r}, true
}

// --- shared ---

// parseHead reads a raw response head: a status line, then header lines.
func parseHead(raw string) Response {
	r := Response{Headers: http.Header{}}
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		raw = raw[:i]
	}
	for i, line := range strings.Split(raw, "\n") {
		if i == 0 && strings.HasPrefix(line, "HTTP/") {
			if f := strings.Fields(line); len(f) > 1 {
				r.Status, _ = strconv.Atoi(f[1])
			}
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if strings.EqualFold(k, "Set-Cookie") {
			r.Cookies = append(r.Cookies, cookieNames(v)...)
			continue
		}
		r.Headers.Add(k, v)
	}
	return r
}

// cookieNames takes the name off one Set-Cookie value.
func cookieNames(v string) []string {
	name, _, ok := strings.Cut(v, "=")
	name = strings.TrimSpace(name)
	if !ok || name == "" {
		return nil
	}
	return []string{name}
}

func pathOf(uri string) string {
	if i := strings.Index(uri, "://"); i >= 0 {
		rest := uri[i+3:]
		if j := strings.Index(rest, "/"); j >= 0 {
			return rest[j:]
		}
		return "/"
	}
	return uri
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

func num(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}
