// Package search parses a Shodan-style query into whitelisted, parameterized
// SQL. It never builds SQL from raw user strings: only known fields map, and
// all values are bound parameters (architecture.md §9).
package search

import (
	"fmt"
	"strconv"
	"strings"
)

// Compiled is the result of compiling a query: a SQL WHERE fragment and args.
type Compiled struct {
	Where string
	Args  []any
}

// field maps a query field to a SQL expression over the search view (see store.Search).
type field struct {
	col     string
	numeric bool
	special string // non-empty for fields needing custom SQL
}

var fields = map[string]field{
	"port":    {col: "sv.port", numeric: true},
	"proto":   {col: "sv.proto"},
	"ip":      {col: "host(ip.addr)"},
	"domain":  {col: "d.name"},
	"country": {col: "ip.country"},
	"cloud":   {col: "ip.cloud"},
	"asn":     {col: "ip.asn", numeric: true},
	"product": {col: "so.product"},
	"version": {col: "so.version"},
	"tech":    {special: "tech"},
	"cookie":  {special: "cookie"},
	"status":  {special: "http_status", numeric: true},
	"title":   {special: "http_title"},
	"cert.expires": {special: "cert_expires", numeric: true},
	"new":     {special: "new_days", numeric: true},
	"severity": {special: "severity"},
	// company/scope filter — only valid in global search, where scope is joined.
	"company": {col: "sc.name"},
	"scope":   {col: "sc.name"},
}

// Compile turns a query string into SQL. An empty query matches everything.
func Compile(q string) (Compiled, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return Compiled{Where: "TRUE"}, nil
	}
	toks, err := lex(q)
	if err != nil {
		return Compiled{}, err
	}
	p := &parser{toks: toks}
	node, err := p.parseOr()
	if err != nil {
		return Compiled{}, err
	}
	if !p.eof() {
		return Compiled{}, fmt.Errorf("unexpected token %q", p.peek().val)
	}
	c := &compiler{}
	where := node.sql(c)
	return Compiled{Where: where, Args: c.args}, nil
}

// ---- lexer ----

type tokKind int

const (
	tWord tokKind = iota
	tAnd
	tOr
	tLParen
	tRParen
)

type token struct {
	kind tokKind
	val  string
}

func lex(s string) ([]token, error) {
	var toks []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '(':
			toks = append(toks, token{tLParen, "("})
			i++
		case c == ')':
			toks = append(toks, token{tRParen, ")"})
			i++
		case c == '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				j++
			}
			if j >= len(s) {
				return nil, fmt.Errorf("unterminated quote")
			}
			toks = append(toks, token{tWord, s[i+1 : j]})
			i = j + 1
		default:
			j := i
			for j < len(s) && s[j] != ' ' && s[j] != '(' && s[j] != ')' {
				j++
			}
			w := s[i:j]
			switch strings.ToUpper(w) {
			case "AND":
				toks = append(toks, token{tAnd, w})
			case "OR":
				toks = append(toks, token{tOr, w})
			default:
				toks = append(toks, token{tWord, w})
			}
			i = j
		}
	}
	return toks, nil
}

// ---- parser (precedence: OR < AND < term) ----

type node interface{ sql(*compiler) string }

type binNode struct {
	op    string // "AND" | "OR"
	l, r  node
}

func (n binNode) sql(c *compiler) string {
	return "(" + n.l.sql(c) + " " + n.op + " " + n.r.sql(c) + ")"
}

type termNode struct{ raw string }

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() token {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return token{}
}
func (p *parser) eof() bool { return p.pos >= len(p.toks) }
func (p *parser) next() token {
	t := p.peek()
	p.pos++
	return t
}

func (p *parser) parseOr() (node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for !p.eof() && p.peek().kind == tOr {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = binNode{"OR", left, right}
	}
	return left, nil
}

func (p *parser) parseAnd() (node, error) {
	left, err := p.parseTerm()
	if err != nil {
		return nil, err
	}
	for !p.eof() {
		k := p.peek().kind
		if k == tAnd {
			p.next()
		} else if k == tWord || k == tLParen {
			// implicit AND between adjacent terms
		} else {
			break
		}
		right, err := p.parseTerm()
		if err != nil {
			return nil, err
		}
		left = binNode{"AND", left, right}
	}
	return left, nil
}

func (p *parser) parseTerm() (node, error) {
	t := p.peek()
	if t.kind == tLParen {
		p.next()
		n, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tRParen {
			return nil, fmt.Errorf("missing )")
		}
		p.next()
		return n, nil
	}
	if t.kind != tWord {
		return nil, fmt.Errorf("expected term, got %q", t.val)
	}
	p.next()
	return termNode{t.val}, nil
}

// ---- compiler ----

type compiler struct{ args []any }

func (c *compiler) bind(v any) string {
	c.args = append(c.args, v)
	return "$" + strconv.Itoa(len(c.args))
}

func (n termNode) sql(c *compiler) string {
	raw := n.raw
	// operators: field:val, field>val, field<val, field>=val, field<=val
	for _, op := range []string{">=", "<=", ":", ">", "<"} {
		if idx := strings.Index(raw, op); idx > 0 {
			key := raw[:idx]
			val := raw[idx+len(op):]
			f, ok := fields[key]
			if !ok {
				break // unknown field -> treat whole token as free text
			}
			return compileField(c, f, op, val)
		}
	}
	// free text over banner/title
	ph := c.bind("%" + raw + "%")
	return "(so.banner ILIKE " + ph + " OR (so.http->>'title') ILIKE " + ph + ")"
}

func compileField(c *compiler, f field, op, val string) string {
	sqlOp := map[string]string{":": "=", ">": ">", "<": "<", ">=": ">=", "<=": "<="}[op]

	switch f.special {
	case "tech":
		return "EXISTS (SELECT 1 FROM technology t WHERE t.service_id=sv.id AND t.name ILIKE " + c.bind("%"+val+"%") + ")"
	case "cookie":
		// Cookie names fingerprint a product where the banner does not:
		// cookie:webvpn* finds Cisco ASA WebVPN across the whole inventory.
		// Wildcards behave as everywhere else; without one the match is exact
		// but case-insensitive, since a name is a short token.
		pat := val
		if strings.ContainsAny(val, "*") {
			pat = strings.ReplaceAll(val, "*", "%")
		}
		return "EXISTS (SELECT 1 FROM jsonb_array_elements_text(" +
			"CASE WHEN jsonb_typeof(so.http->'cookies') = 'array' THEN so.http->'cookies' ELSE '[]'::jsonb END" +
			") AS ck WHERE ck ILIKE " + c.bind(pat) + ")"
	case "http_status":
		return "(so.http->>'status')::int " + sqlOp + " " + c.bind(mustInt(val))
	case "http_title":
		return "(so.http->>'title') ILIKE " + c.bind("%"+val+"%")
	case "cert_expires":
		// cert.expires<30d  -> not_after within N days
		days := mustInt(strings.TrimSuffix(val, "d"))
		return "(so.tls->>'not_after')::timestamptz < now() + make_interval(days => " + c.bind(days) + ")"
	case "new_days":
		days := mustInt(strings.TrimSuffix(val, "d"))
		return "sv.first_seen >= now() - make_interval(days => " + c.bind(days) + ")"
	case "severity":
		order := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
		return "EXISTS (SELECT 1 FROM finding f WHERE f.asset_id=sv.id AND " +
			"array_position(ARRAY['info','low','medium','high','critical'], f.severity) " + sqlOp + " " +
			c.bind(order[strings.ToLower(val)]) + ")"
	}

	if f.numeric {
		return f.col + " " + sqlOp + " " + c.bind(mustInt(val))
	}
	if op == ":" && strings.ContainsAny(val, "*") {
		return f.col + " ILIKE " + c.bind(strings.ReplaceAll(val, "*", "%"))
	}
	if op == ":" {
		return f.col + " ILIKE " + c.bind(val)
	}
	return f.col + " " + sqlOp + " " + c.bind(val)
}

func mustInt(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}
