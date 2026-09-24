package store

import (
	"context"

	"github.com/google/uuid"
)

// SearchResult is one service row returned by a search query.
type SearchResult struct {
	ServiceID uuid.UUID `json:"service_id"`
	// IPID is the host page's id for this row's address.
	IPID    uuid.UUID `json:"ip_id"`
	ScopeID uuid.UUID `json:"scope_id"`
	Company string    `json:"company"`
	IP      string    `json:"ip"`
	Port    int       `json:"port"`
	// Host is the virtual host this row is about; "" is the address itself.
	// One service answers differently per name, so a search sees a row per
	// site and says which one matched.
	Host    string  `json:"host"`
	Product *string `json:"product,omitempty"`
	Version *string `json:"version,omitempty"`
	Title   *string `json:"title,omitempty"`
	Domain  *string `json:"domain,omitempty"`
}

// searchView is the FROM clause every search runs over: one row per service
// per virtual host observed on it (plus one for the address itself), so a
// title or cookie matches on the site that carries it and the result says
// which site that was. Product, version, banner and TLS are properties of
// the port, not of a name, so they come from the latest observation that
// recorded them, whatever host it was made under — the latest observation
// alone is often a per-name row with no product, which is how
// "product:nginx" once missed most of the nginx ports.
const searchView = `
		FROM service sv
		JOIN ip_address ip ON ip.id = sv.ip_id
		JOIN scope sc ON sc.id = ip.scope_id
		JOIN LATERAL (
		  SELECT h.host,
		         (SELECT o.http FROM service_observation o
		           WHERE o.service_id = sv.id AND o.host = h.host AND o.http IS NOT NULL
		           ORDER BY o.observed_at DESC LIMIT 1) AS http,
		         base.product, base.version, base.banner, base.tls
		  FROM (SELECT DISTINCT host FROM service_observation WHERE service_id = sv.id
		        UNION SELECT '') h
		  CROSS JOIN LATERAL (
		    SELECT (SELECT product FROM service_observation WHERE service_id = sv.id
		             AND COALESCE(product,'') <> '' ORDER BY observed_at DESC LIMIT 1) AS product,
		           (SELECT version FROM service_observation WHERE service_id = sv.id
		             AND COALESCE(version,'') <> '' ORDER BY observed_at DESC LIMIT 1) AS version,
		           (SELECT banner FROM service_observation WHERE service_id = sv.id
		             AND COALESCE(banner,'') <> '' ORDER BY observed_at DESC LIMIT 1) AS banner,
		           (SELECT tls FROM service_observation WHERE service_id = sv.id
		             AND tls IS NOT NULL ORDER BY observed_at DESC LIMIT 1) AS tls
		  ) base
		  -- The address row is kept only when nothing was seen by name, or when
		  -- it has a response of its own; a port known only through its sites
		  -- does not also appear as a blank address.
		  WHERE h.host <> '' OR NOT EXISTS (SELECT 1 FROM service_observation WHERE service_id = sv.id AND host <> '')
		     OR EXISTS (SELECT 1 FROM service_observation WHERE service_id = sv.id AND host = '' AND http IS NOT NULL)
		) so ON true`

// Facet is one value and how many services carry it.
type Facet struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// Facets summarizes what a search matched: the service types behind a
// query, as counts per product, port, technology, title and HTTP status.
type Facets struct {
	Services int     `json:"services"`
	Sites    int     `json:"sites"`
	Products []Facet `json:"products"`
	Ports    []Facet `json:"ports"`
	Techs    []Facet `json:"techs"`
	Titles   []Facet `json:"titles"`
	Statuses []Facet `json:"statuses"`
}

// SearchFacets counts, over the rows a query matches, the values of each
// facet — the "what did we find" summary beside the result list. scopeID nil
// means every company.
func (s *Store) SearchFacets(ctx context.Context, scopeID *uuid.UUID, viewer uuid.UUID, whereSQL string, args []any) (Facets, error) {
	var f Facets
	scopePh := len(args) + 1
	viewerPh := len(args) + 2
	full := append(append([]any{}, args...), scopeID, viewer)
	matched := `WITH m AS (
		SELECT DISTINCT sv.id AS service_id, so.host, so.product, so.version, so.http` + searchView + `
		WHERE ($` + itoa(scopePh) + `::uuid IS NULL OR ip.scope_id = $` + itoa(scopePh) + `)
		  AND scope_visible(ip.scope_id, $` + itoa(viewerPh) + `)
		  AND (` + whereSQL + `)
	)`
	if err := s.Pool.QueryRow(ctx, matched+` SELECT count(DISTINCT service_id), count(*) FILTER (WHERE host <> '') FROM m`, full...).
		Scan(&f.Services, &f.Sites); err != nil {
		return f, err
	}
	facet := func(dst *[]Facet, expr, from string) error {
		rows, err := s.Pool.Query(ctx, matched+`
			SELECT v, count(DISTINCT service_id) AS n FROM (SELECT `+expr+` AS v, m.service_id `+from+`) x
			WHERE COALESCE(v,'') <> '' GROUP BY v ORDER BY n DESC, v LIMIT 15`, full...)
		if err != nil {
			return err
		}
		defer rows.Close()
		*dst = []Facet{}
		for rows.Next() {
			var fc Facet
			if err := rows.Scan(&fc.Value, &fc.Count); err != nil {
				return err
			}
			*dst = append(*dst, fc)
		}
		return rows.Err()
	}
	steps := []struct {
		dst        *[]Facet
		expr, from string
	}{
		{&f.Products, `m.product`, `FROM m`},
		{&f.Ports, `m.port::text`, `FROM (SELECT DISTINCT m.service_id, sv.port FROM m JOIN service sv ON sv.id = m.service_id) m`},
		{&f.Techs, `t.name`, `FROM m JOIN technology t ON t.service_id = m.service_id`},
		{&f.Titles, `m.http->>'title'`, `FROM m`},
		{&f.Statuses, `m.http->>'status'`, `FROM m`},
	}
	for _, st := range steps {
		if err := facet(st.dst, st.expr, st.from); err != nil {
			return f, err
		}
	}
	return f, nil
}

// SearchGlobal runs a compiled WHERE fragment across every company's inventory
// (or a single company when scopeID is non-nil), returning the owning company
// with each row. Powers the Shodan-style global search (Phase 14).
func (s *Store) SearchGlobal(ctx context.Context, scopeID *uuid.UUID, viewer uuid.UUID, whereSQL string, args []any, limit int) ([]SearchResult, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	scopePh := len(args) + 1
	limitPh := len(args) + 2
	viewerPh := len(args) + 3
	full := append(append([]any{}, args...), scopeID, limit, viewer)

	q := `
		SELECT DISTINCT sv.id, ip.id, sc.id, sc.name, host(ip.addr), sv.port, so.host, so.product, so.version,
		       (so.http->>'title'),
		       COALESCE(NULLIF(so.host,''), (SELECT d.name FROM domain_ip di JOIN domain d ON d.id=di.domain_id
		        WHERE di.ip_id=ip.id ORDER BY d.name LIMIT 1))` + searchView + `
		WHERE ($` + itoa(scopePh) + `::uuid IS NULL OR ip.scope_id = $` + itoa(scopePh) + `)
		  AND scope_visible(ip.scope_id, $` + itoa(viewerPh) + `)
		  AND (` + whereSQL + `)
		ORDER BY sc.name, host(ip.addr), sv.port, so.host
		LIMIT $` + itoa(limitPh)

	rows, err := s.Pool.Query(ctx, q, full...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SearchResult
	for rows.Next() {
		var r SearchResult
		if err := rows.Scan(&r.ServiceID, &r.IPID, &r.ScopeID, &r.Company, &r.IP, &r.Port, &r.Host,
			&r.Product, &r.Version, &r.Title, &r.Domain); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Search runs a compiled WHERE fragment against the service search view.
// The whereSQL and args come from search.Compile — never from raw user input.
func (s *Store) Search(ctx context.Context, scopeID uuid.UUID, whereSQL string, args []any, limit int) ([]SearchResult, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	// Bind scope and limit as the last two parameters.
	scopePh := len(args) + 1
	limitPh := len(args) + 2
	full := args
	full = append(full, scopeID, limit)

	q := `
		SELECT DISTINCT sv.id, ip.id, host(ip.addr), sv.port, so.host, so.product, so.version,
		       (so.http->>'title'),
		       COALESCE(NULLIF(so.host,''), (SELECT d.name FROM domain_ip di JOIN domain d ON d.id=di.domain_id
		        WHERE di.ip_id=ip.id ORDER BY d.name LIMIT 1))` + searchView + `
		WHERE ip.scope_id = $` + itoa(scopePh) + ` AND (` + whereSQL + `)
		ORDER BY sv.port, host(ip.addr), so.host
		LIMIT $` + itoa(limitPh)

	rows, err := s.Pool.Query(ctx, q, full...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SearchResult
	for rows.Next() {
		var r SearchResult
		if err := rows.Scan(&r.ServiceID, &r.IPID, &r.IP, &r.Port, &r.Host, &r.Product, &r.Version, &r.Title, &r.Domain); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
