package store

import (
	"context"

	"github.com/google/uuid"
)

// SearchResult is one service row returned by a search query.
type SearchResult struct {
	ServiceID uuid.UUID `json:"service_id"`
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	Product   *string   `json:"product,omitempty"`
	Version   *string   `json:"version,omitempty"`
	Title     *string   `json:"title,omitempty"`
	Domain    *string   `json:"domain,omitempty"`
}

// Search runs a compiled WHERE fragment against the service search view.
// The whereSQL and args come from search.Compile — never from raw user input.
func (s *Store) Search(ctx context.Context, scopeID uuid.UUID, whereSQL string, args []any, limit int) ([]SearchResult, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	// Bind scope and limit as the last two parameters.
	scopePh := len(args) + 1
	limitPh := len(args) + 2
	full := args
	full = append(full, scopeID, limit)

	q := `
		SELECT DISTINCT sv.id, host(ip.addr), sv.port, so.product, so.version,
		       (so.http->>'title'),
		       (SELECT d.name FROM domain_ip di JOIN domain d ON d.id=di.domain_id
		        WHERE di.ip_id=ip.id ORDER BY d.name LIMIT 1)
		FROM service sv
		JOIN ip_address ip ON ip.id = sv.ip_id
		LEFT JOIN LATERAL (
		  SELECT * FROM service_observation o WHERE o.service_id=sv.id
		  ORDER BY o.observed_at DESC LIMIT 1
		) so ON true
		WHERE ip.scope_id = $` + itoa(scopePh) + ` AND (` + whereSQL + `)
		ORDER BY sv.port
		LIMIT $` + itoa(limitPh)

	rows, err := s.Pool.Query(ctx, q, full...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SearchResult
	for rows.Next() {
		var r SearchResult
		if err := rows.Scan(&r.ServiceID, &r.IP, &r.Port, &r.Product, &r.Version, &r.Title, &r.Domain); err != nil {
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
