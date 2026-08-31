package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/benlik386/asm/internal/domain"
)

// --- temporal upserts (used by ingest) ---
// Every upsert advances last_seen but preserves first_seen, so the asset
// inventory doubles as its own change history (architecture.md §5.5).

// UpsertDomain inserts or refreshes a domain, merging discovery sources.
func (s *Store) UpsertDomain(ctx context.Context, scopeID uuid.UUID, name, apex, source string, at time.Time) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO domain (scope_id, name, apex, sources, first_seen, last_seen)
		VALUES ($1,$2,$3, CASE WHEN $4<>'' THEN ARRAY[$4] ELSE '{}' END, $5,$5)
		ON CONFLICT (scope_id, name) DO UPDATE SET
		  last_seen = GREATEST(domain.last_seen, EXCLUDED.last_seen),
		  sources = ARRAY(SELECT DISTINCT unnest(domain.sources || EXCLUDED.sources))
		RETURNING id`,
		scopeID, name, apex, source, at,
	).Scan(&id)
	return id, err
}

// UpsertDNSRecord inserts or refreshes a DNS record.
func (s *Store) UpsertDNSRecord(ctx context.Context, domainID uuid.UUID, rtype, value string, ttl int, at time.Time) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO dns_record (domain_id, rtype, value, ttl, first_seen, last_seen)
		VALUES ($1,$2,$3,$4,$5,$5)
		ON CONFLICT (domain_id, rtype, value) DO UPDATE SET
		  last_seen = GREATEST(dns_record.last_seen, EXCLUDED.last_seen), ttl = EXCLUDED.ttl`,
		domainID, rtype, value, ttl, at)
	return err
}

// UpsertIP inserts or refreshes an IP, applying enrichment when provided.
func (s *Store) UpsertIP(ctx context.Context, scopeID uuid.UUID, addr string, at time.Time) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO ip_address (scope_id, addr, first_seen, last_seen)
		VALUES ($1,$2,$3,$3)
		ON CONFLICT (scope_id, addr) DO UPDATE SET
		  last_seen = GREATEST(ip_address.last_seen, EXCLUDED.last_seen)
		RETURNING id`,
		scopeID, addr, at,
	).Scan(&id)
	return id, err
}

// EnrichIP updates ASN/geo/PTR/cloud/range fields for an IP. Every field is
// applied only when non-empty, so a later partial observation (a reverse-DNS
// pass carrying only PTR) never erases ASN data recorded earlier.
func (s *Store) EnrichIP(ctx context.Context, id uuid.UUID, ptr, asOrg, country, cloud, asRange string, asn int, shared bool) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE ip_address SET
		  ptr      = COALESCE(NULLIF($2,''), ptr),
		  as_org   = COALESCE(NULLIF($3,''), as_org),
		  country  = COALESCE(NULLIF($4,''), country),
		  cloud    = COALESCE(NULLIF($5,''), cloud),
		  as_range = COALESCE(NULLIF($6,''), as_range),
		  asn      = COALESCE(NULLIF($7,0), asn),
		  is_shared = is_shared OR $8
		WHERE id=$1`, id, ptr, asOrg, country, cloud, asRange, asn, shared)
	return err
}


// LinkDomainIP records a temporal domain->ip edge (the DNSDumpster map).
func (s *Store) LinkDomainIP(ctx context.Context, domainID, ipID uuid.UUID, via string, at time.Time) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO domain_ip (domain_id, ip_id, via, first_seen, last_seen)
		VALUES ($1,$2,$3,$4,$4)
		ON CONFLICT (domain_id, ip_id, via) DO UPDATE SET
		  last_seen = GREATEST(domain_ip.last_seen, EXCLUDED.last_seen)`,
		domainID, ipID, via, at)
	return err
}

// UpsertService inserts or refreshes an open port.
func (s *Store) UpsertService(ctx context.Context, ipID uuid.UUID, port int, proto, state string, at time.Time) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO service (ip_id, port, proto, last_state, first_seen, last_seen)
		VALUES ($1,$2,$3,$4,$5,$5)
		ON CONFLICT (ip_id, port, proto) DO UPDATE SET
		  last_seen = GREATEST(service.last_seen, EXCLUDED.last_seen), last_state = EXCLUDED.last_state
		RETURNING id`,
		ipID, port, proto, state, at,
	).Scan(&id)
	return id, err
}

// UpsertServiceObservation records the per-run service snapshot.
func (s *Store) UpsertServiceObservation(ctx context.Context, serviceID, runID uuid.UUID, workerID *uuid.UUID, o domain.ServiceObs) error {
	httpJSON, _ := json.Marshal(o.HTTP)
	tlsJSON, _ := json.Marshal(o.TLS)
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO service_observation (service_id, run_id, worker_id, observed_at, banner, product, version, http, tls, screenshot_key, raw_key)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (service_id, run_id) DO UPDATE SET
		  banner=EXCLUDED.banner, product=EXCLUDED.product, version=EXCLUDED.version,
		  http=EXCLUDED.http, tls=EXCLUDED.tls,
		  screenshot_key=COALESCE(EXCLUDED.screenshot_key, service_observation.screenshot_key),
		  raw_key=COALESCE(EXCLUDED.raw_key, service_observation.raw_key)`,
		serviceID, runID, workerID, o.At, o.Banner, o.Product, o.Version, httpJSON, tlsJSON, o.ScreenshotKey, o.RawKey)
	return err
}

// UpsertTechnology records a detected technology on a service.
func (s *Store) UpsertTechnology(ctx context.Context, serviceID uuid.UUID, name, version, cpe string, confidence int, at time.Time) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO technology (service_id, name, version, cpe, confidence, first_seen, last_seen)
		VALUES ($1,$2,$3,NULLIF($4,''),$5,$6,$6)
		ON CONFLICT (service_id, name, version) DO UPDATE SET
		  last_seen = GREATEST(technology.last_seen, EXCLUDED.last_seen), confidence = EXCLUDED.confidence`,
		serviceID, name, version, cpe, confidence, at)
	return err
}

// --- read methods (used by the API) ---

// ListDomains returns domains for a scope, newest activity first.
func (s *Store) ListDomains(ctx context.Context, scopeID uuid.UUID, q string, limit int) ([]domain.Domain, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT id, scope_id, name, apex, is_wildcard, sources, first_seen, last_seen
		FROM domain WHERE scope_id=$1 AND ($2='' OR name ILIKE '%'||$2||'%')
		ORDER BY last_seen DESC LIMIT $3`, scopeID, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Domain
	for rows.Next() {
		var d domain.Domain
		if err := rows.Scan(&d.ID, &d.ScopeID, &d.Name, &d.Apex, &d.IsWildcard, &d.Sources, &d.FirstSeen, &d.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ListHosts returns IP addresses for a scope.
func (s *Store) ListHosts(ctx context.Context, scopeID uuid.UUID, limit int) ([]domain.IPAddress, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT id, scope_id, host(addr), ptr, asn, as_org, as_range, country, cloud, is_shared, first_seen, last_seen
		FROM ip_address WHERE scope_id=$1 ORDER BY last_seen DESC LIMIT $2`, scopeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.IPAddress
	for rows.Next() {
		var ip domain.IPAddress
		if err := rows.Scan(&ip.ID, &ip.ScopeID, &ip.Addr, &ip.PTR, &ip.ASN, &ip.ASOrg, &ip.ASRange,
			&ip.Country, &ip.Cloud, &ip.IsShared, &ip.FirstSeen, &ip.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// HostServices returns the open services on a host.
func (s *Store) HostServices(ctx context.Context, ipID uuid.UUID) ([]domain.Service, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, ip_id, port, proto, last_state, first_seen, last_seen
		FROM service WHERE ip_id=$1 ORDER BY port`, ipID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Service
	for rows.Next() {
		var sv domain.Service
		if err := rows.Scan(&sv.ID, &sv.IPID, &sv.Port, &sv.Proto, &sv.LastState, &sv.FirstSeen, &sv.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, sv)
	}
	return out, rows.Err()
}

// DomainGraph returns the domain->ip edges for the DNSDumpster map view.
func (s *Store) DomainGraph(ctx context.Context, scopeID uuid.UUID) ([]GraphEdge, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT d.name, host(ip.addr), di.via
		FROM domain_ip di
		JOIN domain d ON d.id = di.domain_id
		JOIN ip_address ip ON ip.id = di.ip_id
		WHERE d.scope_id=$1 LIMIT 5000`, scopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GraphEdge
	for rows.Next() {
		var e GraphEdge
		if err := rows.Scan(&e.Domain, &e.IP, &e.Via); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GraphEdge is one domain->ip relationship in the asset map.
type GraphEdge struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	Via    string `json:"via"`
}

// HostRow is the unified Hosts view: one row per subdomain, carrying the
// address it resolves to and that address's network provenance. This replaces
// the split Domains/Hosts pages — a name and where it lives are the same
// question in practice.
type HostRow struct {
	DomainID  *uuid.UUID `json:"domain_id,omitempty"`
	Name      string     `json:"name"`
	IPID      *uuid.UUID `json:"ip_id,omitempty"`
	Addr      *string    `json:"addr,omitempty"`
	PTR       *string    `json:"ptr,omitempty"`
	ASN       *int       `json:"asn,omitempty"`
	ASOrg     *string    `json:"as_org,omitempty"`
	ASRange   *string    `json:"as_range,omitempty"`
	Country   *string    `json:"country,omitempty"`
	Cloud     *string    `json:"cloud,omitempty"`
	IsShared  bool       `json:"is_shared"`
	Services  int        `json:"services"`
	LastSeen  time.Time  `json:"last_seen"`
}

// HostRows returns every discovered name with its resolved address and ASN
// details. Names that do not resolve are still listed, with empty address
// fields, so nothing discovered silently disappears from the inventory.
func (s *Store) HostRows(ctx context.Context, scopeID uuid.UUID, q string, limit int) ([]HostRow, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT d.id, d.name, ip.id, host(ip.addr), ip.ptr, ip.asn, ip.as_org,
		       ip.as_range, ip.country, ip.cloud, COALESCE(ip.is_shared,false),
		       COALESCE((SELECT count(*) FROM service sv WHERE sv.ip_id = ip.id), 0),
		       d.last_seen
		FROM domain d
		LEFT JOIN domain_ip di ON di.domain_id = d.id
		LEFT JOIN ip_address ip ON ip.id = di.ip_id
		WHERE d.scope_id = $1
		  AND ($2 = '' OR d.name ILIKE '%'||$2||'%' OR host(ip.addr) ILIKE '%'||$2||'%'
		       OR ip.as_org ILIKE '%'||$2||'%')
		ORDER BY d.name, host(ip.addr)
		LIMIT $3`, scopeID, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HostRow{}
	for rows.Next() {
		var h HostRow
		if err := rows.Scan(&h.DomainID, &h.Name, &h.IPID, &h.Addr, &h.PTR, &h.ASN,
			&h.ASOrg, &h.ASRange, &h.Country, &h.Cloud, &h.IsShared, &h.Services, &h.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
