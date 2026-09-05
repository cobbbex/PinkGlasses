package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/benlik386/pinkglasses/internal/domain"
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

// RecordDomainIPObservation notes that a run saw this name resolve to this
// address. Best-effort from the caller's side: the edge itself is already
// recorded by LinkDomainIP; this is the history behind it.
func (s *Store) RecordDomainIPObservation(ctx context.Context, domainID, ipID, runID uuid.UUID, at time.Time) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO domain_ip_observation (domain_id, ip_id, run_id, observed_at)
		VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, domainID, ipID, runID, at)
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
	// An absent document is stored as SQL NULL, not as the JSON value `null`
	// that marshalling a nil map produces. The difference matters: COALESCE and
	// the merge below only recognize SQL NULL, and jsonb `null` concatenated
	// with an object yields an array rather than a merge.
	httpJSON := jsonOrNil(o.HTTP)
	tlsJSON := jsonOrNil(o.TLS)
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO service_observation (service_id, run_id, worker_id, observed_at, banner, product, version, http, tls, screenshot_key, raw_key)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (service_id, run_id) DO UPDATE SET
		  -- Several stages write this one row: the port scan brings the banner
		  -- and version, tech detection the HTTP detail, the screenshot stage
		  -- its key. Each sends empty values for the fields it knows nothing
		  -- about, so an unguarded assignment lets whichever stage finishes last
		  -- erase what the others found — COALESCE alone did not help, because
		  -- an absent string arrives as '' rather than NULL, and an absent
		  -- document as jsonb 'null'. Only a non-empty value may overwrite.
		  banner=COALESCE(NULLIF(EXCLUDED.banner,''), service_observation.banner),
		  product=COALESCE(NULLIF(EXCLUDED.product,''), service_observation.product),
		  version=COALESCE(NULLIF(EXCLUDED.version,''), service_observation.version),
		  -- Merged rather than replaced, and the headers with it: the probe
		  -- captures the whole response, tech detection a handful of fields it
		  -- cares about. Assigning the newer document would throw away the
		  -- fuller one purely because it arrived second.
		  http=CASE
		         -- IS DISTINCT FROM, not <>: jsonb_typeof(NULL) is NULL, and a
		         -- NULL comparison is not true, so <> would fall through to the
		         -- merge and NULL out the column it was meant to preserve.
		         WHEN jsonb_typeof(EXCLUDED.http) IS DISTINCT FROM 'object' THEN service_observation.http
		         WHEN jsonb_typeof(service_observation.http) IS DISTINCT FROM 'object' THEN EXCLUDED.http
		         ELSE service_observation.http || EXCLUDED.http
		              || jsonb_build_object('headers',
		                   COALESCE(service_observation.http->'headers','{}'::jsonb)
		                   || COALESCE(EXCLUDED.http->'headers','{}'::jsonb))
		              -- Cookie names are unioned, not replaced: the probe and the
		              -- tech-detect pass may each see a different set, and a
		              -- fingerprint missing because the other stage wrote last
		              -- would be invisible.
		              || CASE
		                   WHEN COALESCE(service_observation.http->'cookies', EXCLUDED.http->'cookies') IS NULL
		                     THEN '{}'::jsonb
		                   ELSE jsonb_build_object('cookies', (
		                     SELECT COALESCE(jsonb_agg(DISTINCT c ORDER BY c), '[]'::jsonb)
		                     FROM jsonb_array_elements_text(
		                       COALESCE(service_observation.http->'cookies','[]'::jsonb)
		                       || COALESCE(EXCLUDED.http->'cookies','[]'::jsonb)) AS c))
		                 END
		       END,
		  tls=COALESCE(NULLIF(EXCLUDED.tls,'null'::jsonb), service_observation.tls),
		  screenshot_key=COALESCE(NULLIF(EXCLUDED.screenshot_key,''), service_observation.screenshot_key),
		  raw_key=COALESCE(NULLIF(EXCLUDED.raw_key,''), service_observation.raw_key)`,
		serviceID, runID, workerID, o.At, o.Banner, o.Product, o.Version, httpJSON, tlsJSON, o.ScreenshotKey, o.RawKey)
	return err
}

// jsonOrNil marshals a document, returning nil — a SQL NULL — when there is
// nothing to store, rather than the four bytes "null".
func jsonOrNil(v map[string]any) []byte {
	if len(v) == 0 {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
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
	DomainID *uuid.UUID `json:"domain_id,omitempty"`
	Name     string     `json:"name"`
	IPID     *uuid.UUID `json:"ip_id,omitempty"`
	Addr     *string    `json:"addr,omitempty"`
	PTR      *string    `json:"ptr,omitempty"`
	ASN      *int       `json:"asn,omitempty"`
	ASOrg    *string    `json:"as_org,omitempty"`
	ASRange  *string    `json:"as_range,omitempty"`
	Country  *string    `json:"country,omitempty"`
	Cloud    *string    `json:"cloud,omitempty"`
	IsShared bool       `json:"is_shared"`
	Services int        `json:"services"`
	// FirstSeen and LastSeen are when this name was first and most recently seen
	// resolving to this address — the pair, not the name or the address alone.
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// ScreenshotServiceID is the service on this address holding the most
	// recent screenshot, so the list can offer to show one without asking for
	// each row's services separately.
	ScreenshotServiceID *uuid.UUID `json:"screenshot_service_id,omitempty"`
}

// HostRowsResult carries the rows plus how many names were filtered out, so the
// UI can say what it is hiding rather than silently dropping discoveries.
type HostRowsResult struct {
	Rows             []HostRow `json:"rows"`
	UnresolvedHidden int       `json:"unresolved_hidden"`
}

// HostRows returns discovered names with their resolved address and ASN details.
//
// By default only names that currently resolve are returned. Passive sources
// (CT logs, passive DNS archives) surface large numbers of names that existed
// once and no longer resolve — tens of thousands for a long-lived domain — and
// they swamp the hosts that actually make up the attack surface today. They are
// still recorded, and includeUnresolved brings them back.
func (s *Store) HostRows(ctx context.Context, scopeID uuid.UUID, q string, limit int, includeUnresolved bool) (HostRowsResult, error) {
	var res HostRowsResult
	if limit <= 0 || limit > 1000 {
		limit = 500
	}

	// Count what the default view is holding back.
	if err := s.Pool.QueryRow(ctx, `
		SELECT count(*) FROM domain d
		LEFT JOIN domain_ip di ON di.domain_id = d.id
		WHERE d.scope_id = $1 AND di.domain_id IS NULL`, scopeID).Scan(&res.UnresolvedHidden); err != nil {
		return res, err
	}

	rows, err := s.Pool.Query(ctx, `
		SELECT d.id, d.name, ip.id, host(ip.addr), ip.ptr, ip.asn, ip.as_org,
		       ip.as_range, ip.country, ip.cloud, COALESCE(ip.is_shared,false),
		       COALESCE((SELECT count(*) FROM service sv WHERE sv.ip_id = ip.id), 0),
		       COALESCE(di.first_seen, d.first_seen), COALESCE(di.last_seen, d.last_seen), shot.service_id
		FROM domain d
		LEFT JOIN domain_ip di ON di.domain_id = d.id
		LEFT JOIN ip_address ip ON ip.id = di.ip_id
		LEFT JOIN LATERAL (
		  SELECT o.service_id
		  FROM service_observation o
		  JOIN service sv ON sv.id = o.service_id
		  WHERE sv.ip_id = ip.id AND COALESCE(o.screenshot_key,'') <> ''
		  ORDER BY o.observed_at DESC LIMIT 1
		) shot ON true
		WHERE d.scope_id = $1
		  AND ($4 OR ip.id IS NOT NULL)
		  AND ($2 = '' OR d.name ILIKE '%'||$2||'%' OR host(ip.addr) ILIKE '%'||$2||'%'
		       OR ip.as_org ILIKE '%'||$2||'%')
		ORDER BY (ip.id IS NULL), d.name, host(ip.addr)
		LIMIT $3`, scopeID, q, limit, includeUnresolved)
	if err != nil {
		return res, err
	}
	defer rows.Close()
	res.Rows = []HostRow{}
	for rows.Next() {
		var h HostRow
		if err := rows.Scan(&h.DomainID, &h.Name, &h.IPID, &h.Addr, &h.PTR, &h.ASN,
			&h.ASOrg, &h.ASRange, &h.Country, &h.Cloud, &h.IsShared, &h.Services,
			&h.FirstSeen, &h.LastSeen, &h.ScreenshotServiceID); err != nil {
			return res, err
		}
		res.Rows = append(res.Rows, h)
	}
	return res, rows.Err()
}

// LatestScreenshotKey returns the object key of the most recent screenshot of a
// service, or "" when none was ever captured. Callers address screenshots by
// service, never by key, so the key never leaves the server.
func (s *Store) LatestScreenshotKey(ctx context.Context, serviceID uuid.UUID) (string, error) {
	var key string
	err := s.Pool.QueryRow(ctx, `
		SELECT screenshot_key FROM service_observation
		WHERE service_id=$1 AND COALESCE(screenshot_key,'') <> ''
		ORDER BY observed_at DESC LIMIT 1`, serviceID).Scan(&key)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return key, err
}

// --- host detail (the Shodan-style per-address page) ---

// HostName is a discovered name that resolves to a host, with the record type
// that connected them.
type HostName struct {
	Name      string    `json:"name"`
	Via       string    `json:"via"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// History has one entry per completed run that resolved this name since
	// per-run resolution records began (00023): observed is whether it pointed
	// at this address in that run.
	History []domain.FindingRun `json:"history"`
	// AlsoResolvedTo lists the other addresses this name has pointed at, so a
	// move is visible from either side.
	AlsoResolvedTo []string `json:"also_resolved_to"`
}

// HostTech is a technology fingerprinted on one service.
type HostTech struct {
	Name    string  `json:"name"`
	Version *string `json:"version,omitempty"`
	CPE     *string `json:"cpe,omitempty"`
}

// HostService is an open port with the most recent thing observed on it. The
// service row records that the port is open; the observation carries what
// answered — banner, product and version, and the HTTP/TLS detail.
type HostService struct {
	domain.Service
	Banner       *string         `json:"banner,omitempty"`
	Product      *string         `json:"product,omitempty"`
	Version      *string         `json:"version,omitempty"`
	HTTP         json.RawMessage `json:"http,omitempty"`
	TLS          json.RawMessage `json:"tls,omitempty"`
	ObservedAt   *time.Time      `json:"observed_at,omitempty"`
	Technologies []HostTech      `json:"technologies"`
	// The key itself stays server-side: the image is fetched by service id,
	// so a caller cannot ask the API for an arbitrary object.
	HasScreenshot bool `json:"has_screenshot"`
	// History has one entry per completed run that port-scanned this address:
	// observed is whether that run found the port open. A port that closed and
	// reopened shows the gap, which first_seen/last_seen alone cannot.
	History []domain.FindingRun `json:"history"`
}

// HostDetailResult is everything known about one address.
type HostDetailResult struct {
	Host     domain.IPAddress `json:"host"`
	Names    []HostName       `json:"names"`
	Services []HostService    `json:"services"`
	Findings []domain.Finding `json:"findings"`
}

// HostDetail assembles the full record for one address: its enrichment, the
// names pointing at it, every open port with its latest observation and
// fingerprinted technologies, and the findings raised against the host or any
// of its services.
func (s *Store) HostDetail(ctx context.Context, ipID uuid.UUID) (HostDetailResult, error) {
	var res HostDetailResult
	res.Names = []HostName{}
	res.Services = []HostService{}
	res.Findings = []domain.Finding{}

	h := &res.Host
	if err := s.Pool.QueryRow(ctx, `
		SELECT id, scope_id, host(addr), ptr, asn, as_org, as_range, country, cloud,
		       is_shared, first_seen, last_seen
		FROM ip_address WHERE id=$1`, ipID).Scan(
		&h.ID, &h.ScopeID, &h.Addr, &h.PTR, &h.ASN, &h.ASOrg, &h.ASRange,
		&h.Country, &h.Cloud, &h.IsShared, &h.FirstSeen, &h.LastSeen); err != nil {
		return res, err
	}

	// Per name: one history entry for every completed run that resolved it
	// (a done dns_resolve task for that name) since 00023, marking whether that
	// run saw it point here. Runs before 00023 resolved names too but left no
	// per-run record, so they are excluded rather than read as "pointed away".
	nameRows, err := s.Pool.Query(ctx, `
		SELECT d.name, di.via, di.first_seen, di.last_seen,
		       COALESCE(h.hist, '[]'::jsonb),
		       COALESCE((SELECT array_agg(host(ip2.addr) ORDER BY ip2.addr)
		                   FROM domain_ip di2 JOIN ip_address ip2 ON ip2.id = di2.ip_id
		                  WHERE di2.domain_id = d.id AND di2.ip_id <> di.ip_id), '{}')
		FROM domain_ip di JOIN domain d ON d.id = di.domain_id
		LEFT JOIN LATERAL (
		  SELECT jsonb_agg(jsonb_build_object(
		           'run_id', r.id, 'at', r.started_at,
		           'observed', o.run_id IS NOT NULL, 'observed_at', o.observed_at)
		         ORDER BY r.started_at) AS hist
		  FROM (SELECT DISTINCT t.run_id FROM scan_task t
		         WHERE t.status = 'done' AND t.stage = 'dns_resolve'
		           AND t.target->>'domain' = d.name) tr
		  JOIN scan_run r ON r.id = tr.run_id AND r.status = 'completed'
		       AND r.started_at >= (SELECT tstamp FROM goose_db_version WHERE version_id = 23)
		  LEFT JOIN domain_ip_observation o
		         ON o.domain_id = di.domain_id AND o.ip_id = di.ip_id AND o.run_id = r.id
		) h ON true
		WHERE di.ip_id=$1 ORDER BY d.name`, ipID)
	if err != nil {
		return res, err
	}
	defer nameRows.Close()
	for nameRows.Next() {
		var n HostName
		var hist []byte
		n.History, n.AlsoResolvedTo = []domain.FindingRun{}, []string{}
		if err := nameRows.Scan(&n.Name, &n.Via, &n.FirstSeen, &n.LastSeen, &hist, &n.AlsoResolvedTo); err != nil {
			return res, err
		}
		_ = json.Unmarshal(hist, &n.History)
		res.Names = append(res.Names, n)
	}
	if err := nameRows.Err(); err != nil {
		return res, err
	}

	// One row per open port, joined to its most recent observation. A service is
	// re-observed on every run, so without the LATERAL limit this would return
	// the whole history of each port.
	svcRows, err := s.Pool.Query(ctx, `
		SELECT sv.id, sv.ip_id, sv.port, sv.proto, sv.last_state, sv.first_seen, sv.last_seen,
		       o.banner, o.product, o.version, o.http, o.tls, o.observed_at,
		       EXISTS (SELECT 1 FROM service_observation so
		                WHERE so.service_id = sv.id AND COALESCE(so.screenshot_key,'') <> ''),
		       COALESCE(h.hist, '[]'::jsonb)
		FROM service sv
		JOIN ip_address ip ON ip.id = sv.ip_id
		LEFT JOIN LATERAL (
		  SELECT banner, product, version, http, tls, observed_at
		  FROM service_observation
		  WHERE service_id = sv.id
		  ORDER BY observed_at DESC LIMIT 1
		) o ON true
		-- One entry per completed run that port-scanned this address. Port scans
		-- are batched, so the address is in target.ips; a single-address task
		-- carries target.ip.
		--
		-- "Observed" is read from the port-scan task's own result — the list of
		-- {ip, port} it reported open — not from service_observation. That table
		-- only gets a row when a probe had a product, version or banner to
		-- record, so 18 of 22 runs that found port 80 open on the test host left
		-- none; built on it, a hollow dot would have said "scanned, not found"
		-- about a port that was found. The observation row still counts as
		-- evidence when it exists, and supplies the timestamp.
		LEFT JOIN LATERAL (
		  SELECT jsonb_agg(jsonb_build_object(
		           'run_id', r.id, 'at', r.started_at,
		           'observed', (ps.found OR so.id IS NOT NULL),
		           'observed_at', COALESCE(so.observed_at, ps.finished_at))
		         ORDER BY r.started_at) AS hist
		  FROM (SELECT t.run_id,
		               bool_or(t.result->'services' @> jsonb_build_array(
		                 jsonb_build_object('ip', host(ip.addr), 'port', sv.port))) AS found,
		               max(t.finished_at) AS finished_at
		          FROM scan_task t
		         WHERE t.status = 'done' AND t.stage = 'port_scan'
		           AND (t.target->'ips' ? host(ip.addr) OR t.target->>'ip' = host(ip.addr))
		         GROUP BY t.run_id) ps
		  JOIN scan_run r ON r.id = ps.run_id AND r.status = 'completed'
		  LEFT JOIN service_observation so ON so.service_id = sv.id AND so.run_id = r.id
		) h ON true
		WHERE sv.ip_id=$1
		ORDER BY sv.port`, ipID)
	if err != nil {
		return res, err
	}
	defer svcRows.Close()
	byService := map[uuid.UUID]int{}
	for svcRows.Next() {
		var sv HostService
		var hist []byte
		sv.Technologies, sv.History = []HostTech{}, []domain.FindingRun{}
		if err := svcRows.Scan(&sv.ID, &sv.IPID, &sv.Port, &sv.Proto, &sv.LastState,
			&sv.FirstSeen, &sv.LastSeen,
			&sv.Banner, &sv.Product, &sv.Version, &sv.HTTP, &sv.TLS, &sv.ObservedAt,
			&sv.HasScreenshot, &hist); err != nil {
			return res, err
		}
		_ = json.Unmarshal(hist, &sv.History)
		byService[sv.ID] = len(res.Services)
		res.Services = append(res.Services, sv)
	}
	if err := svcRows.Err(); err != nil {
		return res, err
	}

	techRows, err := s.Pool.Query(ctx, `
		SELECT t.service_id, t.name, t.version, t.cpe
		FROM technology t JOIN service sv ON sv.id = t.service_id
		WHERE sv.ip_id=$1 ORDER BY t.name`, ipID)
	if err != nil {
		return res, err
	}
	defer techRows.Close()
	for techRows.Next() {
		var sid uuid.UUID
		var t HostTech
		if err := techRows.Scan(&sid, &t.Name, &t.Version, &t.CPE); err != nil {
			return res, err
		}
		if i, ok := byService[sid]; ok {
			res.Services[i].Technologies = append(res.Services[i].Technologies, t)
		}
	}
	if err := techRows.Err(); err != nil {
		return res, err
	}

	// Findings are raised against either the host itself or one of its services;
	// the page shows both, because "which machine is this about" is the question
	// being asked here.
	findRows, err := s.Pool.Query(ctx, `
		SELECT f.id, f.scope_id, f.asset_kind, f.asset_id, f.kind, f.severity,
		       f.title, f.status, f.first_seen, f.last_seen, COALESCE(h.hist, '[]'::jsonb)
		FROM finding f
		`+findingHistorySQL+`
		WHERE (f.asset_kind='ip' AND f.asset_id=$1)
		   OR (f.asset_kind='service' AND f.asset_id IN (SELECT id FROM service WHERE ip_id=$1))
		ORDER BY CASE f.severity
		           WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
		           WHEN 'low' THEN 3 ELSE 4 END, f.last_seen DESC`, ipID)
	if err != nil {
		return res, err
	}
	defer findRows.Close()
	for findRows.Next() {
		f, err := scanFindingWithHistory(findRows)
		if err != nil {
			return res, err
		}
		res.Findings = append(res.Findings, f)
	}
	return res, findRows.Err()
}

// SharedAddresses returns the addresses in a scope marked as shared
// infrastructure — CDN or common hosting — keyed by address. The scope guard
// refuses to port scan these: what is behind them is somebody else's box.
func (s *Store) SharedAddresses(ctx context.Context, scopeID uuid.UUID) (map[string]bool, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT host(addr) FROM ip_address WHERE scope_id=$1 AND is_shared`, scopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out[ip] = true
	}
	return out, rows.Err()
}
