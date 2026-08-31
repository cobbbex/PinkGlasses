// Package ingest normalizes worker observations into the temporal asset graph.
// This is where facts become inventory: workers never write to the database and
// never dedupe or diff — that all happens here (architecture.md §5.5, §8.4).
package ingest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/benlik386/asm/internal/planner"
	"github.com/benlik386/asm/internal/scanproto"
	"github.com/benlik386/asm/internal/store"
)

// Ingestor writes observations for a run.
type Ingestor struct {
	st    *store.Store
	scope map[uuid.UUID]uuid.UUID // runID -> scopeID cache
}

// New builds an Ingestor.
func New(st *store.Store) *Ingestor {
	return &Ingestor{st: st, scope: map[uuid.UUID]uuid.UUID{}}
}

func (in *Ingestor) scopeOf(ctx context.Context, runID uuid.UUID) (uuid.UUID, error) {
	if id, ok := in.scope[runID]; ok {
		return id, nil
	}
	run, err := in.st.GetRun(ctx, runID)
	if err != nil {
		return uuid.Nil, err
	}
	in.scope[runID] = run.ScopeID
	return run.ScopeID, nil
}

// Process upserts a batch of observations and returns a stage summary the
// planner uses to enqueue the next stage.
func (in *Ingestor) Process(ctx context.Context, runID uuid.UUID, workerID *uuid.UUID, stage scanproto.Stage, obs []scanproto.Observation) (planner.StageSummary, error) {
	var sum planner.StageSummary
	scopeID, err := in.scopeOf(ctx, runID)
	if err != nil {
		return sum, err
	}
	now := time.Now()
	domSeen := map[string]bool{}
	ipSeen := map[string]bool{}
	svcSeen := map[string]bool{}
	urlSeen := map[string]bool{}

	for _, o := range obs {
		switch o.Type {
		case scanproto.ObsSubdomain:
			if o.Domain == "" {
				continue
			}
			if _, err := in.st.UpsertDomain(ctx, scopeID, norm(o.Domain), planner.Apex(o.Domain), o.Source, now); err != nil {
				return sum, err
			}
			if !domSeen[o.Domain] {
				sum.Domains = append(sum.Domains, o.Domain)
				domSeen[o.Domain] = true
			}

		case scanproto.ObsDNSRecord:
			domID, err := in.st.UpsertDomain(ctx, scopeID, norm(o.Domain), planner.Apex(o.Domain), "dns", now)
			if err != nil {
				return sum, err
			}
			if err := in.st.UpsertDNSRecord(ctx, domID, o.RType, o.Value, o.TTL, now); err != nil {
				return sum, err
			}
			if o.RType == "A" || o.RType == "AAAA" {
				ipID, err := in.st.UpsertIP(ctx, scopeID, o.Value, now)
				if err != nil {
					return sum, err
				}
				if err := in.st.LinkDomainIP(ctx, domID, ipID, o.RType, now); err != nil {
					return sum, err
				}
				if !ipSeen[o.Value] {
					sum.IPs = append(sum.IPs, o.Value)
					ipSeen[o.Value] = true
				}
			}

		case scanproto.ObsIP:
			ipID, err := in.st.UpsertIP(ctx, scopeID, o.IP, now)
			if err != nil {
				return sum, err
			}
			if o.PTR != "" || o.ASN != 0 || o.ASOrg != "" || o.ASRange != "" ||
				o.Country != "" || o.Cloud != "" || o.Shared {
				_ = in.st.EnrichIP(ctx, ipID, o.PTR, o.ASOrg, o.Country, o.Cloud, o.ASRange, o.ASN, o.Shared)
			}
			if !ipSeen[o.IP] {
				sum.IPs = append(sum.IPs, o.IP)
				ipSeen[o.IP] = true
			}

		case scanproto.ObsService:
			svcID, err := in.serviceID(ctx, scopeID, o.IP, o.Port, o.Proto, o.State, now)
			if err != nil {
				return sum, err
			}
			// nmap -sV style detail: record product/version/banner as an observation.
			if o.Product != "" || o.Version != "" || o.Banner != "" {
				so := domainObs(now)
				so.Product, so.Version, so.Banner = o.Product, o.Version, o.Banner
				_ = in.st.UpsertServiceObservation(ctx, svcID, runID, workerID, so)
			}
			key := fmt.Sprintf("%s:%d", o.IP, o.Port)
			if !svcSeen[key] {
				sum.Services = append(sum.Services, planner.IPPort{IP: o.IP, Port: o.Port})
				svcSeen[key] = true
			}

		case scanproto.ObsHTTP:
			svcID, err := in.serviceID(ctx, scopeID, o.IP, o.Port, "tcp", "open", now)
			if err != nil {
				return sum, err
			}
			so := domainObs(now)
			so.Product = o.Product
			so.Version = o.Version
			so.HTTP = map[string]any{"status": o.Status, "title": o.Title, "headers": o.Headers, "favicon": o.Favicon}
			if err := in.st.UpsertServiceObservation(ctx, svcID, runID, workerID, so); err != nil {
				return sum, err
			}
			if u := urlFor(o); u != "" && !urlSeen[u] {
				sum.WebURLs = append(sum.WebURLs, u)
				urlSeen[u] = true
			}

		case scanproto.ObsTLS:
			svcID, err := in.serviceID(ctx, scopeID, o.IP, o.Port, "tcp", "open", now)
			if err != nil {
				return sum, err
			}
			so := domainObs(now)
			so.TLS = map[string]any{"cert_sha256": o.CertSHA256, "subject_cn": o.SubjectCN, "issuer": o.Issuer, "sans": o.SANs, "not_after": o.NotAfter}
			if err := in.st.UpsertServiceObservation(ctx, svcID, runID, workerID, so); err != nil {
				return sum, err
			}

		case scanproto.ObsTech:
			svcID, err := in.serviceID(ctx, scopeID, o.IP, o.Port, "tcp", "open", now)
			if err != nil {
				return sum, err
			}
			if err := in.st.UpsertTechnology(ctx, svcID, o.TechName, o.TechVersion, o.TechCPE, o.TechConfidence, now); err != nil {
				return sum, err
			}

		case scanproto.ObsScreenshot:
			svcID, err := in.serviceID(ctx, scopeID, o.IP, o.Port, "tcp", "open", now)
			if err != nil {
				return sum, err
			}
			so := domainObs(now)
			so.ScreenshotKey = o.ScreenshotKey
			if err := in.st.UpsertServiceObservation(ctx, svcID, runID, workerID, so); err != nil {
				return sum, err
			}

		case scanproto.ObsPath:
			// content-discovery hit; surfaced as an informational finding on the service
			svcID, err := in.serviceID(ctx, scopeID, o.IP, o.Port, "tcp", "open", now)
			if err == nil {
				_ = in.st.UpsertFinding(ctx, scopeID, svcID, "service", "content_discovery", "info",
					"Discovered path: "+o.Path, map[string]any{"path": o.Path, "status": o.Status}, now)
			}

		case scanproto.ObsFinding:
			var assetID uuid.UUID
			if o.IP != "" && o.Port != 0 {
				assetID, _ = in.serviceID(ctx, scopeID, o.IP, o.Port, "tcp", "open", now)
			}
			_ = in.st.UpsertFinding(ctx, scopeID, assetID, "service", o.FindingKind, sev(o.FindingSeverity),
				o.FindingTitle, map[string]any{"banner": o.Banner}, now)
		}
	}
	return sum, nil
}

func (in *Ingestor) serviceID(ctx context.Context, scopeID uuid.UUID, ip string, port int, proto, state string, at time.Time) (uuid.UUID, error) {
	ipID, err := in.st.UpsertIP(ctx, scopeID, ip, at)
	if err != nil {
		return uuid.Nil, err
	}
	if proto == "" {
		proto = "tcp"
	}
	if state == "" {
		state = "open"
	}
	return in.st.UpsertService(ctx, ipID, port, proto, state, at)
}

func domainObs(at time.Time) domainServiceObs { return domainServiceObs{At: at} }

// domainServiceObs is an alias to the store's expected shape.
type domainServiceObs = domainObsAlias

func norm(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".") }

func urlFor(o scanproto.Observation) string {
	if o.IP == "" || o.Port == 0 {
		return ""
	}
	scheme := "http"
	if o.Port == 443 || o.Port == 8443 {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, o.IP, o.Port)
}

func sev(s string) string {
	switch s {
	case "critical", "high", "medium", "low", "info":
		return s
	default:
		return "info"
	}
}
