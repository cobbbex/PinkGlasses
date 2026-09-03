package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/benlik386/pinkglasses/internal/domain"
)

// findingStage maps a finding kind to the stage that produces it. Presence is
// judged only against runs that executed that stage: a passive run never looks
// for paths, so a path it did not report is not a path that has gone.
const findingStage = `CASE WHEN f.kind = 'content_discovery' THEN 'dir_brute'
                           WHEN f.kind LIKE 'nuclei:%' THEN 'vuln_check'
                           ELSE 'service_probe' END`

// historyStartSQL is when observations began being recorded: the moment
// migration 16 applied. Runs before it did look, and did find things, but left
// no per-run record — so they are excluded rather than shown as "looked and did
// not find", which is what a missing row would otherwise read as.
const historyStartSQL = `(SELECT tstamp FROM goose_db_version WHERE version_id = 16)`

// findingHistorySQL is a LATERAL producing, for finding alias f, one JSON entry
// per completed run that covered the finding's host with the producing stage,
// with whether that run observed the finding.
const findingHistorySQL = `LEFT JOIN LATERAL (
	  SELECT jsonb_agg(jsonb_build_object(
	           'run_id', r.id, 'at', r.started_at,
	           'observed', fo.id IS NOT NULL,
	           'observed_at', fo.observed_at, 'severity', fo.severity)
	         ORDER BY r.started_at) AS hist
	  FROM (SELECT DISTINCT t.run_id
	          FROM scan_task t
	          JOIN service sv ON sv.id = f.asset_id
	          JOIN ip_address ip ON ip.id = sv.ip_id
	         WHERE t.status = 'done'
	           AND t.target->>'ip' = host(ip.addr)
	           AND t.stage = ` + findingStage + `) tr
	  JOIN scan_run r ON r.id = tr.run_id AND r.status = 'completed'
	       AND r.started_at >= ` + historyStartSQL + `
	  LEFT JOIN finding_observation fo ON fo.finding_id = f.id AND fo.run_id = r.id
	) h ON true`

// UpsertFinding inserts or refreshes a finding and returns its id.
func (s *Store) UpsertFinding(ctx context.Context, scopeID, assetID uuid.UUID, assetKind, kind, severity, title string, evidence map[string]any, at time.Time) (uuid.UUID, error) {
	ev, _ := json.Marshal(evidence)
	// A finding is identified by its asset, kind and title (00013). Matching on
	// the asset and kind alone made every finding of a stage that raises one per
	// item — a path per content-discovery hit — collapse onto the last one seen.
	// A resolved finding keeps its timestamps: re-observing it must not quietly
	// reopen something a human has closed.
	var id uuid.UUID
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO finding (scope_id, asset_kind, asset_id, kind, severity, title, evidence, first_seen, last_seen)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8)
		ON CONFLICT (scope_id, asset_kind, asset_id, kind, title) DO UPDATE SET
		  last_seen = GREATEST(finding.last_seen, EXCLUDED.last_seen),
		  severity = EXCLUDED.severity,
		  evidence = EXCLUDED.evidence
		WHERE finding.status <> 'resolved'
		RETURNING id`,
		scopeID, assetKind, assetID, kind, severity, title, ev, at).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		// The conflict hit a resolved finding, which the WHERE left untouched
		// and therefore unreturned; it still exists and still gets an observation.
		err = s.Pool.QueryRow(ctx, `
			SELECT id FROM finding
			WHERE scope_id=$1 AND asset_kind=$2 AND asset_id=$3 AND kind=$4 AND title=$5`,
			scopeID, assetKind, assetID, kind, title).Scan(&id)
	}
	return id, err
}

// RecordFindingObservation notes that a run observed a finding, with the
// severity and evidence as they were at the time. One row per (finding, run):
// several stages re-reporting the same finding within a run collapse to one.
func (s *Store) RecordFindingObservation(ctx context.Context, findingID, runID uuid.UUID, severity string, evidence map[string]any, at time.Time) error {
	ev, _ := json.Marshal(evidence)
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO finding_observation (finding_id, run_id, observed_at, severity, evidence)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (finding_id, run_id) DO UPDATE SET
		  observed_at = EXCLUDED.observed_at, severity = EXCLUDED.severity, evidence = EXCLUDED.evidence`,
		findingID, runID, at, severity, ev)
	return err
}

// ListFindings returns findings for a scope with their run history and derived
// presence, filterable by status/severity.
func (s *Store) ListFindings(ctx context.Context, scopeID uuid.UUID, status, severity string) ([]domain.Finding, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT f.id, f.scope_id, f.asset_kind, f.asset_id, f.kind, f.severity, f.title, f.status,
		       f.first_seen, f.last_seen, COALESCE(h.hist, '[]'::jsonb)
		FROM finding f
		`+findingHistorySQL+`
		WHERE f.scope_id=$1 AND ($2='' OR f.status=$2) AND ($3='' OR f.severity=$3)
		ORDER BY
		  array_position(ARRAY['critical','high','medium','low','info'], f.severity),
		  f.last_seen DESC
		LIMIT 500`, scopeID, status, severity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Finding{}
	for rows.Next() {
		f, err := scanFindingWithHistory(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// scanFindingWithHistory reads the standard finding columns followed by the
// history JSON, and derives presence.
func scanFindingWithHistory(rows pgx.Rows) (domain.Finding, error) {
	var f domain.Finding
	var hist []byte
	if err := rows.Scan(&f.ID, &f.ScopeID, &f.AssetKind, &f.AssetID, &f.Kind,
		&f.Severity, &f.Title, &f.Status, &f.FirstSeen, &f.LastSeen, &hist); err != nil {
		return f, err
	}
	_ = json.Unmarshal(hist, &f.History)
	if f.History == nil {
		f.History = []domain.FindingRun{}
	}
	f.DerivePresence()
	return f, nil
}

// FindingPresenceChange is the differ's view of one finding after a run:
// whether this run saw it, and whether the previous covering run did.
type FindingPresenceChange struct {
	ID             uuid.UUID
	Kind, Severity string
	Title          string
	ObservedNow    bool
	HasPrevious    bool
	ObservedBefore bool
}

// FindingsCoveredByRun returns every finding this run could have observed —
// its host was probed by the producing stage — with what this run and the
// previous covering run saw. It is how the differ tells "gone" from "returned".
func (s *Store) FindingsCoveredByRun(ctx context.Context, runID, scopeID uuid.UUID) ([]FindingPresenceChange, error) {
	rows, err := s.Pool.Query(ctx, `
		WITH covered AS (
		  SELECT DISTINCT f.id, f.kind, f.severity, f.title, ip.addr
		    FROM finding f
		    JOIN service sv ON sv.id = f.asset_id
		    JOIN ip_address ip ON ip.id = sv.ip_id
		    JOIN scan_task t ON t.run_id = $1 AND t.status = 'done'
		         AND t.target->>'ip' = host(ip.addr)
		         AND t.stage = `+findingStage+`
		   WHERE f.scope_id = $2
		),
		prev AS (
		  SELECT c.id AS finding_id, r.id AS run_id
		    FROM covered c
		    JOIN LATERAL (
		      SELECT r2.id
		        FROM scan_run r2
		        JOIN scan_task t2 ON t2.run_id = r2.id AND t2.status = 'done'
		             AND t2.target->>'ip' = host(c.addr)
		             AND t2.stage = (SELECT `+strings.Replace(findingStage, "f.kind", "c.kind", -1)+`)
		       WHERE r2.status = 'completed' AND r2.id <> $1
		         AND r2.started_at >= `+historyStartSQL+`
		         AND r2.started_at < (SELECT started_at FROM scan_run WHERE id = $1)
		       ORDER BY r2.started_at DESC LIMIT 1
		    ) r ON true
		)
		SELECT c.id, c.kind, c.severity, c.title,
		       EXISTS (SELECT 1 FROM finding_observation fo WHERE fo.finding_id = c.id AND fo.run_id = $1),
		       p.run_id IS NOT NULL,
		       COALESCE((SELECT true FROM finding_observation fo2
		                  WHERE fo2.finding_id = c.id AND fo2.run_id = p.run_id), false)
		  FROM covered c
		  LEFT JOIN prev p ON p.finding_id = c.id`, runID, scopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingPresenceChange
	for rows.Next() {
		var c FindingPresenceChange
		if err := rows.Scan(&c.ID, &c.Kind, &c.Severity, &c.Title,
			&c.ObservedNow, &c.HasPrevious, &c.ObservedBefore); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetFindingStatus updates a finding's workflow status.
func (s *Store) SetFindingStatus(ctx context.Context, id uuid.UUID, status string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE finding SET status=$2,
		  resolved_at = CASE WHEN $2='resolved' THEN now() ELSE resolved_at END
		WHERE id=$1`, id, status)
	return err
}

// ExpiringCerts finds certificates near expiry, used by the scheduler sweep.
func (s *Store) ExpiringCerts(ctx context.Context, within time.Duration) ([]uuid.UUID, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id FROM certificate WHERE not_after IS NOT NULL AND not_after < now()+$1::interval`,
		within.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// RecordChangeEvent inserts a change event (used by the differ).
func (s *Store) RecordChangeEvent(ctx context.Context, runID uuid.UUID, runTargetID *uuid.UUID, scopeID uuid.UUID, kind, assetKind string, assetID uuid.UUID, before, after map[string]any) error {
	b, _ := json.Marshal(before)
	a, _ := json.Marshal(after)
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO change_event (run_id, run_target_id, scope_id, kind, asset_kind, asset_id, before, after)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		runID, runTargetID, scopeID, kind, assetKind, assetID, b, a)
	return err
}

// ListChangeEvents returns the change events produced by a run.
func (s *Store) ListChangeEvents(ctx context.Context, runID uuid.UUID) ([]map[string]any, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT kind, asset_kind, asset_id, after, created_at
		FROM change_event WHERE run_id=$1 ORDER BY created_at`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var kind, assetKind string
		var assetID uuid.UUID
		var after []byte
		var createdAt time.Time
		if err := rows.Scan(&kind, &assetKind, &assetID, &after, &createdAt); err != nil {
			return nil, err
		}
		var a map[string]any
		_ = json.Unmarshal(after, &a)
		out = append(out, map[string]any{
			"kind": kind, "asset_kind": assetKind, "asset_id": assetID, "after": a, "created_at": createdAt,
		})
	}
	return out, rows.Err()
}
