package store

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/scanproto"
)

// RunAsset is one name or address a run found, with the values of the run
// targets it was found under: what a follow-up run can be started on.
type RunAsset struct {
	Kind  string   `json:"kind"` // "domain" | "ip"
	Value string   `json:"value"`
	Under []string `json:"under"`
	// Target is set on the run's own targets, listed ahead of what was
	// found below them.
	Target bool `json:"target,omitempty"`
}

// RunAssets lists the names and addresses a run found, read from its tasks'
// own summaries — what that run reported, not what the company's inventory
// holds from every run before it. A name counts once something reported it;
// an address once a name resolved to it or a port answered on it.
func (s *Store) RunAssets(ctx context.Context, runID uuid.UUID) ([]RunAsset, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT t.stage, COALESCE(t.target->>'domain', ''), t.result,
		       COALESCE(array_agg(rt.value) FILTER (WHERE rt.value IS NOT NULL), '{}')
		FROM scan_task t
		LEFT JOIN task_origin o ON o.task_id = t.id
		LEFT JOIN run_target rt ON rt.id = o.run_target_id
		WHERE t.run_id = $1 AND t.result IS NOT NULL AND t.status IN ('done', 'failed')
		GROUP BY t.id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type key struct{ kind, value string }
	under := map[key]map[string]bool{}
	add := func(kind, value string, origins []string) {
		value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
		if value == "" || strings.HasPrefix(value, "*.") {
			return
		}
		k := key{kind, value}
		if under[k] == nil {
			under[k] = map[string]bool{}
		}
		for _, o := range origins {
			under[k][o] = true
		}
	}
	for rows.Next() {
		var stage, dom string
		var raw []byte
		var origins []string
		if err := rows.Scan(&stage, &dom, &raw, &origins); err != nil {
			return nil, err
		}
		var sum struct {
			Domains  []string `json:"domains"`
			IPs      []string `json:"ips"`
			Services []struct {
				IP string `json:"ip"`
			} `json:"services"`
		}
		_ = json.Unmarshal(raw, &sum)
		for _, d := range sum.Domains {
			add("domain", d, origins)
		}
		// A resolution task names its own domain only in its target: the
		// summary carries the addresses. A name that resolved is a result.
		if stage == string(scanproto.StageDNSResolve) && dom != "" && len(sum.IPs) > 0 {
			add("domain", dom, origins)
		}
		for _, ip := range sum.IPs {
			add("ip", ip, origins)
		}
		for _, sv := range sum.Services {
			add("ip", sv.IP, origins)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]RunAsset, 0, len(under))
	for k, set := range under {
		a := RunAsset{Kind: k.kind, Value: k.value, Under: make([]string, 0, len(set))}
		for v := range set {
			a.Under = append(a.Under, v)
		}
		sort.Strings(a.Under)
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Value < out[j].Value
	})
	return out, nil
}

// RunSeed is one name or address a follow-up run was started on, under the
// run target that authorizes scanning it.
type RunSeed struct {
	RunTargetID uuid.UUID
	Kind        string // "domain" | "ip" | "cidr"
	Value       string
}

// InsertRunSeeds records what a follow-up run was started on.
func (s *Store) InsertRunSeeds(ctx context.Context, runID uuid.UUID, seeds []RunSeed) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, sd := range seeds {
		if _, err := tx.Exec(ctx, `
			INSERT INTO run_seed (run_id, run_target_id, kind, value) VALUES ($1,$2,$3,$4)
			ON CONFLICT DO NOTHING`, runID, sd.RunTargetID, sd.Kind, sd.Value); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// RunSeeds returns a run's seeds of one kind ("" for every kind).
func (s *Store) RunSeeds(ctx context.Context, runID uuid.UUID, kind string) ([]RunSeed, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT run_target_id, kind, value FROM run_seed
		WHERE run_id = $1 AND ($2 = '' OR kind = $2) ORDER BY kind, value`, runID, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunSeed
	for rows.Next() {
		var sd RunSeed
		if err := rows.Scan(&sd.RunTargetID, &sd.Kind, &sd.Value); err != nil {
			return nil, err
		}
		out = append(out, sd)
	}
	return out, rows.Err()
}

// StageTargets returns the targets of a run's tasks at one stage, so the
// planner can tell what it already queued.
func (s *Store) StageTargets(ctx context.Context, runID uuid.UUID, stage scanproto.Stage) ([]scanproto.Target, error) {
	rows, err := s.Pool.Query(ctx, `SELECT target FROM scan_task WHERE run_id=$1 AND stage=$2`, runID, stage)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []scanproto.Target
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var t scanproto.Target
		_ = json.Unmarshal(raw, &t)
		out = append(out, t)
	}
	return out, rows.Err()
}
