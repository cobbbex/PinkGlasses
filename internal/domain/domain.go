// Package domain holds the core entities, enums and pure business rules for the
// asset graph. It performs no I/O.
package domain

import (
	"time"

	"github.com/google/uuid"
)

// ---- enums ----

// RunProfile controls scan depth.
type RunProfile string

const (
	ProfilePassive  RunProfile = "passive"  // no packets to targets
	ProfileStandard RunProfile = "standard" // top-1000 ports, standard probes
	ProfileDeep     RunProfile = "deep"     // full range, brute force, more templates
)

// RunStatus is the lifecycle of a scan run.
type RunStatus string

const (
	RunQueued   RunStatus = "queued"
	RunPlanning RunStatus = "planning"
	RunRunning  RunStatus = "running"
	// Paused: no task is leased for the run; tasks already in flight finish and
	// report. Its own fleet stays up so resuming is immediate.
	RunPaused    RunStatus = "paused"
	RunCompleted RunStatus = "completed"
	RunFailed    RunStatus = "failed"
	RunCancelled RunStatus = "cancelled"
)

// TargetStatus is the per-target lifecycle inside a batch run.
type TargetStatus string

const (
	TargetPending    TargetStatus = "pending"
	TargetRunning    TargetStatus = "running"
	TargetCompleted  TargetStatus = "completed"
	TargetIncomplete TargetStatus = "incomplete"
	TargetFailed     TargetStatus = "failed"
	TargetSkipped    TargetStatus = "skipped"
)

// TaskStatus is the lease lifecycle of a single task.
type TaskStatus string

const (
	TaskPending   TaskStatus = "pending"
	TaskLeased    TaskStatus = "leased"
	TaskRunning   TaskStatus = "running"
	TaskDone      TaskStatus = "done"
	TaskFailed    TaskStatus = "failed"
	TaskCancelled TaskStatus = "cancelled"
)

// TargetMode governs what may be done to a scope target.
type TargetMode string

const (
	ModeActive      TargetMode = "active"       // active scanning allowed (needs authorization)
	ModePassiveOnly TargetMode = "passive_only" // passive discovery only
	ModeExclude     TargetMode = "exclude"      // never touch
)

// WorkerStatus is the worker lifecycle (architecture.md §7.2).
type WorkerStatus string

const (
	WorkerPending     WorkerStatus = "pending"
	WorkerActive      WorkerStatus = "active"
	WorkerDraining    WorkerStatus = "draining"
	WorkerQuarantined WorkerStatus = "quarantined"
	WorkerStale       WorkerStatus = "stale"
	WorkerRevoked     WorkerStatus = "revoked"
)

// Severity ranks findings.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// ---- entities ----

// Scope is an authorization boundary and the root of an asset graph.
type Scope struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	// CreatedBy is the actor that created the company. Free text until Phase 17
	// replaces it with a real user; today it is X-Forwarded-User or "local".
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	// The exit a schedule uses and the launch dialog pre-selects. "" means
	// none chosen yet; a scheduled active run then refuses with the reason.
	DefaultExit        string     `json:"default_exit"`
	DefaultVPNConfigID *uuid.UUID `json:"default_vpn_config_id,omitempty"`
	DefaultPoolID      *uuid.UUID `json:"default_pool_id,omitempty"`
}

// ScopeTarget is a domain/CIDR/ASN/IP the scope is allowed to look at.
type ScopeTarget struct {
	ID           uuid.UUID  `json:"id"`
	ScopeID      uuid.UUID  `json:"scope_id"`
	Kind         string     `json:"kind"`
	Value        string     `json:"value"`
	Tags         []string   `json:"tags"`
	Mode         TargetMode `json:"mode"`
	PoolID       *uuid.UUID `json:"pool_id,omitempty"`
	AuthorizedBy *string    `json:"authorized_by,omitempty"`
	AuthorizedAt *time.Time `json:"authorized_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// Authorized reports whether active scanning of this target is permitted.
func (t ScopeTarget) Authorized() bool {
	return t.Mode == ModeActive && t.AuthorizedBy != nil && t.AuthorizedAt != nil
}

// ScanRun is a batch scan over a set of targets.
type ScanRun struct {
	ID             uuid.UUID  `json:"id"`
	ScopeID        uuid.UUID  `json:"scope_id"`
	Profile        RunProfile `json:"profile"`
	Trigger        string     `json:"trigger"`
	Status         RunStatus  `json:"status"`
	PoolID         *uuid.UUID `json:"pool_id,omitempty"`
	MaxConcurrency int        `json:"max_concurrency"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// RunTarget is one domain/CIDR within a batch run, tracked independently.
type RunTarget struct {
	ID         uuid.UUID    `json:"id"`
	RunID      uuid.UUID    `json:"run_id"`
	Kind       string       `json:"kind"`
	Value      string       `json:"value"`
	Status     TargetStatus `json:"status"`
	SkipReason *string      `json:"skip_reason,omitempty"`
	TasksTotal int          `json:"tasks_total"`
	TasksDone  int          `json:"tasks_done"`
}

// Worker is a scan box in the fleet.
type Worker struct {
	ID             uuid.UUID         `json:"id"`
	PoolID         *uuid.UUID        `json:"pool_id,omitempty"`
	Name           string            `json:"name"`
	Kind           string            `json:"kind"`
	Status         WorkerStatus      `json:"status"`
	Capabilities   []string          `json:"capabilities"`
	Tools          map[string]string `json:"tools"`
	AgentVersion   string            `json:"agent_version"`
	EgressIP       *string           `json:"egress_ip,omitempty"`
	Country        *string           `json:"country,omitempty"`
	MaxConcurrency int               `json:"max_concurrency"`
	RunningTasks   int               `json:"running_tasks"`
	LastSeenAt     *time.Time        `json:"last_seen_at,omitempty"`
	EnrolledAt     time.Time         `json:"enrolled_at"`
	// RunScoped marks a worker one scan brought up for itself and will destroy
	// when it finishes (architecture.md §7.6). Worth showing: these appear and
	// vanish on their own, and they will not take anyone else's work.
	RunScoped bool `json:"run_scoped"`
}

// Domain is a discovered (sub)domain.
type Domain struct {
	ID         uuid.UUID `json:"id"`
	ScopeID    uuid.UUID `json:"scope_id"`
	Name       string    `json:"name"`
	Apex       string    `json:"apex"`
	IsWildcard bool      `json:"is_wildcard"`
	Sources    []string  `json:"sources"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// IPAddress is a discovered host address with enrichment.
type IPAddress struct {
	ID        uuid.UUID `json:"id"`
	ScopeID   uuid.UUID `json:"scope_id"`
	Addr      string    `json:"addr"`
	PTR       *string   `json:"ptr,omitempty"`
	ASN       *int      `json:"asn,omitempty"`
	ASOrg     *string   `json:"as_org,omitempty"`
	ASRange   *string   `json:"as_range,omitempty"`
	Country   *string   `json:"country,omitempty"`
	Cloud     *string   `json:"cloud,omitempty"`
	IsShared  bool      `json:"is_shared"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Service is an open port on a host.
type Service struct {
	ID        uuid.UUID `json:"id"`
	IPID      uuid.UUID `json:"ip_id"`
	Port      int       `json:"port"`
	Proto     string    `json:"proto"`
	LastState string    `json:"last_state"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Finding is a security-relevant conclusion about an asset.
type Finding struct {
	ID        uuid.UUID `json:"id"`
	ScopeID   uuid.UUID `json:"scope_id"`
	AssetKind string    `json:"asset_kind"`
	AssetID   uuid.UUID `json:"asset_id"`
	Kind      string    `json:"kind"`
	Severity  Severity  `json:"severity"`
	Title     string    `json:"title"`
	Status    string    `json:"status"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	// History is one entry per completed run that could have observed this
	// finding — a run that executed the stage which produces its kind against
	// its host — whether or not it did. Presence is derived from it: "active"
	// when the latest such run observed the finding, otherwise "gone".
	History     []FindingRun `json:"history,omitempty"`
	Presence    string       `json:"presence,omitempty"`
	SeenIn      int          `json:"seen_in"`
	CoveredRuns int          `json:"covered_runs"`
	GoneSince   *time.Time   `json:"gone_since,omitempty"`
}

// FindingRun is one run's verdict on a finding: it looked, and it did or did
// not see it. ObservedAt and Severity are set only when it did.
type FindingRun struct {
	RunID      uuid.UUID  `json:"run_id"`
	At         time.Time  `json:"at"`
	Observed   bool       `json:"observed"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
	Severity   string     `json:"severity,omitempty"`
}

// DerivePresence fills Presence, SeenIn, CoveredRuns and GoneSince from
// History. A finding nobody has had a chance to re-check is "active": the only
// evidence is that it was seen.
func (f *Finding) DerivePresence() {
	f.CoveredRuns = len(f.History)
	f.SeenIn = 0
	f.GoneSince = nil
	var lastSeenIdx = -1
	for i, h := range f.History {
		if h.Observed {
			f.SeenIn++
			lastSeenIdx = i
		}
	}
	if f.CoveredRuns == 0 || lastSeenIdx == f.CoveredRuns-1 {
		f.Presence = "active"
		return
	}
	f.Presence = "gone"
	at := f.History[lastSeenIdx+1].At // the first run that looked and did not find it
	f.GoneSince = &at
}

// ServiceObs is a per-run snapshot of a service, assembled by ingest before it
// is written to service_observation.
type ServiceObs struct {
	At            time.Time      `json:"at"`
	Banner        string         `json:"banner,omitempty"`
	Product       string         `json:"product,omitempty"`
	Version       string         `json:"version,omitempty"`
	HTTP          map[string]any `json:"http,omitempty"`
	TLS           map[string]any `json:"tls,omitempty"`
	ScreenshotKey string         `json:"screenshot_key,omitempty"`
	RawKey        string         `json:"raw_key,omitempty"`
}
