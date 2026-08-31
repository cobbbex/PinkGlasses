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
	RunQueued    RunStatus = "queued"
	RunPlanning  RunStatus = "planning"
	RunRunning   RunStatus = "running"
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
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
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
	ID             uuid.UUID    `json:"id"`
	PoolID         *uuid.UUID   `json:"pool_id,omitempty"`
	Name           string       `json:"name"`
	Kind           string       `json:"kind"`
	Status         WorkerStatus `json:"status"`
	Capabilities   []string     `json:"capabilities"`
	Tools          map[string]string `json:"tools"`
	AgentVersion   string       `json:"agent_version"`
	EgressIP       *string      `json:"egress_ip,omitempty"`
	Country        *string      `json:"country,omitempty"`
	MaxConcurrency int          `json:"max_concurrency"`
	RunningTasks   int          `json:"running_tasks"`
	LastSeenAt     *time.Time   `json:"last_seen_at,omitempty"`
	EnrolledAt     time.Time    `json:"enrolled_at"`
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
}

// ServiceObs is a per-run snapshot of a service, assembled by ingest before it
// is written to service_observation.
type ServiceObs struct {
	At            time.Time         `json:"at"`
	Banner        string            `json:"banner,omitempty"`
	Product       string            `json:"product,omitempty"`
	Version       string            `json:"version,omitempty"`
	HTTP          map[string]any    `json:"http,omitempty"`
	TLS           map[string]any    `json:"tls,omitempty"`
	ScreenshotKey string            `json:"screenshot_key,omitempty"`
	RawKey        string            `json:"raw_key,omitempty"`
}
