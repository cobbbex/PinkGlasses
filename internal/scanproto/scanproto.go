// Package scanproto is the wire contract shared between the control plane and
// the worker fleet. It is the ONLY package the worker binary shares with the
// server, and it is intentionally dependency-free so remote workers that lag a
// version behind still interoperate.
//
// Versioning: JobSchema and ResultSchema are bumped independently of the
// application. A one-version lag is always tolerated (architecture.md §7.4).
package scanproto

import "time"

// Schema identifiers carried in every envelope.
const (
	JobSchema    = "scanjob/v2"
	ResultSchema = "scanresult/v2"
	ProtoVersion = 2 // minimum protocol the gateway will accept
)

// Stage names the pipeline steps a worker can execute (worker-pipeline.md).
type Stage string

const (
	StagePassiveEnum   Stage = "passive_enum"   // subfinder + alterx
	StageDNSBrute      Stage = "dns_brute"      // shuffledns, one task per wordlist
	StageDNSResolve    Stage = "dns_resolve"    // dnsx (+ shuffledns on deep)
	StageIPEnrich      Stage = "ip_enrich"      // asn/geo/ptr/cloud
	StagePortScan      Stage = "port_scan"      // naabu
	StageServiceProbe  Stage = "service_probe"  // nmap -sV + httpx + tls
	StageTechDetect    Stage = "tech_detect"    // httpx -tech-detect + nuclei tech
	StageScreenshot    Stage = "screenshot"     // httpx -screenshot
	StageDirBrute      Stage = "dir_brute"      // katana -> ffuf/feroxbuster
	StageVulnCheck     Stage = "vuln_check"     // nuclei
)

// AllStages lists the pipeline in canonical order.
var AllStages = []Stage{
	StagePassiveEnum, StageDNSBrute, StageDNSResolve, StageIPEnrich, StagePortScan,
	StageServiceProbe, StageTechDetect, StageScreenshot, StageDirBrute, StageVulnCheck,
}

// Capability is a worker-side capability the dispatcher matches against a
// task's Requires set.
type Capability string

const (
	CapRawSocket     Capability = "raw_socket"     // naabu SYN scan (CAP_NET_RAW)
	CapBrowser       Capability = "browser"        // headless chromium for screenshots
	CapIPv6          Capability = "ipv6"           // routable v6 egress
	CapUDP           Capability = "udp"            // outbound UDP permitted
	CapHighBandwidth Capability = "high_bandwidth" // operator-declared
)

// WorkerKind distinguishes where a worker runs. Both kinds scan the same thing —
// your external attack surface — so kind decides only the egress address the
// traffic leaves from, how the worker enrolls, and how far it is trusted.
type WorkerKind string

const (
	KindLocal WorkerKind = "local" // inside your network; bootstrap-enrolled, auto-approved
	KindVPS   WorkerKind = "vps"   // rented box on the internet; single-use token, manual approval
)

// StageRequires maps a stage to the capabilities a worker must have to run it.
func StageRequires(s Stage) []Capability {
	switch s {
	case StagePortScan:
		return []Capability{CapRawSocket} // falls back to connect-scan; see worker
	case StageScreenshot:
		return []Capability{CapBrowser}
	default:
		return nil
	}
}

// ---- enrollment ----

// EnrollRequest is sent by a worker redeeming a one-time enrollment token.
type EnrollRequest struct {
	Token        string            `json:"token"`
	Hostname     string            `json:"hostname"`
	Name         string            `json:"name"`
	Capabilities []Capability      `json:"capabilities"`
	Tools        map[string]string `json:"tools"` // tool -> version
	AgentVersion string            `json:"agent_version"`
}

// EnrollResponse returns the worker's identity and long-lived credential.
// The credential is shown to nobody else, ever.
type EnrollResponse struct {
	WorkerID   string `json:"worker_id"`
	Credential string `json:"credential"`
}

// ---- control channel messages (WSS) ----

// Envelope wraps every control-channel message with a type tag.
type Envelope struct {
	Type string          `json:"type"` // "job" | "cancel" | "heartbeat_ack" | "rotate_cred" | "config"
	Job  *Job            `json:"job,omitempty"`
	Cancel *CancelMessage `json:"cancel,omitempty"`
}

// CancelMessage tells a worker to stop a task immediately (push, not poll).
type CancelMessage struct {
	TaskID string `json:"task_id"`
}

// Heartbeat is sent by the worker over the control channel while a task runs.
// A final heartbeat with Stopping set announces a clean shutdown, which lets the
// gateway re-queue the worker's tasks at once instead of waiting out their
// leases. An abrupt disconnect carries no such promise and falls back to the
// lease timeout.
type Heartbeat struct {
	WorkerID     string   `json:"worker_id"`
	RunningTasks []string `json:"running_tasks"`
	Stopping     bool     `json:"stopping,omitempty"`
	At           time.Time `json:"at"`
}

// ---- job envelope (server -> worker) ----

// Job is a single unit of scanning work assigned to a worker (scanjob/v2).
type Job struct {
	Schema      string      `json:"schema"`
	JobID       string      `json:"job_id"`
	RunID       string      `json:"run_id"`
	TaskID      string      `json:"task_id"`
	LeaseToken  string      `json:"lease_token"`
	Stage       Stage       `json:"stage"`
	Profile     string      `json:"profile"`
	Targets     []Target    `json:"targets"`
	Params      Params      `json:"params"`
	Constraints Constraints `json:"constraints"`
	Ingest      IngestInfo  `json:"ingest"`
}

// Target identifies one thing to act on. Fields are populated per stage.
type Target struct {
	Domain string `json:"domain,omitempty"`
	// WordlistID names the registry entry a dns_brute task brute-forces with.
	WordlistID string `json:"wordlist_id,omitempty"`
	// IPs carries a pool of addresses for a batched stage. Port scanning takes
	// hosts in batches so nmap can form a real host group and schedule across
	// them, which is what makes its rate and host-group settings mean anything.
	// The gateway expands this into one Target per address when it leases.
	IPs []string `json:"ips,omitempty"`
	IP     string `json:"ip,omitempty"`
	CIDR   string `json:"cidr,omitempty"`
	Port   int    `json:"port,omitempty"`
	URL    string `json:"url,omitempty"`
}

// Params are stage-specific knobs.
type Params struct {
	Ports       string `json:"ports,omitempty"`     // "top-1000" | "1-65535" | "80,443"
	RatePPS     int    `json:"rate_pps,omitempty"`
	TimeoutMS   int    `json:"timeout_ms,omitempty"`
	Wordlist    string `json:"wordlist,omitempty"`  // dir_brute / dns brute
	// WordlistURL is a short-lived presigned download for the list this task
	// must use, issued by the gateway at dispatch. WordlistSHA doubles as the
	// worker's on-disk cache key, so a list is downloaded once per box.
	WordlistURL  string `json:"wordlist_url,omitempty"`
	WordlistSHA  string `json:"wordlist_sha256,omitempty"`
	WordlistName string `json:"wordlist_name,omitempty"`
	// Resolvers is the DNS resolver list shuffledns brute-forces through,
	// delivered the same way as the wordlist: presigned at dispatch, cached on
	// the worker by content hash.
	ResolversURL  string `json:"resolvers_url,omitempty"`
	ResolversSHA  string `json:"resolvers_sha256,omitempty"`
	ResolversName string `json:"resolvers_name,omitempty"`
	Concurrency int    `json:"concurrency,omitempty"`
	Deep        bool   `json:"deep,omitempty"`
	// Tool carries validated per-tool overrides (Phase 15). Keys and values are
	// whitelisted server-side in internal/scanparams before ever reaching here.
	Tool map[string]string `json:"tool,omitempty"`
}

// Constraints bound what the worker may touch and for how long.
type Constraints struct {
	Deadline       time.Time `json:"deadline"`
	Allow          []string  `json:"allow"` // CIDRs the worker may scan
	Deny           []string  `json:"deny"`  // CIDRs the worker must not scan
	MaxConcurrency int       `json:"max_concurrency"`
}

// IngestInfo tells the worker where to POST results.
type IngestInfo struct {
	URL      string `json:"url"`
	JobToken string `json:"job_token"`
}

// ---- result envelope (worker -> server) ----

// Result is one batch of observations for a task (scanresult/v2). Batches carry
// a monotonic Seq; the batch with Final=true closes the task and releases the lease.
type Result struct {
	Schema       string        `json:"schema"`
	JobID        string        `json:"job_id"`
	TaskID       string        `json:"task_id"`
	LeaseToken   string        `json:"lease_token"`
	Seq          int           `json:"seq"`
	Final        bool          `json:"final"`
	Status       string        `json:"status"` // ok | error | cancelled
	Worker       WorkerRef     `json:"worker"`
	Observations []Observation `json:"observations"`
	Artifacts    []Artifact    `json:"artifacts"`
	Errors       []string      `json:"errors,omitempty"`
}

// WorkerRef identifies the reporting worker.
type WorkerRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// Artifact references raw tool output stored in object storage.
type Artifact struct {
	Kind   string `json:"kind"`
	Key    string `json:"key"`
	SHA256 string `json:"sha256"`
}

// ObsType tags an observation's shape.
type ObsType string

const (
	ObsSubdomain ObsType = "subdomain"
	ObsDNSRecord ObsType = "dns_record"
	ObsIP        ObsType = "ip"
	ObsService   ObsType = "service"
	ObsHTTP      ObsType = "http"
	ObsTLS       ObsType = "tls"
	ObsTech      ObsType = "tech"
	ObsScreenshot ObsType = "screenshot"
	ObsPath      ObsType = "path"
	ObsFinding   ObsType = "finding"
)

// Observation is a single fact reported by a worker. It is a fact, never a
// decision: workers do not dedupe, diff, or classify — the server's ingest does.
type Observation struct {
	Type ObsType `json:"type"`

	// subdomain / dns
	Domain string `json:"domain,omitempty"`
	RType  string `json:"rtype,omitempty"`
	Value  string `json:"value,omitempty"`
	TTL    int    `json:"ttl,omitempty"`
	Source string `json:"source,omitempty"`

	// ip / service
	IP    string `json:"ip,omitempty"`
	Port  int    `json:"port,omitempty"`
	Proto string `json:"proto,omitempty"`
	State string `json:"state,omitempty"`

	// ip enrichment
	PTR     string `json:"ptr,omitempty"`
	ASN     int    `json:"asn,omitempty"`
	ASOrg   string `json:"as_org,omitempty"`
	ASRange string `json:"as_range,omitempty"` // announcing prefix, e.g. 93.184.216.0/24
	Country string `json:"country,omitempty"`
	Cloud   string `json:"cloud,omitempty"`
	Shared  bool   `json:"shared,omitempty"`

	// service detail
	Banner  string `json:"banner,omitempty"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`

	// http
	Status  int               `json:"status,omitempty"`
	Title   string            `json:"title,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Favicon string            `json:"favicon,omitempty"`

	// tls
	CertSHA256 string   `json:"cert_sha256,omitempty"`
	SubjectCN  string   `json:"subject_cn,omitempty"`
	Issuer     string   `json:"issuer,omitempty"`
	SANs       []string `json:"sans,omitempty"`
	NotAfter   *time.Time `json:"not_after,omitempty"`

	// tech
	TechName       string `json:"tech_name,omitempty"`
	TechVersion    string `json:"tech_version,omitempty"`
	TechCPE        string `json:"tech_cpe,omitempty"`
	TechConfidence int    `json:"tech_confidence,omitempty"`

	// Cookie NAMES set by the service, never their values: a name like
	// "webvpn" or "BIGipServer..." identifies the product behind the port,
	// while the value is a session token that must not be stored.
	Cookies []string `json:"cookies,omitempty"`

	// screenshot / path
	ScreenshotKey string `json:"screenshot_key,omitempty"`
	Path          string `json:"path,omitempty"`

	// finding
	FindingKind     string `json:"finding_kind,omitempty"`
	FindingSeverity string `json:"finding_severity,omitempty"`
	FindingTitle    string `json:"finding_title,omitempty"`
}
