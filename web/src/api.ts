// Typed client for the ASM REST API. Untrusted, attacker-controlled strings
// (banners, HTTP titles, TLS subjects) are rendered as text by React by
// default — never with dangerouslySetInnerHTML (architecture.md §10.3).

export interface Scope {
  id: string; name: string; created_at: string;
  /** Who created it. Free text until real accounts exist; "local" by default. */
  created_by?: string;
}
/** What a signed-in person may do. Ordered: admin > operator > viewer. */
export type Role = "admin" | "operator" | "viewer";
export interface User {
  id: string; username: string; display_name: string; role: Role;
  disabled: boolean; created_at: string; last_login_at?: string | null;
  has_password: boolean;
}
export interface AuthStatus {
  /** True on a fresh install: there are no accounts yet. */
  setup_required: boolean;
  user?: { id: string; username: string; role: Role; via: string };
}
/** A credential for automation. The secret is returned once, at creation. */
export interface ApiToken {
  id: string; prefix: string; name: string; user_id: string; username: string;
  role: Role; created_at: string; expires_at?: string | null;
  revoked_at?: string | null; last_used_at?: string | null;
}
export interface Summary { domains: number; ips: number; services: number; open_findings: number }
export interface Target {
  id: string; scope_id: string; kind: string; value: string; tags: string[];
  mode: string; authorized_by?: string | null;
}
export interface Domain {
  id: string; name: string; apex: string; is_wildcard: boolean;
  sources: string[]; first_seen: string; last_seen: string;
}
export interface Host {
  id: string; scope_id?: string; addr: string; ptr?: string | null; asn?: number | null;
  as_org?: string | null; as_range?: string | null;
  country?: string | null; cloud?: string | null;
  is_shared: boolean; first_seen: string; last_seen: string;
}
export interface Service {
  id: string; ip_id: string; port: number; proto: string; last_state: string;
  first_seen: string; last_seen: string;
}
export interface Run {
  id: string; scope_id: string; profile: string; status: string;
  started_at?: string | null; finished_at?: string | null; created_at: string;
  /** A label for the row — the first few targets, not the whole list. */
  targets?: string[] | null; target_count?: number;
  tasks_total?: number; tasks_done?: number;
  tasks_failed?: number; tasks_outstanding?: number;
}
export interface RunTarget {
  id: string; run_id: string; kind: string; value: string; status: string;
  skip_reason?: string | null; tasks_total: number; tasks_done: number;
}
export interface Worker {
  id: string; name: string; kind: string; status: string; capabilities: string[];
  tools: Record<string, string>; agent_version: string; egress_ip?: string | null;
  country?: string | null; max_concurrency: number; running_tasks: number;
  last_seen_at?: string | null;
  /** Brought up by one scan for itself, and destroyed when that scan ends. */
  run_scoped?: boolean;
}
/**
 * The containers a run brought up for itself: its own workers, and a VPN
 * gateway when it scans through a tunnel. `error` is the only record of why a
 * run whose fleet failed to come up did — scan_run has no error column.
 */
export interface RunFleet {
  run_id: string; workers: number; status: "requested" | "up" | "failed" | "torn_down";
  vpn_config_id?: string | null; error?: string | null; egress_ip?: string | null;
  created_at: string; ready_at?: string | null;
}
/** One run's verdict on a finding: it looked, and did or did not see it. */
export interface FindingRun {
  run_id: string; at: string; observed: boolean;
  observed_at?: string | null; severity?: string;
}
export interface Finding {
  id: string; asset_kind: string; asset_id: string; kind: string;
  severity: string; title: string; status: string; first_seen: string; last_seen: string;
  /** Every completed run that could have seen this finding, oldest first. */
  history?: FindingRun[] | null;
  /** "active" if the latest covering run observed it, else "gone". */
  presence?: "active" | "gone";
  seen_in?: number; covered_runs?: number; gone_since?: string | null;
}
export interface TaskActivity {
  task_id: string; stage: string; target: string; status: string; attempts: number;
  worker_name?: string | null; worker_kind?: string | null;
  started_at?: string | null; finished_at?: string | null; error?: string | null;
}
export interface StageCount {
  stage: string; pending: number; active: number; done: number; failed: number;
}
export interface WorkerBusy {
  name: string; kind: string; running: number; done: number; stages: string[];
}
export interface RunActivity {
  tasks: TaskActivity[]; stages: StageCount[]; workers: WorkerBusy[];
}
/** What the wire may actually carry, before coercion. */
interface RunActivityWire {
  tasks: TaskActivity[] | null; stages: StageCount[] | null;
  workers: (Omit<WorkerBusy, "stages"> & { stages: string[] | null })[] | null;
}
export interface HostRow {
  screenshot_service_id?: string | null;
  domain_id?: string | null; name: string;
  ip_id?: string | null; addr?: string | null; ptr?: string | null;
  asn?: number | null; as_org?: string | null; as_range?: string | null;
  country?: string | null; cloud?: string | null;
  is_shared: boolean; services: number; last_seen: string;
}
export interface Wordlist {
  id: string; name: string; kind: string;
  sha256?: string | null; size_bytes: number; line_count: number;
  builtin: boolean; is_default: boolean; status: string; error?: string | null;
}
export interface ParamSpec {
  key: string; tool: string; label: string;
  kind: "int" | "enum" | "ports" | "wordlist" | "bool" | "csv" | "text" | "proxy";
  min?: number; max?: number; enum?: string[];
  default: string; help: string;
}
export interface ScanProfilePreset {
  id: string; name: string; owner?: string | null;
  scope_id?: string | null; params: Record<string, string>; is_default: boolean;
}

export interface HostName {
  name: string; via: string; first_seen: string; last_seen: string;
}
export interface HostTech { name: string; version?: string | null; cpe?: string | null }
/** An open port plus the most recent thing observed answering on it. */
export interface HostService extends Service {
  has_screenshot?: boolean;
  banner?: string | null; product?: string | null; version?: string | null;
  http?: { title?: string; status?: number; favicon?: string;
           headers?: Record<string, string>;
           /** Cookie names only — never values. A fingerprint, not a session. */
           cookies?: string[] } | null;
  tls?: Record<string, any> | null;
  observed_at?: string | null;
  technologies: HostTech[];
}
export interface HostDetail {
  host: Host; names: HostName[]; services: HostService[]; findings: Finding[];
}

export interface VPNConfig {
  id: string; scope_id: string; name: string; kind: "wireguard" | "openvpn";
  endpoint?: string | null; last_egress_ip?: string | null; last_checked_at?: string | null;
  created_by: string; created_at: string;
}

export interface NotificationChannel {
  id: string; scope_id: string; name: string; kind: "webhook" | "slack";
  /** masked — the path of a Slack webhook is the secret */
  url: string; events: string[]; min_severity: string; enabled: boolean;
  created_by: string; created_at: string;
}
export interface NotificationDelivery {
  id: string; channel_id: string; channel: string; run_id?: string | null;
  events: number; status: "sent" | "failed" | "skipped"; error?: string | null; sent_at: string;
}

export interface SearchResult {
  service_id: string; scope_id?: string; company?: string;
  ip: string; port: number; product?: string | null;
  version?: string | null; title?: string | null; domain?: string | null;
}

/**
 * Fired when the API says we are not signed in, so the shell can return to the
 * login screen from wherever the user happened to be. A session can end while a
 * tab sits idle — it expired, an administrator disabled the account, or a role
 * changed — and the first sign of that is a 401 on an ordinary request.
 */
export const UNAUTHENTICATED = "pg:unauthenticated";

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch("/api/v1" + path, {
    ...init,
    // The session cookie is HttpOnly, so it is never touched by this code;
    // same-origin requests carry it automatically.
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (res.status === 401 && !path.startsWith("/auth/")) {
    window.dispatchEvent(new CustomEvent(UNAUTHENTICATED));
  }
  if (!res.ok) {
    const body = (await res.text()).trim();
    // The API answers errors as {"error": "..."}; show that sentence rather
    // than the JSON around it.
    let msg = body || res.statusText;
    try {
      const j = JSON.parse(body);
      if (j && typeof j.error === "string") msg = j.error;
    } catch { /* not json; use the text */ }
    throw new Error(msg);
  }
  const text = await res.text();
  return text ? (JSON.parse(text) as T) : (undefined as T);
}

/** A pool a run may choose as its remote exit. */
export interface WorkerPool {
  id: string; name: string; description?: string | null; is_default: boolean;
  /** How many of its workers can take work right now. Zero means "cannot run a scan". */
  active_workers: number; created_at: string;
}

/** Role ranking, mirroring internal/auth.Role.AtLeast. */
const RANK: Record<string, number> = { viewer: 1, operator: 2, admin: 3 };
export function atLeast(have: Role | undefined, min: Role): boolean {
  return (RANK[have ?? ""] ?? 0) >= RANK[min];
}

export const api = {
  // --- authentication ---
  authStatus: () => req<AuthStatus>("/auth/status"),
  setup: (body: { username: string; display_name: string; password: string }) =>
    req<{ user: User }>("/auth/setup", { method: "POST", body: JSON.stringify(body) }),
  login: (username: string, password: string) =>
    req<{ user: User }>("/auth/login", { method: "POST", body: JSON.stringify({ username, password }) }),
  logout: () => req<{ ok: boolean }>("/auth/logout", { method: "POST" }),
  me: () => req<{ user: User; via: string; using_default_password?: boolean }>("/auth/me"),
  changePassword: (current_password: string, new_password: string) =>
    req<{ user: User }>("/auth/password", {
      method: "POST", body: JSON.stringify({ current_password, new_password }),
    }),

  // --- users (admin) ---
  users: () => req<User[] | null>("/users").then((x) => x ?? []),
  createUser: (body: unknown) => req<User>("/users", { method: "POST", body: JSON.stringify(body) }),
  patchUser: (id: string, body: unknown) =>
    req<User>(`/users/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteUser: (id: string) => req<{ deleted: boolean }>(`/users/${id}`, { method: "DELETE" }),

  // --- API tokens ---
  tokens: () => req<ApiToken[] | null>("/tokens").then((x) => x ?? []),
  createToken: (body: { name: string; role: Role; ttl_days?: number }) =>
    req<{ token: ApiToken; secret: string }>("/tokens", { method: "POST", body: JSON.stringify(body) }),
  revokeToken: (id: string) => req<{ revoked: boolean }>(`/tokens/${id}`, { method: "DELETE" }),

  // mine=true narrows the list to companies this caller created. It is a view,
  // not a permission: without verified identity anyone can ask for all of them.
  scopes: (mine = false) =>
    req<Scope[] | null>("/scopes" + (mine ? "?mine=true" : "")).then((x) => x ?? []),
  createScope: (name: string) => req<Scope>("/scopes", { method: "POST", body: JSON.stringify({ name }) }),
  summary: (s: string) => req<Summary>(`/scopes/${s}/summary`),
  targets: (s: string) => req<Target[] | null>(`/scopes/${s}/targets`).then((x) => x ?? []),
  addTarget: (s: string, body: unknown) =>
    req<Target[] | null>(`/scopes/${s}/targets`, { method: "POST", body: JSON.stringify(body) }).then((x) => x ?? []),
  domains: (s: string, q = "") => req<Domain[] | null>(`/scopes/${s}/domains?q=${encodeURIComponent(q)}`).then((x) => x ?? []),
  graph: (s: string) =>
    req<{ nodes: any[] | null; edges: any[] | null }>(`/scopes/${s}/graph`)
      .then((g) => ({ nodes: g.nodes ?? [], edges: g.edges ?? [] })),
  hostRows: (s: string, q = "", unresolved = false) =>
    req<{ rows: HostRow[] | null; unresolved_hidden: number }>(
      `/scopes/${s}/hostrows?q=${encodeURIComponent(q)}&unresolved=${unresolved}`,
    ).then((r) => ({ rows: r.rows ?? [], unresolvedHidden: r.unresolved_hidden })),
  hosts: (s: string) => req<Host[] | null>(`/scopes/${s}/hosts`).then((x) => x ?? []),
  // Served by the API, not object storage: the CSP allows images from 'self'
  // only, and a presigned URL in the page would be a bearer token for it.
  screenshotURL: (serviceID: string) => `/api/v1/services/${serviceID}/screenshot`,
  host: (ip: string) =>
    req<HostDetail>(`/hosts/${ip}`).then((h) => ({
      ...h,
      names: h.names ?? [],
      services: (h.services ?? []).map((sv) => ({ ...sv, technologies: sv.technologies ?? [] })),
      findings: (h.findings ?? []).map((f) => ({ ...f, history: f.history ?? [] })),
    })),
  hostServices: (ip: string) => req<Service[] | null>(`/hosts/${ip}/services`).then((x) => x ?? []),
  search: (s: string, q: string) => req<SearchResult[] | null>(`/scopes/${s}/search?q=${encodeURIComponent(q)}`).then((x) => x ?? []),
  searchGlobal: (q: string, scope?: string) =>
    req<SearchResult[] | null>(`/search?q=${encodeURIComponent(q)}${scope ? "&scope=" + scope : ""}`).then((x) => x ?? []),
  findings: (s: string) =>
    req<Finding[] | null>(`/scopes/${s}/findings`)
      .then((x) => (x ?? []).map((f) => ({ ...f, history: f.history ?? [] }))),
  // Configs are write-only: the body is sealed server-side and no endpoint
  // ever returns it.
  vpnConfigs: (s: string) =>
    req<{ configs: VPNConfig[] | null; secrets_ready: boolean; secrets_reason: string }>(
      `/scopes/${s}/vpn-configs`).then((r) => ({ ...r, configs: r.configs ?? [] })),
  createVPNConfig: (s: string, body: { name: string; config: string }) =>
    req<VPNConfig>(`/scopes/${s}/vpn-configs`, { method: "POST", body: JSON.stringify(body) }),
  deleteVPNConfig: (id: string) => req(`/vpn-configs/${id}`, { method: "DELETE" }),
  notifications: (s: string) =>
    req<{ channels: NotificationChannel[] | null; events: string[] | null }>(`/scopes/${s}/notifications`)
      .then((r) => ({ channels: r.channels ?? [], events: r.events ?? [] })),
  createNotification: (s: string, body: unknown) =>
    req<NotificationChannel>(`/scopes/${s}/notifications`, { method: "POST", body: JSON.stringify(body) }),
  setNotificationEnabled: (id: string, enabled: boolean) =>
    req(`/notifications/${id}`, { method: "PATCH", body: JSON.stringify({ enabled }) }),
  deleteNotification: (id: string) => req(`/notifications/${id}`, { method: "DELETE" }),
  testNotification: (id: string) =>
    req<{ sent: boolean; error?: string }>(`/notifications/${id}/test`, { method: "POST" }),
  notificationDeliveries: (s: string) =>
    req<NotificationDelivery[] | null>(`/scopes/${s}/notifications/deliveries`).then((x) => x ?? []),
  patchFinding: (id: string, status: string) =>
    req(`/findings/${id}`, { method: "PATCH", body: JSON.stringify({ status }) }),
  runs: (s: string) => req<Run[] | null>(`/scopes/${s}/runs`).then((x) => x ?? []),
  scanParams: () => req<ParamSpec[] | null>("/scan-params").then((x) => x ?? []),
  scanProfiles: (s: string) =>
    req<ScanProfilePreset[] | null>(`/scopes/${s}/scan-profiles`).then((x) => x ?? []),
  saveScanProfile: (s: string, body: unknown) =>
    req<{ id: string }>(`/scopes/${s}/scan-profiles`, { method: "POST", body: JSON.stringify(body) }),
  createRun: (s: string, body: unknown) =>
    req<Run>(`/scopes/${s}/runs`, { method: "POST", body: JSON.stringify(body) }),
  run: (id: string) =>
    req<{ run: Run; progress: any; fleet?: RunFleet }>(`/runs/${id}`),
  // The server answers [] for an empty list, but the panels here read .length
  // off every one of these, so a null from an older build white-screens the run
  // view rather than degrading. Coerce on the way in.
  runActivity: (id: string) =>
    req<RunActivityWire>(`/runs/${id}/activity`).then((a) => ({
      tasks: a.tasks ?? [],
      stages: a.stages ?? [],
      workers: (a.workers ?? []).map((w) => ({ ...w, stages: w.stages ?? [] })),
    })),
  runTargets: (id: string) => req<RunTarget[] | null>(`/runs/${id}/targets`).then((x) => x ?? []),
  cancelRun: (id: string) => req(`/runs/${id}/cancel`, { method: "POST" }),
  workers: () => req<Worker[] | null>("/workers").then((x) => x ?? []),
  pools: () => req<WorkerPool[] | null>("/pools").then((x) => x ?? []),
  enrollToken: (body: unknown) =>
    req<{ kind: string; token?: string; install_command: string; expires_in?: string; note?: string }>(
      "/workers/enrollment-tokens", { method: "POST", body: JSON.stringify(body) }),
  workerAction: (id: string, action: string) => req(`/workers/${id}/${action}`, { method: "POST" }),
  deleteWorker: (id: string) =>
    req<{ deleted: boolean; warning?: string }>(`/workers/${id}`, { method: "DELETE" }),
  wordlists: (kind = "dns") =>
    req<Wordlist[] | null>(`/wordlists?kind=${kind}`).then((x) => x ?? []),
  uploadWordlist: async (file: File, name: string, kind = "dns") => {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("name", name);
    fd.append("kind", kind);
    const res = await fetch("/api/v1/wordlists", { method: "POST", body: fd });
    if (!res.ok) throw new Error((await res.text()) || res.statusText);
    return (await res.json()) as Wordlist;
  },
  wordlistContent: (id: string) =>
    req<{ id: string; name: string; kind: string; builtin: boolean; content: string }>(
      `/wordlists/${id}/content`),
  saveWordlistContent: (id: string, content: string) =>
    req<Wordlist>(`/wordlists/${id}/content`, {
      method: "PUT", body: JSON.stringify({ content }),
    }),
  setWordlistDefault: (id: string, isDefault: boolean) =>
    req(`/wordlists/${id}`, { method: "PATCH", body: JSON.stringify({ is_default: isDefault }) }),
  deleteWordlist: (id: string) => req(`/wordlists/${id}`, { method: "DELETE" }),
  provisionStatus: () =>
    req<{ enabled: boolean; count?: number; reason?: string }>("/workers/provision"),
  scaleLocal: (count: number) =>
    req<{ target: number; created: number; removed: number }>("/workers/provision", {
      method: "POST", body: JSON.stringify({ count }),
    }),
};
