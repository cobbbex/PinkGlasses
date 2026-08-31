// Typed client for the ASM REST API. Untrusted, attacker-controlled strings
// (banners, HTTP titles, TLS subjects) are rendered as text by React by
// default — never with dangerouslySetInnerHTML (architecture.md §10.2).

export interface Scope { id: string; name: string; created_at: string }
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
  id: string; addr: string; ptr?: string | null; asn?: number | null;
  as_org?: string | null; country?: string | null; cloud?: string | null;
  is_shared: boolean; first_seen: string; last_seen: string;
}
export interface Service {
  id: string; ip_id: string; port: number; proto: string; last_state: string;
  first_seen: string; last_seen: string;
}
export interface Run {
  id: string; scope_id: string; profile: string; status: string;
  started_at?: string | null; finished_at?: string | null; created_at: string;
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
}
export interface Finding {
  id: string; asset_kind: string; asset_id: string; kind: string;
  severity: string; title: string; status: string; first_seen: string; last_seen: string;
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
export interface HostRow {
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
  kind: "int" | "enum" | "ports" | "wordlist" | "bool" | "csv";
  min?: number; max?: number; enum?: string[];
  default: string; help: string;
}
export interface ScanProfilePreset {
  id: string; name: string; owner?: string | null;
  scope_id?: string | null; params: Record<string, string>; is_default: boolean;
}

export interface SearchResult {
  service_id: string; scope_id?: string; company?: string;
  ip: string; port: number; product?: string | null;
  version?: string | null; title?: string | null; domain?: string | null;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch("/api/v1" + path, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!res.ok) throw new Error((await res.text()) || res.statusText);
  const text = await res.text();
  return text ? (JSON.parse(text) as T) : (undefined as T);
}

export const api = {
  scopes: () => req<Scope[] | null>("/scopes").then((x) => x ?? []),
  createScope: (name: string) => req<Scope>("/scopes", { method: "POST", body: JSON.stringify({ name }) }),
  summary: (s: string) => req<Summary>(`/scopes/${s}/summary`),
  targets: (s: string) => req<Target[] | null>(`/scopes/${s}/targets`).then((x) => x ?? []),
  addTarget: (s: string, body: unknown) =>
    req<Target[] | null>(`/scopes/${s}/targets`, { method: "POST", body: JSON.stringify(body) }).then((x) => x ?? []),
  domains: (s: string, q = "") => req<Domain[] | null>(`/scopes/${s}/domains?q=${encodeURIComponent(q)}`).then((x) => x ?? []),
  graph: (s: string) => req<{ nodes: any[]; edges: any[] }>(`/scopes/${s}/graph`),
  hostRows: (s: string, q = "", unresolved = false) =>
    req<{ rows: HostRow[] | null; unresolved_hidden: number }>(
      `/scopes/${s}/hostrows?q=${encodeURIComponent(q)}&unresolved=${unresolved}`,
    ).then((r) => ({ rows: r.rows ?? [], unresolvedHidden: r.unresolved_hidden })),
  hosts: (s: string) => req<Host[] | null>(`/scopes/${s}/hosts`).then((x) => x ?? []),
  hostServices: (ip: string) => req<Service[] | null>(`/hosts/${ip}/services`).then((x) => x ?? []),
  search: (s: string, q: string) => req<SearchResult[] | null>(`/scopes/${s}/search?q=${encodeURIComponent(q)}`).then((x) => x ?? []),
  searchGlobal: (q: string, scope?: string) =>
    req<SearchResult[] | null>(`/search?q=${encodeURIComponent(q)}${scope ? "&scope=" + scope : ""}`).then((x) => x ?? []),
  findings: (s: string) => req<Finding[] | null>(`/scopes/${s}/findings`).then((x) => x ?? []),
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
  run: (id: string) => req<{ run: Run; progress: any }>(`/runs/${id}`),
  runActivity: (id: string) => req<RunActivity>(`/runs/${id}/activity`),
  runTargets: (id: string) => req<RunTarget[] | null>(`/runs/${id}/targets`).then((x) => x ?? []),
  cancelRun: (id: string) => req(`/runs/${id}/cancel`, { method: "POST" }),
  workers: () => req<Worker[] | null>("/workers").then((x) => x ?? []),
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
