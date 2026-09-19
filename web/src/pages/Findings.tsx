import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, Finding } from "../api";
import { DotStrip, PresenceBadge } from "../components/DotStrip";
import { useSort, SortTh, siteURL, OpenLink } from "../components/ui";

const SEVERITIES = ["", "critical", "high", "medium", "low", "info"];
const PRESENCE = [
  { id: "", label: "Active and gone" },
  { id: "active", label: "Active only" },
  { id: "gone", label: "Gone only" },
];

/**
 * Findings with their history. There is no status workflow here: whether a
 * finding is still present is computed from the runs that looked for it, so it
 * cannot drift out of step with reality the way a hand-set status can.
 *
 * Each row says where: the site it was found on, the address, and — for a
 * discovered path — the status the path answered, which is what a path is
 * about. A finding that has gone says so in that same cell. Every row that
 * is a URL opens.
 */
export default function Findings({ scopeID }: { scopeID: string }) {
  const [sev, setSev] = useState("");
  const [presence, setPresence] = useState("");
  const { data: findings } = useQuery({
    queryKey: ["findings", scopeID], queryFn: () => api.findings(scopeID),
    refetchInterval: 15000,
  });

  const filtered = (findings ?? [])
    .filter((f) => !sev || f.severity === sev)
    .filter((f) => !presence || (f.presence ?? "active") === presence)
    .map(toRow);
  const { sorted: shown, sort, toggle } = useSort<Row>(filtered, { key: "severity", dir: "desc" }, rowSortValue);
  const gone = (findings ?? []).filter((f) => f.presence === "gone").length;

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>Findings</h2>
          <div className="sub">Security-relevant conclusions about your assets.</div>
        </div>
      </div>

      <div className="row">
        <select value={sev} onChange={(e) => setSev(e.target.value)}>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s ? s : "All severities"}</option>)}
        </select>
        <select value={presence} onChange={(e) => setPresence(e.target.value)}>
          {PRESENCE.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
        </select>
        <span className="muted">
          {shown.length} shown{gone > 0 && presence === "" ? ` · ${gone} gone` : ""}
        </span>
      </div>

      {shown.length === 0 ? (
        <div className="empty">No findings.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr>
              <SortTh k="severity" sort={sort} onSort={toggle}>Severity</SortTh>
              <SortTh k="site" sort={sort} onSort={toggle} title="The name the finding was observed under; by address when none">Host</SortTh>
              <SortTh k="ip" sort={sort} onSort={toggle}>IP</SortTh>
              <SortTh k="title" sort={sort} onSort={toggle} title="A discovered path shows its path; hover for the full title">Title</SortTh>
              <SortTh k="kind" sort={sort} onSort={toggle}>Kind</SortTh>
              <SortTh k="status" sort={sort} onSort={toggle} title="The HTTP status the path answered with">Status</SortTh>
              <SortTh k="seen" sort={sort} onSort={toggle} title="One dot per run that looked: filled when it saw the finding, hollow when not; hover a dot for the date. The number is runs that saw it over runs that looked; sorts by that share.">History</SortTh>
              <SortTh k="first_seen" sort={sort} onSort={toggle}>First seen</SortTh>
              <SortTh k="last_seen" sort={sort} onSort={toggle}>Last seen</SortTh>
              <th></th>
            </tr></thead>
            <tbody>
              {shown.map(({ f, site, byAddress, status, url, label }) => (
                <tr key={f.id}>
                  <td><span className={"sev-" + f.severity}>{f.severity}</span></td>
                  <td className="mono">
                    {byAddress || !site
                      ? <span className="muted" title="Observed by address: the request carried no name">—</span>
                      : site}
                  </td>
                  <td className="mono">
                    {f.ip_id
                      ? <a href={`/host/${f.ip_id}`} target="_blank" rel="noreferrer" title="Open host details in a new tab">{f.ip}</a>
                      : (f.ip ?? "—")}
                  </td>
                  <td className="mono" title={f.title}
                      style={{ maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{label}</td>
                  <td className="muted" title={f.kind}>{kindLabel(f.kind)}</td>
                  <td>
                    {status !== undefined && <span className={"mono " + statusClass(status)}>{status}</span>}
                    {f.presence === "gone" && <> <PresenceBadge presence={f.presence} goneSince={f.gone_since} /></>}
                    {status === undefined && f.presence !== "gone" && <span className="muted">—</span>}
                  </td>
                  <td style={{ whiteSpace: "nowrap" }}>
                    <DotStrip history={f.history ?? []} />
                    {(f.covered_runs ?? 0) > 0 && (
                      <span className="muted mono" style={{ marginLeft: 8, fontSize: 12 }}
                            title="runs that observed it / runs that looked">{f.seen_in ?? 0}/{f.covered_runs}</span>
                    )}
                  </td>
                  <td className="muted" style={{ whiteSpace: "nowrap" }}>{new Date(f.first_seen).toLocaleDateString()}</td>
                  <td className="muted" style={{ whiteSpace: "nowrap" }}>{new Date(f.last_seen).toLocaleDateString()}</td>
                  <td>{url && <OpenLink href={url} label="Open" />}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

type Row = {
  f: Finding;
  /** The name the finding was observed under, or the address when none. */
  site?: string;
  byAddress: boolean;
  /** HTTP status a discovered path answered with. */
  status?: number;
  /** Where the finding can be opened, when it is a URL. */
  url?: string;
  /** What the row shows for the title: a discovered path is its path, since
   *  the Kind column already says what it is and the paths are long. */
  label: string;
};

// A discovered path opens at the site it was found on, on its port; a nuclei
// match opens at the URL it recorded.
function toRow(f: Finding): Row {
  const ev = (f.evidence ?? {}) as { path?: string; host?: string; status?: number | string; url?: string };
  const site = ev.host || f.ip || undefined;
  const status = ev.status === undefined || ev.status === null || ev.status === "" ? undefined : Number(ev.status);
  let url: string | undefined = typeof ev.url === "string" && ev.url ? ev.url : undefined;
  let label = f.title;
  if (f.kind === "content_discovery") {
    const path = ev.path || f.title.replace(/^Discovered path: /, "").replace(/ on .*$/, "");
    label = path;
    if (!url && site) url = siteURL(site, f.port ?? 80, path);
  }
  return { f, site, byAddress: !ev.host, status, url, label };
}

// The kind, short: the full name is on hover. "content_discovery" is a
// discovered path; "nuclei:<template>" is a vulnerability check match.
function kindLabel(kind: string): string {
  if (kind === "content_discovery") return "path";
  if (kind.startsWith("nuclei:")) return "vuln";
  return kind;
}

function statusClass(s: number): string {
  return s >= 500 ? "sev-high" : s >= 400 ? "muted" : s >= 300 ? "" : "sev-info";
}

// Severity orders by rank, not alphabetically; "Seen" by the share of covering
// runs that observed the finding.
const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
function rowSortValue(r: Row, key: string): unknown {
  const f = r.f;
  switch (key) {
    case "severity": return SEV_RANK[f.severity] ?? 0;
    case "title": return f.title;
    case "kind": return f.kind;
    case "site": return r.site ?? null;
    case "ip": return f.ip ?? null;
    case "status": return r.status ?? null;
    case "seen": return (f.covered_runs ?? 0) > 0 ? (f.seen_in ?? 0) / (f.covered_runs ?? 1) : null;
    case "first_seen": return new Date(f.first_seen);
    case "last_seen": return new Date(f.last_seen);
    default: return null;
  }
}
