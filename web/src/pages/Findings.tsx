import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, Finding } from "../api";
import { DotStrip, PresenceBadge } from "../components/DotStrip";
import { useSort, SortTh } from "../components/ui";

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
    .filter((f) => !presence || (f.presence ?? "active") === presence);
  const { sorted: shown, sort, toggle } = useSort<Finding>(filtered, { key: "severity", dir: "desc" }, findingSortValue);
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
              <SortTh k="title" sort={sort} onSort={toggle}>Title</SortTh>
              <SortTh k="kind" sort={sort} onSort={toggle}>Kind</SortTh>
              <SortTh k="presence" sort={sort} onSort={toggle}>Presence</SortTh>
              <th title="Filled dot: that run saw it. Hollow: that run looked and did not. Hover a dot for the date.">History</th>
              <SortTh k="seen" sort={sort} onSort={toggle} title="Share of runs that looked and saw it">Seen</SortTh>
              <SortTh k="first_seen" sort={sort} onSort={toggle}>First seen</SortTh>
              <SortTh k="last_seen" sort={sort} onSort={toggle}>Last seen</SortTh>
            </tr></thead>
            <tbody>
              {shown.map((f) => (
                <tr key={f.id}>
                  <td><span className={"sev-" + f.severity}>{f.severity}</span></td>
                  <td className="wrap">{f.title}</td>
                  <td className="muted">{f.kind}</td>
                  <td><PresenceBadge presence={f.presence} goneSince={f.gone_since} /></td>
                  <td><DotStrip history={f.history ?? []} /></td>
                  <td className="muted mono" title="runs that observed it / runs that looked">
                    {(f.covered_runs ?? 0) > 0 ? `${f.seen_in ?? 0}/${f.covered_runs}` : "—"}
                  </td>
                  <td className="muted">{new Date(f.first_seen).toLocaleDateString()}</td>
                  <td className="muted">{new Date(f.last_seen).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// Severity orders by rank, not alphabetically; "Seen" by the share of covering
// runs that observed the finding.
const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
function findingSortValue(f: Finding, key: string): unknown {
  switch (key) {
    case "severity": return SEV_RANK[f.severity] ?? 0;
    case "title": return f.title;
    case "kind": return f.kind;
    case "presence": return f.presence ?? "active";
    case "seen": return (f.covered_runs ?? 0) > 0 ? (f.seen_in ?? 0) / (f.covered_runs ?? 1) : null;
    case "first_seen": return new Date(f.first_seen);
    case "last_seen": return new Date(f.last_seen);
    default: return null;
  }
}
