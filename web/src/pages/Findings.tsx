import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { DotStrip, PresenceBadge } from "../components/DotStrip";

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

  const shown = (findings ?? [])
    .filter((f) => !sev || f.severity === sev)
    .filter((f) => !presence || (f.presence ?? "active") === presence);
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
              <th>Severity</th><th>Title</th><th>Kind</th><th>Presence</th>
              <th title="Filled dot: that run saw it. Hollow: that run looked and did not. Hover a dot for the date.">History</th>
              <th>Seen</th><th>First seen</th><th>Last seen</th>
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
