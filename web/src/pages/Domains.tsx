import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import Graph from "../components/Graph";

// The DNSDumpster-style view: subdomain inventory plus the asset map.
export default function Domains({ scopeID }: { scopeID: string }) {
  const [q, setQ] = useState("");
  const { data: domains } = useQuery({ queryKey: ["domains", scopeID, q], queryFn: () => api.domains(scopeID, q) });
  const { data: graph } = useQuery({ queryKey: ["graph", scopeID], queryFn: () => api.graph(scopeID) });

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>Domains</h2>
          <div className="sub">Every name discovered in this scope, and what it resolves to.</div>
        </div>
      </div>

      <div className="row">
        <input className="grow" style={{ maxWidth: 380 }} placeholder="Filter subdomains…"
          value={q} onChange={(e) => setQ(e.target.value)} />
        <span className="muted">{domains?.length ?? 0} shown</span>
      </div>

      {(domains ?? []).length === 0 ? (
        <div className="empty">No domains discovered yet — run a scan.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Subdomain</th><th>Apex</th><th>Sources</th><th>First seen</th><th>Last seen</th></tr></thead>
            <tbody>
              {(domains ?? []).map((d) => (
                <tr key={d.id}>
                  <td className="mono">{d.name}</td>
                  <td className="mono muted">{d.apex}</td>
                  <td>{(d.sources ?? []).map((s) => <span key={s} className="pill">{s}</span>)}</td>
                  <td className="muted">{fmt(d.first_seen)}</td>
                  <td className="muted">{fmt(d.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="section-title">Asset map</div>
      <Graph nodes={graph?.nodes ?? []} edges={graph?.edges ?? []} />
    </div>
  );
}

function fmt(s: string) { return new Date(s).toLocaleDateString(); }
