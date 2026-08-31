import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, HostRow } from "../api";
import { Modal, InfoDot, Spinner } from "../components/ui";
import Graph from "../components/Graph";

/**
 * Unified Hosts view. A subdomain and the machine it points at are the same
 * question in practice, so names and addresses live in one table: each row is a
 * discovered name with the address it resolves to and that address's network
 * provenance (rDNS, AS number, AS name, announcing prefix), all supplied by dnsx.
 */
export default function Hosts({ scopeID }: { scopeID: string }) {
  const [q, setQ] = useState("");
  const [view, setView] = useState<"table" | "map">("table");
  // Passive sources record names that existed once and no longer resolve. They
  // are kept, but they are not current attack surface, so they are out of the
  // default view.
  const [showUnresolved, setShowUnresolved] = useState(false);
  const [sel, setSel] = useState<HostRow | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["hostrows", scopeID, q, showUnresolved],
    queryFn: () => api.hostRows(scopeID, q, showUnresolved),
  });
  const { data: graph } = useQuery({
    queryKey: ["graph", scopeID], queryFn: () => api.graph(scopeID), enabled: view === "map",
  });

  const list = data?.rows ?? [];
  const hidden = data?.unresolvedHidden ?? 0;
  const uniqueIPs = new Set(list.filter((r) => r.addr).map((r) => r.addr)).size;

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>
            Hosts
            <InfoDot title="What this shows">
              <p style={{ marginTop: 0 }}>
                Every subdomain discovered in this scope, with the address it resolves to.
              </p>
              <p className="muted" style={{ marginBottom: 0 }}>
                Reverse DNS, AS number, AS name and the announcing prefix come from dnsx
                during resolution.
              </p>
              <p className="muted" style={{ marginBottom: 0 }}>
                Names that no longer resolve are hidden by default. Passive sources such as
                certificate transparency surface historical names — often tens of thousands
                for an old domain — which are evidence of past infrastructure rather than
                current attack surface. They are still recorded; tick the box to see them.
              </p>
            </InfoDot>
          </h2>
          <div className="sub">
            {list.length} rows · {uniqueIPs} unique addresses
            {hidden > 0 && !showUnresolved &&
              ` · ${hidden.toLocaleString()} non-resolving name${hidden === 1 ? "" : "s"} hidden`}
          </div>
        </div>
        <div className="row" style={{ margin: 0 }}>
          {isLoading && <Spinner />}
          <button className={view === "table" ? "" : "ghost"} onClick={() => setView("table")}>Table</button>
          <button className={view === "map" ? "" : "ghost"} onClick={() => setView("map")}>Map</button>
        </div>
      </div>

      <div className="row">
        <input className="grow" style={{ maxWidth: 420 }}
          placeholder="Filter by name, address or AS name…"
          value={q} onChange={(e) => setQ(e.target.value)} />
        {hidden > 0 && (
          <label className="param-toggle" title="Names seen by passive sources that no longer resolve">
            <input type="checkbox" checked={showUnresolved}
              onChange={(e) => setShowUnresolved(e.target.checked)} />
            <span className="muted">show {hidden.toLocaleString()} non-resolving</span>
          </label>
        )}
      </div>

      {view === "map" ? (
        <Graph nodes={graph?.nodes ?? []} edges={graph?.edges ?? []} />
      ) : list.length === 0 ? (
        <div className="empty">
          {hidden > 0
            ? `No names currently resolve. ${hidden.toLocaleString()} historical name${hidden === 1 ? " is" : "s are"} recorded — tick "show non-resolving" to see them.`
            : "Nothing discovered yet — run a scan."}
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Subdomain</th><th>Address</th><th>Reverse DNS</th>
                <th>ASN</th><th>AS name</th><th>AS range</th><th>Services</th>
              </tr>
            </thead>
            <tbody>
              {list.map((r, i) => (
                <tr key={(r.domain_id ?? "") + (r.ip_id ?? "") + i}
                    style={{ cursor: r.ip_id ? "pointer" : "default" }}
                    onClick={() => r.ip_id && setSel(r)}>
                  <td className="mono">{r.name}</td>
                  <td className="mono">
                    {r.addr ?? <span className="muted">did not resolve</span>}
                    {r.is_shared && <span className="pill" style={{ marginLeft: 6 }}>shared</span>}
                  </td>
                  <td className="muted mono">{r.ptr ?? "—"}</td>
                  <td className="mono">{r.asn ? "AS" + r.asn : "—"}</td>
                  <td>{r.as_org ?? "—"}</td>
                  <td className="mono muted">{r.as_range ?? "—"}</td>
                  <td className="muted">{r.ip_id ? r.services : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <HostDetail row={sel} onClose={() => setSel(null)} />
    </div>
  );
}

function HostDetail({ row, onClose }: { row: HostRow | null; onClose: () => void }) {
  const { data: services } = useQuery({
    queryKey: ["svc", row?.ip_id], queryFn: () => api.hostServices(row!.ip_id!), enabled: !!row?.ip_id,
  });
  if (!row) return null;

  return (
    <Modal title={row.name} open={!!row} onClose={onClose}
      footer={<button className="ghost" onClick={onClose}>Close</button>}>
      <div className="cards" style={{ gridTemplateColumns: "1fr 1fr", marginBottom: 16 }}>
        <div className="card">
          <div className="l">Address</div><div className="mono">{row.addr ?? "—"}</div>
          <div className="muted" style={{ fontSize: 12 }}>{row.ptr ?? "no reverse DNS"}</div>
        </div>
        <div className="card">
          <div className="l">Network</div>
          <div>{row.asn ? `AS${row.asn}` : "—"}</div>
          <div className="muted" style={{ fontSize: 12 }}>
            {row.as_org ?? ""}{row.as_range ? ` · ${row.as_range}` : ""}
          </div>
        </div>
      </div>

      <div className="section-title" style={{ marginTop: 0 }}>Open services</div>
      {(services ?? []).length === 0 ? (
        <div className="empty">No open services recorded.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Port</th><th>Proto</th><th>State</th><th>First seen</th></tr></thead>
            <tbody>
              {(services ?? []).map((s) => (
                <tr key={s.id}>
                  <td className="mono">{s.port}</td>
                  <td>{s.proto}</td>
                  <td><span className="badge b-open">{s.last_state}</span></td>
                  <td className="muted">{new Date(s.first_seen).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Modal>
  );
}
