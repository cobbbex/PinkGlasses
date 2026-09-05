import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { InfoDot, Spinner } from "../components/ui";
import { ScreenshotButton } from "../components/Screenshot";
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
                <th title="When this name was last seen resolving to this address. Hover a value for when it was first seen.">Seen</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {list.map((r, i) => (
                <tr key={(r.domain_id ?? "") + (r.ip_id ?? "") + i}
                    style={{ cursor: r.ip_id ? "pointer" : "default" }}
                    title={r.ip_id ? "Open host details in a new tab" : undefined}
                    onClick={() => r.ip_id && window.open(`/host/${r.ip_id}`, "_blank", "noopener")}>
                  <td className="mono">
                    {r.ip_id ? (
                      // A real link, so the row also answers to middle-click,
                      // ctrl-click and "copy link address".
                      <a href={`/host/${r.ip_id}`} target="_blank" rel="noreferrer"
                         onClick={(e) => e.stopPropagation()}>{r.name}</a>
                    ) : r.name}
                    {r.apex_wildcard && (
                      <span className="pill" style={{ marginLeft: 6 }}
                            title="This domain answers for any name (wildcard DNS). Names that resolved only to the wildcard address were dropped at discovery; what you see here pointed somewhere else too.">wildcard</span>
                    )}
                  </td>
                  <td className="mono">
                    {r.addr ?? <span className="muted">did not resolve</span>}
                    {r.is_shared && <span className="pill" style={{ marginLeft: 6 }}>shared</span>}
                  </td>
                  <td className="muted mono">{r.ptr ?? "—"}</td>
                  <td className="mono">{r.asn ? "AS" + r.asn : "—"}</td>
                  <td>{r.as_org ?? "—"}</td>
                  <td className="mono muted">{r.as_range ?? "—"}</td>
                  <td className="muted">{r.ip_id ? r.services : "—"}</td>
                  <td className="muted" style={{ whiteSpace: "nowrap", fontSize: 12 }}
                      title={`First seen ${new Date(r.first_seen).toLocaleString()}\nLast seen ${new Date(r.last_seen).toLocaleString()}`}>
                    {new Date(r.last_seen).toLocaleString([], { dateStyle: "short", timeStyle: "short" })}
                  </td>
                  <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                    {r.screenshot_service_id && (
                      <ScreenshotButton
                        serviceID={r.screenshot_service_id}
                        title={r.name}
                        label="Screenshot"
                      />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

    </div>
  );
}
