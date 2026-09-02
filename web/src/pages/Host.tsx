import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, HostService } from "../api";
import { Spinner } from "../components/ui";

/**
 * Everything known about one address, on its own URL so it can be opened in a
 * tab, bookmarked and shared — the Shodan host page, for your own inventory.
 *
 * This deliberately does not take a scopeID prop: the address identifies its
 * own scope, so a link into this page works from a cold start in a new tab.
 */
export default function Host() {
  const { ipID = "" } = useParams();
  const { data, isLoading, error } = useQuery({
    queryKey: ["host", ipID], queryFn: () => api.host(ipID), enabled: !!ipID,
  });

  if (isLoading) return <div className="row"><Spinner /> <span className="muted">Loading host…</span></div>;
  if (error) return <div className="empty">Host not found. It may have been removed by a rescan.</div>;
  if (!data) return null;

  const { host: h, names, services, findings } = data;
  const openPorts = services.filter((s) => s.last_state === "open");

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="muted" style={{ fontSize: 12, marginBottom: 2 }}>
            <Link to="/hosts">Hosts</Link> ·  {h.ptr ?? "no reverse DNS"}
          </div>
          <h2 className="mono" style={{ marginBottom: 2 }}>{h.addr}</h2>
          <div className="sub">
            {openPorts.length} open port{openPorts.length === 1 ? "" : "s"} ·{" "}
            {names.length} name{names.length === 1 ? "" : "s"} ·{" "}
            last seen {new Date(h.last_seen).toLocaleString()}
          </div>
        </div>
      </div>

      <div className="cards" style={{ marginBottom: 18 }}>
        <div className="card">
          <div className="l">Network</div>
          <div>{h.asn ? "AS" + h.asn : "—"}</div>
          <div className="muted" style={{ fontSize: 12 }}>{h.as_org ?? "unknown operator"}</div>
        </div>
        <div className="card">
          <div className="l">Announced prefix</div>
          <div className="mono">{h.as_range ?? "—"}</div>
          <div className="muted" style={{ fontSize: 12 }}>
            {h.country ?? "location unknown"}{h.cloud ? ` · ${h.cloud}` : ""}
          </div>
        </div>
        <div className="card">
          <div className="l">Reverse DNS</div>
          <div className="mono" style={{ wordBreak: "break-all" }}>{h.ptr ?? "—"}</div>
          <div className="muted" style={{ fontSize: 12 }}>
            {h.is_shared ? "shared / CDN address" : "dedicated address"}
          </div>
        </div>
        <div className="card">
          <div className="l">First seen</div>
          <div>{new Date(h.first_seen).toLocaleDateString()}</div>
          <div className="muted" style={{ fontSize: 12 }}>
            in inventory since this date
          </div>
        </div>
      </div>

      {h.is_shared && (
        <div className="empty" style={{ marginBottom: 18, textAlign: "left" }}>
          This address is shared infrastructure (CDN or common hosting). What is
          observed here is not necessarily controlled by the owner of the names
          below, which is why it is excluded from port scanning by default.
        </div>
      )}

      <div className="section-title" style={{ marginTop: 0 }}>
        Names resolving here
      </div>
      {names.length === 0 ? (
        <div className="empty">No names currently resolve to this address.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Record</th><th>First seen</th><th>Last seen</th></tr></thead>
            <tbody>
              {names.map((n) => (
                <tr key={n.name + n.via}>
                  <td className="mono">{n.name}</td>
                  <td><span className="pill">{n.via}</span></td>
                  <td className="muted">{new Date(n.first_seen).toLocaleDateString()}</td>
                  <td className="muted">{new Date(n.last_seen).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="section-title">Services</div>
      {services.length === 0 ? (
        <div className="empty">
          No open ports recorded. Port scanning requires the target to carry an
          active authorization.
        </div>
      ) : (
        services.map((sv) => <ServiceCard key={sv.id} sv={sv} />)
      )}

      <div className="section-title">Findings</div>
      {findings.length === 0 ? (
        <div className="empty">No findings for this host.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Severity</th><th>Title</th><th>Kind</th><th>Status</th><th>Last seen</th></tr></thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.id}>
                  <td><span className={"sev-" + f.severity}>{f.severity}</span></td>
                  <td className="wrap">{f.title}</td>
                  <td className="muted">{f.kind}</td>
                  <td><span className="badge">{f.status.replace("_", " ")}</span></td>
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

/**
 * One open port. Banners, HTTP titles and headers are attacker-controlled, so
 * every one of them is rendered as text by React — never as markup
 * (architecture.md §10.2).
 */
function ServiceCard({ sv }: { sv: HostService }) {
  const http = sv.http ?? null;
  const headers = http?.headers ?? {};
  const headerKeys = Object.keys(headers).sort();
  // A version already spelled out in the product string is not repeated:
  // banners like "Apache/2.4.7 (Ubuntu)" would otherwise read "… 2.4.7 2.4.7".
  const product = sv.version && !(sv.product ?? "").includes(sv.version)
    ? [sv.product, sv.version].filter(Boolean).join(" ")
    : (sv.product ?? "");

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <div className="row" style={{ margin: 0, alignItems: "baseline", gap: 10 }}>
        <strong className="mono" style={{ fontSize: 16 }}>{sv.port}/{sv.proto}</strong>
        <span className={"badge" + (sv.last_state === "open" ? " b-open" : "")}>{sv.last_state}</span>
        {product && <span>{product}</span>}
        {http?.status !== undefined && <span className="pill">HTTP {http.status}</span>}
        <span className="muted" style={{ marginLeft: "auto", fontSize: 12 }}>
          {sv.observed_at
            ? `observed ${new Date(sv.observed_at).toLocaleString()}`
            : `seen ${new Date(sv.last_seen).toLocaleString()}`}
        </span>
      </div>

      {http?.title && (
        <div style={{ marginTop: 8 }}>
          <span className="muted" style={{ fontSize: 12 }}>Title </span>
          {http.title}
        </div>
      )}

      {sv.banner && (
        <div style={{ marginTop: 8 }}>
          <div className="muted" style={{ fontSize: 12 }}>Banner</div>
          <pre className="mono" style={{
            margin: "2px 0 0", padding: 8, overflowX: "auto",
            background: "var(--bg-alt, rgba(127,127,127,.08))", borderRadius: 6,
            fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-all",
          }}>{sv.banner}</pre>
        </div>
      )}

      {sv.technologies.length > 0 && (
        <div className="row" style={{ marginTop: 8, gap: 6 }}>
          {sv.technologies.map((t) => (
            <span key={t.name + (t.version ?? "")} className="pill" title={t.cpe ?? undefined}>
              {t.name}{t.version ? ` ${t.version}` : ""}
            </span>
          ))}
        </div>
      )}

      {headerKeys.length > 0 && (
        <details style={{ marginTop: 8 }}>
          <summary className="muted" style={{ cursor: "pointer", fontSize: 12 }}>
            {headerKeys.length} response header{headerKeys.length === 1 ? "" : "s"}
          </summary>
          <div className="table-wrap" style={{ marginTop: 6 }}>
            <table>
              <tbody>
                {headerKeys.map((k) => (
                  <tr key={k}>
                    <td className="muted mono" style={{ width: 180 }}>{k}</td>
                    <td className="mono wrap">{headers[k]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}

      {sv.tls && (
        <details style={{ marginTop: 8 }}>
          <summary className="muted" style={{ cursor: "pointer", fontSize: 12 }}>TLS</summary>
          <pre className="mono" style={{
            margin: "6px 0 0", padding: 8, overflowX: "auto", fontSize: 12,
            background: "var(--bg-alt, rgba(127,127,127,.08))", borderRadius: 6,
          }}>{JSON.stringify(sv.tls, null, 2)}</pre>
        </details>
      )}
    </div>
  );
}
