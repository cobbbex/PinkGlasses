import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, HostService, HostVhost, Finding } from "../api";
import { Spinner, useSort, SortTh, siteURL, OpenLink } from "../components/ui";
import { ScreenshotButton } from "../components/Screenshot";
import { DotStrip, PresenceBadge } from "../components/DotStrip";

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
            <thead><tr>
              <th>Name</th><th>Record</th><th>First seen</th><th>Last seen</th>
              <th title="One dot per run that resolved this name. Filled: it pointed here. Hollow: it pointed elsewhere. Hover for the date.">Resolution history</th>
            </tr></thead>
            <tbody>
              {names.map((n) => (
                <tr key={n.name + n.via}>
                  <td className="mono">
                    {n.name}
                    {(n.also_resolved_to?.length ?? 0) > 0 && (
                      <div className="muted" style={{ fontSize: 11, marginTop: 2, fontFamily: "inherit" }}
                           title="Other addresses this name has resolved to">
                        also → {n.also_resolved_to!.join(", ")}
                      </div>
                    )}
                  </td>
                  <td><span className="pill">{n.via}</span></td>
                  <td className="muted" title={new Date(n.first_seen).toLocaleString()}>{new Date(n.first_seen).toLocaleString([], { dateStyle: "short", timeStyle: "short" })}</td>
                  <td className="muted" title={new Date(n.last_seen).toLocaleString()}>{new Date(n.last_seen).toLocaleString([], { dateStyle: "short", timeStyle: "short" })}</td>
                  <td><DotStrip history={n.history ?? []} /></td>
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
        services.map((sv) => <ServiceCard key={sv.id} sv={sv} addr={h.addr} names={names.map((n) => n.name)} />)
      )}

      <DiscoveredPaths findings={findings.filter((f) => f.kind === "content_discovery")} services={services} addr={h.addr} />

      <div className="section-title">Findings</div>
      {findings.filter((f) => f.kind !== "content_discovery").length === 0 ? (
        <div className="empty">No findings for this host{findings.length ? " beyond the discovered paths above" : ""}.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr>
              <th>Severity</th><th>Title</th><th>Kind</th><th>Presence</th>
              <th title="One dot per run that looked. Hover for the date.">History</th><th>Last seen</th>
            </tr></thead>
            <tbody>
              {findings.filter((f) => f.kind !== "content_discovery").map((f) => (
                <tr key={f.id}>
                  <td><span className={"sev-" + f.severity}>{f.severity}</span></td>
                  <td className="wrap">{f.title}</td>
                  <td className="muted">{f.kind}</td>
                  <td><PresenceBadge presence={f.presence} goneSince={f.gone_since} /></td>
                  <td><DotStrip history={f.history ?? []} /></td>
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
 * (wiki/Architecture.md §10.3).
 */
function ServiceCard({ sv, addr, names }: { sv: HostService; addr: string; names: string[] }) {
  // Names to open this port by: the sites seen on it, or failing that the
  // names resolving to the address. Up to three get a button in the header;
  // every site still has its own Open in the list below.
  const isWeb = sv.http?.status !== undefined || (sv.vhosts?.length ?? 0) > 0;
  const byHost = ((sv.vhosts?.length ?? 0) > 0 ? sv.vhosts!.map((v) => v.host) : names).slice(0, 3);
  const http = sv.http ?? null;
  // Defensive against a malformed document: only a plain object, and only its
  // string values, are rendered — an object child would take the page down.
  const rawHeaders: unknown = http?.headers;
  const headers: Record<string, string> = {};
  if (rawHeaders && typeof rawHeaders === "object" && !Array.isArray(rawHeaders)) {
    for (const [k, v] of Object.entries(rawHeaders as Record<string, unknown>)) {
      if (typeof v === "string") headers[k] = v;
    }
  }
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
        <span title="One dot per run that port-scanned this address. Filled: this port was open. Hollow: the scan ran and did not find it. Hover a dot for the date.">
          <DotStrip history={sv.history ?? []} />
        </span>
        {product && <span>{product}</span>}
        {http?.status !== undefined && <span className="pill">HTTP {http.status}</span>}
        {isWeb && <OpenLink href={siteURL(addr, sv.port)} label="Open by address" />}
        {isWeb && byHost.map((n) => (
          <OpenLink key={n} href={siteURL(n, sv.port)} label={byHost.length === 1 ? "Open by host" : `Open ${n}`} />
        ))}
        <span className="muted" style={{ marginLeft: "auto", fontSize: 12 }}>
          {sv.observed_at
            ? `observed ${new Date(sv.observed_at).toLocaleString()}`
            : `seen ${new Date(sv.last_seen).toLocaleString()}`}
        </span>
        {sv.has_screenshot && (
          <ScreenshotButton serviceID={sv.id} title={`${sv.port}/${sv.proto}`} />
        )}
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

      {(http?.cookies?.length ?? 0) > 0 && (
        <div style={{ marginTop: 8 }}>
          <div className="muted" style={{ fontSize: 12 }}>
            Cookies set{" "}
            <span style={{ fontSize: 11 }}>
              (names only — search for one with <code>cookie:</code>)
            </span>
          </div>
          <div className="row" style={{ marginTop: 4, gap: 6 }}>
            {http!.cookies!.map((c) => (
              <span key={c} className="pill mono" title={`cookie:${c}`}>{c}</span>
            ))}
          </div>
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

      {(sv.vhosts?.length ?? 0) > 0 && (
        <div style={{ marginTop: 10 }}>
          <div className="muted" style={{ fontSize: 12 }}>
            Sites on this port{" "}
            <span style={{ fontSize: 11 }}>
              (each name asked for by name — a shared address answers differently per site)
            </span>
          </div>
          {sv.vhosts!.map((v) => <VhostRow key={v.host} sv={sv} v={v} />)}
        </div>
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

/** One virtual host's latest observation on a port: status, title, cookies, headers, screenshot. */
function VhostRow({ sv, v }: { sv: HostService; v: HostVhost }) {
  const http = v.http ?? null;
  const headers: Record<string, string> = {};
  const raw: unknown = http?.headers;
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    for (const [k, val] of Object.entries(raw as Record<string, unknown>)) {
      if (typeof val === "string") headers[k] = val;
    }
  }
  const headerKeys = Object.keys(headers).sort();
  return (
    <div className="vhost">
      <div className="row" style={{ margin: 0, gap: 8, alignItems: "baseline" }}>
        <span className="mono">{v.host}</span>
        {http?.status !== undefined && <span className="pill">HTTP {http.status}</span>}
        {http?.title && <span>{http.title}</span>}
        {v.observed_at && (
          <span className="muted" style={{ fontSize: 12, marginLeft: "auto" }}>
            observed {new Date(v.observed_at).toLocaleString()}
          </span>
        )}
        <OpenLink href={siteURL(v.host, sv.port)} />
        {v.has_screenshot && (
          <ScreenshotButton serviceID={sv.id} host={v.host} title={v.host} />
        )}
      </div>
      {(http?.cookies?.length ?? 0) > 0 && (
        <div className="row" style={{ marginTop: 4, gap: 6 }}>
          {http!.cookies!.map((c) => (
            <span key={c} className="pill mono" title={`cookie:${c}`}>{c}</span>
          ))}
        </div>
      )}
      {headerKeys.length > 0 && (
        <details style={{ marginTop: 4 }}>
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
    </div>
  );
}

/**
 * Paths the directory search found, apart from the other findings: they are
 * many, informational, and read as a list of URLs rather than as issues. The
 * response status stands where Presence would — that is what a path is about —
 * and every row opens. Collapsed by default once there are more than a few.
 */
function DiscoveredPaths({ findings, services, addr }: { findings: Finding[]; services: HostService[]; addr: string }) {
  if (findings.length === 0) return null;
  const portOf = (serviceID: string) => services.find((s) => s.id === serviceID)?.port ?? 80;
  const rows = findings.map((f) => {
    const ev = (f.evidence ?? {}) as { path?: string; host?: string; status?: number | string };
    const port = portOf(f.asset_id);
    const site = ev.host || addr;
    const path = ev.path || f.title.replace(/^Discovered path: /, "").replace(/ on .*$/, "");
    return { f, port, site, path, status: ev.status, url: siteURL(site, port, path), byAddress: !ev.host };
  });
  const { sorted, sort, toggle } = useSort(rows, { key: "site", dir: "asc" }, pathSortValue);
  const [open, setOpen] = useState(rows.length <= 8);
  const statusClass = (s?: number | string) => {
    const n = Number(s);
    return n >= 500 ? "sev-high" : n >= 400 ? "muted" : n >= 300 ? "" : "sev-info";
  };
  return (
    <>
      <div className="section-title" style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <button className="ghost sm chev-btn" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
          <span className={"chev" + (open ? " open" : "")} aria-hidden="true" />
          Discovered paths
        </button>
        <span className="muted" style={{ fontSize: 12, fontWeight: 400 }}>
          {rows.length} path{rows.length === 1 ? "" : "s"} found by the directory search, with the status each answered.
        </span>
      </div>
      {open && (
        <div className="table-wrap">
          <table>
            <thead><tr>
              <SortTh k="site" sort={sort} onSort={toggle}>Site</SortTh>
              <SortTh k="path" sort={sort} onSort={toggle}>Path</SortTh>
              <SortTh k="status" sort={sort} onSort={toggle}>Status</SortTh>
              <th title="One dot per run that looked. Hover for the date.">History</th>
              <SortTh k="last_seen" sort={sort} onSort={toggle}>Last seen</SortTh><th></th>
            </tr></thead>
            <tbody>
              {sorted.map(({ f, site, port, path, status, url, byAddress }) => (
                <tr key={f.id}>
                  <td className="mono">
                    {site}{(port !== 80 && port !== 443) ? `:${port}` : ""}
                    {byAddress && <span className="muted" style={{ fontSize: 11 }}> · by address</span>}
                  </td>
                  <td className="mono wrap">{path}</td>
                  <td><span className={"mono " + statusClass(status)}>{status ?? "—"}</span></td>
                  <td><DotStrip history={f.history ?? []} /></td>
                  <td className="muted">{new Date(f.last_seen).toLocaleDateString()}</td>
                  <td style={{ textAlign: "right" }}><OpenLink href={url} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

type PathRow = { f: Finding; port: number; site: string; path: string; status?: number | string; url: string; byAddress: boolean };
// Site orders by name then port; status numerically; dates by time.
function pathSortValue(r: PathRow, key: string): unknown {
  switch (key) {
    case "site": return `${r.site} ${String(r.port).padStart(5, "0")}`;
    case "path": return r.path;
    case "status": return r.status === undefined || r.status === null ? null : Number(r.status);
    case "last_seen": return new Date(r.f.last_seen);
    default: return null;
  }
}
