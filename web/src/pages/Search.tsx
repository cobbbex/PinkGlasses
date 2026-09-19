import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, SearchResult, SearchFacets, Facet } from "../api";
import { Spinner, useSort, SortTh } from "../components/ui";

const EXAMPLES = [
  '*',
  'port:443 product:nginx',
  'product:*',
  'title:*login*',
  'port:22 country:DE',
  'tech:"WordPress"',
  // Cookie names fingerprint appliances their banners keep quiet about:
  // webvpn* is Cisco ASA WebVPN, BIGipServer* an F5 pool, NSC_* Citrix.
  'cookie:webvpn*',
  'cert.expires<30d',
  'new:7d',
];

// Shodan-style query bar. Parsed to whitelisted, parameterized SQL server-side.
// Beside the rows, the facets say what the query matched in aggregate — the
// products, ports, technologies, titles and statuses behind it — and clicking
// one narrows the query by that value.
export default function Search({ scopeID }: { scopeID: string }) {
  // ?q= runs a query on arrival, so another page can hand over to Search
  // with the results already showing — the Dashboard's Services tile does.
  const [sp] = useSearchParams();
  const [q, setQ] = useState(sp.get("q") ?? "*");
  const [rows, setRows] = useState<SearchResult[] | null>(null);
  const [facets, setFacets] = useState<SearchFacets | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [global, setGlobal] = useState(false);
  // Sorting is on the rows in hand, the way the Hosts and Findings tables do
  // it; the server's order (by address, then port) is the starting point.
  const { sorted, sort, toggle } = useSort<SearchResult>(rows ?? [], { key: "ip", dir: "asc" }, searchSortValue);

  useEffect(() => {
    const initial = sp.get("q");
    if (initial) run(initial, false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scopeID]);

  async function run(query = q, g = global) {
    setBusy(true); setErr("");
    try {
      const [r, f] = await Promise.all([
        g ? api.searchGlobal(query) : api.search(scopeID, query),
        g ? api.searchFacetsGlobal(query) : api.searchFacets(scopeID, query),
      ]);
      setRows(r); setFacets(f);
    } catch (e) { setErr(String(e).replace(/^Error:\s*/, "")); setRows(null); setFacets(null); }
    finally { setBusy(false); }
  }

  // Narrow the current query by a facet value. A bare * is replaced rather
  // than kept, and a value with spaces is quoted.
  function narrow(field: string, value: string) {
    const term = `${field}:${/[\s()]/.test(value) ? `"${value}"` : value}`;
    const base = q.trim() === "*" || q.trim() === "" ? "" : q.trim() + " ";
    const next = base + term;
    setQ(next); run(next);
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>Search</h2>
          <div className="sub">
            {global ? "Querying every company's inventory, Shodan-style." : "Querying the current company."}
            {" "}One row per site: a port that serves several names is listed once per name. Click a row for the host.
          </div>
        </div>
      </div>

      <div className="row">
        <input className="grow" style={{ minWidth: 300 }} value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && run()}
          placeholder={global ? "port:443 product:nginx company:acme" : "port:443 product:nginx"} />
        <div className="toggle">
          <button className={global ? "ghost sm" : "sm"} onClick={() => { setGlobal(false); run(q, false); }}>This company</button>
          <button className={global ? "sm" : "ghost sm"} onClick={() => { setGlobal(true); run(q, true); }}>Global search</button>
        </div>
        <button onClick={() => run()} disabled={busy}>{busy ? <Spinner /> : "Search"}</button>
      </div>

      <div className="row" style={{ gap: 6 }}>
        <span className="muted" style={{ fontSize: 12 }}>Try:</span>
        {EXAMPLES.map((ex) => (
          <button key={ex} className="ghost sm" onClick={() => { setQ(ex); run(ex); }}>{ex}</button>
        ))}
        <span className="muted" style={{ fontSize: 12, marginLeft: 6 }}>
          <code>*</code> is a wildcard; <code>field:*</code> means the field has a value; a bare <code>*</code> is everything.
        </span>
      </div>

      {err && <div className="empty" style={{ borderColor: "var(--crit)", color: "var(--high)" }}>{err}</div>}

      {facets && !err && (facets.services > 0) && (
        <div className="facets">
          <div className="facets-head">
            <strong>{facets.services}</strong> service{facets.services === 1 ? "" : "s"}
            {facets.sites > 0 && <> across <strong>{facets.sites}</strong> site{facets.sites === 1 ? "" : "s"}</>}
            <span className="muted" style={{ marginLeft: 8, fontSize: 12 }}>Click a value to narrow the query.</span>
          </div>
          <div className="facet-grid">
            <FacetColumn title="Products" field="product" items={facets.products} onPick={narrow} />
            <FacetColumn title="Ports" field="port" items={facets.ports} onPick={narrow} />
            <FacetColumn title="Technologies" field="tech" items={facets.techs} onPick={narrow} />
            <FacetColumn title="Titles" field="title" items={facets.titles} onPick={narrow} />
            <FacetColumn title="HTTP status" field="status" items={facets.statuses} onPick={narrow} />
          </div>
        </div>
      )}

      {rows !== null && !err && (
        rows.length === 0 ? <div className="empty">No results.</div> : (
          <div className="table-wrap">
            <table>
              <thead><tr>
                {global && <SortTh k="company" sort={sort} onSort={toggle}>Company</SortTh>}
                <SortTh k="site" sort={sort} onSort={toggle}>Site</SortTh>
                <SortTh k="ip" sort={sort} onSort={toggle}>IP</SortTh>
                <SortTh k="port" sort={sort} onSort={toggle}>Port</SortTh>
                <SortTh k="product" sort={sort} onSort={toggle}>Product</SortTh>
                <SortTh k="version" sort={sort} onSort={toggle}>Version</SortTh>
                <SortTh k="title" sort={sort} onSort={toggle}>Title</SortTh>
              </tr></thead>
              <tbody>
                {sorted.map((r) => (
                  <tr key={r.service_id + (r.host ?? "")}
                      style={{ cursor: r.ip_id ? "pointer" : "default" }}
                      title={r.ip_id ? "Open host details in a new tab" : undefined}
                      onClick={() => r.ip_id && window.open(`/host/${r.ip_id}`, "_blank", "noopener")}>
                    {global && <td>{r.company ?? "—"}</td>}
                    <td className="mono">
                      {r.host
                        ? r.host
                        : <span className="muted" title={r.domain ? `by address; ${r.domain} resolves here` : "by address"}>
                            {r.domain ?? "—"}{r.domain && <span style={{ fontSize: 11 }}> · by address</span>}
                          </span>}
                    </td>
                    <td className="mono">
                      {r.ip_id
                        ? <a href={`/host/${r.ip_id}`} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}>{r.ip}</a>
                        : r.ip}
                    </td>
                    <td className="mono">{r.port}</td>
                    <td>{r.product ?? "—"}</td>
                    <td className="mono">{r.version ?? "—"}</td>
                    <td className="wrap">{r.title ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}
    </div>
  );
}

// Site sorts by the name shown, which is the host or, by address, the domain
// that resolves there; addresses sort numerically through compareValues.
function searchSortValue(r: SearchResult, key: string): unknown {
  switch (key) {
    case "company": return r.company ?? null;
    case "site": return r.host || r.domain || null;
    case "ip": return r.ip;
    case "port": return r.port;
    case "product": return r.product ?? null;
    case "version": return r.version ?? null;
    case "title": return r.title ?? null;
    default: return null;
  }
}

function FacetColumn({ title, field, items, onPick }: {
  title: string; field: string; items: Facet[]; onPick: (field: string, value: string) => void;
}) {
  const max = items.length ? items[0].count : 1;
  return (
    <div className="facet-col">
      <div className="facet-title">{title}</div>
      {items.length === 0 ? <div className="muted" style={{ fontSize: 12 }}>—</div> : items.map((f) => (
        <button key={f.value} className="facet" onClick={() => onPick(field, f.value)}
          title={`${field}:${f.value} — ${f.count} service${f.count === 1 ? "" : "s"}`}>
          <span className="facet-bar" style={{ width: `${Math.max(4, (100 * f.count) / max)}%` }} />
          <span className="facet-label">{f.value}</span>
          <span className="facet-n">{f.count}</span>
        </button>
      ))}
    </div>
  );
}
