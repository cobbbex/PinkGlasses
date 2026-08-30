import { useState } from "react";
import { api, SearchResult } from "../api";
import { Spinner } from "../components/ui";

const EXAMPLES = [
  'port:443 product:nginx',
  'port:22 country:DE',
  'tech:"WordPress"',
  'cert.expires<30d',
  'new:7d',
];

// Shodan-style query bar. Parsed to whitelisted, parameterized SQL server-side.
export default function Search({ scopeID }: { scopeID: string }) {
  const [q, setQ] = useState("port:443");
  const [rows, setRows] = useState<SearchResult[] | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [global, setGlobal] = useState(false);

  async function run(query = q, g = global) {
    setBusy(true); setErr("");
    try {
      setRows(g ? await api.searchGlobal(query) : await api.search(scopeID, query));
    } catch (e) { setErr(String(e)); setRows(null); }
    finally { setBusy(false); }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>Search</h2>
          <div className="sub">
            {global ? "Querying every company's inventory, Shodan-style." : "Querying the current company."}
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
          <button className={global ? "sm" : "ghost sm"} onClick={() => { setGlobal(true); run(q, true); }}>All companies</button>
        </div>
        <button onClick={() => run()} disabled={busy}>{busy ? <Spinner /> : "Search"}</button>
      </div>

      <div className="row" style={{ gap: 6 }}>
        <span className="muted" style={{ fontSize: 12 }}>Try:</span>
        {EXAMPLES.map((ex) => (
          <button key={ex} className="ghost sm" onClick={() => { setQ(ex); run(ex); }}>{ex}</button>
        ))}
      </div>

      {err && <div className="empty" style={{ borderColor: "var(--crit)", color: "var(--high)" }}>{err}</div>}

      {rows !== null && !err && (
        rows.length === 0 ? <div className="empty">No results.</div> : (
          <div className="table-wrap">
            <table>
              <thead><tr>
                {global && <th>Company</th>}
                <th>IP</th><th>Port</th><th>Product</th><th>Version</th><th>Title</th><th>Domain</th>
              </tr></thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.service_id}>
                    {global && <td>{r.company ?? "—"}</td>}
                    <td className="mono">{r.ip}</td>
                    <td className="mono">{r.port}</td>
                    <td>{r.product ?? "—"}</td>
                    <td className="mono">{r.version ?? "—"}</td>
                    <td className="wrap">{r.title ?? "—"}</td>
                    <td className="mono muted">{r.domain ?? "—"}</td>
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
