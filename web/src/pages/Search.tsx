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

  async function run(query = q) {
    setBusy(true); setErr("");
    try { setRows(await api.search(scopeID, query)); }
    catch (e) { setErr(String(e)); setRows(null); }
    finally { setBusy(false); }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>Search</h2>
          <div className="sub">Query every service in the inventory.</div>
        </div>
      </div>

      <div className="row">
        <input className="grow" style={{ minWidth: 320 }} value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && run()}
          placeholder="port:443 product:nginx" />
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
              <thead><tr><th>IP</th><th>Port</th><th>Product</th><th>Version</th><th>Title</th><th>Domain</th></tr></thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.service_id}>
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
