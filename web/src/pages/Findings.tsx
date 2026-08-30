import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { useToast } from "../components/ui";

const SEVERITIES = ["", "critical", "high", "medium", "low", "info"];

export default function Findings({ scopeID }: { scopeID: string }) {
  const toast = useToast();
  const [sev, setSev] = useState("");
  const { data: findings, refetch } = useQuery({
    queryKey: ["findings", scopeID], queryFn: () => api.findings(scopeID),
  });

  const shown = (findings ?? []).filter((f) => !sev || f.severity === sev);

  async function setStatus(id: string, status: string) {
    try {
      await api.patchFinding(id, status);
      toast("ok", `Marked ${status}`);
      refetch();
    } catch (e) { toast("err", String(e)); }
  }

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
        <span className="muted">{shown.length} shown</span>
      </div>

      {shown.length === 0 ? (
        <div className="empty">No findings.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Severity</th><th>Title</th><th>Kind</th><th>Status</th><th>First seen</th><th></th></tr></thead>
            <tbody>
              {shown.map((f) => (
                <tr key={f.id}>
                  <td><span className={"sev-" + f.severity}>{f.severity}</span></td>
                  <td className="wrap">{f.title}</td>
                  <td className="muted">{f.kind}</td>
                  <td><span className="badge">{f.status.replace("_", " ")}</span></td>
                  <td className="muted">{new Date(f.first_seen).toLocaleDateString()}</td>
                  <td style={{ textAlign: "right" }}>
                    {f.status === "open" && (
                      <>
                        <button className="ghost sm" onClick={() => setStatus(f.id, "acknowledged")}>ack</button>
                        <button className="ghost sm" style={{ marginLeft: 6 }} onClick={() => setStatus(f.id, "resolved")}>resolve</button>
                      </>
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
