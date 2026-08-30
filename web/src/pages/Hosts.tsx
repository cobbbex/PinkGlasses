import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, Host } from "../api";
import { Modal } from "../components/ui";

// The Shodan-style view: hosts, drill into per-host services.
export default function Hosts({ scopeID }: { scopeID: string }) {
  const { data: hosts } = useQuery({ queryKey: ["hosts", scopeID], queryFn: () => api.hosts(scopeID) });
  const [sel, setSel] = useState<Host | null>(null);

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>Hosts</h2>
          <div className="sub">Click a host to see its open services.</div>
        </div>
      </div>

      {(hosts ?? []).length === 0 ? (
        <div className="empty">No hosts discovered yet — run a scan.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>IP</th><th>PTR</th><th>ASN</th><th>Org</th><th>Cloud</th><th>Country</th><th></th></tr></thead>
            <tbody>
              {(hosts ?? []).map((h) => (
                <tr key={h.id} style={{ cursor: "pointer" }} onClick={() => setSel(h)}>
                  <td className="mono">{h.addr}</td>
                  <td className="muted">{h.ptr ?? "—"}</td>
                  <td>{h.asn ? `AS${h.asn}` : "—"}</td>
                  <td className="muted">{h.as_org ?? "—"}</td>
                  <td>{h.cloud ?? "—"}</td>
                  <td>{h.country ?? "—"}</td>
                  <td>{h.is_shared && <span className="badge b-pending">shared</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <HostDetail host={sel} onClose={() => setSel(null)} />
    </div>
  );
}

function HostDetail({ host, onClose }: { host: Host | null; onClose: () => void }) {
  const { data: services } = useQuery({
    queryKey: ["svc", host?.id], queryFn: () => api.hostServices(host!.id), enabled: !!host,
  });
  if (!host) return null;

  return (
    <Modal title={host.addr} open={!!host} onClose={onClose}
      footer={<button className="ghost" onClick={onClose}>Close</button>}>
      <div className="cards" style={{ gridTemplateColumns: "1fr 1fr", marginBottom: 16 }}>
        <div className="card"><div className="l">ASN</div><div>{host.asn ? `AS${host.asn}` : "—"}</div>
          <div className="muted" style={{ fontSize: 12 }}>{host.as_org ?? ""}</div></div>
        <div className="card"><div className="l">Reverse DNS</div><div className="mono">{host.ptr ?? "—"}</div></div>
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
