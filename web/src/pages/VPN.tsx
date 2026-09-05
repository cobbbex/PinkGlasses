import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { InfoDot, useToast } from "../components/ui";

/**
 * VPN configurations a scan can leave through.
 *
 * A config is write-only. It holds a private key for someone's network, so it
 * is sealed before it reaches the database and no endpoint returns it — what
 * you see here is the name, the kind, and the endpoint parsed out of the file
 * when it was uploaded. To change one, replace it.
 */
export default function VPN({ scopeID }: { scopeID: string }) {
  const toast = useToast();
  const { data, refetch } = useQuery({
    queryKey: ["vpn", scopeID], queryFn: () => api.vpnConfigs(scopeID),
  });
  const configs = data?.configs ?? [];
  const ready = data?.secrets_ready ?? true;

  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [config, setConfig] = useState("");
  const [busy, setBusy] = useState(false);

  async function add() {
    setBusy(true);
    try {
      const v = await api.createVPNConfig(scopeID, { name: name.trim(), config });
      toast("ok", `Added "${v.name}" (${v.kind})`);
      setAdding(false); setName(""); setConfig("");
      refetch();
    } catch (e) { toast("err", String(e)); } finally { setBusy(false); }
  }
  async function remove(id: string, n: string) {
    if (!confirm(`Delete "${n}"? Runs that used it keep their results.`)) return;
    await api.deleteVPNConfig(id); toast("ok", `Deleted "${n}"`); refetch();
  }

  async function onFile(f: File) {
    setConfig(await f.text());
    if (!name.trim()) setName(f.name.replace(/\.(conf|ovpn)$/i, ""));
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>
            VPN
            <InfoDot title="Where active scans leave from">
              <p style={{ marginTop: 0 }}>
                Stages that send traffic at a target — port scan onward — run either from a pool of
                remote workers you enrolled, or from <strong>local workers behind one of these
                tunnels</strong>. Local scanning needs a VPN configuration: there is no option to
                scan from this host's own address.
              </p>
              <p className="muted" style={{ marginBottom: 0 }}>
                The tunnel lives in a gateway container the run's workers share a network namespace
                with; the workers themselves hold no network privilege. Passive stages — discovery,
                DNS, enrichment — never touch the target and never use a tunnel.
              </p>
            </InfoDot>
          </h2>
          <div className="sub">WireGuard and OpenVPN configurations a scan can leave through.</div>
        </div>
        <button onClick={() => setAdding((a) => !a)} disabled={!ready}>
          {adding ? "Cancel" : "+ Add config"}
        </button>
      </div>

      {!ready && (
        <div className="empty" style={{ marginBottom: 16, textAlign: "left", borderColor: "var(--warn)" }}>
          <p style={{ marginTop: 0 }}><strong>Configs cannot be stored yet.</strong></p>
          <p className="muted" style={{ fontSize: 13, marginBottom: 0 }}>{data?.secrets_reason}</p>
        </div>
      )}

      {adding && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="row">
            <input className="grow" placeholder="Name, e.g. amsterdam exit"
              value={name} onChange={(e) => setName(e.target.value)} />
            <input type="file" accept=".conf,.ovpn,text/plain"
              onChange={(e) => e.target.files?.[0] && onFile(e.target.files[0])} />
          </div>
          <textarea
            className="mono" spellCheck={false}
            style={{ width: "100%", minHeight: 160, marginTop: 8 }}
            placeholder={"Paste a WireGuard .conf or OpenVPN .ovpn here.\n\n[Interface]\nPrivateKey = …\n\n[Peer]\nEndpoint = vpn.example.com:51820"}
            value={config} onChange={(e) => setConfig(e.target.value)} />
          <div className="row" style={{ marginTop: 8 }}>
            <span className="hint muted grow">
              The kind and endpoint are read from the file. The config itself is encrypted
              before storage and is never shown again.
            </span>
            <button onClick={add} disabled={busy || !name.trim() || !config.trim()}>
              {busy ? "Saving…" : "Add config"}
            </button>
          </div>
        </div>
      )}

      {configs.length === 0 ? (
        <div className="empty">
          <p>No VPN configurations yet.</p>
          <p className="muted" style={{ fontSize: 13, marginBottom: 0 }}>
            Until one exists, this company cannot start an active scan from local workers —
            there is deliberately no way to scan from this host's own address. Passive scans
            and remote worker pools are unaffected.
          </p>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Kind</th><th>Endpoint</th><th>Last seen exiting from</th><th>Added</th><th></th></tr></thead>
            <tbody>
              {configs.map((c) => (
                <tr key={c.id}>
                  <td>{c.name}</td>
                  <td><span className="pill">{c.kind}</span></td>
                  <td className="mono muted">{c.endpoint ?? "—"}</td>
                  <td className="mono">
                    {c.last_egress_ip
                      ? <span title={c.last_checked_at ? new Date(c.last_checked_at).toLocaleString() : undefined}>{c.last_egress_ip}</span>
                      : <span className="muted">not used yet</span>}
                  </td>
                  <td className="muted">{new Date(c.created_at).toLocaleDateString()}</td>
                  <td style={{ textAlign: "right" }}>
                    <button className="danger sm" onClick={() => remove(c.id, c.name)}>delete</button>
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
