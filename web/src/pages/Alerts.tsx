import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { InfoDot, useToast } from "../components/ui";

const EVENT_LABEL: Record<string, { label: string; hint: string }> = {
  finding_returned: { label: "Finding returned", hint: "Was gone, is back. A regression — the one most worth a message." },
  new_finding: { label: "New finding", hint: "First time this issue has been seen on this asset." },
  finding_gone: { label: "Finding gone", hint: "A run looked for it and did not find it." },
  new_port: { label: "New open port", hint: "A port not seen open before on a host in this company." },
  new_subdomain: { label: "New subdomain", hint: "A name not seen before. Noisy on a first scan." },
};
const SEVERITIES = ["info", "low", "medium", "high", "critical"];

/**
 * Where a company's change digests go. One digest per run per channel, listing
 * the changes that channel asked to hear about; every attempt is recorded, so a
 * destination that has been failing shows up here rather than as silence.
 */
export default function Alerts({ scopeID }: { scopeID: string }) {
  const toast = useToast();
  const { data, refetch } = useQuery({
    queryKey: ["notifications", scopeID], queryFn: () => api.notifications(scopeID),
  });
  const { data: deliveries, refetch: refetchDeliveries } = useQuery({
    queryKey: ["deliveries", scopeID], queryFn: () => api.notificationDeliveries(scopeID),
    refetchInterval: 15000,
  });
  const channels = data?.channels ?? [];
  const events = data?.events ?? Object.keys(EVENT_LABEL);

  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<"webhook" | "slack">("slack");
  const [url, setUrl] = useState("");
  const [picked, setPicked] = useState<string[]>(["finding_returned", "new_finding", "new_port"]);
  const [minSev, setMinSev] = useState("low");
  const [busy, setBusy] = useState(false);

  async function create() {
    setBusy(true);
    try {
      await api.createNotification(scopeID, { name, kind, url, events: picked, min_severity: minSev });
      toast("ok", `Added "${name}"`);
      setAdding(false); setName(""); setUrl("");
      refetch();
    } catch (e) { toast("err", String(e)); } finally { setBusy(false); }
  }
  async function test(id: string, chName: string) {
    const r = await api.testNotification(id);
    toast(r.sent ? "ok" : "err", r.sent ? `Test digest sent to "${chName}"` : `"${chName}": ${r.error}`);
    refetchDeliveries();
  }
  async function toggle(id: string, enabled: boolean) {
    await api.setNotificationEnabled(id, enabled); refetch();
  }
  async function remove(id: string, chName: string) {
    if (!confirm(`Delete "${chName}" and its delivery history?`)) return;
    await api.deleteNotification(id); toast("ok", `Deleted "${chName}"`); refetch(); refetchDeliveries();
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>
            Alerts
            <InfoDot title="How alerts work">
              <p style={{ marginTop: 0 }}>
                When a scan finishes, every change it produced is compared with what each
                channel asked to hear about, and one digest per channel is sent.
              </p>
              <p className="muted" style={{ marginBottom: 0 }}>
                Minimum severity applies to findings only; new ports and names are governed
                by the event list. A Slack webhook URL is a secret and is shown masked.
              </p>
            </InfoDot>
          </h2>
          <div className="sub">Where to send word when something in this company changes.</div>
        </div>
        <button onClick={() => setAdding((a) => !a)}>{adding ? "Cancel" : "+ Add channel"}</button>
      </div>

      {adding && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="row">
            <input className="grow" placeholder="Name, e.g. #security-alerts" value={name} onChange={(e) => setName(e.target.value)} />
            <select value={kind} onChange={(e) => setKind(e.target.value as "webhook" | "slack")}>
              <option value="slack">Slack incoming webhook</option>
              <option value="webhook">Generic JSON webhook</option>
            </select>
          </div>
          <div className="row">
            <input className="grow mono" placeholder={kind === "slack" ? "https://hooks.slack.com/services/…" : "https://example.com/hook"}
              value={url} onChange={(e) => setUrl(e.target.value)} spellCheck={false} />
          </div>
          <div className="row" style={{ flexWrap: "wrap", gap: 10 }}>
            {events.map((ev) => (
              <label key={ev} className="param-toggle" title={EVENT_LABEL[ev]?.hint}>
                <input type="checkbox" checked={picked.includes(ev)}
                  onChange={(e) => setPicked(e.target.checked ? [...picked, ev] : picked.filter((x) => x !== ev))} />
                <span>{EVENT_LABEL[ev]?.label ?? ev}</span>
              </label>
            ))}
          </div>
          <div className="row">
            <label className="param-label">Minimum finding severity</label>
            <select value={minSev} onChange={(e) => setMinSev(e.target.value)}>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <span className="grow" />
            <button onClick={create} disabled={busy || !name.trim() || !url.trim() || picked.length === 0}>
              {busy ? "Adding…" : "Add channel"}
            </button>
          </div>
        </div>
      )}

      {channels.length === 0 ? (
        <div className="empty">
          <p>No channels yet. Scans still record every change — nobody is told about them.</p>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Kind</th><th>Destination</th><th>Events</th><th>Min severity</th><th>Enabled</th><th></th></tr></thead>
            <tbody>
              {channels.map((c) => (
                <tr key={c.id} style={{ opacity: c.enabled ? 1 : 0.55 }}>
                  <td>{c.name}</td>
                  <td className="muted">{c.kind}</td>
                  <td className="mono muted">{c.url}</td>
                  <td>
                    <div className="row" style={{ margin: 0, gap: 4, flexWrap: "wrap" }}>
                      {c.events.map((ev) => <span key={ev} className="pill" title={EVENT_LABEL[ev]?.hint}>{EVENT_LABEL[ev]?.label ?? ev}</span>)}
                    </div>
                  </td>
                  <td><span className={"sev-" + c.min_severity}>{c.min_severity}</span></td>
                  <td>
                    <label className="param-toggle">
                      <input type="checkbox" checked={c.enabled} onChange={(e) => toggle(c.id, e.target.checked)} />
                      <span className="muted">{c.enabled ? "on" : "off"}</span>
                    </label>
                  </td>
                  <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                    <button className="ghost sm" onClick={() => test(c.id, c.name)}>Send test</button>
                    <button className="danger sm" style={{ marginLeft: 6 }} onClick={() => remove(c.id, c.name)}>delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="section-title">Recent deliveries</div>
      {(deliveries ?? []).length === 0 ? (
        <div className="empty">Nothing sent yet.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>When</th><th>Channel</th><th>Run</th><th>Events</th><th>Status</th></tr></thead>
            <tbody>
              {(deliveries ?? []).map((d) => (
                <tr key={d.id}>
                  <td className="muted">{new Date(d.sent_at).toLocaleString()}</td>
                  <td>{d.channel}</td>
                  <td className="mono muted">{d.run_id ? d.run_id.slice(0, 8) : "test"}</td>
                  <td className="muted">{d.events}</td>
                  <td>
                    <span className={"badge" + (d.status === "sent" ? " b-open" : d.status === "failed" ? " b-gone" : "")}>{d.status}</span>
                    {d.error && <div className="sev-high" style={{ fontSize: 11.5 }}>{d.error}</div>}
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
