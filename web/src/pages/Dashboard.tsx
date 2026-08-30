import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, Target } from "../api";
import { Modal, Stat, useToast } from "../components/ui";

export default function Dashboard({ scopeID }: { scopeID: string }) {
  const { data: sum } = useQuery({ queryKey: ["summary", scopeID], queryFn: () => api.summary(scopeID) });
  const { data: targets, refetch } = useQuery({ queryKey: ["targets", scopeID], queryFn: () => api.targets(scopeID) });
  const [open, setOpen] = useState(false);

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>Dashboard</h2>
          <div className="sub">Your external attack surface at a glance.</div>
        </div>
      </div>

      <div className="cards">
        <Stat n={sum?.domains} label="Domains" />
        <Stat n={sum?.ips} label="Hosts" />
        <Stat n={sum?.services} label="Services" />
        <Stat n={sum?.open_findings} label="Open findings" />
      </div>

      <div className="page-head">
        <div className="section-title" style={{ margin: 0 }}>Scope targets</div>
        <button onClick={() => setOpen(true)}>+ Add targets</button>
      </div>

      {(targets ?? []).length === 0 ? (
        <div className="empty">
          <p>No targets yet. Add a domain or CIDR to start discovering.</p>
          <button onClick={() => setOpen(true)}>Add your first target</button>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Value</th><th>Kind</th><th>Mode</th><th>Tags</th></tr></thead>
            <tbody>
              {(targets ?? []).map((t: Target) => (
                <tr key={t.id}>
                  <td className="mono">{t.value}</td>
                  <td className="muted">{t.kind}</td>
                  <td>
                    {t.mode === "active"
                      ? <span className="badge b-active">active</span>
                      : <span className="badge">{t.mode.replace("_", " ")}</span>}
                  </td>
                  <td>{(t.tags ?? []).map((x) => <span key={x} className="pill">{x}</span>)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <AddTargets scopeID={scopeID} open={open} onClose={() => setOpen(false)} onDone={refetch} />
    </div>
  );
}

function AddTargets({
  scopeID, open, onClose, onDone,
}: { scopeID: string; open: boolean; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [text, setText] = useState("");
  const [active, setActive] = useState(false);
  const [tags, setTags] = useState("");
  const [busy, setBusy] = useState(false);

  const values = text.split(/[\s,]+/).map((v) => v.trim()).filter(Boolean);

  async function save() {
    setBusy(true);
    try {
      await api.addTarget(scopeID, {
        values,
        mode: active ? "active" : "passive_only",
        authorize: active,
        tags: tags.split(/[\s,]+/).filter(Boolean),
      });
      toast("ok", `Added ${values.length} target${values.length === 1 ? "" : "s"}`);
      setText(""); setTags(""); setActive(false);
      onDone(); onClose();
    } catch (e) {
      toast("err", String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Add scope targets" open={open} onClose={onClose}
      footer={<>
        <button className="ghost" onClick={onClose}>Cancel</button>
        <button onClick={save} disabled={busy || !values.length}>
          {busy ? "Saving…" : `Add ${values.length || ""} target${values.length === 1 ? "" : "s"}`}
        </button>
      </>}
    >
      <div className="field">
        <label>Domains, IPs or CIDRs</label>
        <textarea rows={5} style={{ width: "100%" }} value={text} onChange={(e) => setText(e.target.value)}
          placeholder={"example.com\nshop.example.com\n203.0.113.0/24"} />
        <div className="hint">One per line, or comma-separated. The kind is detected automatically.</div>
      </div>

      <div className="field">
        <label>Tags (optional)</label>
        <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="production, eu" />
        <div className="hint">Tags let you launch a batch scan over just that group.</div>
      </div>

      <div className="check">
        <input id="auth" type="checkbox" checked={active} onChange={(e) => setActive(e.target.checked)} />
        <label htmlFor="auth" style={{ textTransform: "none", letterSpacing: 0, fontSize: 13, color: "var(--fg)" }}>
          <strong>Authorize active scanning</strong>
          <div className="hint" style={{ marginTop: 3 }}>
            Leave unchecked for passive-only discovery (CT logs, DNS, public APIs — no packets
            sent to the target). Only tick this for infrastructure you are authorized to scan.
          </div>
        </label>
      </div>
    </Modal>
  );
}
