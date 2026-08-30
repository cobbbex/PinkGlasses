import { Fragment, useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, RunTarget } from "../api";
import { Badge, useToast, Modal } from "../components/ui";

const PROFILES = [
  { id: "passive", label: "Passive", desc: "CT logs, DNS and public APIs only. No packets are sent to the target — always safe to run." },
  { id: "standard", label: "Standard", desc: "Top-1000 ports, service probing, tech detection and screenshots. Needs authorized targets." },
  { id: "deep", label: "Deep", desc: "Full port range, DNS brute force, directory brute force. Loud and slow." },
];

export default function Runs({ scopeID }: { scopeID: string }) {
  const toast = useToast();
  const { data: runs, refetch } = useQuery({
    queryKey: ["runs", scopeID], queryFn: () => api.runs(scopeID), refetchInterval: 5000,
  });
  const [open, setOpen] = useState("");
  const [launch, setLaunch] = useState(false);

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>Scan runs</h2>
          <div className="sub">One run covers many targets at once; each is tracked independently.</div>
        </div>
        <button onClick={() => setLaunch(true)}>+ New scan</button>
      </div>

      {(runs ?? []).length === 0 ? (
        <div className="empty">
          <p>No runs yet.</p>
          <button onClick={() => setLaunch(true)}>Start your first scan</button>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Started</th><th>Profile</th><th>Status</th><th></th></tr></thead>
            <tbody>
              {(runs ?? []).map((r) => (
                <Fragment key={r.id}>
                  <tr style={{ cursor: "pointer" }} onClick={() => setOpen(open === r.id ? "" : r.id)}>
                    <td className="muted">{new Date(r.created_at).toLocaleString()}</td>
                    <td>{r.profile}</td>
                    <td><Badge status={r.status} /></td>
                    <td style={{ textAlign: "right" }}>
                      {["queued", "planning", "running"].includes(r.status) && (
                        <button className="danger sm" onClick={(e) => {
                          e.stopPropagation();
                          api.cancelRun(r.id).then(() => { toast("ok", "Run cancelled"); refetch(); });
                        }}>cancel</button>
                      )}
                      <span className="muted" style={{ marginLeft: 10 }}>{open === r.id ? "▾" : "▸"}</span>
                    </td>
                  </tr>
                  {open === r.id && (
                    <tr><td colSpan={4} style={{ background: "var(--bg)" }}><RunDetail runID={r.id} /></td></tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <LaunchModal scopeID={scopeID} open={launch} onClose={() => setLaunch(false)} onDone={refetch} />
    </div>
  );
}

function LaunchModal({
  scopeID, open, onClose, onDone,
}: { scopeID: string; open: boolean; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [profile, setProfile] = useState("passive");
  const [busy, setBusy] = useState(false);

  async function start() {
    setBusy(true);
    try {
      await api.createRun(scopeID, { profile, all: true });
      toast("ok", `${profile} scan started`);
      onDone(); onClose();
    } catch (e) {
      toast("err", String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Start a scan" open={open} onClose={onClose}
      footer={<>
        <button className="ghost" onClick={onClose}>Cancel</button>
        <button onClick={start} disabled={busy}>{busy ? "Starting…" : "Start scan"}</button>
      </>}
    >
      <p className="muted" style={{ marginTop: 0 }}>
        The run covers every non-excluded target in this scope. Targets without an
        active-scanning authorization are skipped automatically.
      </p>
      {PROFILES.map((p) => (
        <label key={p.id} className="check" style={{ cursor: "pointer" }}>
          <input type="radio" name="profile" checked={profile === p.id} onChange={() => setProfile(p.id)} />
          <span>
            <strong>{p.label}</strong>
            <div className="hint" style={{ marginTop: 2 }}>{p.desc}</div>
          </span>
        </label>
      ))}
    </Modal>
  );
}

// Per-target progress; live-updated via the run's SSE stream.
function RunDetail({ runID }: { runID: string }) {
  const [targets, setTargets] = useState<RunTarget[]>([]);
  useEffect(() => {
    let live = true;
    const poll = () => api.runTargets(runID).then((t) => live && setTargets(t)).catch(() => {});
    poll();
    const es = new EventSource(`/api/v1/runs/${runID}/events`);
    es.onmessage = () => poll();
    const iv = setInterval(poll, 4000);
    return () => { live = false; es.close(); clearInterval(iv); };
  }, [runID]);

  if (!targets.length) return <div className="muted" style={{ padding: 12 }}>Planning…</div>;

  return (
    <table style={{ margin: "6px 0" }}>
      <thead><tr><th>Target</th><th>Status</th><th>Progress</th></tr></thead>
      <tbody>
        {targets.map((t) => {
          const pct = t.tasks_total ? Math.round((100 * t.tasks_done) / t.tasks_total) : 0;
          return (
            <tr key={t.id}>
              <td className="mono">{t.value}</td>
              <td>
                <Badge status={t.status} />
                {t.skip_reason && <span className="muted"> ({t.skip_reason.replace(/_/g, " ")})</span>}
              </td>
              <td>
                <div className="row" style={{ margin: 0 }}>
                  <div className="bar"><span style={{ width: pct + "%" }} /></div>
                  <span className="muted">{t.tasks_done}/{t.tasks_total}</span>
                </div>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
