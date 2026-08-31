import { Fragment, useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, RunTarget, RunActivity } from "../api";
import { Badge, useToast, Modal } from "../components/ui";
import ScanSettings from "../components/ScanSettings";

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

  // Manual setup: per-tool parameter overrides, off by default so the common
  // case stays a two-click scan.
  // A scan over a scope with no targets can only fail, so the modal checks
  // first and offers the fix rather than letting the request 400.
  const { data: targets } = useQuery({
    queryKey: ["targets", scopeID], queryFn: () => api.targets(scopeID),
  });
  const usable = (targets ?? []).filter((t) => t.mode !== "exclude");

  const [manual, setManual] = useState(false);
  const [params, setParams] = useState<Record<string, string>>({});
  const [presetID, setPresetID] = useState("");

  async function start() {
    setBusy(true);
    try {
      await api.createRun(scopeID, {
        profile,
        all: true,
        ...(presetID ? { profile_id: presetID } : {}),
        ...(Object.keys(params).length ? { params } : {}),
      });
      toast("ok", `${profile} scan started`);
      onDone();
      onClose();
    } catch (e) {
      toast("err", String(e));
    } finally {
      setBusy(false);
    }
  }

  function close() {
    setManual(false);
    onClose();
  }

  const overrides = Object.keys(params).length;

  return (
    <Modal
      title="Start a scan" open={open} onClose={close} wide={manual}
      footer={<>
        <button className="ghost" onClick={close}>Cancel</button>
        <button onClick={start} disabled={busy || usable.length === 0}>
          {busy ? "Starting…" : `Start scan${usable.length ? ` (${usable.length} target${usable.length === 1 ? "" : "s"})` : ""}`}
        </button>
      </>}
    >
      {usable.length === 0 && (
        <div className="empty" style={{ marginBottom: 14, borderColor: "var(--warn)" }}>
          <p style={{ marginTop: 0 }}>
            This scope has no targets yet, so there is nothing to scan.
          </p>
          <p className="muted" style={{ fontSize: 13, marginBottom: 0 }}>
            A scope is a container — naming it after a domain does not add that domain.
            Add a domain or CIDR on the <strong>Dashboard</strong> first.
          </p>
        </div>
      )}
      <p className="muted" style={{ marginTop: 0 }}>
        The run covers every non-excluded target in this company. Targets without an
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

      <div className="manual-bar">
        <button className="ghost sm" onClick={() => setManual((m) => !m)}>
          {manual ? "▾ Hide manual setup" : "▸ Manual setup"}
        </button>
        <span className="muted" style={{ fontSize: 12 }}>
          {overrides > 0
            ? `${overrides} tool setting${overrides === 1 ? "" : "s"} overridden`
            : "Using default parameters for every tool"}
        </span>
      </div>

      {manual && (
        <div className="manual-panel">
          <ScanSettings
            scopeID={scopeID}
            values={params}
            onChange={setParams}
            presetID={presetID}
            onPresetChange={setPresetID}
          />
        </div>
      )}
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
    <>
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
    <RunWorkers runID={runID} />
    </>
  );
}

/**
 * Live view of which workers are on this scan and what each is doing. Answers
 * the question a progress bar cannot: is anything actually running, and where?
 */
function RunWorkers({ runID }: { runID: string }) {
  const [act, setAct] = useState<RunActivity | null>(null);

  useEffect(() => {
    let live = true;
    const poll = () => api.runActivity(runID).then((a) => live && setAct(a)).catch(() => {});
    poll();
    const iv = setInterval(poll, 3000);
    return () => { live = false; clearInterval(iv); };
  }, [runID]);

  if (!act) return null;
  const active = act.tasks.filter((t) => t.status === "running" || t.status === "leased");
  const recent = act.tasks.filter((t) => t.status === "done" || t.status === "failed").slice(0, 8);

  return (
    <div style={{ margin: "14px 0 6px" }}>
      <div className="section-title" style={{ marginTop: 0 }}>Pipeline</div>
      <div className="row" style={{ gap: 8 }}>
        {act.stages.length === 0 && <span className="muted">No tasks planned yet.</span>}
        {act.stages.map((st) => (
          <span key={st.stage} className="pill" title={
            `${st.done} done · ${st.active} running · ${st.pending} queued · ${st.failed} failed`}>
            {st.stage}
            <span className="muted"> {st.done}/{st.done + st.active + st.pending + st.failed}</span>
            {st.active > 0 && <span style={{ color: "var(--accent)" }}> ●</span>}
            {st.failed > 0 && <span className="sev-high"> ✕{st.failed}</span>}
          </span>
        ))}
      </div>

      <div className="section-title">Workers on this scan</div>
      {act.workers.length === 0 ? (
        <div className="muted" style={{ fontSize: 13 }}>
          No worker has picked up a task yet.
        </div>
      ) : (
        <div className="row" style={{ gap: 8 }}>
          {act.workers.map((w) => (
            <span key={w.name} className="pill">
              <strong>{w.name}</strong>
              <span className="muted"> {w.kind} · {w.running} running · {w.done} done</span>
              {w.stages.length > 0 && <span style={{ color: "var(--accent)" }}> — {w.stages.join(", ")}</span>}
            </span>
          ))}
        </div>
      )}

      <div className="section-title">Activity</div>
      {active.length === 0 && recent.length === 0 ? (
        <div className="muted" style={{ fontSize: 13 }}>Nothing running.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Stage</th><th>Target</th><th>Worker</th><th>Status</th><th>Took</th></tr></thead>
            <tbody>
              {[...active, ...recent].map((t) => (
                <tr key={t.task_id}>
                  <td>{t.stage}</td>
                  <td className="mono">{t.target || "—"}</td>
                  <td className="mono">{t.worker_name ?? <span className="muted">unassigned</span>}</td>
                  <td>
                    <Badge status={t.status} />
                    {t.attempts > 1 && <span className="muted"> retry {t.attempts}</span>}
                    {t.error && <div className="sev-high" style={{ fontSize: 11.5 }}>{t.error}</div>}
                  </td>
                  <td className="muted">{took(t.started_at, t.finished_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// took renders how long a task has been running, or how long it took.
function took(start?: string | null, end?: string | null) {
  if (!start) return "—";
  const a = new Date(start).getTime();
  const b = end ? new Date(end).getTime() : Date.now();
  const s = Math.max(0, Math.round((b - a) / 1000));
  if (s < 60) return s + "s";
  const m = Math.floor(s / 60);
  return m < 60 ? `${m}m ${s % 60}s` : `${Math.floor(m / 60)}h ${m % 60}m`;
}
