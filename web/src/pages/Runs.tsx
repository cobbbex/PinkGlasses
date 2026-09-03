import { Fragment, useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, Run, RunTarget, RunActivity } from "../api";
import { Badge, useToast, Modal } from "../components/ui";
import ScanSettings from "../components/ScanSettings";

// What each profile actually does, not what it sounds like. The difference
// between them is narrow and worth stating precisely: passive changes which
// stages run at all, deep only changes how the port scan behaves.
const PROFILES = [
  {
    id: "passive",
    label: "Passive",
    desc: "Public sources only — certificate transparency, passive DNS and the API providers you have keys for — then resolution and ASN enrichment. Nothing is sent to the targets themselves, so it runs against any target, authorized or not.",
    note: "No port scan, no web probing, no brute force.",
  },
  {
    id: "standard",
    label: "Standard",
    desc: "The whole pipeline at everyday settings: passive discovery and subdomain brute force, the top 100 ports with service versions, web probing and technology detection, screenshots, and directory search.",
    note: "Sends traffic to the target, so only targets carrying an active authorization are scanned — the rest are skipped and reported as such.",
  },
  {
    id: "deep",
    label: "Deep",
    desc: "Standard, with the port scan opened up: all 65,535 ports swept rather than the top 100, and nmap running its aggressive fingerprint (-A) instead of plain version detection.",
    note: "Hours rather than minutes, and unmistakable in anyone's logs. The stages are the same as Standard — only the port scan changes.",
  },
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
            <thead><tr>
              <th>Started</th><th>Target</th><th>Profile</th>
              <th style={{ width: 190 }}>Progress</th><th>Status</th><th></th>
            </tr></thead>
            <tbody>
              {(runs ?? []).map((r) => (
                <Fragment key={r.id}>
                  <tr style={{ cursor: "pointer" }} onClick={() => setOpen(open === r.id ? "" : r.id)}>
                    <td className="muted">{new Date(r.created_at).toLocaleString()}</td>
                    <td className="mono"><TargetLabel run={r} /></td>
                    <td>{r.profile}</td>
                    <td><RunProgress run={r} /></td>
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
                    <tr><td colSpan={6} style={{ background: "var(--bg)" }}><RunDetail runID={r.id} /></td></tr>
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
  // Explicitly chosen lists. Empty is the normal case and means "whatever the
  // registry marks default", so a plain scan needs no wordlist knowledge.
  const [wordlistIDs, setWordlistIDs] = useState<string[]>([]);
  // Which tunnel this run leaves through. Empty means the worker's own address.
  const [vpnID, setVpnID] = useState("");
  const { data: vpn } = useQuery({
    queryKey: ["vpn", scopeID], queryFn: () => api.vpnConfigs(scopeID),
  });

  async function start() {
    setBusy(true);
    try {
      await api.createRun(scopeID, {
        profile,
        all: true,
        ...(presetID ? { profile_id: presetID } : {}),
        ...(Object.keys(params).length ? { params } : {}),
        ...(wordlistIDs.length ? { wordlist_ids: wordlistIDs } : {}),
        ...(vpnID ? { vpn_config_id: vpnID } : {}),
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

  const listChoices = wordlistIDs.length;

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
            <div className="hint muted" style={{ marginTop: 2 }}>{p.note}</div>
          </span>
        </label>
      ))}

      {(vpn?.configs.length ?? 0) > 0 && (
        <div className="row" style={{ marginTop: 10 }}>
          <label className="param-label" style={{ minWidth: 0 }}>Scan from</label>
          <select value={vpnID} onChange={(e) => setVpnID(e.target.value)} style={{ minWidth: 220 }}>
            <option value="">The worker's own address</option>
            {vpn!.configs.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name} ({c.kind}{c.endpoint ? ` · ${c.endpoint}` : ""})
              </option>
            ))}
          </select>
          {vpnID && (
            <span className="hint muted">
              Runs only on a worker that can build the tunnel, and only if its address
              actually changes.
            </span>
          )}
        </div>
      )}

      <div className="manual-bar">
        <button className="ghost sm" onClick={() => setManual((m) => !m)}>
          {manual ? "▾ Hide manual setup" : "▸ Manual setup"}
        </button>
        <span className="muted" style={{ fontSize: 12 }}>
          {overrides > 0 || listChoices > 0
            ? [
                overrides > 0 && `${overrides} tool setting${overrides === 1 ? "" : "s"} overridden`,
                listChoices > 0 && `${listChoices} wordlist${listChoices === 1 ? "" : "s"} chosen`,
              ].filter(Boolean).join(" · ")
            : "Using default parameters and wordlists for every tool"}
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
            wordlistIDs={wordlistIDs}
            onWordlistsChange={setWordlistIDs}
          />
        </div>
      )}
    </Modal>
  );
}

/**
 * What a run is scanning. A run can cover hundreds of targets, so the row shows
 * the first few and says how many more there are; the expanded view lists them
 * all with their own progress.
 */
function TargetLabel({ run }: { run: Run }) {
  const names = run.targets ?? [];
  if (names.length === 0) {
    return <span className="muted">planning…</span>;
  }
  const extra = (run.target_count ?? names.length) - names.length;
  return (
    <span title={names.join(", ") + (extra > 0 ? ` and ${extra} more` : "")}>
      {names.join(", ")}
      {extra > 0 && <span className="muted"> +{extra}</span>}
    </span>
  );
}

/**
 * Task progress for the whole run. Failed tasks count as finished — the run has
 * dealt with them — but are called out separately, because a bar at 100% hides
 * whether everything worked.
 */
function RunProgress({ run }: { run: Run }) {
  const total = run.tasks_total ?? 0;
  const done = run.tasks_done ?? 0;
  const failed = run.tasks_failed ?? 0;
  if (total === 0) {
    return <span className="muted">—</span>;
  }
  const pct = Math.round((100 * (done + failed)) / total);
  return (
    <div className="row" style={{ margin: 0, gap: 8 }}>
      <div className="bar" style={{ flex: 1 }}><span style={{ width: pct + "%" }} /></div>
      <span className="muted" style={{ fontSize: 12, whiteSpace: "nowrap" }}>
        {done}/{total}
        {failed > 0 && <span className="sev-high"> ✕{failed}</span>}
      </span>
    </div>
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
