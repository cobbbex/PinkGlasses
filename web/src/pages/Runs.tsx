import { Fragment, useEffect, useState, type MouseEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, Run, RunTarget, RunActivity, RunFleet, Schedule } from "../api";
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
                    <td>
                      {r.profile}
                      {r.trigger === "scheduled" && (
                        <span className="pill" style={{ marginLeft: 6 }} title="Started by a schedule">scheduled</span>
                      )}
                    </td>
                    <td><RunProgress run={r} /></td>
                    <td><Badge status={r.status} /></td>
                    <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                      <RunControls run={r} onChange={refetch} />
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

      <Schedules scopeID={scopeID} />

      <LaunchModal scopeID={scopeID} open={launch} onClose={() => setLaunch(false)} onDone={refetch} />
    </div>
  );
}

/**
 * What a person can do to a run, by where it is. Pause holds it — nothing more
 * is leased, what is in flight finishes, its own fleet stays up — and Resume
 * lets it go on. Stop ends it. Rerun starts a fresh run with the same choices,
 * through the same checks as a new one.
 */
function RunControls({ run, onChange }: { run: Run; onChange: () => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const act = (label: string, fn: () => Promise<unknown>, done: string) => (e: MouseEvent) => {
    e.stopPropagation();
    setBusy(true);
    fn().then(() => { toast("ok", done); onChange(); })
      .catch((err) => toast("err", `${label}: ${String(err).replace(/^Error:\s*/, "")}`))
      .finally(() => setBusy(false));
  };
  const live = ["queued", "planning", "running", "paused"].includes(run.status);
  return (
    <span className="run-controls">
      {run.status === "running" && (
        <button className="ghost sm" disabled={busy} title="Hold this run: nothing more is handed out, what is in flight finishes"
          onClick={act("Pause", () => api.pauseRun(run.id), "Run paused")}>Pause</button>
      )}
      {run.status === "paused" && (
        <button className="sm" disabled={busy} title="Continue where it stopped"
          onClick={act("Resume", () => api.resumeRun(run.id), "Run resumed")}>Resume</button>
      )}
      {live && (
        <button className="danger sm" disabled={busy} title="End this run; unfinished tasks are cancelled"
          onClick={act("Stop", () => api.cancelRun(run.id), "Run stopped")}>Stop</button>
      )}
      {!live && (
        <button className="ghost sm" disabled={busy} title="Start a new run with the same profile, settings, wordlists and exit"
          onClick={act("Rerun", () => api.rerunRun(run.id), "Scan started again with the same settings")}>Rerun</button>
      )}
    </span>
  );
}

/**
 * Scheduled scans for this company — one-offs and recurring. They are made in
 * the Start-a-scan dialog (When → once / repeat), with the same profile, exit
 * and settings a run gets; this table is where they are paused, resumed and
 * removed, and where a refusal is shown rather than lost in a log.
 */
function Schedules({ scopeID }: { scopeID: string }) {
  const toast = useToast();
  const { data: list, refetch } = useQuery({
    queryKey: ["schedules", scopeID], queryFn: () => api.schedules(scopeID),
    refetchInterval: 15000,
  });
  const { data: vpn } = useQuery({ queryKey: ["vpn", scopeID], queryFn: () => api.vpnConfigs(scopeID) });
  const { data: pools } = useQuery({ queryKey: ["pools"], queryFn: () => api.pools() });
  const vpnConfigs = vpn?.configs ?? [];

  async function toggle(sc: Schedule) {
    try { await api.patchSchedule(sc.id, { enabled: !sc.enabled }); refetch(); }
    catch (e) { toast("err", String(e).replace(/^Error:\s*/, "")); }
  }
  async function remove(sc: Schedule) {
    try { await api.deleteSchedule(sc.id); toast("ok", "Schedule removed"); refetch(); }
    catch (e) { toast("err", String(e).replace(/^Error:\s*/, "")); }
  }
  const exitLabel = (sc: Schedule) =>
    sc.profile === "passive" ? "no exit needed"
    : sc.exit === "local" ? `local · ${vpnConfigs.find((c) => c.id === sc.vpn_config_id)?.name ?? "VPN config missing"}`
    : `remote · ${(pools ?? []).find((p) => p.id === sc.pool_id)?.name ?? "pool missing"}`;
  const settings = (sc: Schedule) => {
    const n = Object.keys(sc.params ?? {}).length, w = (sc.wordlist_ids ?? []).length;
    if (!n && !w && !sc.profile_id) return "defaults";
    return [sc.profile_id && "preset", n > 0 && `${n} setting${n === 1 ? "" : "s"}`, w > 0 && `${w} wordlist${w === 1 ? "" : "s"}`]
      .filter(Boolean).join(" · ");
  };
  const when = (d: string) => new Date(d).toLocaleString([], { dateStyle: "short", timeStyle: "short" });

  return (
    <div style={{ marginTop: 26 }}>
      <div className="page-head" style={{ marginBottom: 6 }}>
        <div>
          <div className="section-title" style={{ margin: 0 }}>Scheduled scans</div>
          <div className="sub">
            Made from <strong>+ New scan</strong> → <em>When</em>: once at a time you pick, or repeating
            from hourly to yearly. If the last run is still going when the next is due, that slot
            is skipped rather than stacked.
          </div>
        </div>
      </div>

      {(list ?? []).length === 0 ? (
        <div className="empty">
          <p style={{ marginTop: 0 }}>Nothing scheduled. Every run so far was started by hand.</p>
          <p className="muted" style={{ fontSize: 13, marginBottom: 0 }}>
            History — findings, resolutions, ports — only accumulates if scans recur.
          </p>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>When</th><th>Profile</th><th>Scan from</th><th>Settings</th><th>Last run</th><th>Next run</th><th>Status</th><th></th></tr></thead>
            <tbody>
              {(list ?? []).map((sc) => {
                const once = sc.every_hours === 0;
                const spent = once && !sc.enabled && !!sc.last_run_at;
                return (
                <tr key={sc.id} style={sc.enabled ? undefined : { opacity: 0.55 }}>
                  <td className="mono">{once ? `once · ${when(sc.next_run_at)}` : cadenceLabel(sc.every_hours)}</td>
                  <td>{sc.profile}</td>
                  <td className="muted" style={{ fontSize: 12.5 }}>{exitLabel(sc)}</td>
                  <td className="muted" style={{ fontSize: 12.5 }}>{settings(sc)}</td>
                  <td className="muted">{sc.last_run_at ? when(sc.last_run_at) : "never"}</td>
                  <td className="muted">{sc.enabled ? when(sc.next_run_at) : "—"}</td>
                  <td>
                    {sc.last_error
                      ? <span className="sev-high" title={sc.last_error}>did not start</span>
                      : spent ? <span className="muted">ran</span>
                      : sc.enabled ? <span className="badge b-open">on</span> : <span className="muted">paused</span>}
                    {sc.last_error && <div className="muted wrap" style={{ fontSize: 11.5, marginTop: 3, maxWidth: 420 }}>{sc.last_error}</div>}
                  </td>
                  <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                    {!spent && <button className="ghost sm" onClick={() => toggle(sc)}>{sc.enabled ? "Pause" : "Resume"}</button>}
                    <button className="ghost sm" onClick={() => remove(sc)}>Remove</button>
                  </td>
                </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// The cadences the dialog offers, in hours. Yearly is a plain 365 days: a
// schedule advances from its planned time, so the date stays put.
const CADENCES = [
  { h: 1, label: "every hour" },
  { h: 24, label: "every day" },
  { h: 168, label: "every week" },
  { h: 720, label: "every 30 days" },
  { h: 2160, label: "every 90 days" },
  { h: 8760, label: "every year" },
];
function cadenceLabel(h: number) {
  const c = CADENCES.find((x) => x.h === h);
  if (c) return c.label;
  return h % 24 === 0 ? `every ${h / 24} days` : `every ${h}h`;
}
// A datetime-local value for a Date, in the browser's zone.
function localInput(d: Date) {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

function LaunchModal({
  scopeID, open, onClose, onDone,
}: { scopeID: string; open: boolean; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const qc = useQueryClient();
  const [profile, setProfile] = useState("passive");
  const [busy, setBusy] = useState(false);
  // When: now is a run; once and repeat are schedules carrying the same choices.
  const [when, setWhen] = useState<"now" | "once" | "repeat">("now");
  const [startAt, setStartAt] = useState(() => localInput(new Date(Date.now() + 3600e3)));
  const [startLater, setStartLater] = useState(false);
  const [every, setEvery] = useState(24);
  const [customEvery, setCustomEvery] = useState(false);

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
  // Where the run's active stages leave from. Passive stages never touch the
  // target and always run on the standing workers, so a passive profile needs
  // no exit. Anything else needs exactly one: "local" builds this run its own
  // workers behind a VPN gateway; "remote" binds it to a pool of enrolled
  // workers. There is deliberately no "from this host".
  const [exit, setExit] = useState<"local" | "remote">("local");
  const [vpnID, setVpnID] = useState("");
  const [poolID, setPoolID] = useState("");
  const [workerCount, setWorkerCount] = useState(2);
  const { data: pools } = useQuery({ queryKey: ["pools"], queryFn: () => api.pools() });
  const { data: vpn } = useQuery({
    queryKey: ["vpn", scopeID], queryFn: () => api.vpnConfigs(scopeID),
  });

  async function start() {
    setBusy(true);
    const choices = {
      profile,
      ...(presetID ? { profile_id: presetID } : {}),
      ...(Object.keys(params).length ? { params } : {}),
      ...(wordlistIDs.length ? { wordlist_ids: wordlistIDs } : {}),
      ...(profile !== "passive"
        ? exit === "local"
          ? { exit, vpn_config_id: vpnID, worker_count: workerCount }
          : { exit, pool_id: poolID }
        : {}),
    };
    try {
      if (when === "now") {
        await api.createRun(scopeID, { ...choices, all: true });
        toast("ok", `${profile} scan started`);
      } else {
        const at = when === "once" || startLater ? new Date(startAt) : null;
        await api.createSchedule(scopeID, {
          ...choices,
          every_hours: when === "once" ? 0 : every,
          ...(at ? { start_at: at.toISOString() } : {}),
        });
        qc.invalidateQueries({ queryKey: ["schedules", scopeID] });
        toast("ok", when === "once"
          ? `${profile} scan scheduled for ${at!.toLocaleString([], { dateStyle: "medium", timeStyle: "short" })}`
          : `${profile} scan ${cadenceLabel(every)}${at ? `, first on ${at.toLocaleString([], { dateStyle: "medium", timeStyle: "short" })}` : ", first run within a minute"}`);
      }
      onDone();
      close();
    } catch (e) {
      toast("err", String(e).replace(/^Error:\s*/, ""));
    } finally {
      setBusy(false);
    }
  }
  const startValid = when === "now" || (!(when === "repeat" && !startLater) && !isNaN(new Date(startAt).getTime()) && new Date(startAt).getTime() > Date.now() - 60e3) || (when === "repeat" && !startLater);
  const verb = when === "now" ? "Start scan" : when === "once" ? "Schedule scan" : "Schedule recurring scan";

  function close() {
    setManual(false);
    setWhen("now");
    onClose();
  }

  // What can actually run this scan. Both lists drive the picker and its
  // disabled states, so the reason a scan cannot start is on the screen
  // before the request is refused.
  const vpnConfigs = vpn?.configs ?? [];
  const remotePools = (pools ?? []).filter((p) => p.active_workers > 0);
  const passive = profile === "passive";
  const exitReady = passive
    || (exit === "local" && !!vpnID)
    || (exit === "remote" && !!poolID);

  // Default each list to its first usable entry so the common case is one click.
  useEffect(() => {
    if (!vpnID && vpnConfigs.length) setVpnID(vpnConfigs[0].id);
  }, [vpnConfigs.length]);
  useEffect(() => {
    if (!poolID && remotePools.length) setPoolID(remotePools[0].id);
    // With no VPN but a usable remote pool, remote is the only thing that works.
    if (!vpnConfigs.length && remotePools.length) setExit("remote");
  }, [remotePools.length, vpnConfigs.length]);

  const listChoices = wordlistIDs.length;

  const overrides = Object.keys(params).length;

  return (
    <Modal
      title="Start a scan" open={open} onClose={close} wide xl={manual}
      footer={<>
        <button className="ghost" onClick={close}>Cancel</button>
        <button onClick={start} disabled={busy || usable.length === 0 || !exitReady || !startValid}>
          {busy ? (when === "now" ? "Starting…" : "Saving…") : `${verb}${usable.length ? ` (${usable.length} target${usable.length === 1 ? "" : "s"})` : ""}`}
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

      {!passive && (
        <div style={{ marginTop: 12 }}>
          <div className="param-label" style={{ minWidth: 0, marginBottom: 6 }}>Scan from</div>

          <label className="check" style={{ cursor: vpnConfigs.length ? "pointer" : "default" }}>
            <input
              type="radio" name="exit" checked={exit === "local"}
              disabled={!vpnConfigs.length}
              onChange={() => setExit("local")}
            />
            <span style={{ flex: 1 }}>
              <strong>Local workers behind a VPN</strong>
              <div className="hint" style={{ marginTop: 2 }}>
                {vpnConfigs.length
                  ? "This run gets its own workers and a gateway holding the tunnel; all three are " +
                    "destroyed when it finishes. Everything the scan sends leaves through the VPN."
                  : "Needs a VPN configuration, so the scan never leaves from this host's own address. " +
                    "Add one under VPN."}
              </div>
              {exit === "local" && vpnConfigs.length > 0 && (
                <div className="row" style={{ marginTop: 8, gap: 10 }}>
                  <select value={vpnID} onChange={(e) => setVpnID(e.target.value)} style={{ minWidth: 220 }}>
                    {vpnConfigs.map((c) => (
                      <option key={c.id} value={c.id}>
                        {c.name} ({c.kind}{c.endpoint ? ` · ${c.endpoint}` : ""})
                      </option>
                    ))}
                  </select>
                  <label className="param-label" style={{ minWidth: 0 }}>Workers</label>
                  <input
                    type="number" min={1} max={8} value={workerCount} style={{ width: 64 }}
                    onChange={(e) => setWorkerCount(Math.min(8, Math.max(1, Number(e.target.value) || 1)))}
                  />
                </div>
              )}
            </span>
          </label>

          <label className="check" style={{ cursor: remotePools.length ? "pointer" : "default" }}>
            <input
              type="radio" name="exit" checked={exit === "remote"}
              disabled={!remotePools.length}
              onChange={() => setExit("remote")}
            />
            <span style={{ flex: 1 }}>
              <strong>Remote workers</strong>
              <div className="hint" style={{ marginTop: 2 }}>
                {remotePools.length
                  ? "A pool of workers you enrolled — a VPS, say. The scan leaves from their addresses."
                  : "No pool has an active worker. Enrol one under Workers → Add VPS worker."}
              </div>
              {exit === "remote" && remotePools.length > 0 && (
                <div className="row" style={{ marginTop: 8 }}>
                  <select value={poolID} onChange={(e) => setPoolID(e.target.value)} style={{ minWidth: 220 }}>
                    {remotePools.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name} · {p.active_workers} worker{p.active_workers === 1 ? "" : "s"}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </span>
          </label>

          {!vpnConfigs.length && !remotePools.length && (
            <div className="empty" style={{ textAlign: "left", marginTop: 8, borderColor: "var(--warn)" }}>
              <p style={{ marginTop: 0 }}>
                This scan sends traffic at its targets, and there is nowhere for it to leave from.
              </p>
              <p className="muted" style={{ fontSize: 13, marginBottom: 0 }}>
                Add a VPN configuration under <strong>VPN</strong> to scan from local workers, or
                enrol a remote worker under <strong>Workers</strong>. A <strong>passive</strong> scan
                needs neither — it never touches the target.
              </p>
            </div>
          )}
          <div className="hint muted" style={{ marginTop: 8 }}>
            Passive stages — subdomain discovery, DNS, enrichment — run on the standing workers
            either way; they talk to third-party sources, never to the target.
          </div>
        </div>
      )}

      <div className="when-block">
        <div className="param-label" style={{ minWidth: 0, marginBottom: 6 }}>When</div>
        <label className="check" style={{ cursor: "pointer" }}>
          <input type="radio" name="when" checked={when === "now"} onChange={() => setWhen("now")} />
          <span><strong>Now</strong><div className="hint" style={{ marginTop: 2 }}>One run, starting as soon as its workers are ready.</div></span>
        </label>
        <label className="check" style={{ cursor: "pointer" }}>
          <input type="radio" name="when" checked={when === "once"} onChange={() => setWhen("once")} />
          <span style={{ flex: 1 }}>
            <strong>Once, at a time I pick</strong>
            <div className="hint" style={{ marginTop: 2 }}>A single run, started for you at that time — overnight, say, or after a maintenance window.</div>
            {when === "once" && (
              <div className="row" style={{ marginTop: 8 }}>
                <input type="datetime-local" value={startAt} min={localInput(new Date())} onChange={(e) => setStartAt(e.target.value)} />
              </div>
            )}
          </span>
        </label>
        <label className="check" style={{ cursor: "pointer" }}>
          <input type="radio" name="when" checked={when === "repeat"} onChange={() => setWhen("repeat")} />
          <span style={{ flex: 1 }}>
            <strong>Repeat</strong>
            <div className="hint" style={{ marginTop: 2 }}>
              Runs again on the cadence with these same settings. A slot whose previous run is still going
              is skipped, never stacked; the next time is counted from the planned time, so it does not drift.
            </div>
            {when === "repeat" && (
              <div className="row" style={{ marginTop: 8, gap: 10, flexWrap: "wrap" }}>
                <select value={customEvery ? "custom" : String(every)}
                  onChange={(e) => { if (e.target.value === "custom") setCustomEvery(true); else { setCustomEvery(false); setEvery(Number(e.target.value)); } }}>
                  {CADENCES.map((c) => <option key={c.h} value={c.h}>{c.label}</option>)}
                  <option value="custom">custom…</option>
                </select>
                {customEvery && (
                  <span className="row" style={{ margin: 0, gap: 6 }}>
                    <input type="number" min={1} max={8784} value={every} style={{ width: 80 }}
                      onChange={(e) => setEvery(Math.min(8784, Math.max(1, Number(e.target.value) || 1)))} />
                    <span className="muted" style={{ fontSize: 12 }}>hours</span>
                  </span>
                )}
                <label className="check" style={{ margin: 0, cursor: "pointer" }}>
                  <input type="checkbox" checked={startLater} onChange={(e) => setStartLater(e.target.checked)} />
                  <span>first run at</span>
                </label>
                {startLater
                  ? <input type="datetime-local" value={startAt} min={localInput(new Date())} onChange={(e) => setStartAt(e.target.value)} />
                  : <span className="muted" style={{ fontSize: 12 }}>within a minute of saving</span>}
              </div>
            )}
          </span>
        </label>
      </div>

      <div className="manual-bar">
        <button className="ghost sm chev-btn" onClick={() => setManual((m) => !m)} aria-expanded={manual}>
          <span className={"chev" + (manual ? " open" : "")} aria-hidden="true" />
          {manual ? "Hide customization" : "Customize scanning"}
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
/**
 * What a run's own containers are doing, when it has any.
 *
 * This is the only place a fleet failure is explained: the run row says
 * "failed" and the database has nowhere else to put the reason, so a VPN
 * gateway that never came up would otherwise be a scan that failed silently.
 */
function FleetBanner({ runID }: { runID: string }) {
  const { data } = useQuery({
    queryKey: ["run", runID], queryFn: () => api.run(runID),
    refetchInterval: (q) => {
      const st = (q.state.data as { fleet?: RunFleet } | undefined)?.fleet?.status;
      return st === "requested" || st === "up" ? 4000 : false;
    },
  });
  const f = data?.fleet;
  if (!f) return null;

  const what = f.vpn_config_id
    ? `a VPN gateway and ${f.workers} worker${f.workers === 1 ? "" : "s"}`
    : `${f.workers} worker${f.workers === 1 ? "" : "s"}`;
  const line: Record<RunFleet["status"], string> = {
    requested: f.error ? `Waiting to start ${what}: ${f.error}` : `Starting ${what} for this run…`,
    up: `Running on ${what} brought up for this run.`,
    failed: `This run could not get ${what} of its own.`,
    torn_down: `Ran on ${what} of its own, since destroyed.`,
  };

  return (
    <div
      className="empty"
      style={{
        textAlign: "left", margin: "8px 0", padding: "8px 12px", fontSize: 13,
        borderColor: f.status === "failed" ? "var(--warn)" : undefined,
      }}
    >
      <strong>{line[f.status]}</strong>
      {f.egress_ip && (
        <span className="muted"> Scanning from <span className="mono">{f.egress_ip}</span>.</span>
      )}
      {f.error && f.status !== "requested" && (
        <div className="mono wrap" style={{ marginTop: 6, fontSize: 12 }}>{f.error}</div>
      )}
    </div>
  );
}

function RunDetail({ runID }: { runID: string }) {
  const qc = useQueryClient();
  const [targets, setTargets] = useState<RunTarget[]>([]);
  useEffect(() => {
    let live = true;
    const poll = () => api.runTargets(runID).then((t) => live && setTargets(t)).catch(() => {});
    poll();
    // Events arrive whenever a task, the run or its fleet changes state, raised
    // by database triggers from whichever process made the change. The poll
    // stays as a fallback for a dropped stream, not as the main signal.
    const es = new EventSource(`/api/v1/runs/${runID}/events`);
    es.onmessage = () => { poll(); qc.invalidateQueries({ queryKey: ["run", runID] }); qc.invalidateQueries({ queryKey: ["runs"] }); };
    const iv = setInterval(poll, 30000);
    return () => { live = false; es.close(); clearInterval(iv); };
  }, [runID]);

  // The banner renders before the targets check: a run waiting on containers
  // that will never arrive is exactly the case where "Planning…" alone is a lie.
  if (!targets.length) {
    return (
      <div style={{ padding: 12 }}>
        <FleetBanner runID={runID} />
        <span className="muted">Planning…</span>
      </div>
    );
  }

  return (
    <>
    <FleetBanner runID={runID} />
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
    // Refresh on run events too; the interval is only a fallback now.
    const es = new EventSource(`/api/v1/runs/${runID}/events`);
    es.onmessage = () => poll();
    const iv = setInterval(poll, 30000);
    return () => { live = false; es.close(); clearInterval(iv); };
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
