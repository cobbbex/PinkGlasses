import { Fragment, useEffect, useState, type MouseEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, Run, RunTarget, RunActivity, RunFleet, Schedule, TaskResult } from "../api";
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
    note: "No port scan, no web probing, no brute force, no vulnerability check.",
  },
  {
    id: "standard",
    label: "Standard",
    desc: "The whole pipeline at everyday settings: passive discovery and subdomain brute force, the top 100 ports with service versions, web probing and technology detection, screenshots, directory search, and a nuclei vulnerability check of every live web endpoint (severity low and up).",
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
  const closeLaunch = () => setLaunch(false);

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
              <th>Started</th><th>By</th><th>Target</th><th>Profile</th>
              <th style={{ width: 190 }}>Progress</th><th>Status</th><th></th>
            </tr></thead>
            <tbody>
              {(runs ?? []).map((r) => (
                <Fragment key={r.id}>
                  <tr style={{ cursor: "pointer" }} onClick={() => setOpen(open === r.id ? "" : r.id)}>
                    <td className="muted">{new Date(r.created_at).toLocaleString()}</td>
                    <td><StartedBy run={r} /></td>
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
                    <tr><td colSpan={7} style={{ background: "var(--bg)" }}><RunDetail runID={r.id} /></td></tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Schedules scopeID={scopeID} />

      <LaunchModal scopeID={scopeID} open={launch} onClose={closeLaunch} onDone={refetch} />
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
  const [confirmDelete, setConfirmDelete] = useState(false);
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
      {!live && (
        <button className="ghost sm" disabled={busy} title="Delete this run and everything it recorded"
          onClick={(e) => { e.stopPropagation(); setConfirmDelete(true); }}>Delete</button>
      )}
      {confirmDelete && (
        <span onClick={(e) => e.stopPropagation()}>
          <Modal
            title="Delete this run?" open onClose={() => setConfirmDelete(false)}
            footer={<>
              <button className="ghost" onClick={() => setConfirmDelete(false)}>Keep it</button>
              <button className="danger" disabled={busy}
                onClick={(e) => { setConfirmDelete(false); act("Delete", () => api.deleteRun(run.id), "Run deleted")(e); }}>
                Delete run
              </button>
            </>}
          >
            <p style={{ marginTop: 0 }}>
              The run from <strong>{new Date(run.created_at).toLocaleString()}</strong> ({run.profile}, {run.status})
              is removed together with everything it recorded:
            </p>
            <DeleteFootprint runID={run.id} />
            <p className="muted" style={{ fontSize: 13, marginBottom: 0 }}>
              The hosts, names, ports and findings themselves stay in the inventory — they belong to
              the company, and other runs may have seen them too. Only this run's record of them goes,
              so a history dot from this run disappears and a finding only this run saw shows no
              observations. This cannot be undone.
            </p>
          </Modal>
        </span>
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
  const { data: vpn } = useQuery({ queryKey: ["vpn"], queryFn: () => api.vpnConfigs() });
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
    const n = Object.keys(sc.params ?? {}).length, w = (sc.wordlist_ids ?? []).length, g = (sc.target_group_ids ?? []).length;
    const parts = [g > 0 && `${g} group${g === 1 ? "" : "s"}`, sc.profile_id && "preset", n > 0 && `${n} setting${n === 1 ? "" : "s"}`, w > 0 && `${w} wordlist${w === 1 ? "" : "s"}`].filter(Boolean);
    return parts.length ? parts.join(" · ") : "all groups · defaults";
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
  const { data: groupsData } = useQuery({
    queryKey: ["target-groups", scopeID], queryFn: () => api.targetGroups(scopeID),
  });
  const usable = (groupsData ?? []).filter((g) => g.targets.length > 0);
  // What to scan: groups. `excluded` holds the ids the person unticked, so a
  // group added while the dialog is open is scanned by default.
  const [excluded, setExcluded] = useState<Set<string>>(new Set());
  const chosen = usable.filter((g) => !excluded.has(g.id));
  const allChosen = chosen.length === usable.length;
  const chosenEntries = chosen.reduce((a, g) => a + g.targets.length, 0);
  const toggleTarget = (id: string) => setExcluded((s) => {
    const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n;
  });

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
  // 0 is Auto: the launcher sizes the fleet from the run's targets. A number
  // is an override, offered under Customize scanning rather than up front.
  const [workerCount, setWorkerCount] = useState(0);
  const { data: pools } = useQuery({ queryKey: ["pools"], queryFn: () => api.pools() });
  const { data: vpn } = useQuery({
    queryKey: ["vpn"], queryFn: () => api.vpnConfigs(),
  });

  async function start() {
    setBusy(true);
    if (chosen.length === 0) { setBusy(false); return; }
    const choices = {
      profile,
      ...(allChosen ? {} : { target_group_ids: chosen.map((g) => g.id) }),
      ...(presetID ? { profile_id: presetID } : {}),
      ...(Object.keys(params).length ? { params } : {}),
      ...(wordlistIDs.length ? { wordlist_ids: wordlistIDs } : {}),
      ...(profile !== "passive"
        ? exit === "local"
          ? { exit, vpn_config_id: vpnID, ...(workerCount > 0 ? { worker_count: workerCount } : {}) }
          : { exit, pool_id: poolID }
        : {}),
    };
    try {
      if (when === "now") {
        await api.createRun(scopeID, { ...choices, ...(allChosen ? { all: true } : {}) });
        toast("ok", `${profile} scan started`);
      } else {
        const at = when === "once" || startLater ? new Date(startAt) : null;
        await api.createSchedule(scopeID, {
          ...choices,
          target_group_ids: allChosen ? [] : chosen.map((g) => g.id),
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
    setExcluded(new Set());
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
        <button onClick={start} disabled={busy || chosen.length === 0 || !exitReady || !startValid}>
          {busy ? (when === "now" ? "Starting…" : "Saving…") : `${verb}${chosen.length ? ` (${chosenEntries} target${chosenEntries === 1 ? "" : "s"})` : ""}`}
        </button>
      </>}
    >
      <div className="param-label" style={{ minWidth: 0, marginBottom: 6 }}>What to scan</div>
      {usable.length === 0 ? (
        <div className="empty" style={{ marginBottom: 10, borderColor: "var(--warn)", textAlign: "left" }}>
          <p style={{ marginTop: 0 }}>This company has no targets yet, so there is nothing to scan.</p>
          <p className="muted" style={{ fontSize: 13, marginBottom: 0 }}>
            A company is a container — naming it after a domain does not add that domain.
            Add a group of domains, IPs or CIDRs on the <strong>Dashboard</strong> first.
          </p>
        </div>
      ) : (
        <>
          <div className="target-pick">
            {usable.map((g) => (
              <label key={g.id} className="target-row" title={g.targets.map((t) => t.value).join(", ")}>
                <input type="checkbox" checked={!excluded.has(g.id)} onChange={() => toggleTarget(g.id)} />
                <strong>{g.name}</strong>
                <span className="muted" style={{ fontSize: 12 }}>
                  {g.targets.length} entr{g.targets.length === 1 ? "y" : "ies"}
                  <span className="mono"> · {g.targets.slice(0, 3).map((t) => t.value).join(", ")}{g.targets.length > 3 ? ", …" : ""}</span>
                </span>
                {g.authorized
                  ? <span className="badge b-active">active</span>
                  : <span className="badge">passive only</span>}
              </label>
            ))}
          </div>
          <div className="row" style={{ marginTop: 6, gap: 10 }}>
            <button className="ghost sm" onClick={() => setExcluded(new Set())} disabled={allChosen}>All</button>
            <button className="ghost sm" onClick={() => setExcluded(new Set(usable.map((g) => g.id)))} disabled={chosen.length === 0}>None</button>
            <span className="muted" style={{ fontSize: 12 }}>
              {allChosen ? "Every group." : `${chosen.length} of ${usable.length} groups.`} Groups without an
              active-scanning authorization are skipped by active stages automatically.
            </span>
          </div>
        </>
      )}
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
                  <span className="muted" style={{ fontSize: 12 }}>
                    {workerCount > 0
                      ? `${workerCount} worker${workerCount === 1 ? "" : "s"}, set under Customize scanning.`
                      : "Workers sized to the targets automatically."}
                  </span>
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
                  : "No pool has an active remote worker. The standing local workers only run passive stages, so they are never an exit. Enrol one under Workers → Add VPS worker."}
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
          {!passive && exit === "local" && (
            <div className="row" style={{ marginBottom: 12, gap: 10 }}>
              <label className="param-label" style={{ minWidth: 0 }}>Run workers</label>
              <select value={String(workerCount)} onChange={(e) => setWorkerCount(Number(e.target.value))}>
                <option value="0">Auto</option>
                {[1, 2, 3, 4, 5, 6, 7, 8].map((n) => <option key={n} value={n}>{n}</option>)}
              </select>
              <span className="muted" style={{ fontSize: 12 }}>
                Auto is one worker, plus one per CIDR /24 or per five targets, at most four. All of a run's
                workers share its tunnel and its target, so more adds noise and RAM rather than speed.
              </span>
            </div>
          )}
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

  const sized = f.workers_auto ? " (sized automatically)" : "";
  const what = f.vpn_config_id
    ? `a VPN gateway and ${f.workers} worker${f.workers === 1 ? "" : "s"}${sized}`
    : `${f.workers} worker${f.workers === 1 ? "" : "s"}${sized}`;
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
            `${st.done} done · ${st.active} running · ${st.pending} queued · ${st.failed} failed` +
            (st.found_kind ? `\n${st.found ?? 0} ${st.found_kind} found` : "") +
            (st.sources && Object.keys(st.sources).length ? "\nby source: " + sourcesText(st.sources) : "")}>
            {st.stage}
            <span className="muted"> {st.done}/{st.done + st.active + st.pending + st.failed}</span>
            {st.found_kind && (st.found ?? 0) > 0 && (
              <span style={{ color: "var(--accent)" }}> · {st.found} {st.found_kind}</span>
            )}
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
            <thead><tr><th>Stage</th><th>Target</th><th>Worker</th><th>Status</th><th>Found</th><th>Took</th></tr></thead>
            <tbody>
              {[...active, ...recent].map((t) => (
                <tr key={t.task_id}>
                  <td>{t.stage}</td>
                  <td className="mono">{t.target || "—"}</td>
                  <td className="mono">{t.worker_name ?? <span className="muted">unassigned</span>}</td>
                  <td>
                    <Badge status={t.status} />
                    {t.attempts > 1 && <span className="muted"> retry {t.attempts}</span>}
                    {t.error && (
                      // A finished task whose text says a lease expired was
                      // redone by a later attempt: a note, not a failure.
                      <div className={t.status === "done" ? "muted" : "sev-high"} style={{ fontSize: 11.5 }}
                           title={t.status === "done" && /lease expired/.test(t.error)
                             ? "An earlier attempt's lease expired — no heartbeat named the task for the lease TTL — and this attempt redid the work. The scheduler and gateway logs say why."
                             : undefined}>
                        {t.status === "done" && /lease expired/.test(t.error) ? "an earlier attempt's lease expired; redone" : t.error}
                      </div>
                    )}
                  </td>
                  <td className="muted" style={{ fontSize: 12.5 }}>{resultText(t.stage, t.result)}</td>
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

// resultText says what a task found, in the unit its stage produces, and
// for discovery stages where the names came from.
function resultText(stage: string, r?: TaskResult | null): string {
  if (!r) return "—";
  const n = (v: number | undefined, one: string, many: string) => `${v ?? 0} ${v === 1 ? one : many}`;
  switch (stage) {
    case "passive_enum":
    case "dns_brute": {
      const base = n(r.names, "name", "names");
      const by = r.sources && Object.keys(r.sources).length ? ` (${sourcesText(r.sources)})` : "";
      return base + by;
    }
    case "dns_resolve":
    case "ip_enrich": return n(r.addresses, "address", "addresses");
    case "port_scan": return n(r.services, "open port", "open ports");
    case "service_probe": return n(r.web_urls, "web endpoint", "web endpoints");
    default: return "—";
  }
}

// sourcesText lists sources by contribution: "crtsh 120, hackertarget 30,
// brute force 37". A subfinder provider drops its prefix; the brute force
// and the seed read as words.
function sourcesText(sources: Record<string, number>): string {
  const label = (s: string) =>
    s === "shuffledns" ? "brute force" : s === "seed" ? "seed" : s.replace(/^subfinder:/, "");
  return Object.entries(sources)
    .sort((a, b) => b[1] - a[1])
    .map(([s, c]) => `${label(s)} ${c}`)
    .join(", ");
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

/** What a run owns, listed with counts, for the delete confirmation. */
function DeleteFootprint({ runID }: { runID: string }) {
  const { data: f, isLoading } = useQuery({ queryKey: ["footprint", runID], queryFn: () => api.runFootprint(runID) });
  if (isLoading || !f) return <div className="muted" style={{ fontSize: 13 }}>Counting what it recorded…</div>;
  const n = (v: number, one: string, many: string) => `${v} ${v === 1 ? one : many}`;
  const items: string[] = [
    n(f.tasks, "task", "tasks") + " — what each worker did, with its results and errors",
    n(f.targets, "target", "targets") + " covered by the run, with their per-target progress",
    n(f.service_observations, "service observation", "service observations") + " — banners, versions, titles, headers and cookie names seen on ports, per site",
    n(f.screenshots, "screenshot", "screenshots") + " — removed from object storage",
    n(f.resolution_records, "resolution record", "resolution records") + " — which address each name pointed at in this run",
    n(f.finding_observations, "finding observation", "finding observations") + " — this run's sightings of paths and nuclei matches (the history dots)",
    n(f.change_events, "change event", "change events") + " — what the differ reported as new, changed or gone after this run",
  ];
  if (f.has_fleet) items.push("the record of the run's own workers and VPN gateway (the containers are already gone)");
  return (
    <ul style={{ margin: "6px 0 10px", paddingLeft: 20, fontSize: 13 }}>
      {items.map((it) => <li key={it} style={{ margin: "2px 0" }}>{it}</li>)}
    </ul>
  );
}

/**
 * Who started a run, and how: the account's name, with a note when it was
 * not a person in the app — an API token (a script or an MCP client) or a
 * schedule, which runs as the account that saved it.
 */
function StartedBy({ run }: { run: Run }) {
  if (!run.started_by) {
    return run.trigger === "scheduled"
      ? <span className="muted" title="Started by a schedule">schedule</span>
      : <span className="muted" title="Recorded before runs kept who started them">—</span>;
  }
  const via = run.started_via === "token" ? "API token"
    : run.started_via === "schedule" ? "schedule"
    : run.started_via === "proxy" ? "sign-in proxy" : "";
  const title = run.started_via === "token"
    ? `Started by ${run.started_by} through an API token — a script or an MCP client`
    : run.started_via === "schedule"
      ? `Started by a schedule ${run.started_by} saved`
      : `Started by ${run.started_by}`;
  return (
    <span title={title} style={{ whiteSpace: "nowrap" }}>
      {run.started_by}
      {via && <span className="muted" style={{ fontSize: 11.5 }}> · {via}</span>}
    </span>
  );
}
