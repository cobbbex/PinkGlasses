import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, Worker, FleetView, User, atLeast } from "../api";
import { Link } from "react-router-dom";
import { Modal, Stat, Badge, useToast, Spinner, InfoDot } from "../components/ui";

// Fleet management. Two kinds of worker, told apart by how they enrol:
//   local — containers beside the control plane. The standing one runs the
//           passive stages; a run's own fleet appears here while it runs and
//           is destroyed with the run. Nobody creates these by hand.
//   vps   — a rented box you enrol, an exit for active scans with its own
//           address and a true outside-in view.
export default function Fleet({ me }: { me: User }) {
  const toast = useToast();
  const { data: workers, refetch, isLoading } = useQuery({
    queryKey: ["workers"], queryFn: () => api.workers(), refetchInterval: 5000,
  });
  const [vpsOpen, setVpsOpen] = useState(false);

  const local = (workers ?? []).filter((w) => w.kind === "local");
  const remote = (workers ?? []).filter((w) => w.kind !== "local");

  async function act(w: Worker, action: string) {
    try {
      await api.workerAction(w.id, action);
      toast("ok", `${w.name}: ${action}`);
      refetch();
    } catch (e) {
      toast("err", String(e));
    }
  }

  const [pendingDelete, setPendingDelete] = useState<Worker | null>(null);

  async function confirmDelete() {
    const w = pendingDelete;
    if (!w) return;
    setPendingDelete(null);
    try {
      const r = await api.deleteWorker(w.id);
      toast(r.warning ? "err" : "ok", r.warning ?? `Removed ${w.name}`);
      refetch();
    } catch (e) {
      toast("err", String(e));
    }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>Workers</h2>
          <div className="sub">
            Local workers are containers beside the control plane: the standing one runs
            passive discovery, and a run's own workers appear here while it runs. Remote
            workers are boxes you enrol, and the exits an active scan can leave from.
          </div>
        </div>
        {isLoading && <Spinner />}
      </div>

      <div className="cards">
        <Stat n={local.length} label="Local workers" hint="Standing worker for passive stages, plus any run's own fleet while it runs" />
        <Stat n={remote.length} label="External (VPS)" hint="Enrolled boxes · an exit for active scans" />
        <Stat n={(workers ?? []).filter((w) => w.status === "active").length} label="Active" hint="Currently leasing work" />
        <Stat n={(workers ?? []).reduce((a, w) => a + w.running_tasks, 0)} label="Running tasks" />
      </div>

      <div className="row">
        <button onClick={() => setVpsOpen(true)}>+ Add VPS worker</button>
      </div>

      <VPSModal open={vpsOpen} onClose={() => setVpsOpen(false)} />

      <RunFleets />

      <WorkerTable title="Local workers" workers={local} act={act} onDelete={setPendingDelete} />
      <WorkerTable title="External (VPS) workers" workers={remote} act={act} onDelete={setPendingDelete} />
      <Pools me={me} />

      <Modal
        title="Remove worker" open={!!pendingDelete} onClose={() => setPendingDelete(null)}
        footer={<>
          <button className="ghost" onClick={() => setPendingDelete(null)}>Cancel</button>
          <button className="danger" onClick={confirmDelete}>Remove worker</button>
        </>}
      >
        <p style={{ marginTop: 0 }}>
          Remove <strong>{pendingDelete?.name}</strong> from the fleet?
        </p>
        <p className="muted" style={{ fontSize: 13 }}>
          {pendingDelete?.kind === "local"
            ? "Its container is destroyed and its credential revoked. Any task it is running now is re-queued and picked up by another worker."
            : "Its credential is revoked, so the agent on that VPS will fail to reconnect and exit. Remember to also stop the container on the box itself."}
        </p>
      </Modal>
    </div>
  );
}

/* ---------- enroll a VPS ---------- */

function VPSModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const toast = useToast();
  const [name, setName] = useState("vps-1");
  const [cmd, setCmd] = useState("");
  const [busy, setBusy] = useState(false);

  async function mint() {
    setBusy(true);
    try {
      const r = await api.enrollToken({ kind: "vps", name, ttl_mins: 60 });
      setCmd(r.install_command);
    } catch (e) {
      toast("err", String(e));
    } finally {
      setBusy(false);
    }
  }

  function close() { setCmd(""); onClose(); }

  return (
    <Modal
      title="Add an external (VPS) worker" open={open} onClose={close}
      footer={cmd
        ? <button className="ghost" onClick={close}>Done</button>
        : (<>
            <button className="ghost" onClick={close}>Cancel</button>
            <button onClick={mint} disabled={busy || !name}>{busy ? "Minting…" : "Generate install command"}</button>
          </>)}
    >
      {!cmd ? (
        <div className="field">
          <label>Worker name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="vps-hetzner-fsn1" />
          <div className="hint">
            A VPS worker adds egress diversity and a true outside-in view: your own
            firewall and egress filtering quietly shape what a local worker sees. It
            connects outbound only (no inbound ports, works behind NAT); approve it here
            once it appears.
          </div>
        </div>
      ) : (
        <>
          <p style={{ marginTop: 0 }}>Run this on the VPS (needs Docker). The token is single-use and expires in 1 hour:</p>
          <div className="pre">{cmd}</div>
          <button className="ghost sm" style={{ marginTop: 10 }}
            onClick={() => { navigator.clipboard?.writeText(cmd); toast("ok", "Copied"); }}>
            Copy command
          </button>
        </>
      )}
    </Modal>
  );
}

/* ---------- table ---------- */

/* ---------- inline help ---------- */

function StatusHelp() {
  return (
    <InfoDot title="Worker statuses">
      <dl>
        <dt>pending</dt>
        <dd>Enrolled but not yet approved. Leases no work until you approve it.</dd>
        <dt>active</dt>
        <dd>Healthy and taking scan tasks.</dd>
        <dt>draining</dt>
        <dd>Finishing its current tasks, taking no new ones. A planned wind-down.</dd>
        <dt>quarantined</dt>
        <dd>Cut off after suspicious behaviour. Kept on the list so you can investigate.</dd>
        <dt>stale</dt>
        <dd>Stopped sending heartbeats. It returns to active by itself if it reconnects.</dd>
        <dt>revoked</dt>
        <dd>Credential invalidated; the agent fails its next connect and exits.</dd>
      </dl>
    </InfoDot>
  );
}

function ActionsHelp() {
  return (
    <InfoDot title="What these actions do">
      <dl>
        <dt>approve</dt>
        <dd>Lets a newly enrolled worker start taking scan tasks.</dd>
        <dt>drain — planned, graceful</dt>
        <dd>
          Stops new work but lets running tasks finish, so you can decommission, reboot or
          patch a worker without breaking a scan in progress. Reverse it with resume.
        </dd>
        <dt>quarantine — unplanned, defensive</dt>
        <dd>
          Cuts the worker off immediately when it may be compromised: no new work and no
          control channel. Its record and history are kept so you can see what it reported.
          Applied automatically if a worker reports assets outside its assigned target.
        </dd>
        <dt>resume</dt>
        <dd>Returns a draining or stale worker to active.</dd>
        <dt>remove</dt>
        <dd>
          Deletes the worker. A local worker's container is destroyed first, otherwise it
          would re-enroll and reappear.
        </dd>
      </dl>
    </InfoDot>
  );
}

function WorkerTable({
  title, workers, act, onDelete,
}: {
  title: string; workers: Worker[];
  act: (w: Worker, a: string) => void;
  onDelete: (w: Worker) => void;
}) {
  return (
    <>
      <div className="section-title">{title}</div>
      {workers.length === 0 ? (
        <div className="empty">None enrolled.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Status<StatusHelp /></th>
                <th>Egress IP</th><th>Capabilities</th>
                <th>Tools</th><th>Load</th>
                <th>Actions<ActionsHelp /></th>
              </tr>
            </thead>
            <tbody>
              {workers.map((w) => (
                <tr key={w.id}>
                  <td>
                    {w.name}
                    {w.run_scoped && (
                      <span
                        className="pill"
                        style={{ marginLeft: 6, fontSize: 10.5 }}
                        title="This worker belongs to one scan. It takes that scan's tasks only, and is destroyed when the scan ends."
                      >one scan</span>
                    )}
                    <div className="muted" style={{ fontSize: 11.5 }}>{w.kind} · {w.agent_version || "—"}</div>
                  </td>
                  <td><Badge status={w.status} /></td>
                  <td className="mono">{w.egress_ip ?? "—"}</td>
                  <td>{(w.capabilities ?? []).map((c) => <span key={c} className="pill">{c}</span>)}</td>
                  <td className="muted" style={{ fontSize: 11.5 }}>
                    {Object.keys(w.tools ?? {}).slice(0, 4).join(", ") || "—"}
                  </td>
                  <td className="muted">{w.running_tasks}/{w.max_concurrency}</td>
                  <td>
                    {w.status === "pending" && <button className="sm" onClick={() => act(w, "approve")}>approve</button>}
                    {w.status === "active" && <button className="ghost sm" onClick={() => act(w, "drain")}>drain</button>}
                    {(w.status === "draining" || w.status === "stale") &&
                      <button className="sm" onClick={() => act(w, "resume")}>resume</button>}
                    {w.status !== "quarantined" && w.status !== "revoked" &&
                      <button className="ghost sm" style={{ marginLeft: 6 }} onClick={() => act(w, "quarantine")}>quarantine</button>}
                    <button className="danger sm" style={{ marginLeft: 6 }}
                      title="Remove this worker from the fleet"
                      onClick={() => onDelete(w)}>remove</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

/**
 * Runs' own containers. The VPN gateway never enrols — it only holds the
 * tunnel — so it is not a worker and appears nowhere else; this is where a
 * person sees that an active scan is leaving through the VPN, from which
 * address, with how many workers beside it.
 */
function RunFleets() {
  const { data: fleets } = useQuery({ queryKey: ["fleets"], queryFn: () => api.fleets(), refetchInterval: 5000 });
  const list = fleets ?? [];
  const live = list.filter((f) => f.status === "requested" || f.status === "up");
  const past = list.filter((f) => f.status !== "requested" && f.status !== "up");
  const when = (d?: string | null) => d ? new Date(d).toLocaleString([], { dateStyle: "short", timeStyle: "short" }) : "—";
  const gateway = (f: FleetView) => {
    const cfg = f.vpn_name ? `${f.vpn_name} (${f.vpn_kind})` : "no VPN";
    switch (f.status) {
      case "requested": return <><span className="badge b-queued">starting</span> <span className="muted">{cfg}{f.error ? ` · ${f.error}` : ""}</span></>;
      case "up": return <><span className="badge b-open">tunnel up</span> <span className="muted">{cfg}</span>{f.egress_ip && <> · exit <span className="mono">{f.egress_ip}</span></>}</>;
      case "failed": return <><span className="badge b-failed">failed</span> <span className="muted">{cfg}</span>{f.error && <div className="sev-high wrap" style={{ fontSize: 11.5 }}>{f.error}</div>}</>;
      default: return <><span className="badge">destroyed</span> <span className="muted">{cfg}</span>{f.egress_ip && <> · was <span className="mono">{f.egress_ip}</span></>}</>;
    }
  };
  const row = (f: FleetView) => (
    <tr key={f.run_id}>
      <td>
        <Link to="/runs" className="mono" title="Open Scan runs">{f.run_id.slice(0, 8)}</Link>
        <div className="muted" style={{ fontSize: 12 }}>{f.company} · {f.profile} · {f.run_status}</div>
      </td>
      <td>{gateway(f)}</td>
      <td>
        {f.workers} worker{f.workers === 1 ? "" : "s"}{f.workers_auto ? <span className="muted"> · auto</span> : null}
        {f.worker_names.length > 0 && <div className="mono muted" style={{ fontSize: 11.5 }}>{f.worker_names.join(", ")}</div>}
      </td>
      <td className="muted" style={{ fontSize: 12.5 }}>
        started {when(f.created_at)}{f.ready_at && <>, up {when(f.ready_at)}</>}{f.torn_down_at && <>, destroyed {when(f.torn_down_at)}</>}
      </td>
    </tr>
  );
  return (
    <div style={{ marginTop: 18 }}>
      <div className="section-title" style={{ marginBottom: 4 }}>Run fleets</div>
      <div className="sub" style={{ marginBottom: 8 }}>
        A run that scans from local workers gets a VPN gateway and workers of its own, built when it
        starts and destroyed when it ends. The gateway holds the tunnel and never enrols, so it is not a
        worker; this is where it shows. Its workers also appear under Local workers while the run lasts.
      </div>
      {list.length === 0 ? (
        <div className="empty" style={{ padding: 14 }}>No run has had its own fleet in the last day.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Run</th><th>VPN gateway</th><th>Workers</th><th>When</th></tr></thead>
            <tbody>
              {live.map(row)}
              {past.map(row)}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/**
 * The pools, and which of them runs discovery.
 *
 * Discovery — public sources, DNS, enrichment — never touches a target, so it
 * is not an exit choice: it is about where the load sits. On a busy install
 * every company's discovery queues behind the standing workers on this host;
 * marking a pool of enrolled workers moves it onto them. If that pool has no
 * active worker the standing ones take it back, so discovery never stalls.
 */
function Pools({ me }: { me: User }) {
  const toast = useToast();
  const { data: pools, refetch } = useQuery({ queryKey: ["pools"], queryFn: () => api.pools(), refetchInterval: 15000 });
  const admin = atLeast(me.role, "admin");
  async function toggle(id: string, v: boolean) {
    try { await api.setPoolDiscovery(id, v); refetch(); }
    catch (e) { toast("err", String(e).replace(/^Error:\s*/, "")); }
  }
  if (!pools || pools.length === 0) return null;
  return (
    <>
      <div className="section-title">Pools</div>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>Description</th><th>Workers that can scan</th><th>Runs discovery</th></tr></thead>
          <tbody>
            {pools.map((p) => (
              <tr key={p.id}>
                <td><strong>{p.name}</strong>{p.is_default && <span className="pill" style={{ marginLeft: 6 }}>default</span>}</td>
                <td className="muted">{p.description ?? "—"}</td>
                <td className={p.active_workers ? "" : "muted"}>{p.active_workers}</td>
                <td>
                  <label className="param-toggle" style={{ cursor: admin ? "pointer" : "default" }}
                    title={admin
                      ? "Discovery never touches a target; this decides which machines carry it"
                      : "Only an administrator changes this"}>
                    <input type="checkbox" checked={!!p.takes_discovery} disabled={!admin}
                      onChange={(e) => toggle(p.id, e.target.checked)} />
                    <span className="muted">{p.takes_discovery ? "yes" : "no"}</span>
                  </label>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
