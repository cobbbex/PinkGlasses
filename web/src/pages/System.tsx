import { useQuery } from "@tanstack/react-query";
import { api, SystemHealth } from "../api";
import { InfoDot, Spinner } from "../components/ui";

const DOT: Record<string, string> = { ok: "var(--ok, #3fb950)", degraded: "var(--warn)", down: "var(--crit)", off: "var(--muted)" };

function Dot({ status }: { status: string }) {
  return <span aria-label={status} style={{ display: "inline-block", width: 9, height: 9, borderRadius: 5,
    background: DOT[status] ?? "var(--muted)", marginRight: 8, verticalAlign: "middle" }} />;
}

function age(s: number): string {
  if (s < 0) return "never";
  if (s < 90) return `${Math.round(s)} s`;
  if (s < 5400) return `${Math.round(s / 60)} min`;
  if (s < 172800) return `${Math.round(s / 3600)} h`;
  return `${Math.round(s / 86400)} d`;
}

/**
 * The install's health, for administrators: every service, every worker's
 * heartbeat, the queue, and the last day's trouble — the first place to look
 * when a scan does not move.
 */
export default function System() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["system-health"], queryFn: () => api.systemHealth(), refetchInterval: 10000,
  });
  if (isLoading) return <Spinner />;
  if (error || !data) return <div className="empty">Could not read the install's health: {String(error)}</div>;
  const h: SystemHealth = data;
  const c = h.counts;
  const headline = { ok: "Everything is up.", degraded: "Up, with something to look at.", down: "Something is down." }[h.status];

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>
            System
            <InfoDot title="What this shows">
              <p style={{ marginTop: 0 }}>Each service of this install, the workers and their heartbeats, the work
                waiting, and the last day's failures. Refreshed every 10 seconds.</p>
              <p className="muted" style={{ marginBottom: 0 }}>The scheduler and the gateway report through the
                database; the rest are probed from here. A heartbeat older than 90 seconds counts as down.</p>
            </InfoDot>
          </h2>
          <div className="sub"><Dot status={h.status} />{headline}
            <span className="muted"> · checked {new Date(h.checked_at).toLocaleTimeString()}</span></div>
        </div>
      </div>

      <div className="cards" style={{ marginBottom: 16 }}>
        <Tile n={c.runs_going} label="Runs going" />
        <Tile n={c.workers_active} label="Workers active" hint={c.workers_stale ? `${c.workers_stale} stale` : undefined} warn={c.workers_active === 0} />
        <Tile n={c.lease_expiries_24h} label="Lease expiries · 24 h" warn={c.lease_expiries_24h > 0} />
        <Tile n={c.failed_runs_24h} label="Failed runs · 24 h" hint={`${c.failed_tasks_24h} failed tasks`} warn={c.failed_runs_24h > 0} />
      </div>

      <div className="section-title">Services</div>
      <div className="table-wrap" style={{ marginBottom: 16 }}>
        <table>
          <tbody>
            {h.components.map((x) => (
              <tr key={x.name}>
                <td style={{ width: 200 }}><Dot status={x.status} /><strong>{x.name}</strong></td>
                <td className="muted" style={{ width: 90 }}>{x.status}</td>
                <td className="wrap">{x.detail}
                  {x.name === "api" && x.extra?.version ? <span className="muted"> · version {String(x.extra.version)}</span> : null}
                  {x.name === "gateway" && x.extra?.detail ? <span className="muted"> · {String((x.extra.detail as Record<string, unknown>).connected_workers ?? 0)} workers connected</span> : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {(h.stranded ?? []).length > 0 && (
        <div className="empty" style={{ textAlign: "left", borderColor: "var(--warn)", marginBottom: 16 }}>
          <strong>Work nobody can pick up.</strong>
          {(h.stranded ?? []).map((s) => (
            <div key={s.RunID + s.Stage} className="mono" style={{ fontSize: 12.5, marginTop: 4 }}>
              run {s.RunID.slice(0, 8)} · {s.Stage} · {s.Tasks} task{s.Tasks === 1 ? "" : "s"} waiting since {new Date(s.Oldest).toLocaleTimeString()}
            </div>
          ))}
          <div className="muted" style={{ fontSize: 12.5, marginTop: 6 }}>No active worker is eligible for these tasks — see "If a run does not move" in the README.</div>
        </div>
      )}

      <div className="section-title">Queue</div>
      {(h.queue ?? []).length === 0 ? <div className="muted" style={{ marginBottom: 16 }}>Nothing waiting.</div> : (
        <div className="table-wrap" style={{ marginBottom: 16 }}>
          <table>
            <thead><tr><th>Stage</th><th>Waiting</th><th>In flight</th><th>Oldest waiting</th></tr></thead>
            <tbody>
              {(h.queue ?? []).map((q) => (
                <tr key={q.stage}>
                  <td className="mono">{q.stage}</td><td>{q.pending}</td><td>{q.in_flight}</td>
                  <td className={q.oldest_pending_s > 600 ? "sev-high" : "muted"}>{q.pending ? age(q.oldest_pending_s) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="section-title">Workers</div>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>Kind</th><th>Status</th><th>Running</th><th>Last heartbeat</th><th>Version</th></tr></thead>
          <tbody>
            {(h.workers ?? []).map((w) => (
              <tr key={w.name}>
                <td className="mono">{w.name}{w.run_fleet && <span className="pill" style={{ marginLeft: 6 }}>run fleet</span>}</td>
                <td>{w.kind}</td>
                <td><Dot status={w.status === "active" ? "ok" : w.status === "stale" ? "down" : "off"} />{w.status}</td>
                <td>{w.running_tasks}</td>
                <td className={w.heartbeat_age_s > 90 ? "sev-high" : "muted"}>{age(w.heartbeat_age_s)}{w.heartbeat_age_s >= 0 ? " ago" : ""}</td>
                <td className="muted mono">{w.version || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Tile({ n, label, hint, warn }: { n: number; label: string; hint?: string; warn?: boolean }) {
  return (
    <div className="card" style={warn ? { borderColor: "var(--warn)" } : undefined}>
      <div className="l">{label}</div>
      <div className="n">{n}</div>
      {hint && <div className="muted" style={{ fontSize: 12 }}>{hint}</div>}
    </div>
  );
}
