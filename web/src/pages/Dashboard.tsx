import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, TargetGroup } from "../api";
import { Modal, Stat, useToast } from "../components/ui";

export default function Dashboard({ scopeID }: { scopeID: string }) {
  const { data: sum } = useQuery({ queryKey: ["summary", scopeID], queryFn: () => api.summary(scopeID) });
  const { data: groups, refetch } = useQuery({ queryKey: ["target-groups", scopeID], queryFn: () => api.targetGroups(scopeID) });
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<TargetGroup | null>(null);
  const [removing, setRemoving] = useState<TargetGroup | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const toast = useToast();

  const toggle = (id: string) => setExpanded((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });

  async function remove(g: TargetGroup) {
    setRemoving(null);
    try {
      await api.deleteTargetGroup(scopeID, g.id);
      toast("ok", `${g.name} removed — what earlier scans found under it stays in the inventory`);
      refetch();
    } catch (e) {
      toast("err", String(e).replace(/^Error:\s*/, ""));
    }
  }

  const list = groups ?? [];
  const entries = list.reduce((a, g) => a + g.targets.length, 0);

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>Dashboard</h2>
          <div className="sub">Your external attack surface at a glance.</div>
        </div>
      </div>

      <div className="cards">
        <Stat n={sum?.domains_resolving} label="Resolving names" to="/hosts"
          title="Open Hosts: every name with the address it resolves to"
          hint={sum && sum.domains > sum.domains_resolving ? `${sum.domains - sum.domains_resolving} more never resolved` : undefined} />
        <Stat n={sum?.ips} label="Hosts" to="/hosts" title="Open Hosts: every name with the address it resolves to" />
        <Stat n={sum?.services} label="Services" to="/search?q=product%3A*"
          title="Open Search with every service listed and summarized by product, port and technology" />
        <Stat n={sum?.open_findings} label="Open findings" to="/findings" title="Open Findings" />
      </div>

      <div className="page-head">
        <div>
          <div className="section-title" style={{ margin: 0 }}>Scope targets</div>
          {list.length > 0 && (
            <div className="sub">
              {list.length} group{list.length === 1 ? "" : "s"}, {entries} entr{entries === 1 ? "y" : "ies"}.
              A scan picks groups; a group is edited and removed as one thing.
            </div>
          )}
        </div>
        <button onClick={() => setOpen(true)}>+ Add targets</button>
      </div>

      {list.length === 0 ? (
        <div className="empty">
          <p>No targets yet. Add a list of domains, IPs or CIDRs to start discovering.</p>
          <button onClick={() => setOpen(true)}>Add your first targets</button>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th></th><th>Group</th><th>Entries</th><th>Mode</th><th>Tags</th><th></th></tr></thead>
            <tbody>
              {list.map((g) => {
                const isOpen = expanded.has(g.id);
                const tags = g.targets[0]?.tags ?? [];
                const kinds = Object.entries(g.targets.reduce<Record<string, number>>((a, t) => { a[t.kind] = (a[t.kind] ?? 0) + 1; return a; }, {}))
                  .map(([k, n]) => `${n} ${k}${n === 1 ? "" : "s"}`).join(", ");
                return [
                  <tr key={g.id} style={{ cursor: "pointer" }} onClick={() => toggle(g.id)} title={isOpen ? "Hide the entries" : "Show the entries"}>
                    <td style={{ width: 24 }}><span className={"chev" + (isOpen ? " open" : "")} aria-hidden="true" /></td>
                    <td><strong>{g.name}</strong></td>
                    <td className="muted">
                      {g.targets.length} entr{g.targets.length === 1 ? "y" : "ies"}
                      {kinds && <span style={{ fontSize: 12 }}> · {kinds}</span>}
                      {!isOpen && g.targets.length > 0 && (
                        <span className="mono" style={{ fontSize: 12, marginLeft: 8 }}>
                          {g.targets.slice(0, 3).map((t) => t.value).join(", ")}{g.targets.length > 3 ? ", …" : ""}
                        </span>
                      )}
                    </td>
                    <td title={g.authorized
                      ? `Active scanning authorized by ${g.targets[0]?.authorized_by ?? "?"}`
                      : "Passive discovery only; nothing is sent to these targets"}>
                      {g.authorized ? <span className="badge b-active">active</span> : <span className="badge">passive only</span>}
                    </td>
                    <td>{tags.map((x) => <span key={x} className="pill">{x}</span>)}</td>
                    <td style={{ textAlign: "right", whiteSpace: "nowrap" }} onClick={(e) => e.stopPropagation()}>
                      <button className="ghost sm" title="Change the group's name, its list, tags or authorization" onClick={() => setEditing(g)}>Edit</button>
                      <button className="ghost sm" title="Remove the group and its entries; future scans stop covering them" onClick={() => setRemoving(g)}>Remove</button>
                    </td>
                  </tr>,
                  isOpen && (
                    <tr key={g.id + ":entries"}>
                      <td></td>
                      <td colSpan={5} style={{ background: "var(--bg)", padding: "6px 12px" }}>
                        <table style={{ margin: 0 }}>
                          <tbody>
                            {g.targets.map((t) => (
                              <tr key={t.id}>
                                <td className="mono" style={{ width: 360 }}>{t.value}</td>
                                <td className="muted">{t.kind}</td>
                                <td className="muted" style={{ fontSize: 12 }}>added {new Date(t.created_at ?? g.created_at).toLocaleDateString()}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </td>
                    </tr>
                  ),
                ];
              })}
            </tbody>
          </table>
        </div>
      )}

      <GroupDialog scopeID={scopeID} open={open} onClose={() => setOpen(false)} onDone={refetch} />
      {editing && (
        <GroupDialog scopeID={scopeID} open group={editing} onClose={() => setEditing(null)} onDone={refetch} />
      )}
      {removing && (
        <Modal
          title={`Remove ${removing.name}?`} open onClose={() => setRemoving(null)}
          footer={<>
            <button className="ghost" onClick={() => setRemoving(null)}>Keep it</button>
            <button className="danger" onClick={() => remove(removing)}>Remove group</button>
          </>}
        >
          <p style={{ marginTop: 0 }}>
            The group and its {removing.targets.length} entr{removing.targets.length === 1 ? "y" : "ies"} are taken out of the
            company, so future scans stop covering them. What earlier scans discovered under them stays in the inventory.
          </p>
        </Modal>
      )}
    </div>
  );
}

/**
 * Add a group, or edit one: the same form. A name, the list — one entry per
 * line — tags, and the one tick for active-scanning authorization. Editing
 * replaces the list: entries taken off it are removed, new ones added, and the
 * tags and authorization apply to every entry.
 */
function GroupDialog({ scopeID, open, group, onClose, onDone }: {
  scopeID: string; open: boolean; group?: TargetGroup; onClose: () => void; onDone: () => void;
}) {
  const toast = useToast();
  const [name, setName] = useState(group?.name ?? "");
  const [text, setText] = useState(group ? group.targets.map((t) => t.value).join("\n") : "");
  const [active, setActive] = useState(group?.authorized ?? false);
  const [tags, setTags] = useState((group?.targets[0]?.tags ?? []).join(", "));
  const [busy, setBusy] = useState(false);
  const values = text.split(/[\s,]+/).map((v) => v.trim()).filter(Boolean);

  async function save() {
    setBusy(true);
    try {
      const body = { name: name.trim() || undefined, values, tags: tags.split(/[\s,]+/).filter(Boolean), authorize: active };
      if (group) {
        await api.patchTargetGroup(scopeID, group.id, body);
        toast("ok", `${name.trim() || group.name} updated`);
      } else {
        await api.createTargetGroup(scopeID, body);
        toast("ok", `${name.trim() || values[0]} added with ${values.length} entr${values.length === 1 ? "y" : "ies"}`);
        setName(""); setText(""); setTags(""); setActive(false);
      }
      onDone(); onClose();
    } catch (e) {
      toast("err", String(e).replace(/^Error:\s*/, ""));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title={group ? `Edit ${group.name}` : "Add targets"} open={open} onClose={onClose}
      footer={<>
        <button className="ghost" onClick={onClose}>Cancel</button>
        <button onClick={save} disabled={busy || !values.length}>
          {busy ? "Saving…" : group ? "Save" : `Add ${values.length || ""} entr${values.length === 1 ? "y" : "ies"}`}
        </button>
      </>}
    >
      <div className="field">
        <label>Name</label>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder={values[0] ? `defaults to ${values[0]}` : "e.g. production, or the main domain"} style={{ width: "100%" }} />
        <div className="hint">How the group appears on this page and in the scan dialog. Left empty, the first entry is used.</div>
      </div>
      <div className="field">
        <label>Domains, IPs or CIDRs</label>
        <textarea rows={6} style={{ width: "100%" }} className="mono" value={text} onChange={(e) => setText(e.target.value)}
          placeholder={"example.com\nshop.example.com\n203.0.113.0/24"} />
        <div className="hint">
          One per line, or comma-separated; the kind is detected automatically.
          {group ? " Entries taken off this list are removed from the group; new lines are added." : " Together they make one group."}
        </div>
      </div>
      <div className="field">
        <label>Tags (optional)</label>
        <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="production, eu" />
        <div className="hint">Applied to every entry. Tags group targets across groups; a run can be started over one tag through the API.</div>
      </div>
      <label className="check" style={{ cursor: "pointer" }}>
        <input type="checkbox" checked={active} onChange={(e) => setActive(e.target.checked)} />
        <span>
          <strong>Authorize active scanning</strong>
          <div className="hint" style={{ marginTop: 3 }}>
            {group?.authorized
              ? `Currently authorized by ${group.targets[0]?.authorized_by ?? "?"}. Untick for passive-only discovery of every entry.`
              : "Leave unticked for passive-only discovery (CT logs, DNS, public APIs — no packets sent to the targets). Only tick this for infrastructure you are authorized to scan."}
          </div>
        </span>
      </label>
    </Modal>
  );
}
