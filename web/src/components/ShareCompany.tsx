import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, Scope } from "../api";
import { Modal, useToast } from "./ui";

/**
 * Who can see a company. Shared: every account on the install. Private: its
 * owner and the accounts listed here. The owner switches between the two and
 * adds or removes accounts by username; a member can remove themselves. Roles
 * still apply inside: sharing with a viewer lets them read, not scan. API
 * tokens and MCP clients act as their account, so they follow the same list.
 */
export default function ShareCompany({ scope, meID, onClose, onChanged }: {
  scope: Scope; meID: string; onClose: () => void; onChanged: () => void;
}) {
  const toast = useToast();
  const qc = useQueryClient();
  const { data, refetch } = useQuery({ queryKey: ["access", scope.id], queryFn: () => api.scopeAccess(scope.id) });
  const [username, setUsername] = useState("");
  const [busy, setBusy] = useState(false);
  const fail = (e: unknown) => toast("err", String(e).replace(/^Error:\s*/, ""));
  const done = () => { refetch(); onChanged(); qc.invalidateQueries({ queryKey: ["access", scope.id] }); };

  async function share() {
    if (!username.trim()) return;
    setBusy(true);
    try { await api.shareScope(scope.id, username.trim()); toast("ok", `Shared with ${username.trim()}`); setUsername(""); done(); }
    catch (e) { fail(e); } finally { setBusy(false); }
  }
  async function unshare(userID: string, name: string) {
    try { await api.unshareScope(scope.id, userID); toast("ok", `${name} no longer has access`); done(); }
    catch (e) { fail(e); }
  }
  async function setVisibility(v: "shared" | "private") {
    try { await api.setScopeVisibility(scope.id, v); toast("ok", v === "private" ? "Now private" : "Now shared with everyone"); done(); }
    catch (e) { fail(e); }
  }

  const priv = data?.visibility === "private";
  const manage = !!data?.can_manage;
  return (
    <Modal title={`Who can see ${scope.name}`} open onClose={onClose}
      footer={<button className="ghost" onClick={onClose}>Close</button>}>
      {!data ? <div className="muted">Loading…</div> : (
        <>
          <label className="check" style={{ cursor: manage ? "pointer" : "default" }}>
            <input type="radio" checked={!priv} disabled={!manage} onChange={() => setVisibility("shared")} />
            <span><strong>Shared</strong><div className="muted" style={{ fontSize: 12.5 }}>Every account on this install sees it.</div></span>
          </label>
          <label className="check" style={{ cursor: manage ? "pointer" : "default" }}>
            <input type="radio" checked={priv} disabled={!manage} onChange={() => setVisibility("private")} />
            <span><strong>Private</strong><div className="muted" style={{ fontSize: 12.5 }}>
              Only {data.owner || "its owner"} and the accounts below. Everyone else — administrators too — does not
              see it exist, through the app, API tokens or MCP.</div></span>
          </label>
          {!manage && <div className="hint muted">Only its owner ({data.owner || "no owner"}) changes this.</div>}

          {priv && (
            <>
              <div className="section-title">Shared with</div>
              {data.members.length === 0 ? <div className="muted" style={{ fontSize: 13 }}>Nobody yet.</div> : (
                <div className="table-wrap" style={{ marginBottom: 10 }}>
                  <table>
                    <tbody>
                      {data.members.map((m) => (
                        <tr key={m.user_id}>
                          <td><strong>{m.username}</strong>{m.display_name && <span className="muted"> · {m.display_name}</span>}</td>
                          <td className="muted" title="Their account role applies inside the company">{m.role}</td>
                          <td className="muted" style={{ fontSize: 12 }}>added by {m.added_by}</td>
                          <td style={{ textAlign: "right" }}>
                            {(manage || m.user_id === meID) && (
                              <button className="ghost sm" onClick={() => unshare(m.user_id, m.username)}>
                                {m.user_id === meID ? "Leave" : "Remove"}
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {manage && (
                <div className="row">
                  <input className="grow" placeholder="Username to share with" value={username}
                    onChange={(e) => setUsername(e.target.value)} onKeyDown={(e) => e.key === "Enter" && share()} />
                  <button onClick={share} disabled={busy || !username.trim()}>Share</button>
                </div>
              )}
              <div className="hint muted">Their account role still applies: a viewer can read the company, not scan it.</div>
            </>
          )}
        </>
      )}
    </Modal>
  );
}
