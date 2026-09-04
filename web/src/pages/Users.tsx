import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiToken, Role, User } from "../api";
import { Modal, useToast } from "../components/ui";

/**
 * Accounts and API tokens.
 *
 * Roles are ordered, and each line below says what the level adds rather than
 * repeating everything it inherits.
 */
const ROLES: { id: Role; label: string; desc: string }[] = [
  { id: "viewer", label: "Viewer", desc: "Reads everything. Changes nothing." },
  { id: "operator", label: "Operator", desc: "Adds companies and targets, and starts scans." },
  { id: "admin", label: "Admin", desc: "Also manages accounts, workers and VPN configurations." },
];

export default function Users({ me }: { me: User }) {
  const toast = useToast();
  const { data: users, refetch } = useQuery({ queryKey: ["users"], queryFn: () => api.users() });
  const [addOpen, setAddOpen] = useState(false);
  const [editing, setEditing] = useState<User | null>(null);
  const [pendingDelete, setPendingDelete] = useState<User | null>(null);

  async function del(u: User) {
    try {
      await api.deleteUser(u.id);
      toast("ok", `${u.username} removed`);
      setPendingDelete(null);
      refetch();
    } catch (e) {
      toast("err", String(e).replace(/^Error:\s*/, ""));
    }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h2 style={{ marginBottom: 2 }}>Accounts</h2>
          <div className="sub">
            Who can sign in, and what each of them may do. A scan sends packets at
            somebody's infrastructure, so starting one needs the operator role.
          </div>
        </div>
        <button onClick={() => setAddOpen(true)}>Add account</button>
      </div>

      <div className="table-wrap">
        <table>
          <thead><tr>
            <th>Username</th><th>Name</th><th>Role</th><th>Status</th>
            <th>Last sign-in</th><th>Actions</th>
          </tr></thead>
          <tbody>
            {(users ?? []).map((u) => (
              <tr key={u.id}>
                <td>
                  <span className="mono">{u.username}</span>
                  {u.id === me.id && <span className="pill" style={{ marginLeft: 6 }}>you</span>}
                </td>
                <td>{u.display_name || <span className="muted">—</span>}</td>
                <td><span className="pill">{u.role}</span></td>
                <td>
                  {u.disabled
                    ? <span className="sev-high">disabled</span>
                    : u.has_password
                      ? <span className="badge b-open">active</span>
                      : <span className="muted" title="Signs in through a trusted proxy only">no password</span>}
                </td>
                <td className="muted">
                  {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "never"}
                </td>
                <td>
                  <button className="ghost sm" onClick={() => setEditing(u)}>edit</button>
                  {u.id !== me.id &&
                    <button className="ghost sm" onClick={() => setPendingDelete(u)}>remove</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <Tokens me={me} />

      <AddUser open={addOpen} onClose={() => setAddOpen(false)} onDone={refetch} />
      {editing && (
        <EditUser user={editing} me={me} onClose={() => setEditing(null)} onDone={refetch} />
      )}
      <Modal
        title="Remove this account?" open={!!pendingDelete} onClose={() => setPendingDelete(null)}
        footer={<>
          <button className="ghost" onClick={() => setPendingDelete(null)}>Cancel</button>
          <button onClick={() => pendingDelete && del(pendingDelete)}>Remove</button>
        </>}
      >
        <p style={{ marginTop: 0 }}>
          <strong className="mono">{pendingDelete?.username}</strong> will no longer be able to
          sign in, and their sessions and API tokens stop working immediately.
        </p>
        <p className="muted" style={{ fontSize: 13, marginBottom: 0 }}>
          What they created stays, and the audit log keeps recording that they did it.
          If you only want to suspend them, edit the account and disable it instead —
          that is reversible.
        </p>
      </Modal>
    </div>
  );
}

function RolePicker({ value, onChange }: { value: Role; onChange: (r: Role) => void }) {
  return (
    <div style={{ marginBottom: 10 }}>
      {ROLES.map((r) => (
        <label key={r.id} className="check" style={{ cursor: "pointer" }}>
          <input type="radio" name="role" checked={value === r.id} onChange={() => onChange(r.id)} />
          <span>
            <strong>{r.label}</strong>
            <div className="hint" style={{ marginTop: 2 }}>{r.desc}</div>
          </span>
        </label>
      ))}
    </div>
  );
}

function AddUser({ open, onClose, onDone }: {
  open: boolean; onClose: () => void; onDone: () => void;
}) {
  const toast = useToast();
  const [username, setUsername] = useState("");
  const [display, setDisplay] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [busy, setBusy] = useState(false);

  async function save() {
    setBusy(true);
    try {
      await api.createUser({ username, display_name: display, password, role });
      toast("ok", `${username} added`);
      setUsername(""); setDisplay(""); setPassword(""); setRole("viewer");
      onDone(); onClose();
    } catch (e) {
      toast("err", String(e).replace(/^Error:\s*/, ""));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Add an account" open={open} onClose={onClose}
      footer={<>
        <button className="ghost" onClick={onClose}>Cancel</button>
        <button onClick={save} disabled={busy || !username || password.length < 12}>
          {busy ? "Adding…" : "Add account"}
        </button>
      </>}
    >
      <label className="param-label">Username</label>
      <input value={username} onChange={(e) => setUsername(e.target.value)}
        style={{ width: "100%", boxSizing: "border-box", marginBottom: 10 }} />
      <label className="param-label">Display name (optional)</label>
      <input value={display} onChange={(e) => setDisplay(e.target.value)}
        style={{ width: "100%", boxSizing: "border-box", marginBottom: 10 }} />
      <label className="param-label">Password</label>
      <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
        style={{ width: "100%", boxSizing: "border-box", marginBottom: 4 }} />
      <div className="muted" style={{ fontSize: 12, marginBottom: 12 }}>
        At least 12 characters. Tell them to change it after their first sign-in.
      </div>
      <RolePicker value={role} onChange={setRole} />
    </Modal>
  );
}

function EditUser({ user, me, onClose, onDone }: {
  user: User; me: User; onClose: () => void; onDone: () => void;
}) {
  const toast = useToast();
  const [username, setUsername] = useState(user.username);
  const [display, setDisplay] = useState(user.display_name);
  const [role, setRole] = useState<Role>(user.role);
  const [disabled, setDisabled] = useState(user.disabled);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  async function save() {
    setBusy(true);
    try {
      await api.patchUser(user.id, {
        ...(username !== user.username ? { username } : {}),
        display_name: display, role, disabled,
        ...(password ? { password } : {}),
      });
      toast("ok", `${user.username} updated`);
      onDone(); onClose();
    } catch (e) {
      toast("err", String(e).replace(/^Error:\s*/, ""));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title={`Edit ${user.username}`} open onClose={onClose}
      footer={<>
        <button className="ghost" onClick={onClose}>Cancel</button>
        <button onClick={save} disabled={busy || !username.trim() || (!!password && password.length < 12)}>
          {busy ? "Saving…" : "Save"}
        </button>
      </>}
    >
      <label className="param-label">Username</label>
      <input value={username} onChange={(e) => setUsername(e.target.value)}
        style={{ width: "100%", boxSizing: "border-box", marginBottom: 4 }} />
      {username !== user.username && (
        <div className="muted" style={{ fontSize: 12, marginBottom: 10 }}>
          They sign in as <strong className="mono">{username}</strong> from now on.
          What they have already done stays attached to them — the audit log records
          the account, not the name.
        </div>
      )}

      <label className="param-label">Display name</label>
      <input value={display} onChange={(e) => setDisplay(e.target.value)}
        style={{ width: "100%", boxSizing: "border-box", marginBottom: 12 }} />

      <RolePicker value={role} onChange={setRole} />

      <label className="check" style={{ cursor: "pointer" }}>
        <input type="checkbox" checked={disabled} onChange={(e) => setDisabled(e.target.checked)} />
        <span>
          <strong>Disabled</strong>
          <div className="hint" style={{ marginTop: 2 }}>
            Cannot sign in. Existing sessions and tokens stop working at once.
            Reversible, unlike removing the account.
          </div>
        </span>
      </label>

      <div className="section-title">Set a new password</div>
      <input type="password" value={password} placeholder="leave blank to keep the current one"
        onChange={(e) => setPassword(e.target.value)}
        style={{ width: "100%", boxSizing: "border-box" }} />
      <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
        At least 12 characters. This signs them out everywhere.
      </div>

      {user.id === me.id && (
        <div className="empty" style={{ textAlign: "left", marginTop: 14, fontSize: 13 }}>
          This is your own account. Changing your role or disabling it signs you out.
        </div>
      )}
    </Modal>
  );
}

/** API tokens: yours, or everyone's if you are an administrator. */
function Tokens({ me }: { me: User }) {
  const toast = useToast();
  const { data: tokens, refetch } = useQuery({ queryKey: ["tokens"], queryFn: () => api.tokens() });
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [role, setRole] = useState<Role>(me.role);
  const [days, setDays] = useState(90);
  const [secret, setSecret] = useState("");

  async function create() {
    try {
      const r = await api.createToken({ name, role, ttl_days: days });
      setSecret(r.secret);
      setName("");
      refetch();
    } catch (e) {
      toast("err", String(e).replace(/^Error:\s*/, ""));
    }
  }

  async function revoke(t: ApiToken) {
    try {
      await api.revokeToken(t.id);
      toast("ok", `${t.name} revoked`);
      refetch();
    } catch (e) {
      toast("err", String(e).replace(/^Error:\s*/, ""));
    }
  }

  const live = (tokens ?? []).filter((t) => !t.revoked_at);
  const dead = (tokens ?? []).filter((t) => t.revoked_at);

  return (
    <div style={{ marginTop: 26 }}>
      <div className="page-head" style={{ marginBottom: 6 }}>
        <div>
          <h2 style={{ marginBottom: 2, fontSize: 17 }}>API tokens</h2>
          <div className="sub">
            For scripts and CI, so automating something does not mean sharing a
            person's password. A token can be narrower than you are, never wider.
          </div>
        </div>
        <button onClick={() => { setSecret(""); setOpen(true); }}>New token</button>
      </div>

      {live.length === 0 && dead.length === 0 ? (
        <div className="empty">No API tokens.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr>
              <th>Name</th><th>Token</th><th>Owner</th><th>Role</th>
              <th>Last used</th><th>Expires</th><th>Actions</th>
            </tr></thead>
            <tbody>
              {[...live, ...dead].map((t) => (
                <tr key={t.id} style={t.revoked_at ? { opacity: 0.5 } : undefined}>
                  <td>{t.name}</td>
                  <td className="mono">{t.prefix}…</td>
                  <td className="mono">{t.username}</td>
                  <td><span className="pill">{t.role}</span></td>
                  <td className="muted">
                    {t.last_used_at ? new Date(t.last_used_at).toLocaleString() : "never"}
                  </td>
                  <td className="muted">
                    {t.revoked_at
                      ? "revoked"
                      : t.expires_at ? new Date(t.expires_at).toLocaleDateString() : "never"}
                  </td>
                  <td>
                    {!t.revoked_at &&
                      <button className="ghost sm" onClick={() => revoke(t)}>revoke</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Modal
        title={secret ? "Copy this token now" : "New API token"}
        open={open} onClose={() => { setOpen(false); setSecret(""); }}
        footer={secret
          ? <button onClick={() => { setOpen(false); setSecret(""); }}>Done</button>
          : <>
              <button className="ghost" onClick={() => setOpen(false)}>Cancel</button>
              <button onClick={create} disabled={!name.trim()}>Create token</button>
            </>}
      >
        {secret ? (
          <>
            <p style={{ marginTop: 0 }}>
              This is the only time it is shown. Only a hash is stored, so it cannot be
              retrieved later — if you lose it, revoke it and make another.
            </p>
            <pre className="mono" style={{
              padding: 10, borderRadius: 6, overflowX: "auto", fontSize: 12,
              background: "var(--bg-alt, rgba(127,127,127,.08))",
            }}>{secret}</pre>
            <p className="muted" style={{ fontSize: 13, marginBottom: 0 }}>
              Send it as <code>Authorization: Bearer …</code>. Treat it like a password:
              anything holding it can do what its role allows.
            </p>
          </>
        ) : (
          <>
            <label className="param-label">Name</label>
            <input value={name} placeholder="nightly scan trigger"
              onChange={(e) => setName(e.target.value)}
              style={{ width: "100%", boxSizing: "border-box", marginBottom: 12 }} />
            <RolePicker value={role} onChange={setRole} />
            <label className="param-label">Expires after</label>
            <div className="row" style={{ margin: 0 }}>
              <input type="number" min={0} max={3650} value={days}
                onChange={(e) => setDays(Math.max(0, Number(e.target.value) || 0))}
                style={{ width: 90 }} />
              <span className="muted" style={{ fontSize: 12 }}>
                days — 0 means it never expires, which is worth avoiding for anything
                that lives in a CI configuration.
              </span>
            </div>
          </>
        )}
      </Modal>
    </div>
  );
}
