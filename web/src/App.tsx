import { useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { api, atLeast, AuthStatus, Scope, UNAUTHENTICATED, User } from "./api";
import { Modal, useToast } from "./components/ui";
import ScopePicker from "./components/ScopePicker";
import Dashboard from "./pages/Dashboard";
import Hosts from "./pages/Hosts";
import Runs from "./pages/Runs";
import Fleet from "./pages/Fleet";
import Wordlists from "./components/Wordlists";
import Findings from "./pages/Findings";
import Search from "./pages/Search";
import Alerts from "./pages/Alerts";
import VPN from "./pages/VPN";
import Host from "./pages/Host";
import Auth from "./pages/Auth";
import Users from "./pages/Users";

const NAV = [
  { to: "/", label: "Dashboard", ic: "◆" },
  { to: "/hosts", label: "Hosts", ic: "▣" },
  { to: "/search", label: "Search", ic: "⌕" },
  { to: "/findings", label: "Findings", ic: "!" },
  { to: "/alerts", label: "Alerts", ic: "◎" },
  { to: "/runs", label: "Scan runs", ic: "▶" },
  { to: "/workers", label: "Workers", ic: "⬢" },
  { to: "/wordlists", label: "Wordlists", ic: "≡" },
  { to: "/vpn", label: "VPN", ic: "⇄" },
  { to: "/accounts", label: "Accounts", ic: "☺", admin: true },
];

const COLLAPSE_KEY = "asm.sidebar.collapsed";
const MINE_KEY = "asm.scopes.mine";
const SCOPE_KEY = "asm.scope.id";

/**
 * The authentication gate.
 *
 * Nothing renders until the API says who is asking. This is deliberately a hard
 * gate rather than a redirect: the app has no useful state for an anonymous
 * visitor, and every request it would make answers 401 anyway.
 */
export default function App() {
  const [status, setStatus] = useState<AuthStatus | null>(null);
  const [me, setMe] = useState<User | null>(null);
  // True while the shipped password still works. Checked against the stored
  // hash on every load, so the banner disappears the moment it is changed and
  // comes back if it is ever set again.
  const [defaultPw, setDefaultPw] = useState(false);

  async function refreshAuth() {
    try {
      const st = await api.authStatus();
      setStatus(st);
      if (st.user) {
        const m = await api.me();
        setMe(m.user);
        setDefaultPw(!!m.using_default_password);
      } else {
        setMe(null);
        setDefaultPw(false);
      }
    } catch {
      setStatus({ setup_required: false });
      setMe(null);
    }
  }

  useEffect(() => { refreshAuth(); }, []);

  // A session can end while a tab sits idle — it expired, the account was
  // disabled, or a role changed. The first sign is a 401 on an ordinary
  // request, so the client raises this and we come back here.
  useEffect(() => {
    const onLost = () => { setMe(null); refreshAuth(); };
    window.addEventListener(UNAUTHENTICATED, onLost);
    return () => window.removeEventListener(UNAUTHENTICATED, onLost);
  }, []);

  if (!status) {
    return <div className="empty" style={{ marginTop: 80 }}>Loading…</div>;
  }
  if (!me) {
    return <Auth status={status} onSignedIn={refreshAuth} />;
  }
  return <Shell me={me} defaultPw={defaultPw} onSignedOut={refreshAuth} />;
}

function Shell({ me, defaultPw, onSignedOut }: {
  me: User; defaultPw: boolean; onSignedOut: () => void;
}) {
  const toast = useToast();
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [allScopes, setAllScopes] = useState<Scope[]>([]);
  // Which company is selected, remembered across loads.
  //
  // Without this the app fell back to the first company alphabetically on every
  // load, which is most visible on the host page: it opens in a new tab by
  // design, so the sidebar would name a different company than the page you
  // were looking at.
  const [scopeID, setScopeID] = useState(() => {
    try { return localStorage.getItem(SCOPE_KEY) ?? ""; } catch { return ""; }
  });
  // Whether the company list is narrowed to the ones this user created. A view
  // preference, so it lives in the browser rather than on the server.
  const [mine, setMine] = useState(() => {
    try { return localStorage.getItem(MINE_KEY) === "1"; } catch { return false; }
  });
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [collapsed, setCollapsed] = useState(() => {
    try { return localStorage.getItem(COLLAPSE_KEY) === "1"; } catch { return false; }
  });

  function toggleSidebar() {
    setCollapsed((c) => {
      const next = !c;
      try { localStorage.setItem(COLLAPSE_KEY, next ? "1" : "0"); } catch { /* private mode */ }
      return next;
    });
  }

  useEffect(() => {
    // Both lists: the filtered one drives the picker, the full one tells the
    // user how many companies the filter is holding back.
    Promise.all([api.scopes(mine), mine ? api.scopes(false) : Promise.resolve(null)])
      .then(([list, all]) => {
        setScopes(list);
        setAllScopes(all ?? list);
        // Keep a selection that is still visible; otherwise fall back to the
        // first, so filtering never leaves the app pointed at nothing. This is
        // also what validates the remembered id: a company that has since been
        // deleted, or that the "mine" filter hides, quietly falls back.
        setScopeID((cur) => (cur && list.some((s) => s.id === cur) ? cur : (list[0]?.id ?? "")));
      })
      .catch(() => toast("err", "Could not load scopes — is the API running?"));
  }, [mine]);

  // Mirrored from the state rather than written by each setter, so the fallback
  // above is remembered too — and a scope that has been deleted, or hidden by
  // the "mine" filter, does not linger in storage.
  useEffect(() => {
    if (!scopeID) return;
    try { localStorage.setItem(SCOPE_KEY, scopeID); } catch { /* private mode */ }
  }, [scopeID]);

  function changeMine(next: boolean) {
    setMine(next);
    try { localStorage.setItem(MINE_KEY, next ? "1" : "0"); } catch { /* private mode */ }
  }

  async function create() {
    try {
      const sc = await api.createScope(name);
      setScopes((p) => [...p, sc]);
      setAllScopes((p) => [...p, sc]);
      setScopeID(sc.id);
      setOpen(false);
      setName("");
      toast("ok", `Added "${sc.name}"`);
    } catch (e) {
      toast("err", String(e));
    }
  }

  return (
    <div className={"app" + (collapsed ? " collapsed" : "")}>
      <aside className="sidebar">
        <div className="brand-row">
          {/* alt is empty while the <h1> beside it names the app; when collapsed the
              heading is gone, so the mark has to carry the name itself. */}
          <img className="brand-mark" src="/logo.svg" alt={collapsed ? "PinkGlasses" : ""} />
          {!collapsed && (
            <h1 className="brand">PinkGlasses<small>external attack surface</small></h1>
          )}
          <button
            className="collapse-btn"
            onClick={toggleSidebar}
            title={collapsed ? "Expand sidebar" : "Collapse to icons"}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? "»" : "«"}
          </button>
        </div>

        <ScopePicker
          scopes={scopes}
          value={scopeID}
          onChange={setScopeID}
          onNew={() => setOpen(true)}
          collapsed={collapsed}
          mine={mine}
          onMineChange={changeMine}
          hiddenCount={Math.max(0, allScopes.length - scopes.length)}
        />

        <nav className="nav">
          {NAV.filter((n) => !n.admin || atLeast(me.role, "admin")).map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === "/"} title={n.label}>
              <span className="ic">{n.ic}</span>
              {!collapsed && <span className="nav-label">{n.label}</span>}
            </NavLink>
          ))}
        </nav>

        <AccountMenu me={me} collapsed={collapsed} onSignedOut={onSignedOut} />
      </aside>

      <main className="main">
        {defaultPw && <DefaultPasswordBanner />}
        <Routes>
          {/* A host page names its own scope, so it renders before one is
              picked — otherwise opening a host in a new tab would land on the
              "no company yet" screen while scopes are still loading. */}
          <Route path="/host/:ipID" element={<Host />} />
          <Route path="*" element={
            !scopeID ? (
              <div className="empty">
                <p>No company yet. Each company is a separate scope — its own targets,
                  inventory and scanning authorization.</p>
                {atLeast(me.role, "operator")
                  ? <button onClick={() => setOpen(true)}>Add your first company</button>
                  : <p className="muted">Adding one needs the operator role. Ask an administrator.</p>}
              </div>
            ) : (
              <Routes>
                <Route path="/" element={<Dashboard scopeID={scopeID} />} />
                {/* Domains merged into Hosts */}
                <Route path="/domains" element={<Navigate to="/hosts" replace />} />
                <Route path="/hosts" element={<Hosts scopeID={scopeID} />} />
                <Route path="/search" element={<Search scopeID={scopeID} />} />
                <Route path="/findings" element={<Findings scopeID={scopeID} />} />
                <Route path="/alerts" element={<Alerts scopeID={scopeID} />} />
                <Route path="/runs" element={<Runs scopeID={scopeID} />} />
                <Route path="/workers" element={<Fleet />} />
                <Route path="/wordlists" element={<Wordlists />} />
                <Route path="/vpn" element={<VPN scopeID={scopeID} />} />
                <Route path="/accounts" element={
                  atLeast(me.role, "admin")
                    ? <Users me={me} />
                    : <div className="empty">Managing accounts needs the admin role.</div>
                } />
                {/* old link kept working */}
                <Route path="/fleet" element={<Navigate to="/workers" replace />} />
                <Route path="*" element={<Navigate to="/" />} />
              </Routes>
            )
          } />
        </Routes>
      </main>

      <Modal
        title="Add a company" open={open} onClose={() => setOpen(false)}
        footer={<>
          <button className="ghost" onClick={() => setOpen(false)}>Cancel</button>
          <button onClick={create} disabled={!name.trim()}>Create</button>
        </>}
      >
        <div className="field">
          <label>Name</label>
          <input autoFocus value={name} onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && name.trim() && create()}
            placeholder="Acme Corp" />
          <div className="hint">
            Everything discovered is grouped under this company, and scanning
            authorization is granted per company.
          </div>
        </div>
      </Modal>
    </div>
  );
}

/**
 * Who you are signed in as, at the foot of the sidebar, with the two things
 * you might want to do about it.
 */
function AccountMenu({ me, collapsed, onSignedOut }: {
  me: User; collapsed: boolean; onSignedOut: () => void;
}) {
  const toast = useToast();
  const [pwOpen, setPwOpen] = useState(false);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);

  async function signOut() {
    try { await api.logout(); } catch { /* the cookie is going either way */ }
    onSignedOut();
  }

  async function changePassword() {
    setBusy(true);
    try {
      await api.changePassword(current, next);
      toast("ok", "Password changed. Other sessions were signed out.");
      setPwOpen(false); setCurrent(""); setNext(""); setConfirm("");
    } catch (e) {
      toast("err", String(e).replace(/^Error:\s*/, ""));
    } finally {
      setBusy(false);
    }
  }

  const ready = next.length >= 12 && next === confirm && current.length > 0;

  return (
    <div className="account-menu">
      {collapsed ? (
        <button className="ghost sm" title={`${me.username} (${me.role}) — sign out`}
          onClick={signOut} style={{ width: "100%" }}>⏻</button>
      ) : (
        <>
          <div style={{ fontSize: 12.5, fontWeight: 600, wordBreak: "break-all" }}>
            {me.display_name || me.username}
          </div>
          <div className="muted" style={{ fontSize: 11.5, marginBottom: 6 }}>
            {me.username} · {me.role}
          </div>
          <div className="row" style={{ margin: 0, gap: 6 }}>
            {me.has_password &&
              <button className="ghost sm" onClick={() => setPwOpen(true)}>password</button>}
            <button className="ghost sm" onClick={signOut}>sign out</button>
          </div>
        </>
      )}

      <Modal
        title="Change your password" open={pwOpen} onClose={() => setPwOpen(false)}
        footer={<>
          <button className="ghost" onClick={() => setPwOpen(false)}>Cancel</button>
          <button onClick={changePassword} disabled={busy || !ready}>
            {busy ? "Changing…" : "Change password"}
          </button>
        </>}
      >
        <label className="param-label">Current password</label>
        <input type="password" value={current} autoComplete="current-password"
          onChange={(e) => setCurrent(e.target.value)}
          style={{ width: "100%", boxSizing: "border-box", marginBottom: 10 }} />
        <label className="param-label">New password</label>
        <input type="password" value={next} autoComplete="new-password"
          onChange={(e) => setNext(e.target.value)}
          style={{ width: "100%", boxSizing: "border-box", marginBottom: 10 }} />
        <label className="param-label">Confirm new password</label>
        <input type="password" value={confirm} autoComplete="new-password"
          onChange={(e) => setConfirm(e.target.value)}
          style={{ width: "100%", boxSizing: "border-box", marginBottom: 6 }} />
        <div className="muted" style={{ fontSize: 12 }}>
          At least 12 characters. Your current password is required even though you
          are signed in — a borrowed browser should not be enough to take the
          account over. Every other session is signed out.
        </div>
      </Modal>
    </div>
  );
}

/**
 * Shown on every page while the account still has the password this project
 * ships with — which is published in the README, so anyone who can reach the
 * install can sign in as an administrator.
 *
 * Deliberately not dismissible. A banner you can click away is one you stop
 * seeing, and the thing it is warning about does not go away with it.
 */
function DefaultPasswordBanner() {
  return (
    <div
      role="alert"
      style={{
        border: "1px solid var(--warn, #d98b2b)",
        borderRadius: 8,
        padding: "10px 14px",
        marginBottom: 14,
        fontSize: 13,
        lineHeight: 1.5,
        background: "rgba(217,139,43,.08)",
      }}
    >
      <strong>This install is still using the default password.</strong>{" "}
      It is published in the README, so anyone who can reach this address can sign
      in as an administrator and read your whole attack surface. Change it under{" "}
      <strong>password</strong> at the foot of the sidebar.
    </div>
  );
}
