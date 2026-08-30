import { useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { api, Scope } from "./api";
import { Modal, useToast } from "./components/ui";
import ScopePicker from "./components/ScopePicker";
import Dashboard from "./pages/Dashboard";
import Domains from "./pages/Domains";
import Hosts from "./pages/Hosts";
import Runs from "./pages/Runs";
import Fleet from "./pages/Fleet";
import Findings from "./pages/Findings";
import Search from "./pages/Search";

const NAV = [
  { to: "/", label: "Dashboard", ic: "◆" },
  { to: "/domains", label: "Domains", ic: "⌘" },
  { to: "/hosts", label: "Hosts", ic: "▣" },
  { to: "/search", label: "Search", ic: "⌕" },
  { to: "/findings", label: "Findings", ic: "!" },
  { to: "/runs", label: "Scan runs", ic: "▶" },
  { to: "/workers", label: "Workers", ic: "⬢" },
];

const COLLAPSE_KEY = "asm.sidebar.collapsed";

export default function App() {
  const toast = useToast();
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [scopeID, setScopeID] = useState("");
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
    api.scopes()
      .then((s) => { setScopes(s); if (s.length) setScopeID((cur) => cur || s[0].id); })
      .catch(() => toast("err", "Could not load scopes — is the API running?"));
  }, []);

  async function create() {
    try {
      const sc = await api.createScope(name);
      setScopes((p) => [...p, sc]);
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
          {!collapsed && (
            <h1 className="brand">Attack Surface Monitor<small>external perimeter</small></h1>
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
        />

        <nav className="nav">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === "/"} title={n.label}>
              <span className="ic">{n.ic}</span>
              {!collapsed && <span className="nav-label">{n.label}</span>}
            </NavLink>
          ))}
        </nav>
      </aside>

      <main className="main">
        {!scopeID ? (
          <div className="empty">
            <p>No company yet. Each company is a separate scope — its own targets,
              inventory and scanning authorization.</p>
            <button onClick={() => setOpen(true)}>Add your first company</button>
          </div>
        ) : (
          <Routes>
            <Route path="/" element={<Dashboard scopeID={scopeID} />} />
            <Route path="/domains" element={<Domains scopeID={scopeID} />} />
            <Route path="/hosts" element={<Hosts scopeID={scopeID} />} />
            <Route path="/search" element={<Search scopeID={scopeID} />} />
            <Route path="/findings" element={<Findings scopeID={scopeID} />} />
            <Route path="/runs" element={<Runs scopeID={scopeID} />} />
            <Route path="/workers" element={<Fleet />} />
            {/* old link kept working */}
            <Route path="/fleet" element={<Navigate to="/workers" replace />} />
            <Route path="*" element={<Navigate to="/" />} />
          </Routes>
        )}
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
