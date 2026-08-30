import { useEffect, useMemo, useRef, useState } from "react";
import { Scope } from "../api";

/**
 * Searchable scope (company) selector for the sidebar. A single-org install has
 * one scope and this behaves like a plain dropdown; with many companies the
 * search box makes the list navigable by typing.
 */
export default function ScopePicker({
  scopes, value, onChange, onNew, collapsed = false,
}: {
  scopes: Scope[];
  value: string;
  onChange: (id: string) => void;
  onNew: () => void;
  collapsed?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const boxRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  const current = scopes.find((s) => s.id === value);

  const matches = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return scopes;
    return scopes.filter((s) => s.name.toLowerCase().includes(needle));
  }, [scopes, q]);

  // close on outside click
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (boxRef.current && !boxRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  // reset + focus the search each time the panel opens
  useEffect(() => {
    if (!open) return;
    setQ("");
    setActive(Math.max(0, scopes.findIndex((s) => s.id === value)));
    requestAnimationFrame(() => searchRef.current?.focus());
  }, [open]);

  useEffect(() => { setActive(0); }, [q]);

  function choose(id: string) {
    onChange(id);
    setOpen(false);
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Escape") { setOpen(false); return; }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => Math.min(matches.length - 1, i + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => Math.max(0, i - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (matches[active]) choose(matches[active].id);
    }
  }

  return (
    <div className={"combo" + (collapsed ? " collapsed" : "")} ref={boxRef} onKeyDown={onKeyDown}>
      {collapsed ? (
        <button
          type="button"
          className="combo-avatar"
          aria-haspopup="listbox"
          aria-expanded={open}
          onClick={() => setOpen((o) => !o)}
          title={current?.name ?? "Select company"}
        >
          {(current?.name ?? "?").trim().charAt(0).toUpperCase()}
        </button>
      ) : (
        <div className="row" style={{ margin: 0, gap: 6 }}>
          <button
            type="button"
            className="combo-btn grow"
            aria-haspopup="listbox"
            aria-expanded={open}
            onClick={() => setOpen((o) => !o)}
            title="Select company"
          >
            <span className="combo-label">{current?.name ?? (scopes.length ? "Select…" : "No companies")}</span>
            <span className="combo-caret">▾</span>
          </button>
          <button className="ghost" onClick={onNew} title="Add a company">+</button>
        </div>
      )}

      {open && (
        <div className="combo-panel" role="listbox">
          <input
            ref={searchRef}
            className="combo-search"
            placeholder="Search companies…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />

          <div className="combo-list">
            {matches.map((s, i) => (
              <button
                key={s.id}
                type="button"
                role="option"
                aria-selected={s.id === value}
                className={"combo-item" + (i === active ? " active" : "") + (s.id === value ? " current" : "")}
                onMouseEnter={() => setActive(i)}
                onClick={() => choose(s.id)}
              >
                <span className="combo-item-name">{s.name}</span>
                {s.id === value && <span className="combo-check">✓</span>}
              </button>
            ))}

            {matches.length === 0 && (
              <div className="combo-none">
                No company matches “{q}”.
              </div>
            )}
          </div>

          <button type="button" className="combo-new" onClick={() => { setOpen(false); onNew(); }}>
            + Add company
          </button>
        </div>
      )}
    </div>
  );
}
