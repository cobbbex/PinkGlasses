import { ReactNode, useEffect, useRef, useState, createContext, useContext, useCallback, useMemo, type CSSProperties } from "react";

/* ---------- Modal ---------- */

export function Modal({
  title, open, onClose, children, footer, wide, xl,
}: {
  title: string; open: boolean; onClose: () => void;
  children: ReactNode; footer?: ReactNode;
  /** wide: 780px, for dialogs with a choice or two; xl: 1040px, for a whole form. */
  wide?: boolean; xl?: boolean;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className={"modal" + (wide || xl ? " wide" : "") + (xl ? " xl" : "")} onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="modal-head">
          <h3>{title}</h3>
          <button className="icon" onClick={onClose} aria-label="Close">✕</button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}

/* ---------- Toasts ---------- */

type Toast = { id: number; kind: "ok" | "err"; text: string };
const ToastCtx = createContext<(kind: "ok" | "err", text: string) => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);
  const push = useCallback((kind: "ok" | "err", text: string) => {
    const id = Date.now() + Math.random();
    setItems((p) => [...p, { id, kind, text }]);
    setTimeout(() => setItems((p) => p.filter((t) => t.id !== id)), 5000);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts">
        {items.map((t) => (
          <div key={t.id} className={"toast " + t.kind} onClick={() => setItems((p) => p.filter((x) => x.id !== t.id))}>
            {t.text}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

export const useToast = () => useContext(ToastCtx);

/* ---------- Info popover ---------- */

/**
 * A small "i" button that reveals an explanation on click.
 *
 * The popover is position:fixed and placed from the button's bounding rect
 * rather than being absolutely positioned inside its parent — table headers
 * live inside `.table-wrap`, whose `overflow-x: auto` would otherwise clip it.
 */
export function InfoDot({ title, children }: { title?: string; children: ReactNode }) {
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const btnRef = useRef<HTMLButtonElement>(null);

  const close = useCallback(() => setPos(null), []);

  useEffect(() => {
    if (!pos) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && close();
    const onDown = (e: MouseEvent) => {
      if (!btnRef.current?.contains(e.target as Node)) close();
    };
    const onScroll = () => close();
    window.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onDown);
    window.addEventListener("scroll", onScroll, true);
    return () => {
      window.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onDown);
      window.removeEventListener("scroll", onScroll, true);
    };
  }, [pos, close]);

  function toggle() {
    if (pos) { close(); return; }
    const r = btnRef.current?.getBoundingClientRect();
    if (!r) return;
    const width = 340;
    setPos({
      top: r.bottom + 6,
      left: Math.max(8, Math.min(r.left, window.innerWidth - width - 12)),
    });
  }

  return (
    <>
      <button
        ref={btnRef}
        type="button"
        className="info-dot"
        aria-label={title ? `About ${title}` : "More information"}
        aria-expanded={!!pos}
        onClick={(e) => { e.stopPropagation(); toggle(); }}
      >
        i
      </button>
      {pos && (
        <div className="info-pop" style={{ top: pos.top, left: pos.left }} role="tooltip"
             onClick={(e) => e.stopPropagation()}>
          {title && <div className="info-pop-title">{title}</div>}
          {children}
        </div>
      )}
    </>
  );
}

/* ---------- Small primitives ---------- */

export function Stat({ n, label, hint }: { n: ReactNode; label: string; hint?: string }) {
  return (
    <div className="card">
      <div className="l">{label}</div>
      <div className="n">{n ?? "—"}</div>
      {hint && <div className="muted" style={{ fontSize: 12 }}>{hint}</div>}
    </div>
  );
}

export function Badge({ status }: { status: string }) {
  return <span className={"badge b-" + status}>{status}</span>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function Spinner() {
  return <span className="spinner" aria-label="loading" />;
}


/* ---------------- column sorting ---------------- */

export type SortDir = "asc" | "desc";
export interface SortState { key: string; dir: SortDir }

/**
 * Client-side column sorting for a table whose rows all arrived in one
 * response. `get` maps a column key to the value to order by; strings sort
 * case-insensitively, numbers numerically, IPv4 addresses by octet, dates by
 * time, and nulls always sink to the bottom whatever the direction.
 */
export function useSort<T>(
  rows: T[], initial: SortState, get: (row: T, key: string) => unknown,
): { sorted: T[]; sort: SortState; toggle: (key: string) => void } {
  const [sort, setSort] = useState<SortState>(initial);
  const sorted = useMemo(() => {
    const dir = sort.dir === "asc" ? 1 : -1;
    return [...rows].map((r, i) => ({ r, i })).sort((a, b) => {
      const c = compareValues(get(a.r, sort.key), get(b.r, sort.key));
      // Nulls last regardless of direction; otherwise stable on the original order.
      if (c === Number.POSITIVE_INFINITY) return 1;
      if (c === Number.NEGATIVE_INFINITY) return -1;
      return c !== 0 ? c * dir : a.i - b.i;
    }).map((x) => x.r);
  }, [rows, sort.key, sort.dir, get]);
  const toggle = (key: string) => setSort((s) =>
    s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: defaultDirFor(rows, key, get) });
  return { sorted, sort, toggle };
}

// A first click on a column of numbers or dates shows the biggest first; on
// text, alphabetical.
function defaultDirFor<T>(rows: T[], key: string, get: (r: T, k: string) => unknown): SortDir {
  const sample = rows.map((r) => get(r, key)).find((v) => v !== null && v !== undefined && v !== "");
  return typeof sample === "number" || sample instanceof Date ? "desc" : "asc";
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
function ipv4Num(s: string): number | null {
  const m = IPV4.exec(s);
  if (!m) return null;
  return ((+m[1]) << 24 >>> 0) + ((+m[2]) << 16) + ((+m[3]) << 8) + (+m[4]);
}

function compareValues(a: unknown, b: unknown): number {
  const an = a === null || a === undefined || a === "";
  const bn = b === null || b === undefined || b === "";
  if (an && bn) return 0;
  if (an) return Number.POSITIVE_INFINITY;
  if (bn) return Number.NEGATIVE_INFINITY;
  if (a instanceof Date && b instanceof Date) return a.getTime() - b.getTime();
  if (typeof a === "number" && typeof b === "number") return a - b;
  if (typeof a === "string" && typeof b === "string") {
    const ia = ipv4Num(a), ib = ipv4Num(b);
    if (ia !== null && ib !== null) return ia - ib;
    return a.localeCompare(b, undefined, { sensitivity: "base", numeric: true });
  }
  return String(a).localeCompare(String(b));
}

/** A header cell that sorts its column: click to sort, click again to flip. */
export function SortTh({ k, sort, onSort, children, title, style }: {
  k: string; sort: SortState; onSort: (key: string) => void;
  children: ReactNode; title?: string; style?: CSSProperties;
}) {
  const on = sort.key === k;
  return (
    <th className={"sortable" + (on ? " sorted" : "")} onClick={() => onSort(k)} title={title}
        aria-sort={on ? (sort.dir === "asc" ? "ascending" : "descending") : "none"} style={style}>
      {children}
      <span className={"sort-arrow" + (on ? " on" : "")} aria-hidden="true">
        {on ? (sort.dir === "asc" ? "▲" : "▼") : "⇅"}
      </span>
    </th>
  );
}
