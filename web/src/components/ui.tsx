import { ReactNode, useEffect, useRef, useState, createContext, useContext, useCallback } from "react";

/* ---------- Modal ---------- */

export function Modal({
  title, open, onClose, children, footer,
}: {
  title: string; open: boolean; onClose: () => void;
  children: ReactNode; footer?: ReactNode;
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
      <div className="modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
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
