import { useCallback, useRef, useState } from "react";
import type { CSSProperties, ReactNode } from "react";
import { ColumnDef, ColumnPicker, ResizeHandle, useColumnWidths, useColumns } from "./ui";

/**
 * Everything a table needs to be the viewer's: which columns show, what
 * width each has, and whether the table fits the screen or takes its
 * natural width — remembered per browser under one key. The Hosts page grew
 * this first; this is the same behaviour for any table, in one hook.
 */
export interface LayoutDef extends ColumnDef {
  /** The least a fitted column gets, and its share of what is left. */
  min?: number; weight?: number;
}

export function useTableLayout(key: string, defs: LayoutDef[]) {
  const cols = useColumns(key + ".columns", defs);
  const cw = useColumnWidths(key + ".widths");
  const [fit, setFitState] = useState<boolean>(() => {
    try { return localStorage.getItem(key + ".fit") !== "0"; } catch { return true; }
  });
  const setFit = (v: boolean) => {
    setFitState(v);
    try { localStorage.setItem(key + ".fit", v ? "1" : "0"); } catch { /* private mode */ }
  };

  const [tableW, setTableW] = useState(0);
  const observer = useRef<ResizeObserver | null>(null);
  const wrapRef = useCallback((el: HTMLDivElement | null) => {
    observer.current?.disconnect();
    observer.current = null;
    if (!el) return;
    const ro = new ResizeObserver(() => setTableW(el.clientWidth));
    ro.observe(el); setTableW(el.clientWidth);
    observer.current = ro;
  }, []);

  const visible = defs.filter((c) => cols.show(c.key));
  const unsized = visible.filter((c) => !(cw.widths[c.key] > 0));
  const fixedPx = visible.reduce((n, c) => n + (cw.widths[c.key] > 0 ? cw.widths[c.key] : 0), 0);
  const minOf = (c: LayoutDef) => c.min ?? 90;
  const weightOf = (c: LayoutDef) => c.weight ?? 5;
  const minSum = unsized.reduce((n, c) => n + minOf(c), 0);
  const weightSum = unsized.reduce((n, c) => n + weightOf(c), 0);
  const room = Math.max(0, tableW - fixedPx);
  const shrink = tableW > 0 && minSum > room ? room / minSum : 1;
  const colWidth = (c: LayoutDef): number => {
    if (cw.widths[c.key] > 0) return cw.widths[c.key];
    const spare = Math.max(0, room - minSum);
    return Math.floor(minOf(c) * shrink + spare * weightOf(c) / Math.max(1, weightSum));
  };

  const show = (k: string) => cols.show(k);
  /** Props for a SortTh: the dragged width and the drag handler. */
  const th = (k: string) => ({ width: cw.widths[k], onResize: cw.set });
  /** Props for a cell: a dragged column's cells take its width and clip. */
  const td = (k: string, base = ""): { className?: string; style?: CSSProperties } => {
    const w = cw.widths[k];
    return w && w > 0
      ? { className: (base + " clip").trim(), style: { width: w, maxWidth: w, minWidth: w } }
      : { className: base || undefined };
  };
  const colgroup: ReactNode = fit
    ? <colgroup>{visible.map((c) => <col key={c.key} style={{ width: colWidth(c) }} />)}</colgroup>
    : null;
  const controls: ReactNode = (
    <>
      {cw.any && <button className="ghost" onClick={cw.reset} title="Let every column size itself again">Reset widths</button>}
      <button className="ghost" onClick={() => setFit(!fit)}
        title={fit ? "Columns share the screen's width; long values clip, and show in full on hover. Click for natural widths with sideways scrolling."
                   : "Columns take their natural width and the table scrolls sideways. Click to fit the screen."}>
        {fit ? "Fit screen ✓" : "Fit screen"}
      </button>
      <ColumnPicker defs={defs} {...cols} />
    </>
  );
  return { show, visible, th, td, colgroup, controls, wrapRef, tableClass: fit ? "fit" : undefined, fit };
}

/** A plain (unsortable) header cell that still resizes. */
export function PlainTh({ k, width, onResize, children, style, title }: {
  k: string; width?: number; onResize: (key: string, px: number) => void;
  children?: ReactNode; style?: CSSProperties; title?: string;
}) {
  const ref = useRef<HTMLTableCellElement>(null);
  const sized = width && width > 0 ? { width, minWidth: width, maxWidth: width } : {};
  return (
    <th ref={ref} className="resizable" style={{ ...sized, ...style }} title={title}>
      {children}
      <ResizeHandle th={ref} onResize={(px) => onResize(k, px)} />
    </th>
  );
}
