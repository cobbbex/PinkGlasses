import { useEffect, useMemo, useRef, useState } from "react";

export interface GNode { id: string; label: string; type: string }
export interface GEdge { source: string; target: string; via?: string }

interface P { x: number; y: number; vx: number; vy: number }

/**
 * Force-directed asset map (domains -> IPs), the DNSDumpster-style view.
 * Hand-rolled rather than pulling in Cytoscape: a few hundred nodes is well
 * within reach of a simple spring/repulsion simulation, and it keeps the
 * bundle small and the rendering fully themable.
 */
export default function Graph({ nodes, edges, height = 460 }: { nodes: GNode[]; edges: GEdge[]; height?: number }) {
  const [, tick] = useState(0);
  const pos = useRef<Record<string, P>>({});
  const [hover, setHover] = useState<string | null>(null);
  const raf = useRef<number>();

  // Cap what we simulate: beyond this the picture is noise anyway.
  const { ns, es } = useMemo(() => {
    const ns = nodes.slice(0, 300);
    const keep = new Set(ns.map((n) => n.id));
    return { ns, es: edges.filter((e) => keep.has(e.source) && keep.has(e.target)) };
  }, [nodes, edges]);

  useEffect(() => {
    const W = 900, H = height;
    const p: Record<string, P> = {};
    ns.forEach((n, i) => {
      // seed domains left, IPs right — converges faster and reads better
      const bias = n.type === "domain" ? 0.3 : 0.7;
      p[n.id] = {
        x: W * bias + Math.cos(i * 2.4) * 120,
        y: H / 2 + Math.sin(i * 2.4) * (H / 3),
        vx: 0, vy: 0,
      };
    });
    pos.current = p;

    let frames = 0;
    const step = () => {
      const P = pos.current;
      // repulsion
      for (let i = 0; i < ns.length; i++) {
        const a = P[ns[i].id];
        for (let j = i + 1; j < ns.length; j++) {
          const b = P[ns[j].id];
          let dx = a.x - b.x, dy = a.y - b.y;
          let d2 = dx * dx + dy * dy || 0.01;
          if (d2 > 90000) continue;
          const f = 900 / d2;
          const d = Math.sqrt(d2);
          const ux = (dx / d) * f, uy = (dy / d) * f;
          a.vx += ux; a.vy += uy; b.vx -= ux; b.vy -= uy;
        }
      }
      // springs
      for (const e of es) {
        const a = P[e.source], b = P[e.target];
        if (!a || !b) continue;
        const dx = b.x - a.x, dy = b.y - a.y;
        const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
        const f = (d - 110) * 0.008;
        const ux = (dx / d) * f, uy = (dy / d) * f;
        a.vx += ux; a.vy += uy; b.vx -= ux; b.vy -= uy;
      }
      // integrate + centre gravity + damping
      for (const n of ns) {
        const q = P[n.id];
        q.vx += (W / 2 - q.x) * 0.0015;
        q.vy += (H / 2 - q.y) * 0.0015;
        q.vx *= 0.82; q.vy *= 0.82;
        q.x += q.vx; q.y += q.vy;
        q.x = Math.max(30, Math.min(W - 30, q.x));
        q.y = Math.max(24, Math.min(H - 24, q.y));
      }
      tick((v) => v + 1);
      if (++frames < 220) raf.current = requestAnimationFrame(step);
    };
    raf.current = requestAnimationFrame(step);
    return () => { if (raf.current) cancelAnimationFrame(raf.current); };
  }, [ns, es, height]);

  if (!ns.length) return <div className="empty">No asset relationships yet — run a scan.</div>;

  const P = pos.current;
  return (
    <div className="graph-wrap">
      <svg viewBox={`0 0 900 ${height}`} width="100%" height={height} role="img" aria-label="Asset map">
        {es.map((e, i) => {
          const a = P[e.source], b = P[e.target];
          if (!a || !b) return null;
          const lit = hover === e.source || hover === e.target;
          return <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
            stroke={lit ? "var(--accent)" : "var(--border)"} strokeWidth={lit ? 1.6 : 1} />;
        })}
        {ns.map((n) => {
          const q = P[n.id];
          if (!q) return null;
          const isDomain = n.type === "domain";
          return (
            <g key={n.id} transform={`translate(${q.x},${q.y})`}
               onMouseEnter={() => setHover(n.id)} onMouseLeave={() => setHover(null)}>
              <circle r={hover === n.id ? 7 : 5}
                fill={isDomain ? "var(--accent)" : "var(--ok)"} stroke="var(--bg)" strokeWidth="1.5" />
              {(hover === n.id || ns.length <= 60) && (
                <text x={9} y={4} fontSize="10" fill="var(--fg)">{n.label}</text>
              )}
            </g>
          );
        })}
      </svg>
      <div className="graph-legend">
        <span><i style={{ background: "var(--accent)" }} /> domain</span>
        <span><i style={{ background: "var(--ok)" }} /> host</span>
        <span className="muted">{ns.length} nodes · {es.length} edges{nodes.length > ns.length ? ` (of ${nodes.length})` : ""}</span>
      </div>
    </div>
  );
}
