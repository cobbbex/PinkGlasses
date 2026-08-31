import { useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, Wordlist } from "../api";
import { useToast, InfoDot, Spinner } from "./ui";

function human(n: number) {
  if (n > 1e9) return (n / 1e9).toFixed(1) + " GB";
  if (n > 1e6) return (n / 1e6).toFixed(1) + " MB";
  if (n > 1e3) return (n / 1e3).toFixed(0) + " KB";
  return n + " B";
}

/**
 * Wordlist registry. Files live in object storage, not in the worker image —
 * the shipped assetnote DNS lists are millions of lines each, and workers
 * download them once and cache by content hash.
 */
const KINDS = [
  { id: "dns", label: "Subdomain wordlists",
    blurb: "Brute-forced by shuffledns. Every list marked default runs as its own task, so several lists spread across workers instead of running one after another." },
  { id: "resolvers", label: "DNS resolvers",
    blurb: "The nameservers shuffledns queries. A large, healthy resolver list is what makes brute-forcing fast and keeps false positives down — a stale one is the usual cause of a slow or wrong brute force." },
];

export default function Wordlists() {
  const toast = useToast();
  const [kind, setKind] = useState("dns");
  const { data: lists, refetch, isLoading } = useQuery({
    queryKey: ["wordlists", kind], queryFn: () => api.wordlists(kind),
    refetchInterval: (q) =>
      (q.state.data ?? []).some((w: Wordlist) => w.status !== "ready" && w.status !== "failed")
        ? 4000 : false,
  });
  const fileRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);

  async function upload(f: File) {
    setBusy(true);
    try {
      const name = prompt("Name for this list", f.name.replace(/\.[^.]+$/, "")) ?? f.name;
      await api.uploadWordlist(f, name, kind);
      toast("ok", `Uploaded ${name}`);
      refetch();
    } catch (e) {
      toast("err", String(e));
    } finally {
      setBusy(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  async function toggle(w: Wordlist) {
    try {
      await api.setWordlistDefault(w.id, !w.is_default);
      refetch();
    } catch (e) { toast("err", String(e)); }
  }

  async function remove(w: Wordlist) {
    if (!confirm(`Delete "${w.name}"?`)) return;
    try {
      await api.deleteWordlist(w.id);
      toast("ok", `Deleted ${w.name}`);
      refetch();
    } catch (e) { toast("err", String(e)); }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>
            {KINDS.find((k) => k.id === kind)?.label}
            <InfoDot title="How wordlists are used">
              <p style={{ marginTop: 0 }}>
                Every list marked <strong>default</strong> is brute-forced during a standard
                scan, each as its own task, so several lists run on different workers rather
                than one after another.
              </p>
              <p className="muted" style={{ marginBottom: 0 }}>
                Files are stored centrally and downloaded by each worker once, then cached by
                content hash — they are not baked into the worker image.
              </p>
            </InfoDot>
          </h2>
          <div className="sub">{KINDS.find((k) => k.id === kind)?.blurb}</div>
        </div>
        <div className="row" style={{ margin: 0 }}>
          {isLoading && <Spinner />}
          <input ref={fileRef} type="file" accept=".txt,text/plain" style={{ display: "none" }}
            onChange={(e) => e.target.files?.[0] && upload(e.target.files[0])} />
          <button disabled={busy} onClick={() => fileRef.current?.click()}>
            {busy ? "Uploading…" : "+ Add wordlist"}
          </button>
        </div>
      </div>

      <div className="row">
        {KINDS.map((k) => (
          <button key={k.id} className={kind === k.id ? "" : "ghost"} onClick={() => setKind(k.id)}>
            {k.label}
          </button>
        ))}
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th><th>Status</th><th>{kind === "resolvers" ? "Resolvers" : "Words"}</th><th>Size</th>
              <th>Used by default</th><th></th>
            </tr>
          </thead>
          <tbody>
            {(lists ?? []).map((w) => (
              <tr key={w.id}>
                <td>
                  {w.name}
                  {w.builtin && <span className="pill" style={{ marginLeft: 6 }}>built-in</span>}
                  {w.error && <div className="sev-high" style={{ fontSize: 11.5 }}>{w.error}</div>}
                </td>
                <td>
                  <span className={"badge b-" + (w.status === "ready" ? "active"
                    : w.status === "failed" ? "failed" : "pending")}>{w.status}</span>
                </td>
                <td className="mono">{w.line_count ? w.line_count.toLocaleString() : "—"}</td>
                <td className="mono">{w.size_bytes ? human(w.size_bytes) : "—"}</td>
                <td>
                  <label className="param-toggle">
                    <input type="checkbox" checked={w.is_default}
                      disabled={w.status !== "ready"}
                      onChange={() => toggle(w)} />
                    <span className="muted">{w.is_default ? "yes" : "no"}</span>
                  </label>
                </td>
                <td style={{ textAlign: "right" }}>
                  {!w.builtin && <button className="danger sm" onClick={() => remove(w)}>delete</button>}
                </td>
              </tr>
            ))}
            {(lists ?? []).length === 0 && (
              <tr><td colSpan={6} className="muted">No wordlists registered.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <p className="muted" style={{ fontSize: 12.5, marginTop: 10 }}>
        Built-in lists are downloaded automatically the first time the stack starts; until
        that finishes they show as <span className="mono">pending</span> and are skipped by
        scans. Uploads are plain text, one entry per line.
      </p>
    </div>
  );
}
