import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, Wordlist } from "../api";
import { useToast, InfoDot, Spinner, Modal } from "./ui";

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
  const [editing, setEditing] = useState<Wordlist | null>(null);

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
                  <button className="ghost sm" disabled={w.status !== "ready"}
                    title={w.size_bytes > 4 << 20
                      ? "Too large to edit here — replace it by uploading a file"
                      : "Edit the entries"}
                    onClick={() => setEditing(w)}>edit</button>
                  {!w.builtin && (
                    <button className="danger sm" style={{ marginLeft: 6 }}
                      onClick={() => remove(w)}>delete</button>
                  )}
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

      <EditModal list={editing} onClose={() => setEditing(null)} onSaved={refetch} />
    </div>
  );
}

/**
 * Edits a list's entries in place. Saving rewrites the object and its content
 * hash, so workers re-download rather than serving the previous version from
 * their content-addressed cache.
 */
function EditModal({
  list, onClose, onSaved,
}: { list: Wordlist | null; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [loadErr, setLoadErr] = useState("");
  const [problems, setProblems] = useState<string[]>([]);

  useEffect(() => {
    if (!list) return;
    setText(""); setLoadErr(""); setProblems([]); setLoading(true);
    api.wordlistContent(list.id)
      .then((r) => setText(r.content))
      .catch((e) => setLoadErr(String(e)))
      .finally(() => setLoading(false));
  }, [list?.id]);

  if (!list) return null;

  // Mirrors the server's normalisation so the count shown matches what is saved.
  const entries = text.split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "" && !l.startsWith("#"));
  const unique = new Set(entries).size;

  async function save() {
    setSaving(true); setProblems([]);
    try {
      const saved = await api.saveWordlistContent(list!.id, text);
      toast("ok", `Saved ${saved.name} — ${saved.line_count.toLocaleString()} entries`);
      onSaved();
      onClose();
    } catch (e) {
      // The server returns the offending lines; show them rather than a blob.
      const msg = String(e);
      try {
        const parsed = JSON.parse(msg.replace(/^Error:\s*/, ""));
        if (parsed.problems) { setProblems(parsed.problems); setSaving(false); return; }
      } catch { /* not structured; fall through */ }
      toast("err", msg);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal
      title={`Edit ${list.name}`} open={!!list} onClose={onClose}
      footer={<>
        <button className="ghost" onClick={onClose}>Cancel</button>
        <button onClick={save} disabled={saving || loading || !!loadErr || unique === 0}>
          {saving ? "Saving…" : `Save ${unique.toLocaleString()} entries`}
        </button>
      </>}
    >
      {loading ? (
        <div className="row"><Spinner /> <span className="muted">Loading…</span></div>
      ) : loadErr ? (
        <div className="empty" style={{ borderColor: "var(--crit)", color: "var(--high)" }}>
          {loadErr}
        </div>
      ) : (
        <>
          <div className="field">
            <label>
              {list.kind === "resolvers" ? "One resolver per line" : "One entry per line"}
            </label>
            <textarea
              rows={16} spellCheck={false}
              style={{ width: "100%", fontFamily: "ui-monospace, monospace", fontSize: 12.5 }}
              value={text} onChange={(e) => setText(e.target.value)}
            />
            <div className="hint">
              {entries.length.toLocaleString()} lines
              {unique !== entries.length && ` · ${(entries.length - unique).toLocaleString()} duplicate(s) will be dropped`}
              {list.kind === "resolvers"
                ? " · IP addresses, optionally with :port. Blank lines and # comments are ignored."
                : " · blank lines and # comments are ignored."}
            </div>
          </div>

          {problems.length > 0 && (
            <div className="empty" style={{ borderColor: "var(--crit)", textAlign: "left" }}>
              <strong className="sev-high">Not saved — fix these lines:</strong>
              <div className="pre" style={{ marginTop: 8 }}>{problems.join("\n")}</div>
            </div>
          )}

          {list.builtin && (
            <p className="muted" style={{ fontSize: 12.5 }}>
              This is a built-in list. Your edits persist and will not be overwritten, but it
              will no longer match the upstream source it was fetched from.
            </p>
          )}
        </>
      )}
    </Modal>
  );
}
