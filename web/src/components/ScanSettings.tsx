import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ParamSpec, ScanProfilePreset } from "../api";
import { useToast, InfoDot } from "./ui";

// Pipeline order, so settings read top-to-bottom the way a scan runs.
const TOOL_ORDER = ["subfinder", "shuffledns", "dnsx", "naabu", "nmap", "httpx", "katana", "gobuster", "nuclei"];

const TOOL_STAGE: Record<string, string> = {
  subfinder: "Subdomain discovery",
  shuffledns: "Subdomain bruteforce",
  dnsx: "DNS resolution",
  naabu: "Port scanning",
  nmap: "Service versions",
  katana: "Web crawling",
  httpx: "Web probing",
  gobuster: "Directory brute force",
  nuclei: "Vulnerability checks",
};

// Where a profile's default differs from the shipped one. Mirrors
// scanparams.ProfileDefaults and ProfileFixed: a run stores these, so they
// must match.
const PROFILE_DEFAULTS: Record<string, Record<string, string>> = {
  passive: { dns_bruteforce: "false" },
  deep: { ports: "full" },
};

// Tools a passive scan never runs: each sends packets at the targets. In a
// passive scan they show as off without their settings; any values already
// set are kept, so a preset saved from here still carries them for a full scan.
const ACTIVE_TOOLS = new Set(["naabu", "nmap", "httpx", "katana", "gobuster", "nuclei"]);

// Tools a follow-up scan never runs: it starts from what an earlier run found,
// so there is nothing to discover. Mirrors scanparams.FollowUpTools.
const FOLLOW_UP_TOOLS = new Set(["subfinder", "shuffledns", "dnsx"]);

/**
 * Per-tool scan settings editor. Shows the shipped default for every parameter,
 * lets the user override any of them, and save the result as a named preset.
 *
 * Values are constrained by the spec the server publishes (type, range, allowed
 * options) — the server re-validates everything, so this is convenience, not
 * the security boundary.
 */
export default function ScanSettings({
  scopeID, profile, values, onChange, presetID, onPresetChange, wordlistIDs, onWordlistsChange, followUp,
}: {
  scopeID: string;
  /** The run's profile: a passive run has DNS bruteforce off unless switched on. */
  profile?: string;
  values: Record<string, string>;
  onChange: (v: Record<string, string>) => void;
  presetID: string;
  onPresetChange: (id: string) => void;
  /** Explicitly chosen lists. A kind with nothing chosen uses its defaults. */
  wordlistIDs: string[];
  onWordlistsChange: (ids: string[]) => void;
  /** A follow-up scan: discovery tools are left out, and so are their lists. */
  followUp?: boolean;
}) {
  const toast = useToast();
  const [specs, setSpecs] = useState<ParamSpec[]>([]);
  const [presets, setPresets] = useState<ScanProfilePreset[]>([]);
  const [saveName, setSaveName] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api.scanParams().then(setSpecs).catch(() => {});
    api.scanProfiles(scopeID).then(setPresets).catch(() => {});
  }, [scopeID]);

  const byTool = useMemo(() => {
    const m: Record<string, ParamSpec[]> = {};
    for (const s of specs) (m[s.tool] ??= []).push(s);
    return m;
  }, [specs]);

  const passive = profile === "passive";
  const deep = profile === "deep";
  // A registry directory list replaces the image's built-in ones, so the
  // dir_wordlist setting only matters on an install without one.
  const { data: dirLists } = useQuery({
    queryKey: ["wordlists", "dir", scopeID], queryFn: () => api.wordlists("dir"),
  });
  const registryDir = (dirLists ?? []).some((l) => l.status === "ready");
  // What a run of this profile does when a setting is left alone; the server
  // stores the same values (scanparams.ProfileDefaults).
  const defaultOf = (s: ParamSpec) => PROFILE_DEFAULTS[profile ?? ""]?.[s.key] ?? s.default;

  const changed = useMemo(
    () => specs.filter((s) => (values[s.key] ?? defaultOf(s)) !== defaultOf(s)).length,
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [specs, values, profile],
  );

  function set(key: string, v: string) {
    onChange({ ...values, [key]: v });
  }

  function resetAll() {
    onChange({});
    onPresetChange("");
    toast("ok", "Reset to defaults");
  }

  function loadPreset(id: string) {
    onPresetChange(id);
    const p = presets.find((x) => x.id === id);
    onChange(p ? { ...p.params } : {});
  }

  async function savePreset() {
    if (!saveName.trim()) return;
    setSaving(true);
    try {
      // Send only genuine overrides so a preset stays readable.
      const overrides: Record<string, string> = {};
      for (const s of specs) {
        const v = values[s.key];
        if (v !== undefined && v !== s.default) overrides[s.key] = v;
      }
      await api.saveScanProfile(scopeID, { name: saveName.trim(), params: overrides });
      toast("ok", `Saved preset "${saveName.trim()}"`);
      setSaveName("");
      setPresets(await api.scanProfiles(scopeID));
    } catch (e) {
      toast("err", String(e));
    } finally {
      setSaving(false);
    }
  }

  if (specs.length === 0) return <div className="muted">Loading settings…</div>;

  const tools = TOOL_ORDER.filter((t) => byTool[t]?.length && !(followUp && FOLLOW_UP_TOOLS.has(t)));
  // Settings a loaded preset carries for tools a follow-up does not run.
  const unused = followUp
    ? specs.filter((s) => FOLLOW_UP_TOOLS.has(s.tool) && values[s.key] !== undefined && values[s.key] !== defaultOf(s)).length
    : 0;

  return (
    <div>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <div className="row" style={{ margin: 0, gap: 8 }}>
          <select value={presetID} onChange={(e) => loadPreset(e.target.value)} style={{ minWidth: 170 }}>
            <option value="">Defaults (Tools.md)</option>
            {presets.map((p) => (
              <option key={p.id} value={p.id}>{p.name}{p.scope_id ? "" : " (shared)"}</option>
            ))}
          </select>
          <span className="muted" style={{ fontSize: 12 }}>
            {changed === 0 ? "all defaults" : `${changed} changed`}
          </span>
        </div>
        <button className="ghost sm" onClick={resetAll} disabled={changed === 0 && !presetID}>
          Reset to defaults
        </button>
      </div>

      {followUp && (
        <div className="hint muted" style={{ margin: "8px 0" }}>
          Discovery is left out — subfinder, shuffledns and dnsx have nothing to do in a scan of names
          and addresses that are already known.
          {unused > 0 && ` ${unused} setting${unused === 1 ? "" : "s"} in this preset belong to them and do not apply.`}
        </div>
      )}

      {tools.map((tool) => passive && ACTIVE_TOOLS.has(tool) ? (
        // A passive run plans none of these, and stores them as off
        // (scanparams.ProfileFixed): show the tool as off, not its knobs.
        <div key={tool} className="tool-group tool-off">
          <div className="tool-head">
            <span className="tool-name">{tool}</span>
            <span className="muted" style={{ fontSize: 12 }}>{TOOL_STAGE[tool] ?? ""}</span>
          </div>
          <div className="param-row">
            <label className="param-label">Enabled</label>
            <label className="param-toggle">
              <input type="checkbox" checked={false} disabled />
              <span className="muted">off — not run by a passive scan: it sends traffic to the targets</span>
            </label>
          </div>
        </div>
      ) : (
        <div key={tool} className="tool-group">
          <div className="tool-head">
            <span className="tool-name">{tool}</span>
            <span className="muted" style={{ fontSize: 12 }}>{TOOL_STAGE[tool] ?? ""}</span>
          </div>
          {passive && tool === "shuffledns" && (
            <div className="hint muted" style={{ marginBottom: 6 }}>
              Off in a passive scan unless you switch it on. It sends nothing to the targets' own
              servers, but a large volume of lookups reaches their nameservers through the resolvers.
            </div>
          )}
          {[...byTool[tool]]
            .sort((a, b) => Number(isEnableKey(b)) - Number(isEnableKey(a)))
            .map((spec) => {
            const val = values[spec.key] ?? defaultOf(spec);
            const isChanged = val !== defaultOf(spec);
            const off = isEnableKey(spec) && val !== "true";
            return (
              <div key={spec.key} className={"param-row" + (off ? " tool-off" : "")}>
                <label className="param-label">
                  {spec.label}
                  <InfoDot title={spec.key}>{spec.help}</InfoDot>
                  {isChanged && <span className="param-changed" title={`default: ${defaultOf(spec)}`}>changed</span>}
                </label>
                {deep && spec.key === "ports" ? (
                  <span className="muted" style={{ fontSize: 12 }}>
                    every port — a deep scan always sweeps the full range
                  </span>
                ) : registryDir && spec.key === "dir_wordlist" ? (
                  <span className="muted" style={{ fontSize: 12 }}>
                    not used — the directory wordlist chosen below is
                  </span>
                ) : (
                  <ParamInput spec={spec} value={val} onChange={(v) => set(spec.key, v)} />
                )}
              </div>
            );
          })}
          {tool === "shuffledns" && (
            <WordlistPicker
              kind="dns" label="Subdomain wordlists" scopeID={scopeID}
              selected={wordlistIDs} onChange={onWordlistsChange}
              hint="Each list you tick becomes its own bruteforce task, so several lists run in parallel across workers. Ticking none uses the lists marked default in the registry."
            />
          )}
          {tool === "dnsx" && (
            <WordlistPicker
              kind="resolvers" label="Resolver list" scopeID={scopeID} single
              selected={wordlistIDs} onChange={onWordlistsChange}
              hint="The nameservers brute-forcing queries through. A run uses one list; choosing none uses the registry default."
            />
          )}
          {tool === "gobuster" && (
            <WordlistPicker
              kind="dir" label="Directory wordlist" scopeID={scopeID} single
              selected={wordlistIDs} onChange={onWordlistsChange}
              hint="Directory search uses one list. Its size is the main thing deciding how loud a scan is."
            />
          )}
        </div>
      ))}

      <div className="row" style={{ marginTop: 16, marginBottom: 0 }}>
        <input
          className="grow"
          placeholder="Save these settings as…"
          value={saveName}
          onChange={(e) => setSaveName(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && savePreset()}
        />
        <button className="ghost" onClick={savePreset} disabled={saving || !saveName.trim()}>
          {saving ? "Saving…" : "Save preset"}
        </button>
      </div>
      <div className="hint muted">Presets are saved for this company and reusable on future scans.</div>
    </div>
  );
}

/** A tool's on/off switch, which leads its group rather than sitting among the knobs. */
function isEnableKey(spec: ParamSpec) {
  return spec.key.endsWith("_enabled") || spec.key === "dns_bruteforce";
}

/**
 * Ticks the lists of one kind a run should use.
 *
 * The launch dialog arrives with the registry's defaults already ticked, so
 * what will run is visible rather than implied. Unticking everything of a kind
 * is still safe: the launcher falls back to those same defaults.
 * Kinds differ in how many lists a run consumes — subdomain brute-forcing runs
 * one task per list, while resolution and directory search take one — which the
 * hint says rather than the UI pretending otherwise.
 */
function WordlistPicker({
  kind, label, scopeID, selected, onChange, hint, single,
}: {
  kind: string; label: string; scopeID: string;
  selected: string[]; onChange: (ids: string[]) => void; hint: string;
  /** The stage uses one list of this kind: choosing one replaces the other. */
  single?: boolean;
}) {
  const { data: lists } = useQuery({
    queryKey: ["wordlists", kind, scopeID], queryFn: () => api.wordlists(kind),
  });
  const all = lists ?? [];
  const ready = all.filter((l) => l.status === "ready");
  const mine = selected.filter((id) => ready.some((l) => l.id === id));

  function toggle(id: string) {
    if (mine.includes(id)) {
      onChange(selected.filter((x) => x !== id));
    } else if (single) {
      // Other kinds' choices stay; this kind's previous choice goes.
      onChange([...selected.filter((x) => !ready.some((l) => l.id === x)), id]);
    } else {
      onChange([...selected, id]);
    }
  }

  if (all.length === 0) return null;

  return (
    <div className="param-row" style={{ alignItems: "flex-start" }}>
      <label className="param-label">
        {label}
        <InfoDot title={label}>{hint}</InfoDot>
        {mine.length > 0 && <span className="param-changed">{mine.length} chosen</span>}
      </label>
      <div style={{ display: "flex", flexDirection: "column", gap: 4, minWidth: 260 }}>
        {ready.map((l) => (
          <label key={l.id} className="param-toggle" style={{ cursor: "pointer" }}>
            <input type={single ? "radio" : "checkbox"} name={single ? `wl-${kind}` : undefined}
              checked={mine.includes(l.id)} onChange={() => toggle(l.id)}
              onClick={() => { if (single && mine.includes(l.id)) toggle(l.id); }} />
            <span>
              {l.name}
              <span className="muted" style={{ fontSize: 11 }}>
                {" "}{l.line_count.toLocaleString()} entries{l.is_default ? " · default" : ""}
              </span>
            </span>
          </label>
        ))}
        {ready.length === 0 && (
          <span className="muted" style={{ fontSize: 12 }}>
            No list of this kind has finished downloading yet.
          </span>
        )}
        {mine.length === 0 && ready.length > 0 && (
          <span className="muted" style={{ fontSize: 11 }}>
            none ticked — using the registry defaults
          </span>
        )}
      </div>
    </div>
  );
}

// ParamInput renders the control the spec's kind calls for, bounded by the
// server-published constraints.
function ParamInput({
  spec, value, onChange,
}: { spec: ParamSpec; value: string; onChange: (v: string) => void }) {
  switch (spec.kind) {
    case "bool":
      return (
        <label className="param-toggle">
          <input type="checkbox" checked={value === "true"}
            onChange={(e) => onChange(e.target.checked ? "true" : "false")} />
          <span className="muted">{value === "true" ? "enabled" : "disabled"}</span>
        </label>
      );
    case "enum":
    case "wordlist":
      return (
        <select value={value} onChange={(e) => onChange(e.target.value)}>
          {(spec.enum ?? []).map((o) => <option key={o} value={o}>{o}</option>)}
        </select>
      );
    case "text":
      return (
        <input
          style={{ width: 320 }}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={spec.default}
          spellCheck={false}
        />
      );
    case "proxy":
      return (
        <textarea
          style={{ width: 320, minHeight: 58, fontFamily: "inherit" }}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={"socks5://host:port\nhttp://user:pass@host:port"}
          spellCheck={false}
        />
      );
    case "csv":
      return (
        <input
          style={{ width: 180 }}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={spec.default || "leave empty for the default"}
          spellCheck={false}
        />
      );
    case "cdn_ports": {
      // Addresses behind a CDN: the web edge by default, the run's own port
      // set ("all"), nothing ("none"), or a list of one's own.
      const preset = ["80,443", "all", "none"].includes(value) ? value : "custom";
      return (
        <div className="row" style={{ margin: 0, gap: 6 }}>
          <select value={preset}
            onChange={(e) => onChange(e.target.value === "custom" ? "80,443,8080,8443" : e.target.value)}>
            <option value="80,443">80 and 443 — the client's site</option>
            <option value="all">same ports as everything else</option>
            <option value="none">none — leave them out</option>
            <option value="custom">custom…</option>
          </select>
          {preset === "custom" && (
            <input style={{ width: 150 }} value={value} onChange={(e) => onChange(e.target.value)}
              placeholder="80,443,8443" />
          )}
        </div>
      );
    }
    case "ports":
      return (
        <div className="row" style={{ margin: 0, gap: 6 }}>
          <select
            value={["top-100", "top-1000", "full"].includes(value) ? value : "custom"}
            onChange={(e) => onChange(e.target.value === "custom" ? "80,443" : e.target.value)}
          >
            <option value="top-100">top-100</option>
            <option value="top-1000">top-1000</option>
            <option value="full">full (1-65535)</option>
            <option value="custom">custom…</option>
          </select>
          {!["top-100", "top-1000", "full"].includes(value) && (
            <input style={{ width: 130 }} value={value} onChange={(e) => onChange(e.target.value)}
              placeholder="80,443 or 1-1024" />
          )}
        </div>
      );
    default: // int
      return (
        <input type="number" style={{ width: 110 }} value={value}
          min={spec.min} max={spec.max}
          onChange={(e) => onChange(e.target.value)} />
      );
  }
}
