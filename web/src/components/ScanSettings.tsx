import { useEffect, useMemo, useState } from "react";
import { api, ParamSpec, ScanProfilePreset } from "../api";
import { useToast, InfoDot } from "./ui";

// Pipeline order, so settings read top-to-bottom the way a scan runs.
const TOOL_ORDER = ["shuffledns", "dnsx", "naabu", "nmap", "katana", "httpx", "gobuster", "nuclei"];

const TOOL_STAGE: Record<string, string> = {
  shuffledns: "Subdomain bruteforce",
  dnsx: "DNS resolution",
  naabu: "Port scanning",
  nmap: "Service versions",
  katana: "Web crawling",
  httpx: "Web probing",
  gobuster: "Directory search",
  nuclei: "Vulnerability checks",
};

/**
 * Per-tool scan settings editor. Shows the shipped default for every parameter,
 * lets the user override any of them, and save the result as a named preset.
 *
 * Values are constrained by the spec the server publishes (type, range, allowed
 * options) — the server re-validates everything, so this is convenience, not
 * the security boundary.
 */
export default function ScanSettings({
  scopeID, values, onChange, presetID, onPresetChange,
}: {
  scopeID: string;
  values: Record<string, string>;
  onChange: (v: Record<string, string>) => void;
  presetID: string;
  onPresetChange: (id: string) => void;
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

  const changed = useMemo(
    () => specs.filter((s) => (values[s.key] ?? s.default) !== s.default).length,
    [specs, values],
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

  const tools = TOOL_ORDER.filter((t) => byTool[t]?.length);

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

      {tools.map((tool) => (
        <div key={tool} className="tool-group">
          <div className="tool-head">
            <span className="tool-name">{tool}</span>
            <span className="muted" style={{ fontSize: 12 }}>{TOOL_STAGE[tool] ?? ""}</span>
          </div>
          {byTool[tool].map((spec) => {
            const val = values[spec.key] ?? spec.default;
            const isChanged = val !== spec.default;
            return (
              <div key={spec.key} className="param-row">
                <label className="param-label">
                  {spec.label}
                  <InfoDot title={spec.key}>{spec.help}</InfoDot>
                  {isChanged && <span className="param-changed" title={`default: ${spec.default}`}>changed</span>}
                </label>
                <ParamInput spec={spec} value={val} onChange={(v) => set(spec.key, v)} />
              </div>
            );
          })}
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
