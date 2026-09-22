import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, Role, User } from "../api";
import { InfoDot, useToast } from "../components/ui";

/**
 * The MCP page: where an AI client connects, with what, and the skill that
 * teaches it to use this server well. The server runs inside the api at
 * /mcp on this same address, so the endpoint is derived from the page's own
 * origin. A token can be minted here and is shown once, and while it is on
 * screen the snippets below carry it, ready to paste.
 */
export default function MCP({ me }: { me: User }) {
  const toast = useToast();
  const { data } = useQuery({ queryKey: ["mcp-settings"], queryFn: () => api.mcpSettings() });
  const origin = window.location.origin;
  const endpoint = `${origin}${data?.path ?? "/mcp"}`;

  const [tokenName, setTokenName] = useState("mcp");
  const roles: Role[] = (["viewer", "operator", "admin"] as Role[]).filter((r) => atMost(r, me.role));
  const [role, setRole] = useState<Role>(roles.includes("operator") ? "operator" : roles[0]);
  const [ttl, setTtl] = useState(90);
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);

  async function mint() {
    setBusy(true);
    try {
      const r = await api.createToken({ name: tokenName.trim() || "mcp", role, ttl_days: ttl });
      setSecret(r.secret);
      toast("ok", "Token created — it is shown once, here");
    } catch (e) { toast("err", String(e).replace(/^Error:\s*/, "")); } finally { setBusy(false); }
  }
  const tok = secret || "pgt_…";
  const copy = async (text: string, what: string) => {
    try { await navigator.clipboard.writeText(text); toast("ok", `${what} copied`); }
    catch { toast("err", "Could not copy; select the text instead"); }
  };

  const claudeCode = `claude mcp add --transport http pinkglasses ${endpoint} \\\n  --header "Authorization: Bearer ${tok}"`;
  const cursor = JSON.stringify({ mcpServers: { pinkglasses: { url: endpoint, headers: { Authorization: `Bearer ${tok}` } } } }, null, 2);
  const stdio = JSON.stringify({ mcpServers: { pinkglasses: { command: "docker", args: [
    "run", "-i", "--rm", "--network", "host",
    `-e`, `ASM_API_URL=${origin}`, `-e`, `ASM_MCP_TOKEN=${tok}`,
    "--entrypoint", "/usr/local/bin/mcp", "ghcr.io/cobbbex/pinkglasses:latest",
  ] } } }, null, 2);

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>
            MCP
            <InfoDot title="What this is">
              <p style={{ marginTop: 0 }}>
                An AI client — Claude Code, Cursor, Claude Desktop, anything that speaks the Model
                Context Protocol — can do what this app does: read the inventory and findings, search,
                triage what changed, and start and watch scans.
              </p>
              <p className="muted" style={{ marginBottom: 0 }}>
                The server runs inside this app and answers at the address below. It holds no
                credential of its own: each client brings an API token, and everything it does is
                audited under that token's account with that token's role.
              </p>
            </InfoDot>
          </h2>
          <div className="sub">Connect an AI client to this PinkGlasses, and give it the skill to use it well.</div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-title" style={{ marginTop: 0 }}>1. The server</div>
        <div className="row">
          <code className="mono grow" style={{ fontSize: 14 }}>{endpoint}</code>
          <button className="ghost sm" onClick={() => copy(endpoint, "Endpoint")}>Copy</button>
        </div>
        <div className="hint muted">
          Both MCP transports are served here: streamable HTTP and the older SSE transport. Reachable
          wherever this page is; if a reverse proxy sits in front, it must pass the
          <code> Authorization</code> header and not buffer this path.
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-title" style={{ marginTop: 0 }}>2. A token for the client</div>
        <div className="hint muted" style={{ marginBottom: 8 }}>
          The client authenticates with an API token of yours. A <strong>viewer</strong> token gives a
          read-only server; <strong>operator</strong> lets it start scans. Tokens are also managed under
          Accounts → API tokens.
        </div>
        <div className="row">
          <input style={{ width: 160 }} value={tokenName} onChange={(e) => setTokenName(e.target.value)} placeholder="name" />
          <select value={role} onChange={(e) => setRole(e.target.value as Role)}>
            {roles.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
          <label className="muted" style={{ fontSize: 12.5 }}>expires in</label>
          <input type="number" min={1} max={3650} style={{ width: 80 }} value={ttl} onChange={(e) => setTtl(Number(e.target.value) || 90)} />
          <span className="muted" style={{ fontSize: 12.5 }}>days</span>
          <button onClick={mint} disabled={busy}>{busy ? "Creating…" : "Create token"}</button>
        </div>
        {secret && (
          <div className="row" style={{ marginTop: 10 }}>
            <code className="mono grow" style={{ fontSize: 13, wordBreak: "break-all" }}>{secret}</code>
            <button className="ghost sm" onClick={() => copy(secret, "Token")}>Copy</button>
            <span className="muted" style={{ fontSize: 12 }}>Shown once. The snippets below carry it while it is here.</span>
          </div>
        )}
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-title" style={{ marginTop: 0 }}>3. Connect a client</div>
        <Snippet title="Claude Code" text={claudeCode} onCopy={copy} />
        <Snippet title="Cursor — Settings → MCP → Add new global MCP server (~/.cursor/mcp.json)" text={cursor} onCopy={copy} />
        <Snippet title="Over stdio through Docker (Claude Desktop, or a client that cannot speak HTTP)" text={stdio} onCopy={copy} />
        <div className="hint muted">
          A file with a token in it is a credential: keep <code>mcp.json</code> out of version control.
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-title" style={{ marginTop: 0 }}>4. The skill</div>
        <div className="hint muted" style={{ marginBottom: 10 }}>
          A skill is a folder an AI client reads to know how to use a tool well: when to reach for
          which call, how companies, target groups, authorization and exits fit together, the search
          query language, and a reference of every tool this server exposes, generated from the server
          itself. Unpack it into <code>~/.claude/skills/</code> (Claude Code, for every project) or
          <code> .claude/skills/</code> inside a project; other clients that read <code>SKILL.md</code>
          folders take the same.
        </div>
        <a className="btn-link" href={api.mcpSkillURL} download="pinkglasses-skill.zip">⬇ Download the skill (zip)</a>
      </div>

      <div className="card">
        <div className="section-title" style={{ marginTop: 0 }}>
          What the client can do
          <span className="muted" style={{ fontWeight: 400, fontSize: 12.5, marginLeft: 8 }}>
            {data ? `${data.tools.length} tools` : ""}
            {data?.allow_delete_company ? " · delete_company is enabled on this install" : ""}
          </span>
        </div>
        {!data ? <div className="muted">Loading…</div> : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Tool</th><th>Does</th><th></th></tr></thead>
              <tbody>
                {data.tools.map((t) => (
                  <tr key={t.name}>
                    <td className="mono" style={{ whiteSpace: "nowrap" }}>{t.name}</td>
                    <td className="wrap" style={{ fontSize: 13 }}>{t.description}</td>
                    <td style={{ whiteSpace: "nowrap" }}>
                      {t.read_only && <span className="pill">read-only</span>}
                      {t.destructive && <span className="pill" title="Refuses unless called with confirm: true">destructive</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function Snippet({ title, text, onCopy }: { title: string; text: string; onCopy: (t: string, what: string) => void }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div className="row" style={{ marginBottom: 4 }}>
        <span className="muted grow" style={{ fontSize: 12.5 }}>{title}</span>
        <button className="ghost sm" onClick={() => onCopy(text, title.split(" — ")[0])}>Copy</button>
      </div>
      <pre className="mono" style={{ margin: 0, padding: 10, background: "var(--panel2)", border: "1px solid var(--border)", borderRadius: 7, fontSize: 12.5, overflowX: "auto", whiteSpace: "pre" }}>{text}</pre>
    </div>
  );
}

const RANK: Record<Role, number> = { viewer: 1, operator: 2, admin: 3 };
function atMost(r: Role, max: Role) { return RANK[r] <= RANK[max]; }
