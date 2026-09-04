import { FormEvent, useState } from "react";
import { api, AuthStatus } from "../api";

/**
 * The sign-in screen, and on a fresh install the screen that creates the first
 * administrator.
 *
 * Both live here because they are the same moment from the user's side: the app
 * will not show them anything until it knows who they are.
 */
export default function Auth({ status, onSignedIn }: {
  status: AuthStatus;
  onSignedIn: () => void;
}) {
  return (
    <div style={{
      minHeight: "100vh", display: "grid", placeItems: "center", padding: 20,
    }}>
      <div style={{ width: "100%", maxWidth: 380 }}>
        <div style={{ textAlign: "center", marginBottom: 22 }}>
          <div style={{ fontSize: 26, fontWeight: 700, letterSpacing: -0.4 }}>PinkGlasses</div>
          <div className="muted" style={{ fontSize: 13, marginTop: 2 }}>
            External attack surface, continuously watched.
          </div>
        </div>
        {status.setup_required
          ? <SetupForm onDone={onSignedIn} />
          : <LoginForm onDone={onSignedIn} />}
      </div>
    </div>
  );
}

function Card({ title, hint, children }: {
  title: string; hint?: string; children: React.ReactNode;
}) {
  return (
    <div className="card" style={{ padding: 20 }}>
      <div style={{ fontWeight: 600, fontSize: 15 }}>{title}</div>
      {hint && <div className="muted" style={{ fontSize: 12.5, marginTop: 4 }}>{hint}</div>}
      <div style={{ marginTop: 14 }}>{children}</div>
    </div>
  );
}

function Field({ label, ...props }: { label: string } & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label style={{ display: "block", marginBottom: 10 }}>
      <div className="muted" style={{ fontSize: 12, marginBottom: 3 }}>{label}</div>
      <input {...props} style={{ width: "100%", boxSizing: "border-box", ...props.style }} />
    </label>
  );
}

function Err({ msg }: { msg: string }) {
  if (!msg) return null;
  return (
    <div className="empty" style={{
      textAlign: "left", padding: "8px 10px", marginBottom: 10,
      borderColor: "var(--warn)", fontSize: 13,
    }}>{msg}</div>
  );
}

function LoginForm({ onDone }: { onDone: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    beginSubmit();
    try {
      await api.login(username, password);
      onDone();
    } catch (e) {
      setErr(String(e).replace(/^Error:\s*/, ""));
      setBusy(false);
    }
  }
  function beginSubmit() { setErr(""); setBusy(true); }

  return (
    <Card title="Sign in">
      <form onSubmit={submit}>
        <Err msg={err} />
        <Field
          label="Username" value={username} autoFocus autoComplete="username"
          onChange={(e) => setUsername(e.target.value)}
        />
        <Field
          label="Password" type="password" value={password} autoComplete="current-password"
          onChange={(e) => setPassword(e.target.value)}
        />
        <button type="submit" disabled={busy || !username || !password} style={{ width: "100%", marginTop: 6 }}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </Card>
  );
}

function SetupForm({ onDone }: { onDone: () => void }) {
  const [username, setUsername] = useState("");
  const [display, setDisplay] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const tooShort = password.length > 0 && password.length < 12;
  const mismatch = confirm.length > 0 && password !== confirm;
  const ready = username && password.length >= 12 && password === confirm;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setErr(""); setBusy(true);
    try {
      await api.setup({ username, display_name: display, password });
      onDone();
    } catch (e) {
      setErr(String(e).replace(/^Error:\s*/, ""));
      setBusy(false);
    }
  }

  return (
    <Card
      title="Create the first administrator"
      hint="This install has no accounts yet. Whoever does this owns it — the API is
            open until it is done, so do it now, before anything else can reach it."
    >
      <form onSubmit={submit}>
        <Err msg={err} />
        <Field
          label="Username" value={username} autoFocus autoComplete="username"
          onChange={(e) => setUsername(e.target.value)}
        />
        <Field
          label="Display name (optional)" value={display} autoComplete="name"
          onChange={(e) => setDisplay(e.target.value)}
        />
        <Field
          label="Password" type="password" value={password} autoComplete="new-password"
          onChange={(e) => setPassword(e.target.value)}
        />
        <Field
          label="Confirm password" type="password" value={confirm} autoComplete="new-password"
          onChange={(e) => setConfirm(e.target.value)}
        />
        <div className="muted" style={{ fontSize: 12, marginBottom: 10 }}>
          {tooShort
            ? <span style={{ color: "var(--warn)" }}>At least 12 characters.</span>
            : mismatch
              ? <span style={{ color: "var(--warn)" }}>The two passwords do not match.</span>
              : "At least 12 characters. Length is the only rule — it is worth more than punctuation."}
        </div>
        <button type="submit" disabled={busy || !ready} style={{ width: "100%" }}>
          {busy ? "Creating…" : "Create administrator and sign in"}
        </button>
      </form>
    </Card>
  );
}
