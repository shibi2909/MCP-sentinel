import { FormEvent, useState } from "react";
import { api, setToken, User } from "../api";

const DEMO_ACCOUNTS = [
  { username: "admin", password: "Admin@123", note: "full access" },
  { username: "analyst", password: "Analyst@123", note: "demos, approvals, audit verify" },
  { username: "viewer", password: "Viewer@123", note: "read-only" },
];

export default function Login({ onLogin }: { onLogin: (user: User) => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await api<{ access_token: string; user: User }>("/api/auth/login", {
        method: "POST",
        body: { username, password },
      });
      setToken(result.access_token);
      onLogin(result.user);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid min-h-screen place-items-center px-4">
      <div className="w-full max-w-md">
        <div className="mb-6 flex items-center gap-3">
          <img src="/shield.svg" alt="" className="h-10 w-10" />
          <div>
            <h1 className="text-xl font-semibold">MCP-Sentinel</h1>
            <p className="text-sm text-ink-muted">MCP: A Control-Theoretic Orchestration Framework</p>
          </div>
        </div>
        <form onSubmit={submit} className="card space-y-4">
          <div>
            <label className="label" htmlFor="username">Username</label>
            <input id="username" className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
          </div>
          <div>
            <label className="label" htmlFor="password">Password</label>
            <input id="password" type="password" className="input" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
          </div>
          {error && <p className="text-sm text-status-critical">{error}</p>}
          <button className="btn-primary w-full" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
        </form>
        <div className="mt-4 rounded-xl border border-white/5 p-4 text-xs text-ink-muted">
          <div className="mb-2 font-medium text-ink-secondary">Demo accounts (local demonstration only)</div>
          {DEMO_ACCOUNTS.map((a) => (
            <button
              key={a.username}
              type="button"
              className="flex w-full justify-between rounded px-2 py-1 text-left hover:bg-surface-2"
              onClick={() => { setUsername(a.username); setPassword(a.password); }}
            >
              <span className="font-mono text-ink-secondary">{a.username} / {a.password}</span>
              <span>{a.note}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
