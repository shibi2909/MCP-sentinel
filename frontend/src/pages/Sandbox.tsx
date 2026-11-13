import { useState } from "react";
import { api, can, User } from "../api";
import { Card, Empty, ErrorBanner, formatTime, StatusPill, useApi } from "../components/ui";

const OUTCOME_COLOR: Record<string, string> = { completed: "#0ca30c", blocked: "#d03b3b", timeout: "#fab219", error: "#8f8e86" };

export default function Sandbox({ user }: { user: User }) {
  const { data: scenarios, error } = useApi<any[]>("/api/sandbox/scenarios");
  const { data: runs, reload } = useApi<any[]>("/api/sandbox/runs");
  const [running, setRunning] = useState<string | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  const allowed = can(user, "sandbox:run");

  async function run(key: string) {
    setRunning(key);
    setRunError(null);
    try {
      await api(`/api/sandbox/run/${key}`, { method: "POST" });
      reload();
    } catch (err) {
      setRunError((err as Error).message);
    } finally {
      setRunning(null);
    }
  }

  return (
    <div className="space-y-6">
      <ErrorBanner error={error || runError} />
      <Card title="Sandbox simulation (M5)"
        subtitle="Fixed test tools run in a separate isolated Python process (temp folder, empty environment, 3 s timeout, audit-hook guard). No user-supplied code is ever executed.">
        <p className="text-xs text-ink-muted">
          Note: Python audit hooks demonstrate the concept but are not a hardened security boundary. Production deployments should use containers or micro-VMs.
        </p>
      </Card>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {scenarios?.map((s) => (
          <Card key={s.key} title={s.title} subtitle={`Expected outcome: ${s.expected}`}>
            <p className="mb-4 text-sm text-ink-secondary">{s.description}</p>
            <button className="btn-secondary w-full" disabled={!allowed || running !== null} onClick={() => run(s.key)}>
              {running === s.key ? "Running in sandbox…" : "Run in sandbox"}
            </button>
          </Card>
        ))}
      </div>
      <Card title="Sandbox results" subtitle="Recorded in the database and the audit log">
        {!runs?.length ? <Empty>No sandbox runs yet.</Empty> : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead><tr><th>Time</th><th>Scenario</th><th>Outcome</th><th>Expected</th><th>Check</th><th>Duration</th><th>Detail</th></tr></thead>
              <tbody>
                {runs.map((r) => (
                  <tr key={r.id}>
                    <td className="whitespace-nowrap">{formatTime(r.created_at)}</td>
                    <td className="font-mono text-xs">{r.scenario}</td>
                    <td>
                      <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase" style={{ color: OUTCOME_COLOR[r.outcome] }}>
                        <span className="h-2 w-2 rounded-full" style={{ background: OUTCOME_COLOR[r.outcome] }} />{r.outcome}
                      </span>
                    </td>
                    <td className="text-xs uppercase">{r.expected}</td>
                    <td><StatusPill ok={r.passed} okText="as expected" badText="unexpected" /></td>
                    <td className="tabular-nums">{r.duration_ms} ms</td>
                    <td className="text-xs">{r.output}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
