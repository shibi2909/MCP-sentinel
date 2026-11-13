import { useState } from "react";
import { api, can, User } from "../api";
import DecisionView from "../components/DecisionView";
import { Card, ErrorBanner, JsonView, StatusPill, useApi } from "../components/ui";

export default function Demos({ user }: { user: User }) {
  const { data: scenarios, error } = useApi<any[]>("/api/demo/scenarios");
  const [results, setResults] = useState<Record<number, any>>({});
  const [running, setRunning] = useState<number | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  const allowed = can(user, "demo:run");

  async function run(id: number) {
    setRunning(id);
    setRunError(null);
    try {
      const result = await api(`/api/demo/scenarios/${id}/run`, { method: "POST" });
      setResults((prev) => ({ ...prev, [id]: result }));
    } catch (err) {
      setRunError((err as Error).message);
    } finally {
      setRunning(null);
    }
  }

  async function runAll() {
    for (const s of scenarios ?? []) await run(s.id);
  }

  return (
    <div className="space-y-6">
      <ErrorBanner error={error || runError} />
      <Card
        title="Demonstration scenarios"
        subtitle="Each button sends real requests through the gateway pipeline and checks the decision against the expected outcome."
        actions={<button className="btn-primary" onClick={runAll} disabled={!allowed || running !== null}>Run all 7</button>}
      >
        {!allowed && <p className="text-sm text-ink-muted">Your role ({user.role}) can view but not run scenarios.</p>}
      </Card>
      <div className="grid gap-6 xl:grid-cols-2">
        {scenarios?.map((s) => {
          const result = results[s.id];
          return (
            <Card
              key={s.id}
              title={`${s.id}. ${s.title}`}
              subtitle={`Expected: ${s.expected}`}
              actions={
                <button className="btn-secondary" onClick={() => run(s.id)} disabled={!allowed || running !== null}>
                  {running === s.id ? "Running…" : "Run scenario"}
                </button>
              }
            >
              <p className="mb-3 text-sm text-ink-secondary">{s.description}</p>
              {result && (
                <div className="space-y-4 border-t border-white/5 pt-4">
                  <StatusPill ok={result.passed} okText="PASSED — behaved as expected" badText="UNEXPECTED RESULT" />
                  {result.steps.map((step: any, i: number) => (
                    <div key={i} className="rounded-lg border border-white/5 p-3">
                      <div className="mb-3 flex flex-wrap items-center justify-between gap-2 text-sm">
                        <span className="font-medium">{step.label}</span>
                        <span className="text-xs text-ink-muted">expected {step.expected} · got {step.actual}</span>
                      </div>
                      {step.outcome?.action ? <DecisionView outcome={step.outcome} /> : <JsonView data={step.outcome} />}
                    </div>
                  ))}
                  {result.notes.map((n: string, i: number) => <p key={i} className="text-xs text-ink-muted">ℹ {n}</p>)}
                </div>
              )}
            </Card>
          );
        })}
      </div>
    </div>
  );
}
