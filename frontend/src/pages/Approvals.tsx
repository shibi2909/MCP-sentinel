import { useState } from "react";
import { api, can, User } from "../api";
import { Card, Empty, ErrorBanner, formatTime, JsonView, useApi } from "../components/ui";

export default function Approvals({ user }: { user: User }) {
  const [filter, setFilter] = useState("pending");
  const { data, error, reload } = useApi<any[]>(`/api/approvals${filter ? `?status=${filter}` : ""}`, 4000);
  const [notes, setNotes] = useState<Record<number, string>>({});
  const [lastOutcome, setLastOutcome] = useState<any>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const allowed = can(user, "approvals:decide");

  async function decide(id: number, decision: "approve" | "reject") {
    setBusy(id);
    setActionError(null);
    try {
      setLastOutcome(await api(`/api/approvals/${id}/${decision}`, { method: "POST", body: { note: notes[id] ?? "" } }));
      reload();
    } catch (err) {
      setActionError((err as Error).message);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-6">
      <ErrorBanner error={error || actionError} />
      <Card
        title="Human-in-the-loop approval queue (M7)"
        subtitle="REQUIRE_APPROVAL requests wait here. Approval re-checks tool integrity before execution."
        actions={
          <div className="flex gap-1 rounded-lg bg-surface-2 p-1">
            {["pending", "approved", "rejected", ""].map((s) => (
              <button key={s || "all"} onClick={() => setFilter(s)}
                className={`rounded-md px-3 py-1 text-xs ${filter === s ? "bg-surface-3 text-ink-primary" : "text-ink-muted"}`}>
                {s || "all"}
              </button>
            ))}
          </div>
        }
      >
        {!data?.length ? <Empty>No {filter || ""} approvals. Run demo scenario 5 to create one.</Empty> : (
          <div className="space-y-4">
            {data.map((a) => (
              <div key={a.id} className="rounded-lg border border-white/5 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <div className="font-medium">#{a.id} · {a.agent} → <span className="font-mono">{a.server}.{a.tool}</span></div>
                    <div className="text-xs text-ink-muted">{formatTime(a.created_at)} · risk {a.risk_score} · status {a.status}</div>
                  </div>
                  {a.status === "pending" && (
                    <div className="flex flex-wrap items-center gap-2">
                      <input className="input w-48" placeholder="Decision note" value={notes[a.id] ?? ""}
                        onChange={(e) => setNotes({ ...notes, [a.id]: e.target.value })} disabled={!allowed} />
                      <button className="btn-primary" disabled={!allowed || busy === a.id} onClick={() => decide(a.id, "approve")}>Approve & execute</button>
                      <button className="btn-danger" disabled={!allowed || busy === a.id} onClick={() => decide(a.id, "reject")}>Reject</button>
                    </div>
                  )}
                </div>
                <div className="mt-3 grid gap-3 md:grid-cols-2">
                  <div>
                    <div className="label">Arguments</div>
                    <JsonView data={a.arguments} maxHeight={120} />
                  </div>
                  <div>
                    <div className="label">Reasons</div>
                    <ul className="space-y-1 text-sm text-ink-secondary">{a.reasons.map((r: string, i: number) => <li key={i}>• {r}</li>)}</ul>
                    {a.decided_by && <p className="mt-2 text-xs text-ink-muted">Decided by {a.decided_by} at {formatTime(a.decided_at)} {a.decision_note && `— "${a.decision_note}"`}</p>}
                  </div>
                </div>
                {a.result_preview && <div className="mt-3"><div className="label">Execution result</div><JsonView data={a.result_preview} maxHeight={120} /></div>}
              </div>
            ))}
          </div>
        )}
        {!allowed && <p className="mt-3 text-xs text-ink-muted">Your role can view the queue but not decide.</p>}
      </Card>
      {lastOutcome && <Card title="Last decision result"><JsonView data={lastOutcome} /></Card>}
    </div>
  );
}
