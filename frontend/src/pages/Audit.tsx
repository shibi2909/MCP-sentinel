import { useState } from "react";
import { api, can, User } from "../api";
import { Card, ErrorBanner, JsonView, shortHash, StatusPill, useApi } from "../components/ui";

export default function Audit({ user }: { user: User }) {
  const { data, error, reload } = useApi<any>("/api/audit?limit=200", 5000);
  const [verification, setVerification] = useState<any>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [selected, setSelected] = useState<any>(null);
  const [busy, setBusy] = useState(false);

  async function run(path: string, handler: (r: any) => void) {
    setBusy(true);
    setActionError(null);
    try {
      handler(await api(path, { method: "POST" }));
      reload();
    } catch (err) {
      setActionError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const invalidSeqs = new Set<number>((verification?.problems ?? []).map((p: any) => p.seq));
  const tamperedSeqs = new Set<number>(data?.tampered_demo_records ?? []);

  return (
    <div className="space-y-6">
      <ErrorBanner error={error || actionError} />
      <Card
        title="Tamper-evident audit log (M9)"
        subtitle="hash = SHA-256(record fields + previous record's hash). Editing any record breaks the chain."
        actions={
          <>
            <button className="btn-primary" disabled={busy || !can(user, "audit:verify")} onClick={() => run("/api/audit/verify", setVerification)}>
              Verify chain integrity
            </button>
            {can(user, "audit:tamper_demo") && (
              <>
                <button className="btn-danger" disabled={busy}
                  onClick={() => run("/api/audit/tamper-demo", (r) => { setMessage(`Record #${r.seq} modified directly in the database: ${JSON.stringify(r.original)} → ${JSON.stringify(r.tampered)}. Now click Verify.`); setVerification(null); })}>
                  Simulate tampering
                </button>
                <button className="btn-secondary" disabled={busy || tamperedSeqs.size === 0}
                  onClick={() => run("/api/audit/restore-demo", (r) => { setMessage(`Restored records ${r.restored.join(", ") || "none"}.`); setVerification(r.verification); })}>
                  Undo tampering
                </button>
              </>
            )}
          </>
        }
      >
        {message && <p className="mb-3 text-sm text-ink-secondary">ℹ {message}</p>}
        {verification && (
          <div className="mb-4 space-y-1 rounded-lg bg-surface-2 p-3 text-sm">
            <StatusPill ok={verification.valid} okText="CHAIN VALID — no tampering detected" badText="INTEGRITY VERIFICATION FAILURE" />
            <div className="text-ink-secondary">{verification.total_records} records verified · latest hash <span className="font-mono text-xs">{shortHash(verification.latest_hash)}</span></div>
            {verification.problems.map((p: any, i: number) => (
              <div key={i} className="text-ink-secondary"><span className="text-status-critical">✕</span> record #{p.seq}: {p.problem}</div>
            ))}
          </div>
        )}
        <div className="text-xs text-ink-muted">{data?.total ?? 0} records in total (showing latest 200)</div>
        <div className="mt-2 overflow-x-auto">
          <table className="table-base">
            <thead><tr><th>#</th><th>Timestamp</th><th>Event</th><th>Actor</th><th>Action</th><th>Risk</th><th>Prev hash</th><th>Record hash</th></tr></thead>
            <tbody>
              {data?.records.map((r: any) => (
                <tr key={r.seq} onClick={() => setSelected(r)}
                  className={`cursor-pointer hover:bg-surface-2 ${invalidSeqs.has(r.seq) ? "bg-status-critical/10" : ""}`}>
                  <td className="tabular-nums text-ink-primary">
                    {r.seq}{tamperedSeqs.has(r.seq) && <span className="ml-1 text-status-critical" title="modified by tampering demo">✎</span>}
                  </td>
                  <td className="whitespace-nowrap font-mono text-xs">{r.timestamp.slice(0, 19).replace("T", " ")}</td>
                  <td className="font-mono text-xs">{r.event_type}</td>
                  <td>{r.actor}</td>
                  <td className="font-mono text-xs text-ink-primary">{r.action}</td>
                  <td className="tabular-nums">{r.risk_score ?? ""}</td>
                  <td className="font-mono text-xs">{shortHash(r.prev_hash)}</td>
                  <td className="font-mono text-xs">{shortHash(r.record_hash)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      {selected && <Card title={`Audit record #${selected.seq}`} actions={<button className="btn-secondary" onClick={() => setSelected(null)}>Close</button>}><JsonView data={selected} /></Card>}
    </div>
  );
}
