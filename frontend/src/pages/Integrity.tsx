import { Fragment, useState } from "react";
import { api, can, User } from "../api";
import { Card, ErrorBanner, formatTime, JsonView, shortHash, StatusPill, useApi } from "../components/ui";

export default function Integrity({ user }: { user: User }) {
  const { data, error, reload } = useApi<any>("/api/integrity/tools", 5000);
  const [checkResult, setCheckResult] = useState<any>(null);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function act(path: string, keep = false) {
    setBusy(true);
    setActionError(null);
    try {
      const result = await api(path, { method: "POST" });
      if (keep) setCheckResult(result);
      reload();
    } catch (err) {
      setActionError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const tampered: Record<string, string[]> = data?.simulated_tampering ?? {};
  const servers: string[] = Array.from(new Set((data?.tools ?? []).map((t: any) => t.server)));

  return (
    <div className="space-y-6">
      <ErrorBanner error={error || actionError} />
      <Card
        title="Trusted tool registry (M3)"
        subtitle="Approved SHA-256 hash of each canonical tool definition vs. the hash of what the server advertises now (MCP tools/list)."
        actions={<button className="btn-primary" disabled={busy || !can(user, "integrity:check")} onClick={() => act("/api/integrity/check", true)}>Run integrity check</button>}
      >
        {checkResult && (
          <div className="mb-4"><StatusPill ok={checkResult.all_trusted} okText="ALL TOOLS MATCH APPROVED HASHES" badText="INTEGRITY VIOLATION DETECTED" /></div>
        )}
        <div className="overflow-x-auto">
          <table className="table-base">
            <thead><tr><th>Server</th><th>Tool</th><th>Sensitivity</th><th>Status</th><th>Approved hash</th><th>Current hash</th><th>Last checked</th><th></th></tr></thead>
            <tbody>
              {data?.tools.map((t: any) => (
                <Fragment key={t.id}>
                  <tr>
                    <td>{t.server}</td>
                    <td className="font-mono text-xs text-ink-primary">{t.name}</td>
                    <td className="capitalize">{t.sensitivity}</td>
                    <td><StatusPill ok={t.integrity_status === "trusted"} okText="trusted" badText={t.integrity_status} /></td>
                    <td className="font-mono text-xs">{shortHash(t.approved_hash)}</td>
                    <td className={`font-mono text-xs ${t.current_hash !== t.approved_hash ? "text-status-critical" : ""}`}>{shortHash(t.current_hash)}</td>
                    <td className="whitespace-nowrap">{formatTime(t.last_checked)}</td>
                    <td className="whitespace-nowrap">
                      <button className="text-xs text-accent hover:underline" onClick={() => setExpanded(expanded === t.id ? null : t.id)}>
                        {expanded === t.id ? "hide" : "compare"}
                      </button>
                      {t.integrity_status === "modified" && can(user, "integrity:manage") && (
                        <button className="ml-3 text-xs text-status-serious hover:underline" disabled={busy}
                          onClick={() => window.confirm("Accept the CURRENT (changed) definition as trusted? Only do this after reviewing the change.") && act(`/api/integrity/tools/${t.id}/approve`)}>
                          approve new definition
                        </button>
                      )}
                    </td>
                  </tr>
                  {expanded === t.id && (
                    <tr>
                      <td colSpan={8}>
                        <div className="grid gap-3 md:grid-cols-2">
                          <div><div className="label">Approved definition</div><JsonView data={t.approved_definition} maxHeight={220} /></div>
                          <div><div className="label">Current definition (from server)</div><JsonView data={t.current_definition} maxHeight={220} /></div>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Simulated servers" subtitle="Demo control: restore the original trusted tool definitions after the tool-poisoning scenario.">
        <div className="grid gap-3 md:grid-cols-3">
          {servers.map((s) => (
            <div key={s} className="rounded-lg border border-white/5 p-3">
              <div className="font-mono text-sm">{s}</div>
              <div className="mb-3 mt-1 text-xs text-ink-muted">
                {tampered[s]?.length ? `Tampered tools: ${tampered[s].join(", ")}` : "Serving original definitions"}
              </div>
              <button className="btn-secondary w-full" disabled={busy || !can(user, "integrity:manage")} onClick={() => act(`/api/integrity/servers/${s}/restore`)}>
                Restore trusted definition
              </button>
            </div>
          ))}
        </div>
        {!can(user, "integrity:manage") && <p className="mt-3 text-xs text-ink-muted">Only admins can restore servers or approve definitions.</p>}
      </Card>
    </div>
  );
}
