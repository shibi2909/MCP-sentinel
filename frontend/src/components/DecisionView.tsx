import { ActionBadge, JsonView, SeverityBadge } from "./ui";

/** Explains one gateway decision: action, score breakdown, findings and the (redacted) result. */
export default function DecisionView({ outcome }: { outcome: any }) {
  if (!outcome) return null;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <ActionBadge action={outcome.action} />
        <span className="text-sm text-ink-secondary">
          {outcome.agent} → <span className="font-mono">{outcome.server}.{outcome.tool}</span>
        </span>
        {outcome.violation && (
          <span className="rounded bg-status-critical/15 px-2 py-0.5 font-mono text-xs text-ink-primary">{outcome.violation}</span>
        )}
        <span className="text-xs text-ink-muted">status: {outcome.status}</span>
        {outcome.approval_id && <span className="text-xs text-ink-muted">approval #{outcome.approval_id}</span>}
      </div>

      <div className="grid gap-3 sm:grid-cols-4">
        <Metric label="Final risk" value={outcome.risk_score} />
        <Metric label="Rule-based score" value={outcome.rule_score} />
        <Metric label="ML score" value={outcome.ml_score ?? "not used"} />
        <Metric label="Mode" value={outcome.security_mode} small />
      </div>

      <div>
        <div className="label">Why this decision</div>
        <ul className="space-y-1 text-sm text-ink-secondary">
          {outcome.reasons?.map((r: string, i: number) => <li key={i}>• {r}</li>)}
        </ul>
      </div>

      {outcome.risk_factors?.length > 0 && (
        <div>
          <div className="label">Risk factors ({outcome.risk_method})</div>
          <div className="space-y-1.5">
            {outcome.risk_factors.map((f: any) => (
              <div key={f.factor} className="flex items-center gap-3 text-sm">
                <div className="w-48 shrink-0 font-mono text-xs text-ink-secondary">{f.factor}</div>
                <div className="h-2 flex-1 rounded bg-surface-0">
                  <div className="h-2 rounded bg-accent" style={{ width: `${Math.min(100, f.points)}%` }} />
                </div>
                <div className="w-12 text-right tabular-nums text-ink-primary">+{f.points}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {outcome.validation_findings?.length > 0 && (
        <FindingList title="Input validation findings (M4)" items={outcome.validation_findings.map((f: any) => ({ ...f, detail: `${f.field}: ${f.detail}` }))} />
      )}
      {outcome.output_findings?.length > 0 && <FindingList title="Output anomalies (M8)" items={outcome.output_findings} />}
      {outcome.integrity && outcome.integrity.status !== "trusted" && (
        <div>
          <div className="label">Integrity check (M3)</div>
          <JsonView data={outcome.integrity} maxHeight={180} />
        </div>
      )}
      {(outcome.result || outcome.error) && (
        <div>
          <div className="label">{outcome.result ? "MCP result returned to agent (redacted if needed)" : "Error returned to agent"}</div>
          <JsonView data={outcome.result ?? outcome.error} maxHeight={200} />
        </div>
      )}
    </div>
  );
}

function Metric({ label, value, small }: { label: string; value: any; small?: boolean }) {
  return (
    <div className="rounded-lg bg-surface-2 px-3 py-2">
      <div className="text-[11px] uppercase tracking-wide text-ink-muted">{label}</div>
      <div className={`${small ? "text-xs" : "text-xl"} font-semibold tabular-nums`}>{value}</div>
    </div>
  );
}

function FindingList({ title, items }: { title: string; items: any[] }) {
  return (
    <div>
      <div className="label">{title}</div>
      <ul className="space-y-1">
        {items.map((f, i) => (
          <li key={i} className="flex flex-wrap items-center gap-3 text-sm">
            <SeverityBadge severity={f.severity} />
            <span className="font-mono text-xs text-ink-primary">{f.category}</span>
            <span className="text-ink-secondary">{f.detail}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
