import { useState } from "react";
import { Bar, BarChart, CartesianGrid, Cell, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, can, User } from "../api";
import {
  ACTION_STYLE, ActionBadge, axisProps, Card, Empty, ErrorBanner, formatTime, SeverityBadge, StatTile, StatusPill,
  tooltipStyle, useApi,
} from "../components/ui";

const MODE_COLOR: Record<string, string> = { NORMAL: "#0ca30c", ELEVATED: "#fab219", LOCKDOWN: "#d03b3b" };

export default function Overview({ user }: { user: User }) {
  const { data, error, reload } = useApi<any>("/api/dashboard/summary", 4000);
  const [verifyResult, setVerifyResult] = useState<any>(null);
  const [verifying, setVerifying] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  async function verifyAudit() {
    setVerifying(true);
    setActionError(null);
    try {
      setVerifyResult(await api("/api/audit/verify", { method: "POST" }));
      reload();
    } catch (err) {
      setActionError((err as Error).message);
    } finally {
      setVerifying(false);
    }
  }

  if (!data) return <><ErrorBanner error={error} />{!error && <div className="text-ink-muted">Loading dashboard…</div>}</>;
  const t = data.totals;
  const c = data.controller;

  return (
    <div className="space-y-6">
      <ErrorBanner error={error || actionError} />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-6">
        <StatTile label="Total requests" value={t.total} hint={`avg risk ${t.average_risk}`} accent="#3987e5" />
        <StatTile label="Allowed" value={t.allowed} accent={ACTION_STYLE.ALLOW.color} />
        <StatTile label="Blocked" value={t.blocked} accent={ACTION_STYLE.BLOCK.color} />
        <StatTile label="Suspicious" value={t.suspicious} hint={`${t.monitored} monitored · ${t.approval_required} approval`} accent={ACTION_STYLE.MONITOR.color} />
        <StatTile label="Pending approvals" value={t.pending_approvals} accent={ACTION_STYLE.REQUIRE_APPROVAL.color} />
        <StatTile label="Audit records" value={t.audit_records} hint="SHA-256 hash chain" accent="#8f8e86" />
      </div>

      <div className="grid gap-6 xl:grid-cols-3">
        <Card title="Controller state" subtitle={c.security_mode_description} className="xl:col-span-1">
          <div className="mb-4 flex items-center gap-3">
            <span
              className="rounded-md px-2.5 py-1 text-sm font-semibold"
              style={{ color: MODE_COLOR[c.enforcement_mode], background: `${MODE_COLOR[c.enforcement_mode]}1f`, border: `1px solid ${MODE_COLOR[c.enforcement_mode]}55` }}
            >
              {c.enforcement_mode}
            </span>
            <span className="text-xs text-ink-muted">{c.controller_active ? "controller enforcing" : "controller observing only (static thresholds enforced)"}</span>
          </div>
          <dl className="grid grid-cols-2 gap-3 text-sm">
            <Info label="Estimated risk x̂" value={c.estimated_risk.toFixed(3)} />
            <Info label="Setpoint" value={c.config.setpoint} />
            <Info label="Error e" value={c.error.toFixed(3)} />
            <Info label="Integral I" value={c.integral.toFixed(3)} />
            <Info label="Control signal u" value={c.control_signal.toFixed(3)} />
            <Info label="Step" value={c.step} />
          </dl>
          <div className="mt-4 grid grid-cols-3 gap-2 text-center text-xs">
            {(["monitor", "approval", "block"] as const).map((k) => (
              <div key={k} className="rounded-lg bg-surface-2 p-2">
                <div className="uppercase text-ink-muted">{k}</div>
                <div className="text-lg font-semibold tabular-nums">{data.controller.controller_active ? c.thresholds[k] : c.static_thresholds[k]}</div>
              </div>
            ))}
          </div>
        </Card>

        <Card title="Decisions by action" subtitle="All requests processed by the gateway">
          {t.total === 0 ? <Empty>No requests yet. Run a demo scenario.</Empty> : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={data.actions} layout="vertical" margin={{ left: 10, right: 30 }} barCategoryGap={6}>
                <CartesianGrid horizontal={false} stroke="rgba(255,255,255,0.05)" />
                <XAxis type="number" allowDecimals={false} {...axisProps} />
                <YAxis type="category" dataKey="action" width={130} {...axisProps} />
                <Tooltip {...tooltipStyle} cursor={{ fill: "rgba(255,255,255,0.04)" }} />
                <Bar dataKey="count" name="Requests" isAnimationActive={false} radius={[0, 4, 4, 0]} label={{ position: "right", fill: "#c3c2b7", fontSize: 12 }}>
                  {data.actions.map((a: any) => <Cell key={a.action} fill={ACTION_STYLE[a.action as keyof typeof ACTION_STYLE].color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </Card>

        <Card title="Risk score distribution" subtitle="Number of requests per risk band (0-100)">
          {t.total === 0 ? <Empty>No requests yet.</Empty> : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={data.risk_distribution} margin={{ right: 10 }} barCategoryGap={2}>
                <CartesianGrid vertical={false} stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="range" {...axisProps} interval={0} angle={-30} textAnchor="end" height={45} />
                <YAxis allowDecimals={false} {...axisProps} width={30} />
                <Tooltip {...tooltipStyle} cursor={{ fill: "rgba(255,255,255,0.04)" }} />
                <Bar dataKey="count" name="Requests" isAnimationActive={false} fill="#3987e5" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </Card>
      </div>

      <Card title="Recent requests vs. current thresholds" subtitle="Each bar is one request (risk score); colour and tooltip show the action taken">
        {data.timeline.length === 0 ? <Empty>No requests yet.</Empty> : (
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={data.timeline.map((r: any, i: number) => ({ ...r, n: i + 1 }))} barCategoryGap={2}>
              <CartesianGrid vertical={false} stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="n" {...axisProps} />
              <YAxis domain={[0, 100]} {...axisProps} width={30} />
              <Tooltip
                {...tooltipStyle}
                cursor={{ fill: "rgba(255,255,255,0.04)" }}
                formatter={(v: number, _n: string, item: any) => [`${v} → ${item.payload.action}`, item.payload.tool]}
                labelFormatter={(n) => `Request #${n}`}
              />
              {(["monitor", "approval", "block"] as const).map((k) => (
                <ReferenceLine
                  key={k}
                  y={c.controller_active ? c.thresholds[k] : c.static_thresholds[k]}
                  stroke="#8f8e86"
                  strokeDasharray="4 4"
                  label={{ value: k, position: "insideTopRight", fill: "#8f8e86", fontSize: 11 }}
                />
              ))}
              <Bar dataKey="risk_score" name="Risk" isAnimationActive={false} radius={[4, 4, 0, 0]}>
                {data.timeline.map((r: any) => <Cell key={r.id} fill={ACTION_STYLE[r.action as keyof typeof ACTION_STYLE].color} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
        <div className="mt-2 flex flex-wrap gap-3">
          {Object.keys(ACTION_STYLE).map((a) => <ActionBadge key={a} action={a} />)}
        </div>
      </Card>

      <div className="grid gap-6 md:grid-cols-2">
          <Card title="Tool integrity status" subtitle="SHA-256 of approved tool definitions">
            <div className="grid grid-cols-3 gap-2 text-center">
              <IntegrityCount label="Trusted" value={data.integrity.trusted} color="#0ca30c" />
              <IntegrityCount label="Modified" value={data.integrity.modified} color="#d03b3b" />
              <IntegrityCount label="Missing" value={data.integrity.missing} color="#fab219" />
            </div>
            <a href="#integrity" className="mt-3 inline-block text-xs text-accent hover:underline">Open integrity registry →</a>
          </Card>
          <Card title="Audit chain integrity" subtitle="Recompute every hash and link">
            <button className="btn-primary w-full" onClick={verifyAudit} disabled={verifying || !can(user, "audit:verify")}>
              {verifying ? "Verifying…" : "Verify audit-chain integrity"}
            </button>
            {!can(user, "audit:verify") && <p className="mt-2 text-xs text-ink-muted">Your role cannot run verification.</p>}
            {verifyResult && (
              <div className="mt-3 space-y-1 text-sm">
                <StatusPill ok={verifyResult.valid} okText="CHAIN VALID" badText="TAMPERING DETECTED" />
                <div className="text-ink-secondary">{verifyResult.total_records} records checked</div>
                {!verifyResult.valid && (
                  <div className="text-ink-secondary">First invalid record: #{verifyResult.first_invalid_seq} — {verifyResult.problems[0]?.problem}</div>
                )}
              </div>
            )}
          </Card>
      </div>

        <Card title="Recent security events">
          {data.recent_events.length === 0 ? <Empty>No security events recorded.</Empty> : (
            <div className="overflow-x-auto">
              <table className="table-base">
                <thead><tr><th>Time</th><th>Severity</th><th>Event</th><th>Module</th><th>Message</th></tr></thead>
                <tbody>
                  {data.recent_events.map((e: any) => (
                    <tr key={e.id}>
                      <td className="whitespace-nowrap">{formatTime(e.created_at)}</td>
                      <td><SeverityBadge severity={e.severity} /></td>
                      <td className="font-mono text-xs text-ink-primary">{e.event_type}</td>
                      <td className="whitespace-nowrap text-xs">{e.source_module}</td>
                      <td className="min-w-[320px]">{e.message}</td>
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

function Info({ label, value }: { label: string; value: any }) {
  return (
    <div>
      <dt className="text-[11px] uppercase tracking-wide text-ink-muted">{label}</dt>
      <dd className="font-mono tabular-nums text-ink-primary">{value}</dd>
    </div>
  );
}

function IntegrityCount({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="rounded-lg bg-surface-2 p-3">
      <div className="text-2xl font-semibold tabular-nums">{value}</div>
      <div className="flex items-center justify-center gap-1.5 text-xs text-ink-muted">
        <span className="h-2 w-2 rounded-full" style={{ background: color }} aria-hidden />
        {label}
      </div>
    </div>
  );
}
