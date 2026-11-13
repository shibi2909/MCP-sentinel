import { useState } from "react";
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, can, User } from "../api";
import { axisProps, Card, Empty, ErrorBanner, tooltipStyle, useApi } from "../components/ui";

// Categorical slots 1-3 (dark mode) of the validated palette
const SERIES = { monitor: "#3987e5", approval: "#d95926", block: "#199e70" };

export default function Controller({ user }: { user: User }) {
  const { data: state, error, reload } = useApi<any>("/api/controller", 4000);
  const { data: history, reload: reloadHistory } = useApi<any[]>("/api/dashboard/controller-history?limit=200", 4000);
  const [actionError, setActionError] = useState<string | null>(null);
  const manage = can(user, "controller:manage");

  async function call(path: string, method: string, body?: unknown) {
    setActionError(null);
    try {
      await api(path, { method, body });
      reload();
      reloadHistory();
    } catch (err) {
      setActionError((err as Error).message);
    }
  }

  const series = (history ?? []).map((h) => ({ ...h, estimated_x100: +(h.estimated_risk * 100).toFixed(1), observed_x100: +(h.observed_risk * 100).toFixed(1) }));

  return (
    <div className="space-y-6">
      <ErrorBanner error={error || actionError} />
      {state && (
        <div className="grid gap-6 xl:grid-cols-3">
          <Card title="Security configuration" subtitle="Which configuration the live gateway enforces">
            <div className="space-y-2">
              {[
                ["A_STATIC", "A. Static thresholds (rule score only)"],
                ["B_ML", "B. Risk engine + ML (static thresholds)"],
                ["C_CONTROLLER", "C. Risk engine + PI feedback controller"],
              ].map(([key, label]) => (
                <button key={key} disabled={!manage} onClick={() => call("/api/controller/mode", "PUT", { mode: key })}
                  className={`w-full rounded-lg border px-3 py-2 text-left text-sm transition ${
                    state.security_mode === key ? "border-accent bg-accent/10 text-ink-primary" : "border-white/10 text-ink-secondary hover:bg-surface-2"}`}>
                  {state.security_mode === key ? "● " : "○ "}{label}
                </button>
              ))}
            </div>
            <button className="btn-secondary mt-4 w-full" disabled={!manage}
              onClick={() => window.confirm("Reset the controller state and history?") && call("/api/controller/reset", "POST")}>
              Reset controller state
            </button>
            {can(user, "system:reset") && (
              <button className="btn-danger mt-2 w-full"
                onClick={() => window.confirm("Delete ALL requests, events, approvals and audit records and start with fresh demo data?") && call("/api/admin/reset", "POST")}>
                Reset all demo data
              </button>
            )}
            {!manage && <p className="mt-2 text-xs text-ink-muted">Only admins can change the configuration.</p>}
          </Card>

          <Card title="Controller equations" subtitle="Discrete-time PI controller, one step per request" className="xl:col-span-2">
            <div className="grid gap-4 md:grid-cols-2">
              <pre className="rounded-lg bg-surface-0 p-3 font-mono text-xs leading-6 text-ink-secondary">{`x̂ₖ = α·rₖ + (1-α)·x̂ₖ₋₁        (observer)
eₖ = x̂ₖ − setpoint             (error)
Iₖ = clamp(Iₖ₋₁ + eₖ)          (anti-windup)
uₖ = clamp(Kp·eₖ + Ki·Iₖ)      (control)
Tᵢ = clamp(Tᵢ,base − gᵢ·uₖ)    (thresholds)`}</pre>
              <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                <KV k="α (observer gain)" v={state.config.alpha} />
                <KV k="Setpoint" v={state.config.setpoint} />
                <KV k="Kp" v={state.config.kp} />
                <KV k="Ki" v={state.config.ki} />
                <KV k="Integral bounds" v={state.config.integral_bounds.join(" … ")} />
                <KV k="u bounds" v={state.config.control_bounds.join(" … ")} />
                <KV k="Current u" v={state.control_signal} />
                <KV k="Enforcement mode" v={state.enforcement_mode} />
              </dl>
            </div>
            <p className="mt-3 text-xs text-ink-muted">
              Modes: NORMAL (u &lt; 0.15) · ELEVATED (u ≥ 0.15: high-sensitivity tools monitored) · LOCKDOWN (u ≥ 0.45: high-sensitivity tools and
              suspicious monitored requests need approval). Every quantity is clamped, so thresholds always stay within their configured ranges.
            </p>
          </Card>
        </div>
      )}

      <Card title="Adaptive thresholds over time" subtitle="Threshold values chosen by the controller after each request (risk-score scale 0-100)">
        {!series.length ? <Empty>No controller history yet. Run some demo scenarios.</Empty> : (
          <ResponsiveContainer width="100%" height={280}>
            <LineChart data={series} margin={{ right: 20 }}>
              <CartesianGrid vertical={false} stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="step" {...axisProps} />
              <YAxis domain={[0, 100]} {...axisProps} width={30} />
              <Tooltip {...tooltipStyle} labelFormatter={(s) => `Step ${s}`} />
              <Legend wrapperStyle={{ fontSize: 12, color: "#c3c2b7" }} />
              <Line type="stepAfter" dataKey="monitor" name="Monitor threshold" stroke={SERIES.monitor} strokeWidth={2} dot={false} isAnimationActive={false} />
              <Line type="stepAfter" dataKey="approval" name="Approval threshold" stroke={SERIES.approval} strokeWidth={2} dot={false} isAnimationActive={false} />
              <Line type="stepAfter" dataKey="block" name="Block threshold" stroke={SERIES.block} strokeWidth={2} dot={false} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </Card>

      <Card title="Observed vs. estimated risk" subtitle="Raw observation rₖ (×100) and the smoothed state estimate x̂ₖ (×100) the controller acts on">
        {!series.length ? <Empty>No controller history yet.</Empty> : (
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={series} margin={{ right: 20 }}>
              <CartesianGrid vertical={false} stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="step" {...axisProps} />
              <YAxis domain={[0, 100]} {...axisProps} width={30} />
              <Tooltip {...tooltipStyle} labelFormatter={(s) => `Step ${s}`} />
              <Legend wrapperStyle={{ fontSize: 12, color: "#c3c2b7" }} />
              <Line type="linear" dataKey="observed_x100" name="Observed risk" stroke="#8f8e86" strokeWidth={1.5} dot={{ r: 3 }} isAnimationActive={false} />
              <Line type="monotone" dataKey="estimated_x100" name="Estimated risk" stroke={SERIES.monitor} strokeWidth={2} dot={false} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </Card>
    </div>
  );
}

function KV({ k, v }: { k: string; v: any }) {
  return (
    <>
      <dt className="text-ink-muted">{k}</dt>
      <dd className="font-mono text-ink-primary">{v}</dd>
    </>
  );
}
