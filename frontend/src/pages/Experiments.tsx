import { useState } from "react";
import { Bar, BarChart, CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, can, User } from "../api";
import { axisProps, Card, Empty, ErrorBanner, formatTime, tooltipStyle, useApi } from "../components/ui";

// Categorical slots 1-3 (dark mode): A, B, C
const CONFIG_COLOR: Record<string, string> = { A_STATIC: "#3987e5", B_ML: "#d95926", C_CONTROLLER: "#199e70" };
const pct = (v: number | null) => (v === null || v === undefined ? "-" : `${(v * 100).toFixed(1)}%`);

export default function Experiments({ user }: { user: User }) {
  const { data: latest, error, setData } = useApi<any>("/api/experiments/latest");
  const { data: ml } = useApi<any>("/api/ml/info");
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);

  async function run() {
    setRunning(true);
    setRunError(null);
    try {
      setData(await api("/api/experiments/run", { method: "POST" }));
    } catch (err) {
      setRunError((err as Error).message);
    } finally {
      setRunning(false);
    }
  }

  const results = latest?.results;
  const configs: [string, any][] = results ? Object.entries(results.configurations) : [];
  const comparison = configs.map(([key, c]) => ({
    key, label: c.label.split(". ")[0],
    "Detection rate": +(c.overall.detection_rate * 100).toFixed(1),
    "False-positive rate": +(c.overall.false_positive_rate * 100).toFixed(1),
  }));
  const cSeries = results?.configurations.C_CONTROLLER.series.map((s: any) => ({ ...s, est: +(s.estimated_risk * 100).toFixed(1) })) ?? [];

  return (
    <div className="space-y-6">
      <ErrorBanner error={error || runError} />
      <Card
        title="Configuration comparison: A vs. B vs. C"
        subtitle="Repeatable seeded traffic (normal → attack campaign → recovery) replayed through the real validation, risk, policy and controller code."
        actions={<button className="btn-primary" disabled={running || !can(user, "experiments:run")} onClick={run}>{running ? "Running (≈20 s)…" : "Run experiment"}</button>}
      >
        {!results ? <Empty>No experiment has been run yet. Click "Run experiment" — results are computed, never hard-coded.</Empty> : (
          <>
            <p className="mb-4 text-xs text-ink-muted">
              Run {formatTime(latest.created_at)} by {latest.run_by} · seed {results.seed} · {results.trace.total_requests} requests ({results.trace.malicious_requests} malicious) ·
              "caught" = {results.definitions.caught}
            </p>
            <div className="overflow-x-auto">
              <table className="table-base">
                <thead><tr><th>Configuration</th><th>Detection rate</th><th>False-positive rate</th><th>Precision</th><th>F1</th><th>TP / FN / FP / TN</th><th>Missed attack kinds</th></tr></thead>
                <tbody>
                  {configs.map(([key, c]) => (
                    <tr key={key}>
                      <td className="text-ink-primary"><span className="mr-2 inline-block h-2.5 w-2.5 rounded-sm" style={{ background: CONFIG_COLOR[key] }} />{c.label}</td>
                      <td className="tabular-nums text-ink-primary">{pct(c.overall.detection_rate)}</td>
                      <td className="tabular-nums">{pct(c.overall.false_positive_rate)}</td>
                      <td className="tabular-nums">{pct(c.overall.precision)}</td>
                      <td className="tabular-nums">{c.overall.f1 ?? "-"}</td>
                      <td className="tabular-nums">{c.overall.tp} / {c.overall.fn} / {c.overall.fp} / {c.overall.tn}</td>
                      <td className="text-xs">{Object.entries(c.missed_attack_kinds).map(([k, v]) => `${k} ×${v}`).join(", ") || "none"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Card>

      {results && (
        <>
          <div className="grid gap-6 xl:grid-cols-2">
            <Card title="Detection vs. false positives (seed run)" subtitle="Percent of malicious / benign requests caught">
              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={comparison} barCategoryGap="25%" barGap={2}>
                  <CartesianGrid vertical={false} stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="label" {...axisProps} />
                  <YAxis unit="%" {...axisProps} width={40} />
                  <Tooltip {...tooltipStyle} cursor={{ fill: "rgba(255,255,255,0.04)" }} formatter={(v: number) => `${v}%`} />
                  <Legend wrapperStyle={{ fontSize: 12, color: "#c3c2b7" }} />
                  <Bar dataKey="Detection rate" fill="#3987e5" radius={[4, 4, 0, 0]} label={{ position: "top", fill: "#c3c2b7", fontSize: 11 }} />
                  <Bar dataKey="False-positive rate" fill="#d95926" radius={[4, 4, 0, 0]} label={{ position: "top", fill: "#c3c2b7", fontSize: 11 }} />
                </BarChart>
              </ResponsiveContainer>
            </Card>
            <Card title={`Robustness: mean over seeds ${results.multi_seed.seeds.join(", ")}`} subtitle="Same configurations on independently generated traces">
              <table className="table-base">
                <thead><tr><th>Configuration</th><th>Mean detection</th><th>Mean false positives</th></tr></thead>
                <tbody>
                  {Object.entries(results.multi_seed.configurations).map(([key, c]: [string, any]) => (
                    <tr key={key}>
                      <td className="text-ink-primary"><span className="mr-2 inline-block h-2.5 w-2.5 rounded-sm" style={{ background: CONFIG_COLOR[key] }} />{c.label}</td>
                      <td className="tabular-nums text-ink-primary">{pct(c.mean_detection_rate)}</td>
                      <td className="tabular-nums">{pct(c.mean_false_positive_rate)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="label mt-5">Controller gain sensitivity (mean over seeds)</div>
              <table className="table-base">
                <thead><tr><th>Setpoint</th><th>Kp</th><th>Ki</th><th>Detection</th><th>False positives</th></tr></thead>
                <tbody>
                  {results.sensitivity_analysis.map((r: any, i: number) => (
                    <tr key={i} className={r.is_default ? "bg-accent/10" : ""}>
                      <td>{r.setpoint}{r.is_default && " (default)"}</td><td>{r.kp}</td><td>{r.ki}</td>
                      <td className="tabular-nums text-ink-primary">{pct(r.mean_detection_rate)}</td>
                      <td className="tabular-nums">{pct(r.mean_false_positive_rate)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          </div>

          <Card title="Configuration C: controller response over the trace" subtitle="Approval and monitor thresholds fall during the attack phase (steps 120-239) and recover afterwards">
            <ResponsiveContainer width="100%" height={280}>
              <LineChart data={cSeries} margin={{ right: 20 }}>
                <CartesianGrid vertical={false} stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="step" {...axisProps} />
                <YAxis domain={[0, 100]} {...axisProps} width={30} />
                <Tooltip {...tooltipStyle} labelFormatter={(s) => `Request ${s}`} />
                <Legend wrapperStyle={{ fontSize: 12, color: "#c3c2b7" }} />
                <Line type="stepAfter" dataKey="monitor" name="Monitor threshold" stroke="#3987e5" strokeWidth={2} dot={false} />
                <Line type="stepAfter" dataKey="approval" name="Approval threshold" stroke="#d95926" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="est" name="Estimated risk ×100" stroke="#199e70" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </Card>

          <Card title="Honesty notes">
            <ul className="space-y-1 text-sm text-ink-secondary">{results.notes.map((n: string, i: number) => <li key={i}>• {n}</li>)}</ul>
          </Card>
        </>
      )}

      {ml && (
        <Card title="ML risk classifier" subtitle={ml.model}>
          <p className="mb-3 text-sm text-status-warning">⚠ {ml.warning}</p>
          <div className="grid gap-3 sm:grid-cols-5">
            {["accuracy", "precision", "recall", "f1", "roc_auc"].map((k) => (
              <div key={k} className="rounded-lg bg-surface-2 p-3">
                <div className="text-[11px] uppercase text-ink-muted">{k}</div>
                <div className="text-xl font-semibold tabular-nums">{ml[k]}</div>
              </div>
            ))}
          </div>
          <p className="mt-3 text-xs text-ink-muted">Dataset: {ml.dataset} · {ml.test_samples} held-out test samples</p>
        </Card>
      )}
    </div>
  );
}
