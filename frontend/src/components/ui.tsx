import { ReactNode, useCallback, useEffect, useRef, useState } from "react";
import { api, Action } from "../api";

// Status colours are reserved for security state and always paired with a text label + icon.
export const ACTION_STYLE: Record<Action, { color: string; icon: string; label: string }> = {
  ALLOW: { color: "#0ca30c", icon: "✓", label: "ALLOW" },
  MONITOR: { color: "#fab219", icon: "◉", label: "MONITOR" },
  REQUIRE_APPROVAL: { color: "#ec835a", icon: "⏸", label: "APPROVAL" },
  BLOCK: { color: "#d03b3b", icon: "✕", label: "BLOCK" },
};

const SEVERITY_COLOR: Record<string, string> = {
  info: "#8f8e86", low: "#3987e5", medium: "#fab219", high: "#ec835a", critical: "#d03b3b",
};

export function ActionBadge({ action }: { action: string }) {
  const style = ACTION_STYLE[action as Action];
  if (!style) return <span className="text-ink-muted">{action}</span>;
  return (
    <span
      className="inline-flex items-center gap-1 whitespace-nowrap rounded-md px-2 py-0.5 text-xs font-semibold"
      style={{ color: style.color, background: `${style.color}1f`, border: `1px solid ${style.color}55` }}
    >
      <span aria-hidden>{style.icon}</span>
      {style.label}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const color = SEVERITY_COLOR[severity] ?? "#8f8e86";
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium uppercase text-ink-secondary">
      <span className="h-2 w-2 rounded-full" style={{ background: color }} aria-hidden />
      {severity}
    </span>
  );
}

export function StatusPill({ ok, okText, badText }: { ok: boolean; okText: string; badText: string }) {
  const color = ok ? "#0ca30c" : "#d03b3b";
  return (
    <span
      className="inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold"
      style={{ color, background: `${color}1f`, border: `1px solid ${color}55` }}
    >
      <span aria-hidden>{ok ? "✓" : "✕"}</span>
      {ok ? okText : badText}
    </span>
  );
}

export function Card({ title, subtitle, actions, children, className = "" }: {
  title?: string; subtitle?: string; actions?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div>
            {title && <h2 className="text-sm font-semibold text-ink-primary">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-xs text-ink-muted">{subtitle}</p>}
          </div>
          {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function StatTile({ label, value, hint, accent }: { label: string; value: ReactNode; hint?: string; accent?: string }) {
  return (
    <div className="card relative overflow-hidden p-4">
      {accent && <span className="absolute inset-y-0 left-0 w-1" style={{ background: accent }} aria-hidden />}
      <div className="text-xs font-medium uppercase tracking-wide text-ink-muted">{label}</div>
      <div className="mt-1.5 text-3xl font-semibold tabular-nums text-ink-primary">{value}</div>
      {hint && <div className="mt-1 text-xs text-ink-muted">{hint}</div>}
    </div>
  );
}

export function JsonView({ data, maxHeight = 320 }: { data: unknown; maxHeight?: number }) {
  return (
    <pre
      className="overflow-auto rounded-lg border border-white/5 bg-surface-0 p-3 font-mono text-xs leading-relaxed text-ink-secondary"
      style={{ maxHeight }}
    >
      {JSON.stringify(data, null, 2)}
    </pre>
  );
}

export function ErrorBanner({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <div className="mb-4 rounded-lg border border-status-critical/40 bg-status-critical/10 px-4 py-2.5 text-sm text-ink-primary">
      <span className="mr-2 text-status-critical" aria-hidden>✕</span>
      {error}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="rounded-lg border border-dashed border-white/10 p-6 text-center text-sm text-ink-muted">{children}</div>;
}

export function formatTime(iso: string | null | undefined) {
  if (!iso) return "-";
  const date = new Date(iso);
  return date.toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function shortHash(hash: string | null | undefined) {
  return hash ? `${hash.slice(0, 10)}…${hash.slice(-6)}` : "-";
}

/** Fetch data from the backend, optionally refreshing on an interval. */
export function useApi<T>(path: string | null, refreshMs = 0) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const mounted = useRef(true);

  const reload = useCallback(async () => {
    if (!path) return;
    setLoading(true);
    try {
      const result = await api<T>(path);
      if (mounted.current) {
        setData(result);
        setError(null);
      }
    } catch (err) {
      if (mounted.current) setError((err as Error).message);
    } finally {
      if (mounted.current) setLoading(false);
    }
  }, [path]);

  useEffect(() => {
    mounted.current = true;
    reload();
    if (!refreshMs) return () => { mounted.current = false; };
    const timer = setInterval(reload, refreshMs);
    return () => {
      mounted.current = false;
      clearInterval(timer);
    };
  }, [reload, refreshMs]);

  return { data, error, loading, reload, setData };
}

/** Shared dark tooltip style for Recharts. */
export const tooltipStyle = {
  contentStyle: { background: "#232321", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, fontSize: 12 },
  labelStyle: { color: "#f0efec" },
  itemStyle: { color: "#c3c2b7" },
};

export const axisProps = {
  stroke: "#8f8e86",
  tick: { fill: "#8f8e86", fontSize: 11 },
  tickLine: false,
  axisLine: { stroke: "rgba(255,255,255,0.1)" },
};
