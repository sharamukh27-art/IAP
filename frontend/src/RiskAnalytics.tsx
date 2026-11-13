import { useEffect, useState } from "react";
import { Activity, AlertTriangle, BarChart3, RefreshCw, ShieldCheck } from "lucide-react";
import { getRiskAnalytics, type RiskAnalyticsData } from "./api";
import { PageHeader, Panel, ErrorState } from "./App";

/* ─── Horizontal bar chart ───────────────────────────────── */
function BarChart({
  items,
  colorClass = "bg-emerald",
}: {
  items: Array<{ label: string; value: number }>;
  colorClass?: string;
}) {
  const max = Math.max(1, ...items.map((i) => i.value));
  if (!items.length || items.every((i) => i.value === 0)) {
    return <div className="empty-state text-[11px]">No records collected yet.</div>;
  }
  return (
    <div className="space-y-3">
      {items.map((item) => (
        <div key={item.label}>
          <div className="flex justify-between gap-2 mb-1 text-[10.5px]">
            <span className="text-ink-secondary truncate">{item.label}</span>
            <span className="font-semibold text-ink flex-shrink-0">{item.value}</span>
          </div>
          <div className="score-bar-track">
            <div
              className={`${colorClass} h-full rounded-sm transition-all duration-300`}
              style={{ width: `${(item.value / max) * 100}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─── Score distribution mini chart ─────────────────────── */
function ScoreChart({ scores }: { scores: RiskAnalyticsData["survival_scores"] }) {
  if (!scores.length) return <div className="empty-state text-[11px]">No device scores available.</div>;
  return (
    <div className="space-y-2.5">
      {scores.map((device) => (
        <div key={device.device_id} className="grid grid-cols-[minmax(0,1fr)_80px_32px] items-center gap-3">
          <span className="text-[10.5px] text-ink-secondary truncate">{device.name}</span>
          <div className="score-bar-track">
            <div
              className={`${
                device.risk_level === "low" ? "bg-emerald" :
                device.risk_level === "medium" ? "bg-amber" : "bg-ruby"
              } h-full rounded-sm transition-all duration-300`}
              style={{ width: `${device.score}%` }}
            />
          </div>
          <span className={`text-right text-[11px] font-semibold ${
            device.risk_level === "low" ? "text-emerald" :
            device.risk_level === "medium" ? "text-amber" : "text-ruby"
          }`}>{device.score}</span>
        </div>
      ))}
    </div>
  );
}

/* ─── Donut-style ratio ──────────────────────────────────── */
function RatioDisplay({
  passed,
  failed,
  label,
}: {
  passed: number;
  failed: number;
  label: string;
}) {
  const total = passed + failed;
  const pct = total === 0 ? null : Math.round((passed / total) * 100);
  return (
    <div className="flex items-center gap-4">
      <div className="relative w-16 h-16 flex-shrink-0">
        <svg viewBox="0 0 36 36" className="w-16 h-16 -rotate-90">
          <circle cx="18" cy="18" r="14" fill="none" stroke="#1e2520" strokeWidth="4" />
          {total > 0 && (
            <circle
              cx="18" cy="18" r="14" fill="none"
              stroke={pct !== null && pct >= 70 ? "#34c97a" : pct !== null && pct >= 40 ? "#f59e0b" : "#f43f5e"}
              strokeWidth="4"
              strokeDasharray={`${(passed / total) * 87.96} 87.96`}
              strokeLinecap="round"
            />
          )}
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className={`text-[13px] font-bold ${
            pct === null ? "text-ink-muted" :
            pct >= 70 ? "text-emerald" : pct >= 40 ? "text-amber" : "text-ruby"
          }`}>
            {pct === null ? "—" : `${pct}%`}
          </span>
        </div>
      </div>
      <div>
        <div className="text-[11px] font-semibold text-ink-secondary">{label}</div>
        <div className="mt-1 flex gap-3 text-[10px]">
          <span className="text-emerald font-medium">{passed} passed</span>
          <span className="text-ruby font-medium">{failed} failed</span>
        </div>
        <div className="text-[9.5px] text-ink-muted mt-0.5">
          {total} total evaluated
        </div>
      </div>
    </div>
  );
}

export default function RiskAnalytics() {
  const [data, setData] = useState<RiskAnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = () => {
    setLoading(true);
    setError("");
    getRiskAnalytics()
      .then((d) => { setData(d); setLoading(false); })
      .catch((reason: unknown) => {
        setError(reason instanceof Error ? reason.message : "Could not load analytics.");
        setLoading(false);
      });
  };

  useEffect(() => { load(); }, []);

  return (
    <>
      <PageHeader
        eyebrow="OPERATIONAL RISK"
        title="Risk Analytics"
        description="Reports computed from persisted device, evidence, patch and Guardian records."
        actions={
          <button onClick={load} disabled={loading} className="btn btn-secondary btn-sm">
            <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
            Refresh
          </button>
        }
      />

      {error && <ErrorState message={error} onRetry={load} />}

      <div className="overview-strip mb-5">
        {[
          {
            label: "Patch test pass rate",
            value: data?.patch_testing.pass_rate_percent == null ? "—" : `${data.patch_testing.pass_rate_percent}%`,
          },
          {
            label: "Recovery success rate",
            value: data?.recovery.success_rate_percent == null ? "—" : `${data.recovery.success_rate_percent}%`,
          },
          {
            label: "Successful recoveries",
            value: data?.recovery.successful ?? "—",
          },
          {
            label: "Avg recovery time",
            value: data?.recovery.average_recovery_seconds == null ? "—" : `${data.recovery.average_recovery_seconds}s`,
          },
        ].map(({ label, value }) => (
          <div key={label} className="overview-metric">
            <span>{label}</span>
            <strong>{loading ? "—" : value}</strong>
          </div>
        ))}
      </div>

      {!loading && data && (
        <>
          <div className="grid gap-4 lg:grid-cols-2 mb-4">
            <Panel title="Device Survival Scores" description="Recalculated from passport factors — not estimated." actions={<ShieldCheck size={14} className="text-emerald" />}>
              <ScoreChart scores={data.survival_scores} />
            </Panel>

            <Panel title="Unpatched Vulnerability Severity" description="Counts exclude vulnerabilities marked patched." actions={<AlertTriangle size={14} className="text-ruby" />}>
              <BarChart
                items={Object.entries(data.vulnerability_severity_distribution).map(([label, value]) => ({ label, value }))}
                colorClass="bg-ruby"
              />
            </Panel>
          </div>

          <div className="grid gap-4 lg:grid-cols-2 mb-4">
            <Panel title="Patch Laboratory Results" description={`${data.patch_testing.other} submitted or in-progress records.`} actions={<BarChart3 size={14} className="text-sapphire" />}>
              <RatioDisplay
                passed={data.patch_testing.passed}
                failed={data.patch_testing.failed}
                label="Automated test outcomes"
              />
            </Panel>

            <Panel title="Recovery Outcomes" description="Based on Guardian post-update result events." actions={<Activity size={14} className="text-emerald" />}>
              <RatioDisplay
                passed={data.recovery.successful}
                failed={data.recovery.failed}
                label="Firmware recovery results"
              />
              <div className="mt-3 text-[10px] text-ink-muted">
                Average time uses matched recovery-pending and final-result event timestamps.
              </div>
            </Panel>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <Panel title="Orphan Detection Trends" description="Monthly claim, verification and failure audit events.">
              <BarChart
                items={Object.entries(data.orphan_detection_trends.monthly_events).map(([label, value]) => ({ label, value }))}
                colorClass="bg-sapphire"
              />
              <div className="flex flex-wrap gap-2 mt-4 pt-3 border-t border-border-subtle">
                {Object.entries(data.orphan_detection_trends.current_states).map(([label, value]) => (
                  <span key={label} className="badge badge-muted text-[9px]">{label}: <strong className="text-ink ml-1">{value}</strong></span>
                ))}
              </div>
            </Panel>

            <Panel title="Quarantine & Blocked Traffic" description="Policy transitions and gateway logs grouped by month.">
              <BarChart
                items={Object.entries(data.quarantine_events_by_month).map(([label, value]) => ({ label, value }))}
                colorClass="bg-ruby"
              />
            </Panel>
          </div>
        </>
      )}

      {loading && !data && (
        <div className="grid gap-4 lg:grid-cols-2">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="panel">
              <div className="panel-header"><div className="skeleton h-3 w-32 rounded" /></div>
              <div className="panel-body space-y-3">
                {[...Array(4)].map((__, j) => (
                  <div key={j} className="flex gap-2 items-center">
                    <div className="skeleton h-2.5 flex-1 rounded" />
                    <div className="skeleton h-3 w-8 rounded" />
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {data && (
        <div className="mt-4 alert alert-info text-[10.5px]">
          {data.data_source} All data describes simulated virtual devices.
        </div>
      )}
    </>
  );
}
