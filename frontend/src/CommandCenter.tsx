import { useCallback, useEffect, useState } from "react";
import { Clock3, RefreshCw } from "lucide-react";
import { Link } from "react-router-dom";
import { getCommandCenter, type CommandCenterData } from "./api";
import { PageHeader, Panel, ErrorState, SkeletonRow } from "./App";

const overviewMetrics = [
  { key: "registered_devices", label: "Registered devices" },
  { key: "supported_devices", label: "Vendor supported" },
  { key: "devices_at_risk", label: "At risk" },
  { key: "orphaned_devices", label: "Verified orphans" },
  { key: "approved_patches", label: "Approved patches" },
] as const;

const EVENT_CATEGORY_BADGE: Record<string, string> = {
  guardian: "badge-green",
  network:  "badge-ruby",
  orphan:   "badge-amber",
  patch:    "badge-blue",
};

function stamp(value: string) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? "—"
    : new Intl.DateTimeFormat("en", {
        month: "short", day: "numeric",
        hour: "2-digit", minute: "2-digit",
      }).format(parsed);
}

export default function CommandCenter() {
  const [data, setData] = useState<CommandCenterData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try { setData(await getCommandCenter()); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Could not load dashboard."); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <>
      <PageHeader
        eyebrow="SECURITY OPERATIONS"
        title="Command Center"
        description="Current device exposure, lifecycle evidence, and security activity across the virtual fleet."
        actions={
          <button onClick={() => void load()} disabled={loading} className="btn btn-secondary btn-sm">
            <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
            Refresh
          </button>
        }
      />

      {error && <ErrorState message={error} onRetry={() => void load()} />}

      <div className="overview-strip mb-5">
        {overviewMetrics.map(({ key, label }) => (
          <div className="overview-metric" key={key}>
            <span>{label}</span>
            <strong>{loading ? "—" : data?.totals[key] ?? "—"}</strong>
          </div>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
        {/* Survival scores */}
        <Panel
          title="Fleet risk overview"
          description="Survival scores calculated from documented passport factors."
          actions={
            <Link to="/analytics" className="btn btn-ghost btn-xs text-lime">
              Full analytics →
            </Link>
          }
        >
          {loading ? (
            <table className="data-table w-full">
              <tbody>{[...Array(5)].map((_, i) => <SkeletonRow key={i} cols={3} />)}</tbody>
            </table>
          ) : data?.survival_scores.length ? (
            <>
              <div className="space-y-3 mb-4">
                {data.survival_scores.map((device) => (
                  <Link
                    key={device.device_id}
                    to={`/devices/${encodeURIComponent(device.device_id)}`}
                    className="fleet-score-row"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="fleet-score-name">{device.name}</div>
                      <div className="mono mt-1">{device.device_id}</div>
                    </div>
                    <div className="w-28 score-bar-track flex-shrink-0">
                      <div
                        className={`score-bar-fill ${device.risk_level === "low" ? "high" : device.risk_level === "medium" ? "medium" : "low"}`}
                        style={{ width: `${device.score}%` }}
                      />
                    </div>
                    <span className={`text-[12px] font-semibold w-7 text-right flex-shrink-0 ${
                      device.risk_level === "high" ? "text-ruby" :
                      device.risk_level === "medium" ? "text-amber" : "text-emerald"
                    }`}>{device.score}</span>
                  </Link>
                ))}
              </div>
              <div className="divider" />
              <div className="flex flex-wrap gap-2 pt-3" aria-label="Device risk counts">
                {Object.entries(data.risk_overview).map(([level, count]) => (
                  <span key={level} className={`badge ${
                    level === "low" ? "badge-green" : level === "medium" ? "badge-amber" : "badge-ruby"
                  }`}>
                    {level}: {count}
                  </span>
                ))}
              </div>
            </>
          ) : (
            <div className="empty-state">No devices registered yet.</div>
          )}
        </Panel>

        {/* Recent security events */}
        <Panel
          title="Recent Security Events"
          description="From orphan, patch, gateway and Guardian records."
        >
          {loading ? (
            <div className="space-y-3">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="border-l-2 border-border pl-3">
                  <div className="skeleton h-2.5 w-16 rounded mb-1.5" />
                  <div className="skeleton h-3 w-full rounded mb-1" />
                  <div className="skeleton h-2.5 w-24 rounded" />
                </div>
              ))}
            </div>
          ) : data?.recent_security_events.length ? (
            <div className="max-h-[380px] overflow-y-auto space-y-3 pr-1">
              {data.recent_security_events.map((event, index) => (
                <article
                  key={`${event.category}-${event.device_id}-${event.timestamp}-${index}`}
                  className="border-l-2 border-border pl-3"
                >
                  <div className="flex flex-wrap items-center justify-between gap-1 mb-1">
                    <span className={`badge ${EVENT_CATEGORY_BADGE[event.category] ?? "badge-muted"} text-[8.5px]`}>
                      {event.category}
                    </span>
                    <time className="text-[9px] text-ink-muted">{stamp(event.timestamp)}</time>
                  </div>
                  <p className="text-[10.5px] leading-5 text-ink-secondary">{event.summary}</p>
                  {(event.device_id ?? event.actor) && (
                    <div className="mono mt-0.5">{event.device_id}{event.actor ? ` · ${event.actor}` : ""}</div>
                  )}
                </article>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <Clock3 size={20} />
              No security events recorded yet.
            </div>
          )}
        </Panel>
      </div>

      {data && (
        <div className="mt-3 alert alert-info text-[10.5px]">
        {data.data_source} All firmware, devices and network behavior are virtual simulations. End-of-support proximity and patch validation queue totals are not currently exposed by the API.
        </div>
      )}
    </>
  );
}
