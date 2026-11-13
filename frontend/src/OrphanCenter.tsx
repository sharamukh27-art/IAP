import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  BadgeCheck,
  Check,
  Clock3,
  FileCheck2,
  LoaderCircle,
  Radio,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import {
  finalizeOrphanClaim,
  getOrphanDashboard,
  scanOrphans,
  simulateManufacturer,
  submitAttestation,
  submitOrphanClaim,
} from "./api";
import { useAuth } from "./AuthContext";
import type { OrphanDashboard, OrphanState } from "./types";
import { PageHeader, Panel } from "./App";

const scenarios = [
  { value: "manufacturer_shutdown", label: "Manufacturer shutdown" },
  { value: "end_of_support",        label: "End of support" },
  { value: "maintenance_failure",   label: "Maintenance failure" },
  { value: "reset",                 label: "Reset scenario evidence" },
];

function orphanBadgeClass(state: OrphanState) {
  if (state === "Verified Orphan")               return "os-verified";
  if (state === "Orphan Candidate")              return "os-candidate";
  if (state === "Verification Pending")          return "os-pending";
  if (state === "Support At Risk")               return "os-at-risk";
  if (state === "Disputed / Verification Failed") return "os-disputed";
  return "os-supported";
}

function dateTime(value: string | null) {
  if (!value) return "—";
  return new Intl.DateTimeFormat("en", {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC",
  }).format(new Date(value));
}

function challengeSeconds(value: string | null, now: number) {
  if (!value) return 0;
  return Math.max(0, Math.ceil((new Date(value).getTime() - now) / 1000));
}

const lifecycleStates: OrphanState[] = [
  "Supported",
  "Support At Risk",
  "Orphan Candidate",
  "Verification Pending",
  "Verified Orphan",
  "Disputed / Verification Failed",
];

export default function OrphanCenter() {
  const { user } = useAuth();
  const [dashboard, setDashboard] = useState<OrphanDashboard | null>(null);
  const [selectedId, setSelectedId] = useState("");
  const [manufacturer, setManufacturer] = useState("");
  const [scenario, setScenario] = useState(scenarios[0].value);
  const [claimNote, setClaimNote] = useState("Multiple independent lifecycle and security signals require a community verification review.");
  const [decision, setDecision] = useState<"approve" | "reject">("approve");
  const [reviewNote, setReviewNote] = useState("Reviewed the recorded evidence and challenge details.");
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [clock, setClock] = useState(Date.now());

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await getOrphanDashboard();
      setDashboard(response);
      setSelectedId((prev) =>
        response.cases.some((c) => c.device_id === prev)
          ? prev
          : response.cases[0]?.device_id ?? "",
      );
      setManufacturer((prev) =>
        response.cases.some((c) => c.manufacturer === prev)
          ? prev
          : response.cases[0]?.manufacturer ?? "",
      );
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load orphan records.");
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    const timer = window.setInterval(() => setClock(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const selected = useMemo(
    () => dashboard?.cases.find((c) => c.device_id === selectedId) ?? null,
    [dashboard, selectedId],
  );
  const manufacturers = useMemo(
    () => [...new Set(dashboard?.cases.map((c) => c.manufacturer) ?? [])].sort(),
    [dashboard],
  );
  const approvals  = selected?.attestations.filter((a) => a.decision === "approve").length ?? 0;
  const rejections = selected?.attestations.filter((a) => a.decision === "reject").length ?? 0;
  const actorId    = user?.user_id ?? "";
  const isAdmin    = user?.role === "administrator";
  const canPublish = isAdmin || user?.role === "manufacturer";
  const isReviewer = user?.role === "independent_reviewer";
  const selectedScenario = user?.role === "manufacturer" ? "end_of_support" : scenario;
  const alreadyReviewed  = selected?.attestations.some((a) => a.reviewer_id === actorId) ?? false;
  const remaining        = challengeSeconds(selected?.challenge_until ?? null, clock);

  const runAction = async (action: () => Promise<unknown>, message: string) => {
    setWorking(true); setError(""); setNotice("");
    try { await action(); setNotice(message); await load(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "The request could not be completed."); }
    finally { setWorking(false); }
  };

  return (
    <>
      <PageHeader
        eyebrow="AUTONOMOUS LIFECYCLE MONITOR"
        title="Orphan Detection Center"
        description="Corroborate manufacturer lifecycle evidence before a device can be verified as orphaned."
        actions={
          isAdmin ? (
            <button className="btn btn-secondary btn-sm" onClick={() => void runAction(scanOrphans, "Evidence scan complete.")} disabled={working || loading}>
              <RefreshCw size={12} className={working ? "animate-spin" : ""} />
              Refresh evidence
            </button>
          ) : undefined
        }
      />

      {error  && <div className="alert alert-error  mb-4 text-[11px]"><AlertTriangle size={13} />{error}</div>}
      {notice && <div className="alert alert-success mb-4 text-[11px]"><ShieldCheck size={13} />{notice}</div>}

      {loading && !dashboard ? (
        <div className="flex items-center justify-center min-h-64 text-ink-muted text-sm gap-2">
          <LoaderCircle size={16} className="animate-spin" /> Loading evidence records…
        </div>
      ) : dashboard && (
        <>
          <div className="lifecycle-track mb-4" aria-label="Device lifecycle state counts">
            {lifecycleStates.map((state) => (
              <div className="lifecycle-stage" key={state}>
                <div className="lifecycle-stage-label">{state}</div>
                <div className={`lifecycle-stage-count ${state === "Verified Orphan" ? "alert" : ""}`}>
                  {dashboard.counts[state] ?? 0}
                </div>
              </div>
            ))}
          </div>

          {/* Simulation controls */}
          {canPublish && (
            <Panel
              title="Simulation Controls"
              description="Fictional vendors only. Simulated signals are evidence — not standalone proof of abandonment."
              actions={
                <span className="badge badge-muted text-[8.5px] font-bold tracking-wide">
                  {isAdmin ? "ADMINISTRATOR" : "MANUFACTURER SCOPE"}
                </span>
              }
            >
              <div className="grid gap-2 md:grid-cols-[1fr_1.2fr_auto]">
                <select
                  aria-label="Select fictional manufacturer"
                  className="field"
                  value={manufacturer}
                  disabled={user?.role === "manufacturer"}
                  onChange={(e) => setManufacturer(e.target.value)}
                >
                  {manufacturers.map((n) => <option key={n}>{n}</option>)}
                </select>
                <select
                  aria-label="Select shutdown scenario"
                  className="field"
                  value={selectedScenario}
                  disabled={user?.role === "manufacturer"}
                  onChange={(e) => setScenario(e.target.value)}
                >
                  {scenarios
                    .filter((s) => isAdmin || s.value === "end_of_support")
                    .map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
                </select>
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => void runAction(
                    () => simulateManufacturer(manufacturer, selectedScenario),
                    `Scenario recorded for ${manufacturer}. Evidence refreshed.`,
                  )}
                  disabled={working || !manufacturer}
                >
                  <Radio size={13} /> Apply scenario
                </button>
              </div>
              <div className="flex flex-wrap gap-1.5 mt-3">
                {["shutdown / EOL notice", "support date", "stale updates", "endpoint / certificate"].map((s) => (
                  <span key={s} className="signal-chip">{s}</span>
                ))}
              </div>
            </Panel>
          )}

          {/* Case list + detail */}
          <div className="mt-4 grid gap-4 xl:grid-cols-[280px_1fr]">
            {/* Case list */}
            <div className="panel overflow-hidden">
              <div className="panel-header">
                <div>
                  <div className="panel-title">Device Lifecycle</div>
                  <div className="panel-desc">{dashboard.total_devices} evidence records</div>
                </div>
              </div>
              <div className="divide-y divide-border-subtle">
                {dashboard.cases.map((item) => (
                  <button
                    key={item.device_id}
                    className={`orphan-case-row w-full text-left${selectedId === item.device_id ? " selected" : ""}`}
                    onClick={() => setSelectedId(item.device_id)}
                  >
                    <div className="flex items-start justify-between gap-2 mb-1.5">
                      <div className="min-w-0">
                        <div className="text-[11.5px] font-medium text-ink-secondary truncate">{item.device_name}</div>
                        <div className="mono mt-0.5 truncate">{item.device_id}</div>
                      </div>
                      <span className="text-[9px] text-ink-muted flex-shrink-0">{item.evidence_count} sig.</span>
                    </div>
                    <span className={`orphan-badge ${orphanBadgeClass(item.state)}`}>{item.state}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Detail */}
            {selected ? (
              <div className="panel">
                <div className="panel-header">
                  <div>
                    <div className="mono mb-1">EVIDENCE RECORD · {selected.device_id}</div>
                    <div className="panel-title text-[15px]">{selected.device_name}</div>
                    <div className="panel-desc">{selected.manufacturer}</div>
                  </div>
                  <span className={`orphan-badge ${orphanBadgeClass(selected.state)}`}>{selected.state}</span>
                </div>

                <div className="panel-body space-y-5">
                  {/* Rationale */}
                  <div className="bg-elevated border border-border rounded-lg p-3">
                    <div className="text-[9.5px] font-bold tracking-widest text-ink-muted mb-1.5">CLASSIFICATION RATIONALE</div>
                    {selected.rationale.map((r) => (
                      <div key={r} className="text-[10.5px] text-ink-secondary leading-5">· {r}</div>
                    ))}
                  </div>

                  {/* Evidence signals */}
                  <div>
                    <div className="text-[10px] font-semibold text-ink-secondary mb-2">
                      Detection evidence ({selected.evidence_count} active signals)
                    </div>
                    <div className="grid gap-2 sm:grid-cols-2">
                      {selected.evidence.map((item) => (
                        <div key={item.signal} className={`evidence-card ${item.detected ? "detected" : ""}`}>
                          <div className="flex items-center justify-between gap-2 mb-1">
                            <span className="text-[10px] font-medium text-ink-secondary">
                              {item.signal.replace(/_/g, " ")}
                            </span>
                            {item.detected
                              ? <Check size={12} className="text-lime flex-shrink-0" />
                              : <span className="text-[9px] text-ink-muted">not detected</span>}
                          </div>
                          <p className="text-[9.5px] text-ink-muted leading-4">{item.details}</p>
                          <div className="mt-1 mono">
                            {item.source} · {item.simulated ? "simulated" : "recorded"}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Admin claim */}
                  {selected.state === "Orphan Candidate" && isAdmin && (
                    <div className="border border-border rounded-lg p-4 bg-elevated">
                      <div className="text-[11px] font-semibold text-ink-secondary mb-1">Administrator Verification</div>
                      <p className="text-[10.5px] text-ink-muted mb-3">
                        Submit an evidence claim to begin the {dashboard.challenge_period_seconds}-second prototype challenge period.
                      </p>
                      <label className="form-label">Claim note (submitted by {actorId})</label>
                      <textarea
                        className="field w-full min-h-[60px] mb-3 text-[11px]"
                        value={claimNote}
                        onChange={(e) => setClaimNote(e.target.value)}
                      />
                      <button
                        type="button"
                        className="btn btn-primary btn-sm"
                        onClick={() => void runAction(
                          () => submitOrphanClaim(selected.device_id, actorId, claimNote),
                          "Claim submitted. The challenge period has started.",
                        )}
                        disabled={working || claimNote.trim().length < 10 || !actorId}
                      >
                        {working ? <LoaderCircle size={13} className="animate-spin" /> : <FileCheck2 size={13} />}
                        {working ? "Submitting claim…" : "Submit for verification"}
                      </button>
                    </div>
                  )}

                  {/* Attestations */}
                  {selected.state === "Verification Pending" && (
                    <div className="border border-border rounded-lg p-4 bg-elevated">
                      <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
                        <div>
                          <div className="text-[11px] font-semibold text-ink-secondary">Independent Attestations</div>
                          <div className="text-[10px] text-ink-muted mt-0.5">
                            Submitted by {selected.submitted_by ?? "unknown"} · closes {dateTime(selected.challenge_until)}
                          </div>
                        </div>
                        <div className={`challenge-clock ${remaining ? "" : "ready"}`}>
                          <Clock3 size={11} />
                          {remaining ? `${remaining}s remaining` : "Challenge complete"}
                        </div>
                      </div>
                      <div className="flex gap-2 mb-3 text-[10px]">
                        <span className="vote-count vote-approve">{approvals} approve</span>
                        <span className="vote-count vote-reject">{rejections} reject</span>
                        <span className="text-ink-muted">· {dashboard.required_approvals} required</span>
                      </div>
                      {isReviewer && (
                        <>
                          <div className="grid gap-2 sm:grid-cols-2 mb-2">
                            <div className="field text-[10.5px]">{user?.display_name} · {actorId}</div>
                            <select className="field text-[10.5px]" value={decision} onChange={(e) => setDecision(e.target.value as "approve" | "reject")}>
                              <option value="approve">Approve claim</option>
                              <option value="reject">Reject claim</option>
                            </select>
                          </div>
                          <textarea className="field w-full min-h-[50px] mb-2 text-[11px]" value={reviewNote} onChange={(e) => setReviewNote(e.target.value)} />
                        </>
                      )}
                      <div className="flex flex-wrap gap-2">
                        {isReviewer && (
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => void runAction(
                              () => submitAttestation(selected.device_id, actorId, decision, reviewNote),
                              `Attestation recorded from ${user?.display_name ?? actorId}.`,
                            )}
                            disabled={working || alreadyReviewed || !actorId}
                          >
                            <FileCheck2 size={13} />
                            {alreadyReviewed ? "Already voted" : "Record attestation"}
                          </button>
                        )}
                        {isAdmin && (
                          <>
                            <button
                              type="button"
                              className="btn btn-primary btn-sm"
                              onClick={() => void runAction(
                                () => finalizeOrphanClaim(selected.device_id, actorId),
                                "Verification lifecycle updated.",
                              )}
                              disabled={working || remaining > 0 || (approvals < dashboard.required_approvals && rejections < dashboard.required_approvals)}
                            >
                              {working ? <LoaderCircle size={13} className="animate-spin" /> : <BadgeCheck size={13} />}
                              {working ? "Finalizing…" : "Finalize decision"}
                            </button>
                            {(remaining > 0 || (approvals < dashboard.required_approvals && rejections < dashboard.required_approvals)) && (
                              <p role="status" className="basis-full text-[10px] leading-4 text-ink-muted">
                                {remaining > 0 && `${remaining}s left in the challenge. `}
                                {approvals < dashboard.required_approvals && rejections < dashboard.required_approvals &&
                                  `Waiting for ${dashboard.required_approvals} matching independent votes (${approvals} approve, ${rejections} reject).`}
                              </p>
                            )}
                          </>
                        )}
                      </div>
                    </div>
                  )}

                  {selected.state === "Verified Orphan" && (
                    <div className="alert alert-success text-[10.5px]">
                      <ShieldCheck size={13} />
                      Verified after the challenge period and required independent approvals.
                    </div>
                  )}

                  {/* Audit trail */}
                  <div>
                    <div className="text-[10px] font-semibold text-ink-secondary mb-3">Audit History</div>
                    <div className="audit-timeline">
                      {[...selected.audit_history].reverse().map((entry, index) => (
                        <div className="audit-entry" key={`${entry.timestamp}-${index}`}>
                          <div className={`audit-dot ${index === 0 ? "active" : ""}`} />
                          <div className="text-[10.5px] font-medium text-ink-secondary">
                            {entry.action.replace(/_/g, " ")}
                            <span className="font-normal text-ink-muted ml-1">by {entry.actor}</span>
                          </div>
                          <p className="text-[9.5px] text-ink-muted leading-4 mt-0.5">{entry.detail}</p>
                          <time className="text-[9px] text-ink-muted block mt-0.5">{dateTime(entry.timestamp)}</time>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="panel">
                <div className="empty-state min-h-[300px]">
                  <ShieldAlert size={22} />
                  Select a device evidence record from the list.
                </div>
              </div>
            )}
          </div>

          <div className="mt-4 alert alert-info text-[10.5px]">
            <ShieldAlert size={13} className="flex-shrink-0" />
            A candidate requires ≥3 distinct signals including lifecycle + corroborating security evidence. Each case requires a challenge period and two distinct reviewer votes. All evidence is simulated.
          </div>
        </>
      )}
    </>
  );
}
