import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  BadgeCheck,
  CheckCircle2,
  CircleAlert,
  ClipboardCheck,
  FileCheck2,
  FileUp,
  FlaskConical,
  LoaderCircle,
  ShieldAlert,
  ShieldCheck,
  UserRound,
  XCircle,
} from "lucide-react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { useAuth } from "./AuthContext";
import {
  getPatch,
  getResearcher,
  downloadSamplePackage,
  listEligiblePatchDevices,
  listPatches,
  listResearchers,
  listSamplePackages,
  releasePatch,
  reviewPatch,
  uploadPatch,
} from "./api";
import type {
  CommunityPatch,
  EligiblePatchDevice,
  PatchStatus,
  ResearcherProfile,
} from "./types";

function showDate(value: string) {
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function statusClass(status: PatchStatus) {
  return `patch-status status-${status.toLowerCase().replace(/[^a-z]+/g, "-")}`;
}

function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const run = async (action: () => Promise<unknown>, success: string) => {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await action();
      setNotice(success);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The request failed.");
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, notice, run, setError };
}

function ActionFeedback({ error, notice }: { error: string; notice: string }) {
  return (
    <>
      {error && <div role="alert" className="portal-alert error"><CircleAlert size={15} />{error}</div>}
      {notice && <div role="status" className="portal-alert success"><CheckCircle2 size={15} />{notice}</div>}
    </>
  );
}

function PageIntro({ label, title, description }: { label: string; title: string; description: string }) {
  return (
    <header className="page-header">
      <div>
      <div className="eyebrow"><span className="eyebrow-dot" /> {label}</div>
      <h1 className="page-title">{title}</h1>
      <p className="page-desc">{description}</p>
      </div>
    </header>
  );
}

function PatchRow({ patch }: { patch: CommunityPatch }) {
  const approvals = patch.reviews.filter((review) => review.decision === "approve").length;
  return (
    <tr>
      <td>
        <Link to={`/patches/${patch.patch_id}`} className="font-medium text-ink no-underline hover:text-lime">
          {patch.device_name} · v{patch.patch_version}
        </Link>
        <div className="mono mt-1">{patch.device_id}</div>
      </td>
      <td>{patch.manufacturer}<div className="mt-1 text-[9px] text-ink-muted">{patch.model}</div></td>
      <td>{patch.researcher_name}<div className="mono mt-1">{patch.researcher_id}</div></td>
      <td><span className={statusClass(patch.status)}>{patch.status}</span></td>
      <td>{approvals}/{patch.required_approvals}<div className="mt-1 text-[9px] text-ink-muted">approvals</div></td>
      <td className="font-mono text-[9px]">{showDate(patch.created_at)}</td>
      <td><Link to={`/patches/${patch.patch_id}`} className="btn btn-ghost btn-sm">Details</Link></td>
    </tr>
  );
}

export function PatchMarketplace() {
  const { user } = useAuth();
  const location = useLocation();
  const [patches, setPatches] = useState<CommunityPatch[]>([]);
  const [filter, setFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [submissionNotice, setSubmissionNotice] = useState("");
  const submittedPatchId = (location.state as { submittedPatchId?: unknown } | null)?.submittedPatchId;

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    listPatches(filter || undefined)
      .then((items) => {
        if (!active) return;
        setPatches(items);
        if (typeof submittedPatchId === "string") {
          const submittedPatch = items.find((patch) => patch.patch_id === submittedPatchId);
          setSubmissionNotice(
            submittedPatch
              ? `Patch submitted and listed. Current status: ${submittedPatch.status}.`
              : "",
          );
          if (!submittedPatch) {
            setError("The submitted patch was not returned by the marketplace. Refresh to try again.");
          }
        }
      })
      .catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : "Could not load patch marketplace."); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [filter, submittedPatchId]);

  const passed = patches.filter((patch) => patch.test_status === "Passed").length;
  return (
    <>
      <PageIntro label="COMMUNITY PATCH PROGRAM" title="Patch marketplace" description="Browse tested recovery patches for verified orphan devices. Every submitted package is hashed from its actual bytes and evaluated in the synthetic safety lab." />
      {error && <ActionFeedback error={error} notice="" />}
      {submissionNotice && <ActionFeedback error="" notice={submissionNotice} />}
      <div className="mb-5 grid gap-3 sm:grid-cols-3">
        <div className="portal-metric"><span>Listed patches</span><strong>{loading ? "—" : patches.length}</strong></div>
        <div className="portal-metric"><span>Automated tests passed</span><strong>{loading ? "—" : passed}</strong></div>
        {user?.role === "security_researcher" ? <Link to="/patches/submit" className="action-button primary justify-center"><FileUp size={15} /> Submit a patch</Link> : <Link to="/patch-lab" className="action-button secondary justify-center"><FlaskConical size={15} /> Open patch lab</Link>}
      </div>
      <section className="portal-panel">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div><h2 className="text-sm font-bold">Patch submissions</h2><p className="mt-1 text-[10px] text-muted">Validation, independent review, and release are separate workflow stages.</p></div>
          <select className="filter-field max-w-52" value={filter} onChange={(event) => setFilter(event.target.value)}>
            <option value="">All statuses</option>
            {["Awaiting Review", "Approved", "Rejected", "Released", "Failed"].map((item) => <option key={item}>{item}</option>)}
          </select>
        </div>
        {loading ? <div className="portal-empty"><LoaderCircle size={18} className="animate-spin" /> Loading marketplace…</div> : patches.length ? (
          <div className="overflow-x-auto">
            <table className="data-table min-w-[850px]">
              <thead><tr><th>PATCH / TARGET</th><th>MANUFACTURER</th><th>RESEARCHER</th><th>STATUS</th><th>REVIEW</th><th>SUBMITTED</th><th></th></tr></thead>
              <tbody>{patches.map((patch) => <PatchRow key={patch.patch_id} patch={patch} />)}</tbody>
            </table>
          </div>
        ) : error ? <div className="portal-empty">Marketplace data could not be loaded.</div> : <div className="portal-empty">No patches yet. After verifying an orphaned device, submit a synthetic package to begin.</div>}
      </section>
      <section className="portal-panel mt-5">
        <h2 className="text-sm font-bold">Safe demonstration packages</h2>
        <p className="mt-1 text-[10px] leading-5 text-muted">JSON metadata and synthetic payload strings only; neither package is executable firmware.</p>
        <SamplePackageDownloads />
      </section>
    </>
  );
}

function SamplePackageDownloads() {
  const [samples, setSamples] = useState<Array<{ filename: string; label: string; description: string; expected_test_status: string }>>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    void listSamplePackages()
      .then(setSamples)
      .catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Could not load sample package metadata."));
  }, []);

  async function download(filename: string) {
    setError("");
    try {
      const blob = await downloadSamplePackage(filename);
      const objectUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = objectUrl;
      link.download = filename;
      link.click();
      URL.revokeObjectURL(objectUrl);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not download the sample package.");
    }
  }

  return (
    <div className="mt-3 grid gap-2 md:grid-cols-2">
      {error && <div role="alert" className="portal-alert error md:col-span-2">{error}</div>}
      {samples.map((sample) => (
        <div className="sample-package" key={sample.filename}>
          <div className="flex items-center justify-between gap-2"><strong className="text-[11px]">{sample.label}</strong><span className={statusClass(sample.expected_test_status as PatchStatus)}>{sample.expected_test_status}</span></div>
          <p className="mt-1 text-[10px] leading-4 text-muted">{sample.description}</p>
          <button type="button" className="mt-2 inline-flex text-[10px] font-bold text-forest underline" onClick={() => void download(sample.filename)}>Download {sample.filename}</button>
        </div>
      ))}
    </div>
  );
}

export function SubmitPatch() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const { busy, error, notice, run } = useAction();
  const [devices, setDevices] = useState<EligiblePatchDevice[]>([]);
  const [deviceId, setDeviceId] = useState("");
  const [version, setVersion] = useState("");
  const [description, setDescription] = useState("");
  const [selectedVulnerabilities, setSelectedVulnerabilities] = useState<string[]>([]);
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(true);
  const [formError, setFormError] = useState("");

  useEffect(() => {
    let active = true;
    listEligiblePatchDevices()
      .then((eligible) => {
        if (!active) return;
        setDevices(eligible);
        setDeviceId(eligible[0]?.device_id ?? "");
      })
      .catch((reason: unknown) => setFormError(reason instanceof Error ? reason.message : "Could not load submission options."))
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  const selectedDevice = devices.find((device) => device.device_id === deviceId);
  const targetVulnerabilities = selectedDevice?.known_vulnerabilities.filter((item) => !item.patched) ?? [];
  useEffect(() => {
    setSelectedVulnerabilities(targetVulnerabilities.map((item) => item.identifier));
  }, [deviceId, devices]);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFormError("");
    if (!file || !selectedVulnerabilities.length) {
      setFormError("Select a package and at least one unpatched vulnerability to remediate.");
      return;
    }
    const form = new FormData();
    form.append("device_id", deviceId);
    if (!user) {
      setFormError("Sign in with an authorized researcher account before submitting.");
      return;
    }
    form.append("researcher_id", user.user_id);
    form.append("patch_version", version);
    form.append("description", description);
    form.append("vulnerabilities", JSON.stringify(selectedVulnerabilities));
    form.append("patch_file", file);
    let created: CommunityPatch | undefined;
    await run(async () => { created = await uploadPatch(form); }, "Patch package received and tested.");
    if (created) navigate("/patches", { state: { submittedPatchId: created.patch_id } });
  };

  if (loading) return <div className="portal-empty"><LoaderCircle size={18} className="animate-spin" /> Loading eligible devices…</div>;
  return (
    <>
      <Link to="/patches" className="back-link"><ArrowLeft size={14} /> Marketplace</Link>
      <PageIntro label="RESEARCHER PORTAL" title="Submit a community patch" description="Only devices already verified as orphaned are eligible. Upload a bounded synthetic JSON package; the backend calculates its SHA-256 and never executes its contents." />
      <ActionFeedback error={error || formError} notice={notice} />
      {devices.length === 0 ? (
        <div className="portal-panel">
          <div className="flex items-start gap-3"><ShieldAlert className="mt-1 text-amber-700" size={18} /><div><h2 className="text-sm font-bold">No eligible devices yet</h2><p className="mt-1 text-xs leading-5 text-muted">A device becomes available here only after its orphan claim passes the Phase 2 challenge and reviewer approvals. Start in <Link to="/orphans" className="font-bold text-forest underline">Orphan Detection Center</Link>.</p></div></div>
        </div>
      ) : (
        <form className="portal-panel max-w-3xl" onSubmit={(event) => void submit(event)}>
          <div className="grid gap-4 sm:grid-cols-2">
            <label className="portal-label">Verified orphan device
              <select className="filter-field mt-1.5 w-full" value={deviceId} onChange={(event) => setDeviceId(event.target.value)}>
                {devices.map((device) => <option value={device.device_id} key={device.device_id}>{device.name} · {device.device_id}</option>)}
              </select>
            </label>
            <div className="portal-label rounded-md border border-border bg-elevated p-3">Authenticated researcher<br /><strong className="mt-1 inline-block text-[11px] text-ink">{user?.display_name} · {user?.user_id}</strong></div>
            <label className="portal-label">Patch version
              <input className="portal-input mt-1.5" required maxLength={60} value={version} onChange={(event) => setVersion(event.target.value)} placeholder="2.0.9-community.1" />
            </label>
            <label className="portal-label">Package file (.json, up to 1 MiB)
              <input className="portal-input mt-1.5" required type="file" accept=".json,application/json" onChange={(event) => setFile(event.target.files?.[0] ?? null)} />
            </label>
          </div>
          <label className="portal-label mt-4 block">Description
            <textarea className="portal-input mt-1.5 min-h-24 resize-y" required minLength={10} maxLength={2000} value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Describe the change and its safety assumptions." />
          </label>
          <fieldset className="mt-4">
            <legend className="portal-label">Vulnerabilities this patch intends to fix</legend>
            <div className="mt-2 grid gap-2 sm:grid-cols-2">
              {targetVulnerabilities.map((vulnerability) => (
                <label key={vulnerability.identifier} className="vuln-select">
                  <input type="checkbox" checked={selectedVulnerabilities.includes(vulnerability.identifier)} onChange={(event) => setSelectedVulnerabilities((current) => event.target.checked ? [...current, vulnerability.identifier] : current.filter((value) => value !== vulnerability.identifier))} />
                  <span><strong>{vulnerability.identifier}</strong><small>{vulnerability.severity} · {vulnerability.description}</small></span>
                </label>
              ))}
            </div>
          </fieldset>
          <div className="mt-4 rounded-md border border-border bg-elevated p-3 text-[10px] leading-5 text-muted">
            The synthetic JSON format describes device and firmware capabilities. Fixed backend test scripts check those capabilities; suspicious indicators, incompatible hardware, missing remediation, regressions, behavioural failures, or missing rollback fail. No uploaded firmware runs on the host.
          </div>
          <button type="submit" className="action-button primary mt-4" disabled={busy || !user || !deviceId}>
            {busy ? <LoaderCircle size={15} className="animate-spin" /> : <FlaskConical size={15} />} Submit for safety testing
          </button>
        </form>
      )}
      <div className="mt-5"><SamplePackageDownloads /></div>
    </>
  );
}

function loadPatch(patchId: string, callback: (patch: CommunityPatch) => void, fail: (message: string) => void) {
  return getPatch(patchId).then(callback).catch((reason: unknown) => fail(reason instanceof Error ? reason.message : "Could not load patch."));
}

export function PatchDetails() {
  const { patchId = "" } = useParams();
  const [patch, setPatch] = useState<CommunityPatch | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    void loadPatch(patchId, (item) => { if (active) setPatch(item); }, (message) => { if (active) setError(message); });
    return () => { active = false; };
  }, [patchId]);
  if (error) return <ActionFeedback error={error} notice="" />;
  if (!patch) return <div className="portal-empty"><LoaderCircle size={18} className="animate-spin" /> Loading patch…</div>;
  return (
    <>
      <Link to="/patches" className="back-link"><ArrowLeft size={14} /> Marketplace</Link>
      <PageIntro label="PATCH DETAILS" title={`${patch.device_name} · ${patch.patch_version}`} description={patch.description} />
      <div className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
        <section className="portal-panel">
          <div className="flex flex-wrap items-center justify-between gap-3"><h2 className="text-sm font-bold">Submission metadata</h2><span className={statusClass(patch.status)}>{patch.status}</span></div>
          <div className="patch-detail-grid mt-4">
            <Info label="Patch ID" value={patch.patch_id} mono />
            <Info label="Target device" value={`${patch.device_name} · ${patch.device_id}`} />
            <Info label="Manufacturer / model" value={`${patch.manufacturer} · ${patch.model}`} />
            <Info label="Hardware revision" value={patch.hardware_revision} />
            <Info label="Researcher" value={`${patch.researcher_name} (${patch.researcher_id})`} />
            <Info label="Submitted" value={showDate(patch.created_at)} />
            <Info label="Uploaded file" value={`${patch.original_filename} · ${patch.file_size.toLocaleString()} bytes`} />
          </div>
          <div className="mt-4">
            <div className="text-[9px] font-bold tracking-wide text-muted">SERVER-CALCULATED SHA-256</div>
            <code className="mt-1 block break-all font-mono text-[10px] leading-5">{patch.sha256}</code>
          </div>
          {patch.blockchain_sync ? (
            <div className={`mt-4 rounded-md border p-3 text-[10px] leading-5 ${patch.blockchain_sync.status === "confirmed" ? "border-emerald/30 bg-emerald/10 text-emerald" : "border-ruby/30 bg-ruby/10 text-ruby"}`}>
              <strong>On-chain submission: {patch.blockchain_sync.status}</strong>
              {patch.blockchain_submission && <code className="mt-1 block break-all">Tx {patch.blockchain_submission.transaction_hash} · block {patch.blockchain_submission.block_number}</code>}
              {patch.blockchain_sync.error && <p className="mt-1">{patch.blockchain_sync.error}</p>}
            </div>
          ) : (
            <div className="mt-4 rounded-md border border-amber/30 bg-amber/10 p-3 text-[10px] leading-5 text-amber">
              No blockchain deployment was configured when this patch was submitted; this patch has no on-chain submission.
            </div>
          )}
          {patch.blockchain_release && (
            <div className="mt-3 rounded-md border border-emerald/30 bg-emerald/10 p-3 text-[10px] leading-5 text-emerald">
              <strong>On-chain firmware release confirmed</strong>
              <code className="mt-1 block break-all">Tx {patch.blockchain_release.transaction_hash} · block {patch.blockchain_release.block_number}</code>
            </div>
          )}
          <div className="mt-4 border-t border-border pt-4">
            <h3 className="text-[11px] font-bold">Intended vulnerability fixes</h3>
            <div className="mt-2 flex flex-wrap gap-2">{patch.vulnerabilities.map((item) => <span className="signal-chip" key={item}>{item}</span>)}</div>
          </div>
          <Link className="action-button secondary mt-5 inline-flex" to={`/patches/${patch.patch_id}/tests`}><ClipboardCheck size={14} /> View testing results</Link>
        </section>
        <section className="portal-panel">
          <h2 className="text-sm font-bold">Community review</h2>
          <p className="mt-1 text-[10px] leading-5 text-muted">Automated tests must pass before this review queue. Approval requires {patch.required_approvals} distinct authorized reviewers.</p>
          <div className="mt-3 space-y-3">
            {patch.reviews.length ? patch.reviews.map((review) => (
              <div className="review-card" key={review.reviewer_id}>
                <div className="flex items-center justify-between gap-2"><strong className="text-[11px]">{review.reviewer_name}</strong><span className={`vote-count ${review.decision}`}>{review.decision}</span></div>
                <p className="mt-1 text-[10px] leading-5 text-muted">{review.comment}</p>
                {review.rejection_reason && <p className="mt-1 text-[10px] font-semibold text-ruby">Reason: {review.rejection_reason}</p>}
              </div>
            )) : <p className="text-[11px] text-muted">No reviews submitted yet.</p>}
          </div>
          <div className="mt-4 space-y-2 border-t border-border pt-3">
            {patch.audit_history.map((entry, index) => <div className="text-[9px] leading-4 text-muted" key={`${entry.timestamp}-${index}`}><strong className="text-ink">{entry.action.replace(/_/g, " ")}</strong> · {entry.actor} · {entry.detail}</div>)}
          </div>
          <div className="mt-4 border-t border-border pt-3">
            <h3 className="text-[10px] font-bold">Status lifecycle</h3>
            <div className="mt-2 flex flex-wrap items-center gap-1">
              {patch.status_history.map((transition, index) => (
                <span className="inline-flex items-center gap-1" key={`${transition.status}-${index}`}>
                  <span className={statusClass(transition.status)}>{transition.status}</span>
                  {index < patch.status_history.length - 1 && <ArrowRight size={11} className="text-muted" />}
                </span>
              ))}
            </div>
          </div>
        </section>
      </div>
    </>
  );
}

export function PatchTestingResults() {
  const { patchId = "" } = useParams();
  const [patch, setPatch] = useState<CommunityPatch | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    void loadPatch(patchId, (item) => { if (active) setPatch(item); }, (message) => { if (active) setError(message); });
    return () => { active = false; };
  }, [patchId]);
  if (error) return <ActionFeedback error={error} notice="" />;
  if (!patch) return <div className="portal-empty"><LoaderCircle size={18} className="animate-spin" /> Loading safety results…</div>;
  const failed = patch.test_results.filter((item) => item.status === "failed");
  return (
    <>
      <Link to={`/patches/${patch.patch_id}`} className="back-link"><ArrowLeft size={14} /> Patch details</Link>
      <PageIntro label="PATCH SAFETY LABORATORY" title="Testing results" description={`${patch.device_name} · patch ${patch.patch_version} · SHA-256 ${patch.sha256.slice(0, 16)}…`} />
      <div className={`lab-summary ${patch.test_status === "Passed" ? "passed" : "failed"}`}>
        {patch.test_status === "Passed" ? <CheckCircle2 size={20} /> : <XCircle size={20} />}
        <div><strong>{patch.test_status === "Passed" ? "All automated safety checks passed" : "Patch failed automated safety checks"}</strong><p>{patch.status === "Awaiting Review" ? "Awaiting independent reviewer approval; passing tests alone do not approve or release the patch." : patch.status === "Failed" ? "This patch cannot be approved or released. Review each failed check below." : `Current workflow status: ${patch.status}.`}</p></div>
      </div>
      {failed.length > 0 && <div className="alert alert-error mt-4"><div><strong>Why it failed:</strong><ul className="mt-2 list-disc space-y-1 pl-5">{failed.map((test) => <li key={test.name}><strong>{test.name}:</strong> {test.summary} {test.details.join(" ")}</li>)}</ul></div></div>}
      <section className="mt-5 grid gap-3 md:grid-cols-2">
        {patch.test_results.map((test, index) => (
          <article className={`test-result ${test.status}`} key={test.name}>
            <div className="flex items-start justify-between gap-3"><div className="flex items-center gap-2"><span className={`test-number ${test.status}`}>{String(index + 1).padStart(2, "0")}</span><h2 className="text-xs font-bold">{test.name}</h2></div>{test.status === "passed" ? <CheckCircle2 size={16} className="shrink-0 text-forest" /> : <XCircle size={16} className="shrink-0 text-red-600" />}</div>
            <p className="mt-3 text-[11px] font-semibold">{test.summary}</p>
            <ul className="mt-2 space-y-1">{test.details.map((detail) => <li className="text-[10px] leading-4 text-muted" key={detail}>• {detail}</li>)}</ul>
          </article>
        ))}
      </section>
      <p className="alert alert-info mt-4">Safety boundary: fixed backend scripts check a bounded JSON metadata package against simulated model requirements. The patch bytes are never executed on the host or in a container.</p>
    </>
  );
}

export function ResearcherDirectory() {
  const [profiles, setProfiles] = useState<ResearcherProfile[]>([]);
  const [error, setError] = useState("");
  useEffect(() => { void listResearchers("researcher").then(setProfiles).catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Could not load researcher profiles.")); }, []);
  return (
    <>
      <PageIntro label="COMMUNITY DIRECTORY" title="Researcher profiles" description="Profiles are linked to authenticated accounts. Reputation increases only for patches that pass testing, earn reviewer quorum and are released." />
      {error && <ActionFeedback error={error} notice="" />}
      <div className="grid gap-5">
        <section className="portal-panel">
          <h2 className="text-sm font-bold">Community researchers</h2>
          <div className="mt-3 space-y-2">
            {profiles.map((profile) => (
              <Link to={`/researchers/${profile.researcher_id}`} className="profile-row" key={profile.researcher_id}>
                <span className="profile-avatar"><UserRound size={17} /></span>
                <span className="min-w-0 flex-1"><strong className="block text-xs">{profile.display_name}</strong><small className="mt-1 block truncate text-[10px] text-muted">{profile.affiliation} · {profile.researcher_id}</small></span>
                <span className="text-right"><strong className="block text-xs">{profile.reputation} rep</strong><small className="text-[9px] text-muted">{profile.verified_contributions} releases</small></span>
                <ArrowRight size={14} className="text-muted" />
              </Link>
            ))}
            {!profiles.length && !error && <p className="text-xs text-muted">No researcher profiles are registered yet.</p>}
          </div>
        </section>
      </div>
    </>
  );
}

export function ResearcherProfilePage() {
  const { researcherId = "" } = useParams();
  const [profile, setProfile] = useState<ResearcherProfile | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    getResearcher(researcherId).then((value) => { if (active) setProfile(value); }).catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : "Could not load profile."); });
    return () => { active = false; };
  }, [researcherId]);
  if (error) return <ActionFeedback error={error} notice="" />;
  if (!profile) return <div className="portal-empty"><LoaderCircle size={18} className="animate-spin" /> Loading profile…</div>;
  return (
    <>
      <Link to="/researchers" className="back-link"><ArrowLeft size={14} /> Researcher directory</Link>
      <div className="portal-panel mt-3 max-w-3xl">
        <div className="flex items-start gap-4"><span className="profile-avatar large"><UserRound size={24} /></span><div><div className="flex flex-wrap items-center gap-2"><h1 className="text-2xl font-bold">{profile.display_name}</h1><span className="role-pill">{profile.role}</span></div><p className="mt-1 text-xs text-muted">{profile.affiliation} · {profile.researcher_id}</p><p className="mt-3 max-w-2xl text-sm leading-6 text-muted">{profile.bio}</p></div></div>
        <div className="mt-6 grid gap-3 sm:grid-cols-3"><div className="portal-metric"><span>Reputation</span><strong>{profile.reputation}</strong></div><div className="portal-metric"><span>Verified releases</span><strong>{profile.verified_contributions}</strong></div><div className="portal-metric"><span>Role</span><strong className="capitalize">{profile.role}</strong></div></div>
        <h2 className="mt-6 text-sm font-bold">Released contributions</h2>
        {profile.released_patches.length ? <div className="mt-3 space-y-2">{profile.released_patches.map((patch) => <Link className="profile-row" key={patch.patch_id} to={`/patches/${patch.patch_id}`}><span><strong className="text-xs">{patch.patch_version}</strong><small className="mt-1 block text-[10px] text-muted">{patch.device_id} · {patch.patch_id}</small></span><ArrowRight size={14} /></Link>)}</div> : <p className="mt-2 text-xs text-muted">No verified releases yet. Failed or unreleased patches do not increase reputation.</p>}
      </div>
    </>
  );
}

export function ReviewerApproval() {
  const { user } = useAuth();
  const [patches, setPatches] = useState<CommunityPatch[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [selectedId, setSelectedId] = useState("");
  const [decision, setDecision] = useState<"approve" | "reject">("approve");
  const [comment, setComment] = useState("Automated results and target metadata reviewed.");
  const [reason, setReason] = useState("");
  const [releaseNote, setReleaseNote] = useState("Approved synthetic patch released for the virtual device.");
  const [signatureB64, setSignatureB64] = useState("");
  const { busy, error, notice, run } = useAction();
  const reviewerId = user?.role === "independent_reviewer" ? user.user_id : "";

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError("");
    try {
      const allPatches = await listPatches();
      setPatches(allPatches);
      setSelectedId((current) => allPatches.some((patch) => patch.patch_id === current) ? current : allPatches.find((patch) => patch.status === "Awaiting Review" || patch.status === "Approved")?.patch_id ?? "");
    } catch (reason) {
      setLoadError(reason instanceof Error ? reason.message : "Could not load the reviewer queue.");
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => { void load(); }, [load]);
  const selected = useMemo(() => patches.find((patch) => patch.patch_id === selectedId) ?? null, [patches, selectedId]);
  const reviewed = selected?.reviews.some((review) => review.reviewer_id === reviewerId) ?? false;

  const submitReview = () => selected && void run(async () => {
    await reviewPatch(selected.patch_id, reviewerId, decision, comment, reason);
    await load();
  }, "Reviewer decision recorded.");
  const submitRelease = () => selected && void run(async () => {
    if (!user || user.role !== "administrator") throw new Error("Administrator access is required to release a patch.");
    await releasePatch(selected.patch_id, releaseNote, signatureB64, user.user_id);
    await load();
  }, "Approved patch released.");

  return (
    <>
      <PageIntro label="INDEPENDENT PATCH REVIEW" title="Reviewer approval" description="Only server-assigned reviewer profiles can vote. A patch must pass every lab check and receive two distinct approvals; votes alone cannot override a failed test." />
      <ActionFeedback error={error || loadError} notice={notice} />
      <div className="grid gap-5 xl:grid-cols-[0.8fr_1.2fr]">
        <section className="portal-panel">
          <h2 className="text-sm font-bold">Review queue</h2>
          <div className="mt-3 space-y-2">
            {loading ? <div className="portal-empty"><LoaderCircle size={18} className="animate-spin" /> Loading reviewer queue…</div> : patches.filter((patch) => ["Awaiting Review", "Approved", "Rejected"].includes(patch.status)).map((patch) => (
              <button className={`queue-row ${selectedId === patch.patch_id ? "active" : ""}`} onClick={() => setSelectedId(patch.patch_id)} key={patch.patch_id}>
                <span className="min-w-0 flex-1 text-left"><strong className="block truncate text-[11px]">{patch.device_name} · {patch.patch_version}</strong><small className="mt-1 block text-[9px] text-muted">{patch.patch_id} · {patch.reviews.length} review(s)</small></span><span className={statusClass(patch.status)}>{patch.status}</span>
              </button>
            ))}
            {!loading && !loadError && !patches.some((patch) => ["Awaiting Review", "Approved", "Rejected"].includes(patch.status)) && <p className="text-xs text-muted">No patches in the reviewer queue.</p>}
          </div>
        </section>
        {selected ? (
          <section className="portal-panel">
            <div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="text-sm font-bold">{selected.device_name} · {selected.patch_version}</h2><p className="mt-1 text-[10px] text-muted">{selected.patch_id} · lab result: {selected.test_status ?? "not run"}</p></div><span className={statusClass(selected.status)}>{selected.status}</span></div>
            <Link to={`/patches/${selected.patch_id}/tests`} className="action-button secondary mt-3 inline-flex"><ClipboardCheck size={14} /> Review test report</Link>
            {selected.test_status !== "Passed" && <div className="alert alert-error mt-4">Automated tests failed. This submission is not eligible for reviewer approval.</div>}
            {selected.status === "Awaiting Review" && selected.test_status === "Passed" && user?.role === "independent_reviewer" && (
              <div className="mt-4 border-t border-border pt-4">
                <div className="rounded-md border border-border bg-elevated p-3 text-[10px]">Reviewing as <strong className="text-ink">{user.display_name} · {user.user_id}</strong></div>
                <label className="portal-label mt-3 block">Decision
                  <select className="filter-field mt-1.5 w-full" value={decision} onChange={(event) => setDecision(event.target.value as "approve" | "reject")}><option value="approve">Approve</option><option value="reject">Reject</option></select>
                </label>
                <label className="portal-label mt-3 block">Reviewer comment<textarea className="portal-input mt-1.5 min-h-20" required minLength={5} value={comment} onChange={(event) => setComment(event.target.value)} /></label>
                {decision === "reject" && <label className="portal-label mt-3 block">Rejection reason<textarea className="portal-input mt-1.5 min-h-16" required minLength={5} value={reason} onChange={(event) => setReason(event.target.value)} /></label>}
                <button className="action-button primary mt-3" onClick={submitReview} disabled={busy || reviewed || !reviewerId || comment.trim().length < 5 || (decision === "reject" && reason.trim().length < 5)}>{busy ? <LoaderCircle size={14} className="animate-spin" /> : <FileCheck2 size={14} />}{reviewed ? "This reviewer already voted" : "Record independent review"}</button>
                <p className="mt-2 text-[9px] text-muted">Quorum: {selected.reviews.filter((item) => item.decision === "approve").length}/{selected.required_approvals} approvals. A single vote cannot approve.</p>
              </div>
            )}
            {user?.role === "administrator" && selected.status === "Awaiting Review" && <div className="alert alert-info mt-4">Independent reviewers record their own decisions. Administrators cannot impersonate reviewer identities.</div>}
            {selected.status === "Approved" && user?.role === "administrator" && (
              <div className="mt-4 border-t border-border pt-4">
                <div className="flex items-center gap-2 text-xs font-bold text-emerald"><BadgeCheck size={16} /> Reviewer quorum reached; admin release required.</div>
                <label className="portal-label mt-3 block">Release note<textarea className="portal-input mt-1.5 min-h-16" minLength={5} value={releaseNote} onChange={(event) => setReleaseNote(event.target.value)} /></label>
                <div className="mt-3 rounded-md border border-border bg-elevated p-3 text-[10px] leading-5 text-muted">
                  When the local chain is deployed, sign the exact stored package with the community maintainer key from the backend terminal:
                  <code className="mt-1 block break-all font-mono">cd backend &amp;&amp; python -m app.sign_patch {selected.patch_id}</code>
                  Paste only the resulting Base64 signature below. Never paste or upload the private key.
                </div>
                <label className="portal-label mt-3 block">Community Ed25519 signature<textarea className="portal-input mt-1.5 min-h-16 font-mono" value={signatureB64} onChange={(event) => setSignatureB64(event.target.value)} placeholder="Signature returned by the backend signing command" /></label>
                <button className="action-button primary mt-3" onClick={submitRelease} disabled={busy || releaseNote.trim().length < 5}>{busy ? <LoaderCircle size={14} className="animate-spin" /> : <ShieldCheck size={14} />} Release patch as simulated admin</button>
                <p className="mt-2 text-[9px] text-muted">The API re-hashes stored file bytes, verifies the Ed25519 signature, then submits the release using the pre-authorized local maintainer account. The audit actor is your authenticated administrator account.</p>
              </div>
            )}
            {selected.status === "Approved" && user?.role === "independent_reviewer" && <div className="alert alert-info mt-4">Reviewer quorum reached. An administrator must release this patch.</div>}
            <div className="mt-4 space-y-2 border-t border-border pt-3">{selected.reviews.map((review) => <div className="review-card" key={review.reviewer_id}><div className="flex items-center justify-between"><strong className="text-[10px]">{review.reviewer_name}</strong><span className={`vote-count ${review.decision}`}>{review.decision}</span></div><p className="mt-1 text-[10px] text-muted">{review.comment}</p>{review.rejection_reason && <p className="mt-1 text-[10px] text-ruby">Reason: {review.rejection_reason}</p>}</div>)}</div>
          </section>
        ) : <div className="portal-empty">Select a patch from the queue to review.</div>}
      </div>
    </>
  );
}

function Info({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return <div><div className="text-[9px] font-semibold text-muted">{label}</div><div className={`mt-1 break-words text-[11px] font-semibold ${mono ? "font-mono" : ""}`}>{value}</div></div>;
}
