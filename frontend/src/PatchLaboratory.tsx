import { useEffect, useState } from "react";
import { FlaskConical, RefreshCw } from "lucide-react";
import { Link } from "react-router-dom";
import { listPatches } from "./api";
import type { CommunityPatch } from "./types";

export default function PatchLaboratory() {
  const [patches, setPatches] = useState<CommunityPatch[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try { setPatches(await listPatches()); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Could not load patch lab records."); }
    finally { setLoading(false); }
  }

  useEffect(() => { void load(); }, []);
  return (
    <div>
      <header className="page-header">
        <div><div className="eyebrow"><span className="eyebrow-dot" /> SYNTHETIC ISOLATED TESTING</div>
          <h1 className="page-title">Patch Safety Laboratory</h1>
          <p className="page-desc">Review server-calculated integrity, compatibility, remediation, regression, behavior, and rollback checks. Uploaded package contents are never executed.</p>
        </div>
        <button onClick={() => void load()} disabled={loading} className="btn btn-secondary btn-sm">
          <RefreshCw size={13} /> Refresh
        </button>
      </header>
      {error && <div role="alert" className="alert alert-error mb-4">{error}</div>}
      <section className="panel">
        <div className="panel-header">
          <div><div className="panel-title">Validation runs</div><div className="panel-desc">Actual patch submissions and backend test outcomes.</div></div>
          <span className="badge badge-muted">{loading ? "Loading" : `${patches.length} submissions`}</span>
        </div>
        {loading && patches.length === 0 ? <div className="portal-empty">Loading patch test records…</div> : patches.length ? (
          <div className="overflow-x-auto">
            <table className="data-table min-w-[760px]">
              <thead><tr><th>TARGET</th><th>PACKAGE</th><th>INTEGRITY</th><th>CHECKS</th><th>RESULT</th><th></th></tr></thead>
              <tbody>
                {patches.map((patch) => {
                  const passed = patch.test_results.filter((test) => test.status === "passed").length;
                  const failed = patch.test_results.length - passed;
                  return (
                    <tr key={patch.patch_id}>
                      <td><strong className="text-ink">{patch.device_name}</strong><div className="mono mt-1">{patch.device_id}</div></td>
                      <td>v{patch.patch_version}<div className="mono mt-1">{patch.patch_id}</div></td>
                      <td><code className="mono" title={patch.sha256}>{patch.sha256.slice(0, 16)}…</code></td>
                      <td>{patch.test_results.length ? `${passed} pass · ${failed} fail` : "Not run"}</td>
                      <td><span className={`patch-status ps-${(patch.test_status ?? "submitted").toLowerCase()}`}>{patch.test_status ?? "Pending"}</span></td>
                      <td><Link to={patch.test_results.length ? `/patches/${patch.patch_id}/tests` : `/patches/${patch.patch_id}`} className="btn btn-ghost btn-sm">{patch.test_results.length ? "Report" : "Details"}</Link></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : <div className="portal-empty"><FlaskConical size={18} />No patch submissions have entered the laboratory yet.</div>}
      </section>
    </div>
  );
}
