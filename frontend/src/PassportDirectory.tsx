import { useEffect, useMemo, useState } from "react";
import { ArrowUpRight, Fingerprint, Search } from "lucide-react";
import { Link } from "react-router-dom";
import { listDevices } from "./api";
import type { Device } from "./types";
import { ErrorState, PageHeader, SkeletonRow } from "./App";

export default function PassportDirectory() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    listDevices()
      .then((result) => { if (active) setDevices(result); })
      .catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : "Could not load device passports."); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  const filtered = useMemo(() => devices.filter((device) =>
    `${device.name} ${device.device_id} ${device.manufacturer} ${device.model}`
      .toLowerCase()
      .includes(search.trim().toLowerCase()),
  ), [devices, search]);

  return (
    <>
      <PageHeader
        eyebrow="DEVICE IDENTITY"
        title="Security Passports"
        description="Technical identity records for firmware provenance, support lifecycle, vulnerabilities, and recovery eligibility."
        actions={<label className="field passport-search"><Search size={13} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Find a device…" aria-label="Search device passports" /></label>}
      />
      {error ? <ErrorState message={error} /> : (
        <section className="panel">
          <div className="panel-header">
            <div><div className="panel-title">Device identities</div><div className="panel-desc">Select a record to inspect its full passport.</div></div>
            <span className="badge badge-muted">{loading ? "Loading" : `${filtered.length} records`}</span>
          </div>
          {loading && devices.length === 0 ? (
            <div className="overflow-x-auto"><table className="data-table min-w-[760px]"><tbody>{[...Array(5)].map((_, index) => <SkeletonRow key={index} cols={6} />)}</tbody></table></div>
          ) : filtered.length ? (
            <div className="overflow-x-auto">
              <table className="data-table min-w-[760px]">
                <thead><tr><th>DEVICE</th><th>MANUFACTURER / MODEL</th><th>FIRMWARE</th><th>SUPPORT</th><th>SURVIVAL SCORE</th><th></th></tr></thead>
                <tbody>
                  {filtered.map((device) => (
                    <tr key={device.device_id}>
                      <td><Link className="passport-row-link" to={`/devices/${encodeURIComponent(device.device_id)}`}><Fingerprint size={14} />{device.name}</Link><div className="mono mt-1">{device.device_id}</div></td>
                      <td>{device.manufacturer}<div className="mt-1 text-[9px] text-ink-muted">{device.model} · Rev {device.hardware_revision}</div></td>
                      <td className="font-mono text-[9px]">{device.firmware_version}</td>
                      <td><span className={`status-pill status-${device.support_status}`}>{device.support_status}</span><div className="mt-1 text-[9px] text-ink-muted">{device.compatibility_category}</div></td>
                      <td>
                        <div className="passport-score">
                          <span>{device.survival_score}</span>
                          <div className="score-bar-track"><div className={`score-bar-fill ${device.risk_level === "low" ? "high" : device.risk_level}`} style={{ width: `${device.survival_score}%` }} /></div>
                          <span className={`badge badge-${device.risk_level === "low" ? "green" : device.risk_level === "medium" ? "amber" : "ruby"}`}>{device.risk_level}</span>
                        </div>
                      </td>
                      <td><Link to={`/devices/${encodeURIComponent(device.device_id)}`} className="btn btn-ghost btn-icon btn-sm" aria-label={`Open ${device.name} passport`}><ArrowUpRight size={14} /></Link></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <div className="empty-state"><Fingerprint size={18} />{search ? "No passports match this search." : "No device passports have been registered yet."}</div>}
        </section>
      )}
    </>
  );
}
