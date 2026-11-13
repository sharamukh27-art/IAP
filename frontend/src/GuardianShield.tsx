import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  CheckCircle2,
  CircleAlert,
  LoaderCircle,
  LockKeyhole,
  Radio,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Wifi,
  WifiOff,
} from "lucide-react";
import { Link } from "react-router-dom";
import {
  getGuardianDashboard,
  listPatches,
  simulateGuardianNetworkAttempt,
  startGuardianRecovery,
} from "./api";
import { useAuth } from "./AuthContext";
import type { CommunityPatch, GuardianDashboard, GuardianEvent } from "./types";
import { PageHeader, Panel } from "./App";

function guardianBadgeClass(state: string) {
  if (state === "NORMAL" || state === "RECOVERY VERIFIED") return "g-normal";
  if (state === "QUARANTINED") return "g-quarantined";
  if (state === "RECOVERY PENDING") return "g-pending";
  return "g-restricted";
}

function readableTime(value?: string) {
  if (!value) return "No activity recorded";
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf())
    ? value
    : new Intl.DateTimeFormat("en", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }).format(parsed);
}

export default function GuardianShield() {
  const { user } = useAuth();
  const [dashboard, setDashboard] = useState<GuardianDashboard | null>(null);
  const [patches, setPatches] = useState<CommunityPatch[]>([]);
  const [selectedPatches, setSelectedPatches] = useState<Record<string, string>>({});
  const [destinations, setDestinations] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [result, released] = await Promise.all([getGuardianDashboard(), listPatches("Released")]);
      setDashboard(result);
      setPatches(released);
      setSelectedPatches((current) => {
        const next = { ...current };
        for (const device of result.devices) {
          if (!next[device.device_id])
            next[device.device_id] = released.find((p) => p.device_id === device.device_id)?.patch_id ?? "";
        }
        return next;
      });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load Guardian Shield.");
    } finally { setLoading(false); }
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 10000);
    return () => window.clearInterval(timer);
  }, [load]);

  const blockedCount = dashboard?.blocked_connections ?? 0;
  const stateCounts = useMemo(() => {
    const r: Record<string, number> = {};
    for (const d of dashboard?.devices ?? []) r[d.protection_state] = (r[d.protection_state] ?? 0) + 1;
    return r;
  }, [dashboard]);

  async function attemptNetwork(deviceId: string) {
    setBusy(`${deviceId}:network`); setError(""); setNotice("");
    try {
      const result = await simulateGuardianNetworkAttempt(deviceId, destinations[deviceId] || "exfiltration.attacker.test");
      setNotice(result.allowed
        ? `${deviceId}: gateway allowed ${result.destination}.`
        : `${deviceId}: gateway blocked ${result.destination} — ${result.reason}`);
      await load();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Network simulation failed.");
    } finally { setBusy(""); }
  }

  async function recover(deviceId: string) {
    const patchId = selectedPatches[deviceId];
    if (!patchId) { setError("Select a released patch for this device first."); return; }
    setBusy(`${deviceId}:recovery`); setError(""); setNotice("");
    try {
      const result = await startGuardianRecovery(deviceId, patchId);
      setNotice(result.passed
        ? `${deviceId}: firmware checks passed. Gateway access restored and protection is NORMAL.`
        : `${deviceId}: recovery refused. ${result.reason}`);
      await load();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Recovery simulation failed.");
    } finally { setBusy(""); }
  }

  if (loading && !dashboard) {
    return (
      <div className="flex items-center justify-center min-h-[50vh] text-ink-muted text-sm gap-2">
        <LoaderCircle size={16} className="animate-spin" /> Loading Guardian Shield…
      </div>
    );
  }

  const events = dashboard?.events ?? [];

  return (
    <>
      <PageHeader
        eyebrow="AUTONOMOUS DEVICE PROTECTION"
        title="Guardian Shield"
        description="Virtual per-device Guardians enforce backend policies through a simulated MQTT gateway."
        actions={
          <button className="btn btn-secondary btn-sm" onClick={() => void load()}>
            <RefreshCw size={12} /> Refresh
          </button>
        }
      />

      {error  && <div className="alert alert-error  mb-4 text-[11px]"><CircleAlert size={13} />{error}</div>}
      {notice && <div className={`alert mb-4 text-[11px] ${notice.includes("blocked") || notice.includes("refused") ? "alert-error" : "alert-success"}`}><Activity size={13} />{notice}</div>}

      <div className="guardian-status-strip mb-4">
        <div><span>MQTT broker</span><strong className={dashboard?.mqtt.available ? "text-emerald" : "text-ruby"}>{dashboard?.mqtt.available ? "Connected" : "Unavailable"}</strong></div>
        <div><span>Virtual agents</span><strong>{dashboard?.mqtt.virtual_agents ?? dashboard?.devices.length ?? 0}</strong></div>
        <div><span>Restricted</span><strong>{stateCounts["RESTRICTED"] ?? 0}</strong></div>
        <div><span>Quarantined</span><strong>{stateCounts["QUARANTINED"] ?? 0}</strong></div>
        <div><span>Blocked connections</span><strong>{blockedCount}</strong></div>
      </div>

      {!dashboard?.mqtt.available && (
        <div className="alert alert-warning mb-4 text-[11px]">
          <WifiOff size={13} />
          MQTT actions are disabled until Mosquitto is reachable.
          Run <code className="font-mono text-amber">docker compose up -d mosquitto</code>
        </div>
      )}

      <Panel title="Virtual network topology" description="Device state and gateway activity reported by the backend agent network.">
        <div className="network-topology">
          <div className="network-gateway">
            <Radio className="network-gateway-icon" size={17} />
            <div className="min-w-0 flex-1">
              <div className="text-[10px] font-semibold text-ink">Simulated MQTT gateway</div>
              <div className="mono mt-1">{dashboard?.mqtt.gateway ?? dashboard?.mqtt.broker ?? "Broker status unavailable"}</div>
            </div>
            <span className={`status-pill ${dashboard?.mqtt.available ? "status-supported" : "status-unsupported"}`}>
              {dashboard?.mqtt.available ? "Online" : "Offline"}
            </span>
          </div>
          <div className="network-device-grid">
            {(dashboard?.devices ?? []).map((device) => (
              <Link className="network-device-node" to={`/devices/${encodeURIComponent(device.device_id)}`} key={device.device_id}>
                <span className="network-device-name">{device.name}</span>
                <span className="network-device-meta">{device.device_id} · {device.model}</span>
                <span className={`guardian-badge network-node-state ${guardianBadgeClass(device.protection_state)}`}>{device.protection_state}</span>
                <span className="text-[9px] text-ink-muted">{device.network_access} · {device.blocked_connections} blocked</span>
              </Link>
            ))}
            {!dashboard?.devices.length && <div className="empty-state">No device agents are registered.</div>}
          </div>
        </div>
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2 mb-5">
        {(dashboard?.devices ?? []).map((device) => {
          const devicePatches = patches.filter((p) => p.device_id === device.device_id);
          const isBusy = busy.startsWith(`${device.device_id}:`);
          return (
            <div key={device.device_id} className="panel">
              <div className="panel-header">
                <div>
                  <div className="mono mb-1">{device.manufacturer} · {device.device_id}</div>
                  <div className="panel-title text-[14px]">{device.name}</div>
                  <div className="panel-desc">{device.model} · Firmware {device.firmware_version}</div>
                </div>
                <span className={`guardian-badge ${guardianBadgeClass(device.protection_state)}`}>
                  {device.protection_state === "NORMAL" ? <ShieldCheck size={11} /> :
                   device.protection_state === "QUARANTINED" ? <LockKeyhole size={11} /> :
                   <ShieldAlert size={11} />}
                  {device.protection_state}
                </span>
              </div>

              <div className="panel-body space-y-4">
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                  {[
                    ["Maintenance",    device.maintenance_status],
                    ["Firmware auth",  device.firmware_authentic ? "Verified" : "Unverified"],
                    ["Recovery",       device.recovery_state],
                    ["Gateway access", device.network_access],
                    ["Blocked",        String(device.blocked_connections)],
                  ].map(([label, value]) => (
                    <div key={label} className="border border-border rounded-lg px-3 py-2">
                      <div className="text-[9px] text-ink-muted">{label}</div>
                      <div className={`text-[11px] font-medium mt-0.5 capitalize ${
                        value === "Unverified" || value === "isolated" ? "text-ruby" :
                        value === "Verified" || value === "restored" ? "text-emerald" :
                        "text-ink-secondary"
                      }`}>{value}</div>
                    </div>
                  ))}
                </div>

                <div className="hash-display">
                  <div className="text-[8.5px] font-bold tracking-widest text-ink-muted mb-1">CURRENT FIRMWARE SHA-256</div>
                  {device.firmware_sha256}
                </div>

                {device.firmware_verification.length > 0 && (
                  <div>
                    <div className="text-[9.5px] font-semibold text-ink-muted mb-2 uppercase tracking-wide">Latest Firmware Verification</div>
                    <div className="space-y-1.5">
                      {device.firmware_verification.map((check) => (
                        <div key={check.name} className="flex items-start gap-2 text-[10.5px]">
                          {check.passed
                            ? <CheckCircle2 size={12} className="text-emerald flex-shrink-0 mt-0.5" />
                            : <CircleAlert   size={12} className="text-ruby flex-shrink-0 mt-0.5" />}
                          <span className="text-ink-secondary">
                            <span className="font-medium">{check.name}:</span>{" "}
                            <span className="text-ink-muted">{check.details}</span>
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {(user?.role === "administrator" || user?.role === "device_owner") && (
                  <div className="border border-border rounded-lg p-3">
                    <div className="text-[9.5px] font-semibold text-ink-muted uppercase tracking-wide mb-2 flex items-center gap-1.5">
                      <Wifi size={11} /> Simulated network test
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <label className="field flex-1 min-w-[150px]">
                        <input
                          aria-label={`Simulated destination for ${device.name}`}
                          value={destinations[device.device_id] ?? "exfiltration.attacker.test"}
                          onChange={(e) => setDestinations((c) => ({ ...c, [device.device_id]: e.target.value }))}
                          placeholder="hostname.example"
                        />
                      </label>
                      <button
                        disabled={!dashboard?.mqtt.available || isBusy}
                        onClick={() => void attemptNetwork(device.device_id)}
                        className="btn btn-secondary btn-sm"
                      >
                        {isBusy && busy.endsWith(":network") ? <LoaderCircle size={12} className="animate-spin" /> : <Wifi size={12} />}
                        Test
                      </button>
                    </div>
                    <p className="mt-1.5 text-[9.5px] text-ink-muted">
                      Last activity: {readableTime(device.network_activity?.timestamp)}
                      {device.network_activity && ` · ${device.network_activity.allowed ? "allowed" : "blocked"} ${device.network_activity.destination}`}
                    </p>
                  </div>
                )}

                {user?.role === "administrator" && (
                  <div className="border border-border rounded-lg p-3">
                    <div className="text-[9.5px] font-semibold text-ink-muted uppercase tracking-wide mb-2">Recovery package</div>
                    <div className="flex flex-wrap gap-2">
                      <select
                        aria-label={`Released patch for ${device.name}`}
                        className="field flex-1 min-w-[150px]"
                        value={selectedPatches[device.device_id] ?? ""}
                        onChange={(e) => setSelectedPatches((c) => ({ ...c, [device.device_id]: e.target.value }))}
                      >
                        <option value="">Select a released patch</option>
                        {devicePatches.map((p) => <option key={p.patch_id} value={p.patch_id}>{p.patch_id} · {p.patch_version}</option>)}
                      </select>
                      <button
                        disabled={!dashboard?.mqtt.available || !selectedPatches[device.device_id] || isBusy}
                        onClick={() => void recover(device.device_id)}
                        className="btn btn-primary btn-sm"
                      >
                        {isBusy && busy.endsWith(":recovery") ? <LoaderCircle size={12} className="animate-spin" /> : <Shield size={12} />}
                        Notify Guardian
                      </button>
                    </div>
                    <p className="mt-1.5 text-[9.5px] text-ink-muted">
                      Requires matching chain record, file hash, Ed25519 signature, compatibility, and post-update checks.
                    </p>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Event timeline */}
      <Panel title="Security Event Timeline" description="Guardian, firmware verification and gateway events.">
        {events.length === 0 ? (
          <div className="empty-state">
            <Shield size={20} />
            No Guardian or gateway events recorded yet.
          </div>
        ) : (
          <div className="space-y-2">
            {events.map((event: GuardianEvent) => (
              <div
                key={event.event_id}
                className="flex flex-wrap items-start justify-between gap-2 rounded-lg border border-border p-3 hover:border-border-subtle transition-colors"
              >
                <div className="flex items-start gap-2">
                  {event.event_type === "gateway_connection" && event.blocked
                    ? <LockKeyhole size={13} className="mt-0.5 text-ruby flex-shrink-0" />
                    : <ShieldCheck  size={13} className="mt-0.5 text-emerald flex-shrink-0" />}
                  <div>
                    <div className="text-[11px] font-medium text-ink-secondary">
                      {event.event_type.replace(/_/g, " ")}
                      <span className="text-ink-muted font-normal ml-1">· {event.device_id}</span>
                    </div>
                    <div className="text-[9.5px] text-ink-muted mt-0.5">
                      {event.reason ?? event.detail ?? event.recovery_state ?? event.destination}
                    </div>
                  </div>
                </div>
                <time className="text-[9px] text-ink-muted flex-shrink-0">{readableTime(event.timestamp)}</time>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </>
  );
}
