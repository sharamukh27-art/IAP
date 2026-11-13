import { useEffect, useMemo, useState } from "react";
import { Blocks, CircleAlert, RefreshCw, ShieldCheck } from "lucide-react";
import { PageHeader, Panel, ErrorState } from "./App";
import { getBlockchainHistory, getBlockchainStatus, listDevices } from "./api";
import type { BlockchainRecord, BlockchainStatus, Device } from "./types";

function formatTime(timestamp: number) {
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(new Date(timestamp * 1000));
}

function shorten(value: string) {
  return value.length > 22 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value;
}

function eventValue(record: BlockchainRecord, pattern: RegExp) {
  const entry = Object.entries(record.args).find(([key]) => pattern.test(key.toLowerCase()));
  return entry ? String(entry[1]) : "—";
}

function RecordRow({ record }: { record: BlockchainRecord }) {
  const entries = Object.entries(record.args).filter(([key]) => key.toLowerCase() !== "timestamp");
  return (
    <tr>
      <td><code className="mono" title={record.transaction_hash}>{shorten(record.transaction_hash)}</code></td>
      <td className="font-mono text-[9px]">{eventValue(record, /device.?id|device/)}</td>
      <td><span className="badge badge-muted">{record.event.replace(/([A-Z])/g, " $1").trim()}</span></td>
      <td><code className="mono" title={eventValue(record, /firmware.?hash|file.?hash|sha.?256/)}>{shorten(eventValue(record, /firmware.?hash|file.?hash|sha.?256/))}</code></td>
      <td className="font-mono text-[9px]">{eventValue(record, /approver|reviewer|actor|owner/)}</td>
      <td className="font-mono">{record.block_number}</td>
      <td className="font-mono text-[9px]">{formatTime(record.timestamp)}</td>
      <td><span className="status-pill status-supported">Mined</span></td>
      <td>
        <details className="chain-record-details">
          <summary aria-label={`View arguments for ${record.event}`}>Args</summary>
          <dl>{entries.map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{String(value)}</dd></div>)}</dl>
        </details>
      </td>
    </tr>
  );
}

export default function BlockchainExplorer() {
  const [status, setStatus] = useState<BlockchainStatus | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [deviceId, setDeviceId] = useState("");
  const [records, setRecords] = useState<BlockchainRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function load(selectedDevice = deviceId) {
    setLoading(true);
    setError("");
    try {
      const currentStatus = await getBlockchainStatus();
      setStatus(currentStatus);
      if (!currentStatus.available) {
        setRecords([]);
        return;
      }
      const history = await getBlockchainHistory(selectedDevice || undefined);
      setRecords(history.records);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load local-chain history.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let active = true;
    Promise.all([getBlockchainStatus(), listDevices()])
      .then(async ([currentStatus, registeredDevices]) => {
        if (!active) return;
        setStatus(currentStatus);
        setDevices(registeredDevices);
        if (currentStatus.available) {
          const history = await getBlockchainHistory();
          if (active) setRecords(history.records);
        }
      })
      .catch((reason: unknown) => {
        if (active) setError(reason instanceof Error ? reason.message : "Could not load blockchain data.");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => { active = false; };
  }, []);

  const sortedRecords = useMemo(
    () => [...records].sort((a, b) => b.block_number - a.block_number || b.log_index - a.log_index),
    [records],
  );

  return (
    <>
      <PageHeader
        eyebrow="AUDIT LEDGER"
        title="Blockchain Explorer"
        description="Inspect contract events and transaction evidence read from the local Hardhat deployment."
        actions={<button onClick={() => void load()} disabled={loading} className="btn btn-secondary btn-sm"><RefreshCw size={13} />Refresh</button>}
      />

      {status?.available ? (
        <div className="chain-status-bar mb-4">
          <div><span>Network</span><strong>Hardhat local · chain {status.chain_id}</strong></div>
          <div><span>Latest block</span><strong className="font-mono">{status.block_number}</strong></div>
          <div><span>Contract</span><code title={status.contract_address}>{status.contract_address ? shorten(status.contract_address) : "—"}</code></div>
        </div>
      ) : null}

      <Panel
        title="Contract events"
        description="Transaction IDs, event arguments, mined block, and timestamp."
        actions={
          <div className="flex items-center gap-2">
            <select aria-label="Filter by device" value={deviceId} onChange={(event) => { setDeviceId(event.target.value); void load(event.target.value); }} className="filter-field min-w-[170px]">
              <option value="">All devices</option>
              {devices.map((device) => <option key={device.device_id} value={device.device_id}>{device.device_id}</option>)}
            </select>
            <span className="badge badge-muted">{records.length} events</span>
          </div>
        }
      >
        {error ? <ErrorState message={error} onRetry={() => void load()} /> :
          loading ? <div className="portal-empty">Reading local-chain event logs…</div> :
          !status?.available ? (
            <div className="empty-state">
              <CircleAlert size={18} />
              <strong className="text-ink-secondary">Local blockchain unavailable</strong>
              <span>{status?.reason ?? "Start the Hardhat node and deploy the governance contract."}</span>
              <span>No transaction history is shown until a live local contract is reachable.</span>
            </div>
          ) : sortedRecords.length ? (
            <div className="overflow-x-auto">
              <table className="data-table min-w-[1080px]">
                <thead><tr><th>TRANSACTION</th><th>DEVICE</th><th>EVENT</th><th>FIRMWARE HASH</th><th>APPROVER / ACTOR</th><th>BLOCK</th><th>TIMESTAMP · UTC</th><th>STATE</th><th></th></tr></thead>
                <tbody>{sortedRecords.map((record) => <RecordRow key={`${record.transaction_hash}-${record.log_index}`} record={record} />)}</tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state"><Blocks size={20} /><strong className="text-ink-secondary">No on-chain events match this filter</strong><span>Events appear after they are mined by the local Hardhat node.</span></div>
          )}
      </Panel>

      {status?.available && (
        <div className="mt-3 alert alert-info">
          <ShieldCheck size={14} className="mt-0.5 shrink-0 text-emerald" />
          Firmware binaries and private keys are never displayed or stored on-chain. “Mined” indicates the event was returned from the configured contract log.
        </div>
      )}
    </>
  );
}
