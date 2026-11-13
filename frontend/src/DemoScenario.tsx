import { useState } from "react";
import {
  AlertTriangle as _AlertTriangle,
  BadgeCheck,
  Blocks,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Cpu,
  FileCheck2,
  FlaskConical,
  LockKeyhole as _LockKeyhole,
  RefreshCw,
  Shield,
  ShieldAlert as _ShieldAlert,
  ShieldCheck,
  Siren,
  Wifi as _Wifi,
  WifiOff,
  X as _X,
} from "lucide-react";
import { Link } from "react-router-dom";

interface DemoStep {
  id: number;
  phase: string;
  title: string;
  description: string;
  icon: React.ElementType;
  color: string;
  actions: Array<{
    label: string;
    path: string;
    role?: string;
  }>;
  outcome: string;
  simulated: boolean;
}

const DEMO_STEPS: DemoStep[] = [
  {
    id: 1,
    phase: "1 · Registry",
    title: "Manufacturer registers three virtual smart cameras",
    description:
      "A fictional manufacturer (Aster Devices) registers three smart cameras — Smart Camera B, C, and D — in the device registry. Each gets a device passport recording model, hardware revision, firmware SHA-256, signing authority, support end date, and known vulnerabilities.",
    icon: Cpu,
    color: "text-sapphire bg-elevated",
    actions: [
      { label: "Open Device Registry", path: "/devices" },
      { label: "View Security Passports", path: "/passports" },
    ],
    outcome:
      "Three Aster Devices cameras are visible in the registry. Each shows a survival score and compatibility classification. CAM-B-002 is Community Recoverable.",
    simulated: false,
  },
  {
    id: 2,
    phase: "2 · Orphan",
    title: "Manufacturer announces end of support",
    description:
      "Sign in as a Manufacturer account scoped to Aster Devices. Open Orphan Detection and run Simulate end of support. This records a lifecycle evidence signal for each of the three cameras. A single signal is not enough — it must be corroborated by independent service and security signals.",
    icon: Siren,
    color: "text-amber bg-elevated",
    actions: [
      { label: "Open Orphan Detection", path: "/orphans", role: "manufacturer" },
    ],
    outcome:
      "Each camera collects multiple evidence signals. Once ≥ 3 distinct signals including a lifecycle + corroborating signal exist, the state advances to Orphan Candidate.",
    simulated: true,
  },
  {
    id: 3,
    phase: "3 · Verification",
    title: "Administrator verifies the orphan declaration",
    description:
      "Sign in as Administrator. For CAM-B-002, submit a claim — this starts the 60-second prototype challenge window and proposes the orphan on-chain. Then sign in as two distinct independent reviewers (reviewer-ada and reviewer-linus) to cast separate attestation votes.",
    icon: BadgeCheck,
    color: "text-emerald bg-elevated",
    actions: [
      { label: "Open Orphan Detection", path: "/orphans", role: "administrator" },
      { label: "Blockchain audit", path: "/blockchain" },
    ],
    outcome:
      "After the challenge period and two distinct reviewer approvals, administrator finalizes. CAM-B-002 becomes Verified Orphan. The on-chain orphan record is visible in the Blockchain Audit Explorer.",
    simulated: false,
  },
  {
    id: 4,
    phase: "4 · Patch — Rejected",
    title: "Demonstrate malicious patch rejection",
    description:
      "Sign in as Security Researcher (researcher-ada). Submit cam-b-incompatible-malicious.json for CAM-B-002. The Patch Safety Laboratory runs all eight synthetic checks — it finds a malware marker, wrong hardware revision, and missing remediation. Status becomes Failed.",
    icon: CircleAlert,
    color: "text-ruby bg-elevated",
    actions: [
      { label: "Submit a Patch", path: "/patches/submit", role: "security_researcher" },
      { label: "Patch Safety Lab", path: "/patch-lab" },
    ],
    outcome:
      "The malicious patch fails all safety checks and cannot advance to reviewer approval. The lab report lists exact failure reasons for each of the eight checks.",
    simulated: true,
  },
  {
    id: 5,
    phase: "5 · Patch — Valid",
    title: "Security researcher submits a community patch",
    description:
      "Still as researcher-ada, submit cam-b-community-fix-2.0.9.json for CAM-B-002. The lab hashes the actual uploaded bytes, parses the synthetic JSON package, and runs all eight checks: file integrity, firmware compatibility, device model/hardware revision, vulnerability remediation, malware scan, regression tests, virtual-device behavior, and rollback.",
    icon: FlaskConical,
    color: "text-sapphire bg-elevated",
    actions: [
      { label: "Submit a Patch", path: "/patches/submit", role: "security_researcher" },
      { label: "Patch Safety Lab", path: "/patch-lab" },
    ],
    outcome:
      "All eight lab checks pass. Status advances to Awaiting Review. SHA-256 is recorded; the package is on-chain via a Hardhat transaction.",
    simulated: false,
  },
  {
    id: 6,
    phase: "6 · Approval",
    title: "Independent reviewers approve the patch",
    description:
      "Sign in as reviewer-ada and open the Reviewer Queue. Approve the passing patch and add a comment. Sign in as reviewer-linus and cast a second independent vote. Two distinct votes reach the required quorum. Status advances to Approved. The on-chain vote is a mined transaction.",
    icon: FileCheck2,
    color: "text-emerald bg-elevated",
    actions: [
      { label: "Reviewer Queue", path: "/patch-review", role: "independent_reviewer" },
      { label: "Blockchain Audit", path: "/blockchain" },
    ],
    outcome:
      "Patch status is Approved. Reviewer names, decisions, and timestamps appear in the patch audit history. Two FirmwareReviewSubmitted on-chain events are mined.",
    simulated: false,
  },
  {
    id: 7,
    phase: "7 · Release",
    title: "Blockchain records authorization and firmware hash",
    description:
      "Sign in as Administrator. Open the Reviewer Queue and find the Approved patch. The release requires the local Hardhat node, a confirmed on-chain submission, the stored file hash to match, and an Ed25519 signature from the community maintainer key. Run python -m app.sign_patch PATCH-ID in the backend directory to generate the Base64 signature.",
    icon: Blocks,
    color: "text-sapphire bg-elevated",
    actions: [
      { label: "Reviewer Queue / Release", path: "/patch-review", role: "administrator" },
      { label: "Blockchain Audit", path: "/blockchain" },
    ],
    outcome:
      "Status is Released. A mined FirmwareReleased transaction with the exact firmware hash is visible in the Blockchain Audit Explorer. The researcher earns a verified contribution.",
    simulated: false,
  },
  {
    id: 8,
    phase: "8 · Guardian",
    title: "Guardian Agent verifies the patch and applies protection",
    description:
      "Sign in as Administrator. Open Guardian Shield, select the released patch for CAM-B-002, and click Notify Guardian. The backend runs six recovery checks in sequence: SHA-256 of stored bytes, Ed25519 community maintainer signature, mined on-chain release + active authorization, device model and hardware revision, vulnerability remediation coverage, and virtual post-update tests.",
    icon: Shield,
    color: "text-emerald bg-elevated",
    actions: [
      { label: "Guardian Shield", path: "/guardian", role: "administrator" },
    ],
    outcome:
      "All six checks pass. The simulated firmware record is updated, RECOVERY VERIFIED is recorded, and the gateway policy is restored to NORMAL. No check is skipped.",
    simulated: false,
  },
  {
    id: 9,
    phase: "9 · Recovery",
    title: "Virtual camera receives the update",
    description:
      "The Guardian Agent publishes the new policy through the MQTT broker. The virtual camera's maintenance_status becomes community-maintained, the firmware version and SHA-256 are updated to the community patch, firmware_authentic becomes True, and the previously unpatched vulnerabilities are marked patched.",
    icon: RefreshCw,
    color: "text-emerald bg-elevated",
    actions: [
      { label: "View Device Passport", path: "/devices/CAM-B-002" },
      { label: "Guardian Shield", path: "/guardian" },
    ],
    outcome:
      "Device passport shows updated firmware version, authenticated firmware hash, reduced vulnerability count, and Community Maintained status. Survival score increases.",
    simulated: true,
  },
  {
    id: 10,
    phase: "10 · Verification",
    title: "Post-update checks succeed; dashboard reflects recovery",
    description:
      "Open the Command Center. The live MongoDB aggregation now shows one more successful recovery, an updated survival score for CAM-B-002, and a Guardian recovery event in the security event feed. Inspect the Risk Analytics page for the updated patch test pass rate and recovery success rate.",
    icon: ShieldCheck,
    color: "text-emerald bg-elevated",
    actions: [
      { label: "Command Center", path: "/" },
      { label: "Risk Analytics", path: "/analytics" },
    ],
    outcome:
      "Dashboard metrics reflect the completed recovery. CAM-B-002 shows Community Maintained and Recovery Verified. No value is fabricated — all counts come from persisted MongoDB records.",
    simulated: false,
  },
];

const GATEWAY_DEMO: {
  title: string;
  description: string;
  outcome: string;
  path: string;
  role: string;
} = {
  title: "Gateway protection for a non-reflashable device",
  description:
    "LOCK-003 (Smart Door Lock, Hearth & Key) is classified Gateway Protectable — it cannot receive alternative firmware. Sign in as Administrator and use Guardian Shield to attempt an external connection from LOCK-003. The virtual gateway restricts or blocks the destination without opening any real socket. The device remains protected through network isolation even without a community firmware path.",
  outcome:
    "LOCK-003 stays under gateway restrictions. No recovery workflow attempts to reflash it. The Guardian dashboard confirms restricted network access and no recovery state.",
  path: "/guardian",
  role: "administrator",
};

export default function DemoScenario() {
  const [expanded, setExpanded] = useState<number | null>(null);

  return (
    <div>
      <header className="page-header">
        <div>
        <div className="eyebrow">
          <span className="eyebrow-dot" /> END-TO-END DEMONSTRATION
        </div>
        <h1 className="page-title">Demo scenario guide</h1>
        <p className="page-desc">
          A complete walkthrough of the IoT Afterlife lifecycle — from device registration through manufacturer
          end-of-support, evidence collection, orphan verification, patch submission, safety testing,
          reviewer approval, blockchain release, and Guardian-verified recovery.
        </p>
        </div>
      </header>

      <div className="demo-facts mb-4">
        <span>Target device <strong>CAM-B-002</strong></span>
        <span>Manufacturer <strong>Aster Devices</strong></span>
        <span>Lifecycle workflow <strong>10 steps</strong></span>
      </div>

      {/* Prerequisites */}
      <section className="panel p-4 mb-4">
        <h2 className="text-sm font-bold">Prerequisites before running the demo</h2>
        <ul className="mt-3 space-y-1.5 text-[10px] leading-5 text-ink-secondary">
          <li className="flex items-start gap-2">
            <CheckCircle2 size={13} className="mt-0.5 shrink-0 text-forest" />
            MongoDB, Mosquitto, Hardhat local node, and FastAPI are all running
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle2 size={13} className="mt-0.5 shrink-0 text-forest" />
            Contract deployed via <code className="font-mono text-[10px]">npm run deploy:local</code> in the{" "}
            <code className="font-mono text-[10px]">chain/</code> directory
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle2 size={13} className="mt-0.5 shrink-0 text-forest" />
            <code className="font-mono text-[10px]">python -m app.seed</code> run from{" "}
            <code className="font-mono text-[10px]">backend/</code>
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle2 size={13} className="mt-0.5 shrink-0 text-forest" />
            Admin account provisioned with the bootstrap credentials from <code className="font-mono text-[10px]">.env</code>
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle2 size={13} className="mt-0.5 shrink-0 text-forest" />
            Accounts created in Settings &amp; Users:{" "}
            <span className="font-mono text-[10px]">aster-support</span> (Manufacturer · Aster Devices),{" "}
            <span className="font-mono text-[10px]">researcher-ada</span> (Security Researcher),{" "}
            <span className="font-mono text-[10px]">reviewer-ada</span> and{" "}
            <span className="font-mono text-[10px]">reviewer-linus</span> (Independent Reviewer)
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle2 size={13} className="mt-0.5 shrink-0 text-forest" />
            Sample patches available at{" "}
            <code className="font-mono text-[10px]">backend/sample_patches/</code>
          </li>
        </ul>
        <div className="mt-3 text-[10px] text-muted">
          See <Link to="/" className="font-semibold text-forest underline">README</Link> and{" "}
          <code className="font-mono">docs/INSTALLATION_GUIDE.md</code> for the full setup walkthrough.
        </div>
      </section>

      {/* Steps */}
      <div className="demo-steps">
        {DEMO_STEPS.map((step) => (
          <article
            key={step.id}
            className="demo-step"
          >
            <button
              type="button"
              className="flex w-full items-center gap-4 px-5 py-4 text-left"
              onClick={() => setExpanded(expanded === step.id ? null : step.id)}
              aria-expanded={expanded === step.id}
            >
              <div
                className={`demo-step-icon ${step.color}`}
              >
                <step.icon size={16} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-[9px] font-bold uppercase tracking-[0.12em] text-muted">
                  {step.phase}
                </div>
                <div className="mt-0.5 text-xs font-bold text-ink">{step.title}</div>
              </div>
              <div className="flex items-center gap-2">
                {step.simulated && (
                  <span className="badge badge-amber">
                    SIMULATED DATA
                  </span>
                )}
                <ChevronRight
                  size={15}
                  className={`text-muted transition-transform ${expanded === step.id ? "rotate-90" : ""}`}
                />
              </div>
            </button>

            {expanded === step.id && (
              <div className="demo-step-content">
                <p className="text-[10.5px] leading-6 text-ink-secondary">{step.description}</p>

                <div className="mt-4 flex flex-wrap gap-2">
                  {step.actions.map((action) => (
                    <Link
                      key={action.path}
                      to={action.path}
                      className="btn btn-secondary btn-sm"
                    >
                      {action.label}
                      {action.role && (
                        <span className="badge badge-muted">
                          as {action.role.replace(/_/g, " ")}
                        </span>
                      )}
                    </Link>
                  ))}
                </div>

                <div className="demo-outcome mt-4">
                  <div className="text-[9px] font-bold uppercase tracking-[0.1em] text-emerald">
                    Expected outcome
                  </div>
                  <p className="mt-1.5 text-[10px] leading-5 text-ink-secondary">
                    {step.outcome}
                  </p>
                </div>
              </div>
            )}
          </article>
        ))}
      </div>

      {/* Gateway / non-reflashable demo */}
      <section className="panel p-4 mt-4">
        <div className="flex items-start gap-3">
          <div className="mini-icon text-ruby">
            <WifiOff size={16} />
          </div>
          <div>
            <div className="text-[9px] font-bold uppercase tracking-[0.12em] text-muted">
              Bonus scenario · Gateway-only protection
            </div>
            <h2 className="mt-0.5 text-xs font-bold">
              {GATEWAY_DEMO.title}
            </h2>
          </div>
        </div>
        <p className="mt-3 text-[10.5px] leading-6 text-ink-secondary">{GATEWAY_DEMO.description}</p>
        <div className="demo-outcome mt-3">
          <div className="text-[9px] font-bold uppercase tracking-[0.1em] text-emerald">
            Expected outcome
          </div>
          <p className="mt-1.5 text-[10px] leading-5 text-ink-secondary">{GATEWAY_DEMO.outcome}</p>
        </div>
        <div className="mt-3">
          <Link
            to={GATEWAY_DEMO.path}
            className="btn btn-secondary btn-sm"
          >
            Guardian Shield{" "}
            <span className="badge badge-muted">
              as {GATEWAY_DEMO.role}
            </span>
          </Link>
        </div>
      </section>

      {/* Safety notes */}
      <div className="alert alert-info mt-4 text-[10px]">
        <strong className="font-bold text-ink">Simulation notice:</strong> All devices, manufacturers, vulnerabilities,
        firmware payloads, and reviewer identities are fictional. Steps marked SIMULATED DATA rely on the
        orphan simulation engine to reproduce realistic evidence. No physical IoT device, real vendor API, or
        external network connection is involved. Blockchain events are actual mined local-chain transactions;
        they reset when the Hardhat node is restarted.
      </div>
    </div>
  );
}
