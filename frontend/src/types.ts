export type CompatibilityCategory =
  | "Community Recoverable"
  | "Gateway Protectable"
  | "Unsafe to Maintain";

export type SupportStatus = "supported" | "unsupported";
export type RiskLevel = "low" | "medium" | "high";

export interface Vulnerability {
  identifier: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  patched: boolean;
}

export interface ScoreFactor {
  factor: string;
  points: number;
  maximum: number;
  explanation: string;
}

export interface Device {
  device_id: string;
  name: string;
  manufacturer: string;
  model: string;
  hardware_revision: string;
  firmware_version: string;
  firmware_sha256: string;
  firmware_signing_authority: string;
  release_date: string;
  security_support_end_date: string;
  last_update_date: string;
  known_vulnerabilities: Vulnerability[];
  network_status: string;
  maintenance_status: string;
  supports_alternative_firmware: boolean;
  gateway_protection_available: boolean;
  safe_to_isolate: boolean;
  firmware_authentic: boolean;
  network_protection: string;
  compatibility_category: CompatibilityCategory;
  support_status: SupportStatus;
  survival_score: number;
  risk_level: RiskLevel;
  score_breakdown: ScoreFactor[];
}

export type OrphanState =
  | "Supported"
  | "Support At Risk"
  | "Orphan Candidate"
  | "Verification Pending"
  | "Verified Orphan"
  | "Disputed / Verification Failed";

export interface OrphanEvidence {
  signal: string;
  detected: boolean;
  source: string;
  details: string;
  observed_at: string;
  simulated: boolean;
}

export interface OrphanAttestation {
  reviewer_id: string;
  decision: "approve" | "reject";
  note: string;
  submitted_at: string;
}

export interface AuditEntry {
  action: string;
  actor: string;
  detail: string;
  timestamp: string;
}

export interface OrphanCase {
  device_id: string;
  device_name: string;
  manufacturer: string;
  state: OrphanState;
  evidence: OrphanEvidence[];
  evidence_count: number;
  rationale: string[];
  simulation: Record<string, boolean>;
  submitted_by: string | null;
  challenge_started_at: string | null;
  challenge_until: string | null;
  claim_note?: string;
  attestations: OrphanAttestation[];
  audit_history: AuditEntry[];
  created_at: string;
  updated_at: string;
}

export interface OrphanDashboard {
  total_devices: number;
  counts: Record<OrphanState, number>;
  reviewers: string[];
  required_approvals: number;
  challenge_period_seconds: number;
  cases: OrphanCase[];
}

export type PatchStatus =
  | "Submitted"
  | "Testing"
  | "Passed"
  | "Failed"
  | "Awaiting Review"
  | "Approved"
  | "Rejected"
  | "Released";

export interface PatchTestResult {
  name: string;
  status: "passed" | "failed";
  summary: string;
  details: string[];
}

export interface PatchReview {
  reviewer_id: string;
  reviewer_name: string;
  decision: "approve" | "reject";
  comment: string;
  rejection_reason: string | null;
  submitted_at: string;
}

export interface PatchAuditEntry {
  action: string;
  actor: string;
  detail: string;
  timestamp: string;
}

export interface PatchStatusTransition {
  status: PatchStatus;
  timestamp: string;
}

export interface CommunityPatch {
  patch_id: string;
  device_id: string;
  device_name: string;
  manufacturer: string;
  model: string;
  hardware_revision: string;
  researcher_id: string;
  researcher_name: string;
  patch_version: string;
  description: string;
  vulnerabilities: string[];
  original_filename: string;
  sha256: string;
  file_size: number;
  status: PatchStatus;
  status_history: PatchStatusTransition[];
  test_status: "Passed" | "Failed" | null;
  test_results: PatchTestResult[];
  reviews: PatchReview[];
  required_approvals: number;
  audit_history: PatchAuditEntry[];
  created_at: string;
  updated_at: string;
  release_note?: string;
  released_at?: string;
  blockchain_sync?: { status: "confirmed" | "failed"; error?: string };
  blockchain_submission?: {
    transaction_hash: string;
    block_number: number;
    timestamp: number;
  };
  blockchain_release?: {
    transaction_hash: string;
    block_number: number;
    timestamp: number;
  };
}

export interface ResearcherProfile {
  researcher_id: string;
  display_name: string;
  affiliation: string;
  bio: string;
  role: "researcher" | "reviewer" | "admin";
  reputation: number;
  verified_contributions: number;
  released_patches: Array<{
    patch_id: string;
    patch_version: string;
    device_id: string;
  }>;
}

export interface EligiblePatchDevice {
  device_id: string;
  name: string;
  manufacturer: string;
  model: string;
  hardware_revision: string;
  firmware_version: string;
  known_vulnerabilities: Vulnerability[];
  orphan_state: string;
}

export interface SamplePackage {
  filename: string;
  label: string;
  description: string;
  expected_test_status: "Passed" | "Failed";
}

export interface GuardianFirmwareCheck {
  name: string;
  passed: boolean;
  details: string;
}

export interface GuardianNetworkActivity {
  allowed: boolean;
  blocked: boolean;
  destination: string;
  reason: string;
  timestamp: string;
}

export interface GuardianDevice {
  device_id: string;
  name: string;
  manufacturer: string;
  model: string;
  firmware_version: string;
  firmware_sha256: string;
  maintenance_status: string;
  protection_state: string;
  recovery_state: string;
  firmware_authentic: boolean;
  firmware_verification: GuardianFirmwareCheck[];
  network_activity?: GuardianNetworkActivity;
  network_access: string;
  blocked_connections: number;
  policy: Record<string, unknown>;
}

export interface GuardianEvent {
  event_id: string;
  device_id: string;
  event_type: string;
  timestamp: string;
  reason?: string;
  detail?: string;
  recovery_state?: string;
  destination?: string;
  allowed?: boolean;
  blocked?: boolean;
}

export interface GuardianDashboard {
  mqtt: {
    available: boolean;
    broker: string | null;
    virtual_agents: number;
    gateway: string;
  };
  devices: GuardianDevice[];
  blocked_connections: number;
  events: GuardianEvent[];
}

export interface GuardianNetworkResult {
  device_id: string;
  destination: string;
  allowed: boolean;
  blocked: boolean;
  reason: string;
  timestamp: string;
}

export interface GuardianRecoveryResult {
  passed: boolean;
  protection_state: string;
  recovery_state: string;
  firmware_version: string;
  firmware_sha256: string;
  network_access: string;
  checks: GuardianFirmwareCheck[];
  reason: string;
  timestamp: string;
}

export interface BlockchainStatus {
  available: boolean;
  reason?: string;
  chain_id?: number;
  block_number?: number;
  contract_address?: string;
  rpc_url?: string;
  devices_registered?: string[];
  policy?: Record<string, unknown>;
}

export interface BlockchainRecord {
  event: string;
  args: Record<string, string | number | boolean | string[]>;
  transaction_hash: string;
  block_number: number;
  log_index: number;
  timestamp: number;
}

export interface BlockchainHistory {
  available: boolean;
  chain_id: number;
  contract_address: string;
  records: BlockchainRecord[];
}
