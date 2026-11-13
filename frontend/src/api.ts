import type {
  CommunityPatch,
  Device,
  BlockchainHistory,
  BlockchainStatus,
  EligiblePatchDevice,
  GuardianDashboard,
  GuardianNetworkResult,
  GuardianRecoveryResult,
  OrphanCase,
  OrphanDashboard,
  ResearcherProfile,
  SamplePackage,
} from "./types";

const apiBase = (import.meta.env.VITE_API_URL as string | undefined) ?? "/api";
const tokenKey = "afterlife.access-token";

export interface AuthUser {
  user_id: string;
  display_name: string;
  role: "administrator" | "manufacturer" | "security_researcher" | "independent_reviewer" | "device_owner";
  active: boolean;
  manufacturer?: string | null;
  device_ids: string[];
  created_at?: string;
}

export interface ManagedUserInput {
  user_id: string;
  display_name: string;
  role: AuthUser["role"];
  password: string;
  manufacturer?: string;
  device_ids: string[];
  affiliation?: string;
  bio?: string;
}

export interface DeviceFilters {
  manufacturer?: string;
  compatibility_category?: string;
  support_status?: string;
  risk_level?: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  const headers = new Headers(init?.headers);
  const token = sessionStorage.getItem(tokenKey);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (!(init?.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  try {
    response = await fetch(`${apiBase}${path}`, {
      ...init,
      headers,
    });
  } catch {
    throw new Error("Cannot reach the API. Check that FastAPI is running on port 8000.");
  }
  if (!response.ok) {
    if (response.status === 401) {
      window.dispatchEvent(new Event("afterlife-auth-expired"));
    }
    const body = (await response.json().catch(() => null)) as
      | { detail?: string }
      | null;
    throw new Error(body?.detail ?? `API request failed (${response.status}).`);
  }
  return response.json() as Promise<T>;
}

export function login(username: string, password: string): Promise<{
  access_token: string;
  token_type: string;
  expires_in: number;
  user: AuthUser;
}> {
  return request("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
}

export function currentUser(): Promise<AuthUser> {
  return request<AuthUser>("/auth/me");
}

export function logoutToken(): void {
  sessionStorage.removeItem(tokenKey);
}

export function saveToken(token: string): void {
  sessionStorage.setItem(tokenKey, token);
}

export function listManagedUsers(): Promise<AuthUser[]> {
  return request<AuthUser[]>("/auth/users");
}

export function createManagedUser(user: ManagedUserInput): Promise<AuthUser> {
  return request<AuthUser>("/auth/users", {
    method: "POST",
    body: JSON.stringify(user),
  });
}

export function setManagedUserActive(userId: string, active: boolean): Promise<AuthUser> {
  return request<AuthUser>(`/auth/users/${encodeURIComponent(userId)}`, {
    method: "PATCH",
    body: JSON.stringify({ active }),
  });
}

export interface CommandCenterData {
  totals: {
    registered_devices: number;
    supported_devices: number;
    orphaned_devices: number;
    devices_at_risk: number;
    quarantined_devices: number;
    approved_patches: number;
    successful_recoveries: number;
    failed_patch_attempts: number;
  };
  survival_scores: Array<{ device_id: string; name: string; score: number; risk_level: string }>;
  risk_overview: Record<string, number>;
  recent_security_events: Array<{
    device_id?: string;
    event: string;
    category: string;
    summary: string;
    timestamp: string;
    actor?: string;
  }>;
  data_source: string;
}

export interface RiskAnalyticsData {
  survival_scores: CommandCenterData["survival_scores"];
  orphan_detection_trends: {
    monthly_events: Record<string, number>;
    current_states: Record<string, number>;
  };
  vulnerability_severity_distribution: Record<string, number>;
  patch_testing: {
    passed: number;
    failed: number;
    other: number;
    pass_rate_percent: number | null;
  };
  recovery: {
    successful: number;
    failed: number;
    success_rate_percent: number | null;
    average_recovery_seconds: number | null;
  };
  quarantine_events_by_month: Record<string, number>;
  data_source: string;
}

export function getCommandCenter(): Promise<CommandCenterData> {
  return request<CommandCenterData>("/command-center");
}

export function getRiskAnalytics(): Promise<RiskAnalyticsData> {
  return request<RiskAnalyticsData>("/analytics");
}

export function getHealth(): Promise<{ status: string }> {
  const rootBase = apiBase.endsWith("/api") ? apiBase.slice(0, -4) : "";
  return requestAt<{ status: string }>(`${rootBase}/health`);
}

async function requestAt<T>(url: string): Promise<T> {
  let response: Response;
  try {
    response = await fetch(url);
  } catch {
    throw new Error("Cannot reach the API.");
  }
  if (!response.ok) throw new Error(`Health check failed (${response.status}).`);
  return response.json() as Promise<T>;
}

export function listDevices(filters: DeviceFilters = {}): Promise<Device[]> {
  const query = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (value) query.set(key, value);
  });
  const search = query.toString();
  return request<Device[]>(`/devices${search ? `?${search}` : ""}`);
}

export function getBlockchainStatus(): Promise<BlockchainStatus> {
  return request<BlockchainStatus>("/blockchain/status");
}

export function getBlockchainHistory(deviceId?: string): Promise<BlockchainHistory> {
  const query = deviceId ? `?device_id=${encodeURIComponent(deviceId)}` : "";
  return request<BlockchainHistory>(`/blockchain/history${query}`);
}

export function getDevice(deviceId: string): Promise<Device> {
  return request<Device>(`/devices/${encodeURIComponent(deviceId)}`);
}

export function getOrphanDashboard(): Promise<OrphanDashboard> {
  return request<OrphanDashboard>("/orphans/dashboard");
}

export function scanOrphans(): Promise<OrphanDashboard> {
  return request<OrphanDashboard>("/orphans/scan", { method: "POST" });
}

export function simulateManufacturer(
  manufacturer: string,
  scenario: string,
  actor = "simulated-admin",
): Promise<{ cases: OrphanCase[]; affected_devices: number }> {
  return request("/orphans/simulations", {
    method: "POST",
    body: JSON.stringify({ manufacturer, scenario, actor }),
  });
}

export function submitOrphanClaim(
  deviceId: string,
  submittedBy: string,
  note: string,
): Promise<OrphanCase> {
  return request(`/orphans/${encodeURIComponent(deviceId)}/claims`, {
    method: "POST",
    body: JSON.stringify({ submitted_by: submittedBy, note }),
  });
}

export function submitAttestation(
  deviceId: string,
  reviewerId: string,
  decision: "approve" | "reject",
  note: string,
): Promise<OrphanCase> {
  return request(`/orphans/${encodeURIComponent(deviceId)}/attestations`, {
    method: "POST",
    body: JSON.stringify({ reviewer_id: reviewerId, decision, note }),
  });
}

export function finalizeOrphanClaim(deviceId: string, actor: string): Promise<OrphanCase> {
  return request(`/orphans/${encodeURIComponent(deviceId)}/finalize`, {
    method: "POST",
    body: JSON.stringify({ actor }),
  });
}

export function listPatches(statusFilter?: string): Promise<CommunityPatch[]> {
  const query = statusFilter
    ? `?status_filter=${encodeURIComponent(statusFilter)}`
    : "";
  return request<CommunityPatch[]>(`/patches${query}`);
}

export function getPatch(patchId: string): Promise<CommunityPatch> {
  return request<CommunityPatch>(`/patches/${encodeURIComponent(patchId)}`);
}

export function listEligiblePatchDevices(): Promise<EligiblePatchDevice[]> {
  return request<EligiblePatchDevice[]>("/patches/eligible-devices");
}

export function listResearchers(role?: string): Promise<ResearcherProfile[]> {
  const query = role ? `?role=${encodeURIComponent(role)}` : "";
  return request<ResearcherProfile[]>(`/researchers${query}`);
}

export function getResearcher(researcherId: string): Promise<ResearcherProfile> {
  return request<ResearcherProfile>(`/researchers/${encodeURIComponent(researcherId)}`);
}

export function registerResearcher(profile: {
  researcher_id: string;
  display_name: string;
  affiliation: string;
  bio: string;
}): Promise<ResearcherProfile> {
  return request<ResearcherProfile>("/researchers", {
    method: "POST",
    body: JSON.stringify(profile),
  });
}

export function uploadPatch(form: FormData): Promise<CommunityPatch> {
  return request<CommunityPatch>("/patches", { method: "POST", body: form });
}

export function reviewPatch(
  patchId: string,
  reviewerId: string,
  decision: "approve" | "reject",
  comment: string,
  rejectionReason: string,
): Promise<CommunityPatch> {
  return request<CommunityPatch>(`/patches/${encodeURIComponent(patchId)}/reviews`, {
    method: "POST",
    body: JSON.stringify({
      reviewer_id: reviewerId,
      decision,
      comment,
      rejection_reason: decision === "reject" ? rejectionReason : null,
    }),
  });
}

export function releasePatch(
  patchId: string,
  releaseNote: string,
  signatureB64: string,
  actorId: string,
): Promise<CommunityPatch> {
  return request<CommunityPatch>(`/patches/${encodeURIComponent(patchId)}/release`, {
    method: "POST",
    body: JSON.stringify({
      actor_id: actorId,
      release_note: releaseNote,
      signature_b64: signatureB64.trim() || undefined,
    }),
  });
}

export function listSamplePackages(): Promise<SamplePackage[]> {
  return request<SamplePackage[]>("/patches/sample-packages");
}

export async function downloadSamplePackage(filename: string): Promise<Blob> {
  const headers = new Headers();
  const token = sessionStorage.getItem(tokenKey);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  let response: Response;
  try {
    response = await fetch(
      `${apiBase}/patches/sample-packages/${encodeURIComponent(filename)}`,
      { headers },
    );
  } catch {
    throw new Error("Cannot reach the API to download this sample package.");
  }
  if (!response.ok) {
    if (response.status === 401) window.dispatchEvent(new Event("afterlife-auth-expired"));
    const body = (await response.json().catch(() => null)) as { detail?: string } | null;
    throw new Error(body?.detail ?? `Sample package download failed (${response.status}).`);
  }
  return response.blob();
}

export function getGuardianDashboard(): Promise<GuardianDashboard> {
  return request<GuardianDashboard>("/guardian");
}

export function simulateGuardianNetworkAttempt(
  deviceId: string,
  destination: string,
): Promise<GuardianNetworkResult> {
  return request<GuardianNetworkResult>(
    `/guardian/devices/${encodeURIComponent(deviceId)}/network-attempts`,
    {
      method: "POST",
      body: JSON.stringify({ destination, protocol: "tcp" }),
    },
  );
}

export function startGuardianRecovery(
  deviceId: string,
  patchId: string,
): Promise<GuardianRecoveryResult> {
  return request<GuardianRecoveryResult>(
    `/guardian/devices/${encodeURIComponent(deviceId)}/recoveries`,
    {
      method: "POST",
      body: JSON.stringify({ patch_id: patchId }),
    },
  );
}
