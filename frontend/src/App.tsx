import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowDownLeft,
  ArrowLeft,
  Bell,
  Blocks,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Cpu,
  FileText,
  Fingerprint,
  FlaskConical,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  Menu,
  RefreshCw,
  Search,
  Settings as SettingsIcon,
  Shield,
  SlidersHorizontal,
  Siren,
  Users,
  Wifi,
  Zap,
} from "lucide-react";
import { Link, Navigate, NavLink, Route, Routes, useLocation, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { getCommandCenter, getDevice, getHealth, listDevices, type CommandCenterData } from "./api";
import OrphanCenter from "./OrphanCenter";
import BlockchainExplorer from "./BlockchainExplorer";
import GuardianShield from "./GuardianShield";
import CommandCenter from "./CommandCenter";
import RiskAnalytics from "./RiskAnalytics";
import Settings from "./Settings";
import SignIn from "./SignIn";
import PatchLaboratory from "./PatchLaboratory";
import PassportDirectory from "./PassportDirectory";
import DemoScenario from "./DemoScenario";
import { AuthProvider, useAuth } from "./AuthContext";
import {
  PatchDetails,
  PatchMarketplace,
  PatchTestingResults,
  ResearcherDirectory,
  ResearcherProfilePage,
  ReviewerApproval,
  SubmitPatch,
} from "./PatchPortal";
import type { Device } from "./types";

interface NavItem {
  to: string;
  label: string;
  icon: React.ElementType;
  roles: string[];
}

const mainNavigation: NavItem[] = [
  { to: "/",           label: "Command Center",   icon: LayoutDashboard, roles: [] },
  { to: "/devices",    label: "Device Registry",  icon: Cpu,             roles: [] },
  { to: "/passports",  label: "Security Passports", icon: Fingerprint,   roles: [] },
  { to: "/orphans",    label: "Orphan Detection", icon: Siren,           roles: [] },
  { to: "/patches",    label: "Patch Marketplace", icon: FileText,       roles: [] },
  { to: "/patch-lab",  label: "Patch Safety Lab", icon: FlaskConical,    roles: [] },
  { to: "/guardian",   label: "Guardian Shield",  icon: Shield,          roles: [] },
  { to: "/blockchain", label: "Blockchain Audit", icon: Blocks,          roles: [] },
  { to: "/analytics",  label: "Risk Analytics",   icon: Activity,        roles: [] },
  { to: "/demo",       label: "Demo Scenario",    icon: Zap,             roles: [] },
];

const adminNavigation: NavItem[] = [
  { to: "/patch-review", label: "Reviewer Queue", icon: CheckCircle2,   roles: ["administrator", "independent_reviewer"] },
  { to: "/researchers",  label: "Researchers",    icon: Users,           roles: [] },
  { to: "/settings",     label: "Settings",       icon: SettingsIcon,    roles: ["administrator"] },
];

const categoryOptions = [
  "Community Recoverable",
  "Gateway Protectable",
  "Unsafe to Maintain",
];

export function formatDate(value: string) {
  return new Intl.DateTimeFormat("en", {
    month: "short", day: "numeric", year: "numeric", timeZone: "UTC",
  }).format(new Date(value));
}

function stamp(value: string) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? "—"
    : new Intl.DateTimeFormat("en", {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      }).format(parsed);
}

export function categoryBadgeClass(category: string) {
  if (category === "Community Recoverable") return "badge-green";
  if (category === "Gateway Protectable") return "badge-blue";
  return "badge-ruby";
}

function riskBarClass(risk: string) {
  if (risk === "low") return "high";
  if (risk === "medium") return "medium";
  return "low";
}

function roleInitial(displayName: string) {
  return displayName.trim().charAt(0).toUpperCase();
}

function Shell({
  children,
  user,
  signOut,
}: {
  children: React.ReactNode;
  user: NonNullable<ReturnType<typeof useAuth>["user"]>;
  signOut: () => void;
}) {
  const [apiStatus, setApiStatus] = useState<"connecting" | "connected" | "offline">("connecting");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [notificationEvents, setNotificationEvents] = useState<CommandCenterData["recent_security_events"] | null>(null);
  const [notificationError, setNotificationError] = useState("");
  const [searchValue, setSearchValue] = useState("");
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    let active = true;
    const check = () => {
      getHealth()
        .then(() => { if (active) setApiStatus("connected"); })
        .catch(() => { if (active) setApiStatus("offline"); });
    };
    check();
    const interval = window.setInterval(check, 15000);
    return () => { active = false; window.clearInterval(interval); };
  }, []);

  const currentPage = useMemo(() => {
    const all = [...mainNavigation, ...adminNavigation];
    const match = all.find((item) =>
      item.to === "/"
        ? location.pathname === "/"
        : location.pathname.startsWith(item.to),
    );
    return match?.label ?? "IoT Afterlife Protocol";
  }, [location.pathname]);

  const visibleMain = mainNavigation.filter(
    (item) => !item.roles.length || item.roles.includes(user.role),
  );
  const visibleAdmin = adminNavigation.filter(
    (item) => !item.roles.length || item.roles.includes(user.role),
  );

  const openNotifications = async () => {
    setNotificationsOpen((open) => !open);
    setProfileOpen(false);
    if (notificationEvents) return;
    try {
      const data = await getCommandCenter();
      setNotificationEvents(data.recent_security_events);
      setNotificationError("");
    } catch (reason) {
      setNotificationError(reason instanceof Error ? reason.message : "Could not load recent security events.");
    }
  };

  const submitSearch = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    navigate(`/devices${searchValue.trim() ? `?q=${encodeURIComponent(searchValue.trim())}` : ""}`);
    setMobileNavOpen(false);
  };

  return (
    <div className="app-shell">
      {mobileNavOpen && <button className="sidebar-backdrop visible" onClick={() => setMobileNavOpen(false)} aria-label="Close navigation" />}
      <aside className={`sidebar${mobileNavOpen ? " mobile-open" : ""}`}>
        <div className="sidebar-logo">
          <div className="sidebar-logo-icon">
            <Shield size={15} strokeWidth={2.2} />
          </div>
          <div className="sidebar-logo-text">
            <div className="sidebar-logo-name">IoT AFTERLIFE</div>
            <div className="sidebar-logo-sub">PROTOCOL · SECURITY</div>
          </div>
        </div>

        <div className="sidebar-section">
          <div className="sidebar-section-label">Operations</div>
          {visibleMain.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                `sidebar-nav-item${isActive ? " active" : ""}`
              }
              title={label}
              onClick={() => setMobileNavOpen(false)}
            >
              <Icon className="nav-icon" />
              <span>{label}</span>
            </NavLink>
          ))}
        </div>

        {visibleAdmin.length > 0 && (
          <div className="sidebar-section">
            <div className="sidebar-section-label">Administration</div>
            {visibleAdmin.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) =>
                  `sidebar-nav-item${isActive ? " active" : ""}`
                }
                title={label}
                onClick={() => setMobileNavOpen(false)}
              >
                <Icon className="nav-icon" />
                <span>{label}</span>
              </NavLink>
            ))}
          </div>
        )}

        <div className="sidebar-footer">
          <div className="sidebar-user-role">LOCAL SIMULATION · API V5</div>
        </div>
      </aside>

      <div className="main-content">
        <div className="topbar">
          <button className="mobile-menu-toggle topbar-icon-button" onClick={() => setMobileNavOpen(true)} aria-label="Open navigation">
            <Menu size={16} />
          </button>
          <nav className="topbar-breadcrumb" aria-label="Breadcrumb">
            <span>Operations</span>
            <span className="topbar-breadcrumb-sep">/</span>
            <span className="topbar-breadcrumb-current">{currentPage}</span>
          </nav>
          <div className="topbar-right">
            <form className="topbar-search" role="search" onSubmit={submitSearch}>
              <Search size={13} />
              <input aria-label="Search devices" placeholder="Search devices…" value={searchValue} onChange={(event) => setSearchValue(event.target.value)} />
              <button type="submit" className="sr-only" aria-label="Submit device search">Search</button>
            </form>
            <div className="topbar-menu-wrap">
              <button className="topbar-icon-button" onClick={() => void openNotifications()} aria-label="Recent security events" aria-expanded={notificationsOpen}>
                <Bell size={15} />
              </button>
              {notificationsOpen && (
                <div className="topbar-dropdown" role="dialog" aria-label="Recent security events">
                  <div className="topbar-dropdown-head">
                    <span>Recent security events</span>
                    <Link to="/" onClick={() => setNotificationsOpen(false)} className="text-[9px] text-lime no-underline">Command Center</Link>
                  </div>
                  {notificationError ? <div className="p-3 text-[10px] text-ruby">{notificationError}</div> :
                    notificationEvents === null ? <div className="p-3 text-[10px] text-ink-muted">Loading events…</div> :
                    notificationEvents.length ? notificationEvents.slice(0, 5).map((event, index) => (
                      <div className="topbar-dropdown-row" key={`${event.category}-${event.timestamp}-${index}`}>
                        <div className="topbar-dropdown-meta"><span>{event.category}</span><time>{stamp(event.timestamp)}</time></div>
                        <div className="topbar-dropdown-text">{event.summary}</div>
                      </div>
                    )) : <div className="p-3 text-[10px] text-ink-muted">No security events have been recorded.</div>}
                </div>
              )}
            </div>
            <div className="topbar-menu-wrap">
              <button className="topbar-profile" onClick={() => { setProfileOpen((open) => !open); setNotificationsOpen(false); }} aria-expanded={profileOpen} aria-label="Open user profile">
                <span className="profile-trigger-avatar">{roleInitial(user.display_name)}</span>
                <span className="topbar-profile-copy">
                  <span className="topbar-profile-name block">{user.display_name}</span>
                  <span className="topbar-profile-role block">{user.role.replace(/_/g, " ")}</span>
                </span>
              </button>
              {profileOpen && (
                <div className="topbar-dropdown profile-dropdown" role="menu">
                  <div className="topbar-dropdown-head"><span>{user.user_id}</span><span className="badge badge-green">{user.role.replace(/_/g, " ")}</span></div>
                  <button className="topbar-dropdown-row flex w-full items-center gap-2 text-left text-[10px] text-ink-secondary" onClick={() => { setProfileOpen(false); signOut(); }}>
                    <LogOut size={13} /> Sign out
                  </button>
                </div>
              )}
            </div>
            <div className={`api-status ${apiStatus}`}>
              <span className={`api-dot ${apiStatus}`} />
              <span>
                {apiStatus === "connected" ? "API online" : apiStatus === "offline" ? "API offline" : "Connecting"}
              </span>
            </div>
          </div>
        </div>

        <main className="page-content">
          {children}
        </main>

        <footer className="app-footer">
          <span>IoT AFTERLIFE PROTOCOL · V5</span>
          <span>Virtual device environment · Governance events reflect the local chain.</span>
        </footer>
      </div>
    </div>
  );
}

/* ── Shared sub-components ───────────────────────────────── */
export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description?: string;
  actions?: React.ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        <div className="page-eyebrow">
          <span className="page-eyebrow-dot" />
          {eyebrow}
        </div>
        <h1 className="page-title mt-1">{title}</h1>
        {description && <p className="page-desc">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}

export function Panel({
  title,
  description,
  actions,
  footer,
  noPad,
  children,
}: {
  title?: string;
  description?: string;
  actions?: React.ReactNode;
  footer?: React.ReactNode;
  noPad?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className="panel">
      {title && (
        <div className="panel-header">
          <div>
            <div className="panel-title">{title}</div>
            {description && <div className="panel-desc">{description}</div>}
          </div>
          {actions && <div>{actions}</div>}
        </div>
      )}
      <div className={noPad ? "" : "panel-body"}>{children}</div>
      {footer && <div className="panel-footer">{footer}</div>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="alert alert-error">
      <CircleAlert size={15} className="mt-0.5 flex-shrink-0" />
      <div className="flex-1">
        <div className="font-semibold">Error loading data</div>
        <div className="mt-0.5 text-[10.5px] opacity-80">{message}</div>
      </div>
      {onRetry && (
        <button onClick={onRetry} className="btn btn-ghost btn-xs text-ruby">
          Retry
        </button>
      )}
    </div>
  );
}

export function SkeletonRow({ cols = 5 }: { cols?: number }) {
  return (
    <tr>
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} className="px-3 py-3">
          <div className={`skeleton h-3 rounded ${i === 0 ? "w-32" : i === cols - 1 ? "w-16" : "w-24"}`} />
        </td>
      ))}
    </tr>
  );
}

/* ── Device Registry ─────────────────────────────────────── */
function Registry() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [manufacturerOptions, setManufacturerOptions] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [manufacturer, setManufacturer] = useState("");
  const [category, setCategory] = useState("");
  const [support, setSupport] = useState("");
  const [risk, setRisk] = useState("");
  const [searchParams, setSearchParams] = useSearchParams();
  const search = searchParams.get("q") ?? "";
  const [sortBy, setSortBy] = useState<"name" | "manufacturer" | "model" | "firmware_version" | "support_status" | "survival_score" | "last_update_date">("name");
  const [sortAscending, setSortAscending] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const results = await listDevices({
        manufacturer: manufacturer || undefined,
        compatibility_category: category || undefined,
        support_status: support || undefined,
        risk_level: risk || undefined,
      });
      setDevices(results);
      if (!manufacturer && !category && !support && !risk) {
        setManufacturerOptions([...new Set(results.map((d) => d.manufacturer))].sort());
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load device registry.");
    } finally {
      setLoading(false);
    }
  }, [manufacturer, category, support, risk]);

  useEffect(() => { void load(); }, [load]);

  const shown = useMemo(() => devices
    .filter((device) =>
      `${device.name} ${device.device_id} ${device.manufacturer} ${device.model} ${device.firmware_version}`
        .toLowerCase()
        .includes(search.trim().toLowerCase()),
    )
    .sort((left, right) => {
      const a = left[sortBy];
      const b = right[sortBy];
      const comparison = typeof a === "number" && typeof b === "number"
        ? a - b
        : String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: "base" });
      return sortAscending ? comparison : -comparison;
    }), [devices, search, sortBy, sortAscending]);

  const supportedCount = devices.filter((d) => d.support_status === "supported").length;
  const highRiskCount = devices.filter((d) => d.risk_level === "high").length;
  const toggleSort = (field: typeof sortBy) => {
    if (sortBy === field) setSortAscending((current) => !current);
    else { setSortBy(field); setSortAscending(true); }
  };
  const sortButton = (field: typeof sortBy, label: string) => (
    <button className="table-sort" onClick={() => toggleSort(field)} aria-label={`Sort by ${label}`}>
      {label}{sortBy === field ? (sortAscending ? " ↑" : " ↓") : ""}
    </button>
  );

  return (
    <>
      <PageHeader
        eyebrow="DEVICE INVENTORY"
        title="Device Registry"
        description="Search and compare device identity, support lifecycle, firmware, and calculated risk."
        actions={<span className="badge badge-muted">{loading ? "Syncing…" : `${devices.length} records`}</span>}
      />

      {error ? (
        <ErrorState message={error} onRetry={() => void load()} />
      ) : (
        <>
          <div className="registry-summary mb-4">
            <span><strong>{loading ? "—" : devices.length}</strong> registered devices</span>
            <span><strong>{loading ? "—" : supportedCount}</strong> currently supported</span>
            <span><strong>{loading ? "—" : highRiskCount}</strong> high risk</span>
          </div>

          <Panel
            title="Inventory"
            description="Support and risk are derived from recorded device data."
            actions={
              <div className="flex items-center gap-2">
                <span className="badge badge-muted text-[9.5px]">
                  {loading ? "Loading…" : `${shown.length} devices`}
                </span>
                <button onClick={() => void load()} disabled={loading} className="btn btn-ghost btn-icon btn-sm">
                  <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
                </button>
              </div>
            }
          >
            {/* Filters */}
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5 mb-4">
              <label className="field col-span-full lg:col-span-1">
                <Search size={13} className="text-ink-muted flex-shrink-0" />
                <input placeholder="Name, ID, manufacturer, model…" value={search} onChange={(e) => setSearchParams(e.target.value ? { q: e.target.value } : {})} />
              </label>
              <select className="field" value={manufacturer} onChange={(e) => setManufacturer(e.target.value)}>
                <option value="">All manufacturers</option>
                {manufacturerOptions.map((n) => <option key={n}>{n}</option>)}
              </select>
              <select className="field" value={category} onChange={(e) => setCategory(e.target.value)}>
                <option value="">All categories</option>
                {categoryOptions.map((o) => <option key={o}>{o}</option>)}
              </select>
              <select className="field" value={support} onChange={(e) => setSupport(e.target.value)}>
                <option value="">All support</option>
                <option value="supported">Supported</option>
                <option value="unsupported">Unsupported</option>
              </select>
              <select className="field" value={risk} onChange={(e) => setRisk(e.target.value)}>
                <option value="">All risk levels</option>
                <option value="low">Low risk</option>
                <option value="medium">Medium risk</option>
                <option value="high">High risk</option>
              </select>
            </div>

            {/* Table */}
            {loading ? (
              <div className="overflow-x-auto">
                <table className="data-table min-w-[1020px]">
                  <thead><tr>
                    <th>DEVICE</th><th>MANUFACTURER</th><th>MODEL</th><th>FIRMWARE</th><th>SUPPORT</th><th>RISK / SCORE</th><th>LAST UPDATE</th><th></th>
                  </tr></thead>
                  <tbody>{[...Array(5)].map((_, i) => <SkeletonRow key={i} cols={8} />)}</tbody>
                </table>
              </div>
            ) : shown.length ? (
              <div className="overflow-x-auto">
                <table className="data-table min-w-[1020px]">
                  <thead><tr>
                    <th>{sortButton("name", "DEVICE")}</th>
                    <th>{sortButton("manufacturer", "MANUFACTURER")}</th>
                    <th>{sortButton("model", "MODEL")}</th>
                    <th>{sortButton("firmware_version", "FIRMWARE")}</th>
                    <th>{sortButton("support_status", "SUPPORT")}</th>
                    <th>{sortButton("survival_score", "RISK / SCORE")}</th>
                    <th>{sortButton("last_update_date", "LAST UPDATE")}</th><th></th>
                  </tr></thead>
                  <tbody>
                    {shown.map((device) => (
                      <tr key={device.device_id}>
                        <td>
                          <div className="min-w-[150px]">
                            <Link to={`/devices/${encodeURIComponent(device.device_id)}`} className="font-medium text-ink no-underline hover:text-lime">{device.name}</Link>
                            <div className="mono mt-1">{device.device_id}</div>
                          </div>
                        </td>
                        <td>{device.manufacturer}</td>
                        <td>{device.model}<div className="text-[9px] text-ink-muted mt-1">Rev {device.hardware_revision}</div></td>
                        <td className="font-mono text-[9.5px]">{device.firmware_version}</td>
                        <td>
                          <span className={`status-pill status-${device.support_status}`}>
                            {device.support_status === "supported" ? "Supported" : "Unsupported"}
                          </span>
                          <div className="text-[9px] text-ink-muted mt-1">Until {formatDate(device.security_support_end_date)}</div>
                        </td>
                        <td>
                          <div className="min-w-[100px]">
                            <div className="flex items-center justify-between gap-2 mb-1">
                              <span className={`badge badge-${device.risk_level === "low" ? "green" : device.risk_level === "medium" ? "amber" : "ruby"}`}>{device.risk_level}</span>
                              <span className="font-mono text-[9px]">{device.survival_score}</span>
                            </div>
                            <div className="score-bar-track">
                              <div
                                className={`score-bar-fill ${riskBarClass(device.risk_level)}`}
                                style={{ width: `${device.survival_score}%` }}
                              />
                            </div>
                          </div>
                        </td>
                        <td className="font-mono text-[9px]">{formatDate(device.last_update_date)}</td>
                        <td>
                          <Link
                            to={`/devices/${encodeURIComponent(device.device_id)}`}
                            aria-label={`View ${device.name} passport`}
                            className="btn btn-ghost btn-icon btn-sm"
                          >
                            <ChevronRight size={14} />
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty-state">
                <SlidersHorizontal size={22} />
                <p>No devices match these filters.</p>
                <button
                  className="btn btn-ghost btn-xs text-lime"
                  onClick={() => { setManufacturer(""); setCategory(""); setSupport(""); setRisk(""); setSearchParams({}); }}
                >
                  Clear filters
                </button>
              </div>
            )}
          </Panel>

          <div className="mt-3 alert alert-info text-[10.5px]">
            <CircleAlert size={13} className="flex-shrink-0 mt-0.5" />
            Support status uses the recorded vendor end date. Update date alone does not classify a device as abandoned.
          </div>
        </>
      )}
    </>
  );
}

/* ── Device Passport ─────────────────────────────────────── */
function Passport() {
  const { deviceId = "" } = useParams();
  const [device, setDevice] = useState<Device | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    getDevice(deviceId)
      .then((r) => { if (active) setDevice(r); })
      .catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : "API error."); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [deviceId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[50vh] text-ink-muted text-sm gap-2">
        <div className="w-4 h-4 border-2 border-lime border-t-transparent rounded-full animate-spin" />
        Loading device passport…
      </div>
    );
  }
  if (error || !device) return <ErrorState message={error || "Device not found."} onRetry={() => window.location.reload()} />;

  const unpatched = device.known_vulnerabilities.filter((v) => !v.patched);
  const scoreAngle = `${device.survival_score * 3.6}deg`;

  return (
    <>
      <Link to="/devices" className="inline-flex items-center gap-1.5 text-[11px] text-ink-muted hover:text-ink transition-colors mb-6">
        <ArrowLeft size={13} /> Back to registry
      </Link>

      {/* Hero */}
      <section className="passport-hero mb-5">
        <div className="relative z-10 flex flex-wrap items-start justify-between gap-5">
          <div>
            <div className="page-eyebrow mb-2">
              <span className="page-eyebrow-dot" />
              DEVICE SECURITY PASSPORT
            </div>
            <h1 className="text-2xl font-bold text-ink leading-tight">{device.name}</h1>
            <p className="text-[11px] text-ink-muted mt-1">{device.manufacturer} · {device.model} · Rev {device.hardware_revision}</p>
            <div className="flex flex-wrap items-center gap-2 mt-3">
              <span className="font-mono text-[10px] text-ink-muted border border-border bg-elevated px-2.5 py-1 rounded">
                {device.device_id}
              </span>
              <span className={`badge ${categoryBadgeClass(device.compatibility_category)}`}>
                {device.compatibility_category}
              </span>
            </div>
          </div>
          <div className="score-ring" style={{ "--score": scoreAngle } as React.CSSProperties}>
            <div className="score-ring-inner">
              <span className="score-ring-value">{device.survival_score}</span>
              <span className="score-ring-label">/ 100</span>
            </div>
          </div>
        </div>
        <div className="relative z-10 mt-6 grid gap-4 border-t border-border-subtle pt-5 sm:grid-cols-3">
          <div>
            <div className="hero-meta-label">SUPPORT STATUS</div>
            <div className="hero-meta-value">{device.support_status}</div>
          </div>
          <div>
            <div className="hero-meta-label">RISK LEVEL</div>
            <div className={`hero-meta-value ${device.risk_level === "high" ? "text-ruby" : device.risk_level === "medium" ? "text-amber" : "text-emerald"}`}>
              {device.risk_level}
            </div>
          </div>
          <div>
            <div className="hero-meta-label">MAINTENANCE STATUS</div>
            <div className="hero-meta-value">{device.maintenance_status}</div>
          </div>
        </div>
      </section>

      {/* Detail grid */}
      <div className="grid gap-4 lg:grid-cols-[1.3fr_0.7fr] mb-4">
        <Panel title="Digital Identity" description="Hardware, firmware and release provenance">
          <div className="info-grid mb-4">
            <InfoCell label="Device identifier" value={device.device_id} mono />
            <InfoCell label="Hardware revision" value={device.hardware_revision} />
            <InfoCell label="Firmware version" value={device.firmware_version} />
            <InfoCell label="Signing authority" value={device.firmware_signing_authority} />
            <InfoCell label="Release date" value={formatDate(device.release_date)} />
            <InfoCell label="Last update" value={formatDate(device.last_update_date)} />
          </div>
          <div className="hash-display">
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[9px] font-bold tracking-widest text-ink-muted">FIRMWARE SHA-256</span>
              <span className={`text-[9px] font-bold ${device.firmware_authentic ? "text-emerald" : "text-ruby"}`}>
                {device.firmware_authentic ? "AUTHENTICITY RECORDED" : "NOT VERIFIED"}
              </span>
            </div>
            <span>{device.firmware_sha256}</span>
          </div>
        </Panel>

        <Panel title="Support & Protection" description="Current maintenance envelope">
          <div className="space-y-0">
            <ProtectionRow icon={<LockKeyhole size={13} />} label="Security support ends" value={formatDate(device.security_support_end_date)}>
              <span className={`status-pill status-${device.support_status}`}>{device.support_status}</span>
            </ProtectionRow>
            <ProtectionRow icon={<Wifi size={13} />} label="Network status" value={device.network_status}>
              <span className={`status-pill ${device.network_protection === "unprotected" ? "status-unsupported" : "status-supported"}`}>{device.network_protection}</span>
            </ProtectionRow>
            <ProtectionRow icon={<ArrowDownLeft size={13} />} label="Recovery path" value={
              device.supports_alternative_firmware
                ? "Alternative firmware capable"
                : device.gateway_protection_available && device.safe_to_isolate
                  ? "Virtual gateway isolation"
                  : "No safe path recorded"
            } />
          </div>
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Survival Score Breakdown" description={`Deterministic factors · total ${device.survival_score} / 100`}>
          <div className="space-y-5">
            {device.score_breakdown.map((f) => (
              <div key={f.factor}>
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <span className="text-[11px] font-medium text-ink-secondary">{f.factor}</span>
                  <span className="text-[11px] font-semibold text-ink">
                    {f.points}
                    <span className="text-ink-muted font-normal"> / {f.maximum}</span>
                  </span>
                </div>
                <div className="factor-bar">
                  <div className="factor-bar-fill" style={{ width: `${(f.points / f.maximum) * 100}%` }} />
                </div>
                <p className="mt-1.5 text-[9.5px] leading-4 text-ink-muted">{f.explanation}</p>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Known Vulnerability Record" description={`${unpatched.length} unpatched of ${device.known_vulnerabilities.length} recorded`}>
          {device.known_vulnerabilities.length ? (
            <div className="space-y-2">
              {device.known_vulnerabilities.map((v) => (
                <div className="vuln-row" key={v.identifier}>
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <code className="font-mono text-[10.5px] font-semibold text-ink-secondary">{v.identifier}</code>
                    <span className={`badge text-[8.5px] ${
                      v.severity === "critical" ? "badge-ruby" :
                      v.severity === "high" ? "badge-amber" :
                      v.severity === "medium" ? "badge-amber" : "badge-green"
                    }`}>{v.severity}</span>
                  </div>
                  <p className="text-[10.5px] leading-5 text-ink-muted">{v.description}</p>
                  <div className={`mt-1.5 flex items-center gap-1 text-[9.5px] font-semibold ${v.patched ? "text-emerald" : "text-amber"}`}>
                    {v.patched ? <CheckCircle2 size={11} /> : <CircleAlert size={11} />}
                    {v.patched ? "Recorded as patched" : "Recorded as unpatched"}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">No known vulnerabilities recorded.</div>
          )}
        </Panel>
      </div>

      <div className="mt-4 alert alert-info text-[10.5px]">
        This passport reflects declared simulation data. Firmware hashes are identifiers in the registry.
      </div>
    </>
  );
}

function InfoCell({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="info-cell-label">{label}</div>
      <div className={`info-cell-value ${mono ? "font-mono text-[10px]" : ""}`}>{value}</div>
    </div>
  );
}

function ProtectionRow({
  icon,
  label,
  value,
  children,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="flex items-center gap-3 py-3 border-b border-border-subtle last:border-b-0">
      <div className="w-7 h-7 flex-shrink-0 rounded-lg bg-elevated border border-border grid place-items-center text-ink-muted">
        {icon}
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-[9.5px] text-ink-muted">{label}</div>
        <div className="text-[11px] font-medium text-ink-secondary mt-0.5 truncate">{value}</div>
      </div>
      {children}
    </div>
  );
}

/* ── Auth gate ───────────────────────────────────────────── */
export default function App() {
  return <AuthProvider><Application /></AuthProvider>;
}

function RoleGate({ roles, children }: { roles: string[]; children: React.ReactNode }) {
  const { user } = useAuth();
  if (!user || !roles.includes(user.role)) return <Navigate to="/" replace />;
  return <>{children}</>;
}

function Application() {
  const { user, loading, signOut } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="grid min-h-screen place-items-center bg-obsidian text-ink-muted">
        <div className="flex items-center gap-3 text-sm">
          <div className="w-5 h-5 border-2 border-lime border-t-transparent rounded-full animate-spin" />
          Verifying secure session…
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <Routes>
        <Route path="/login" element={<SignIn />} />
        <Route path="*" element={<Navigate to="/login" state={{ from: location }} replace />} />
      </Routes>
    );
  }

  return (
    <Shell user={user} signOut={signOut}>
      <Routes>
        <Route path="/login" element={<Navigate to="/" replace />} />
        <Route path="/" element={<CommandCenter />} />
        <Route path="/devices" element={<Registry />} />
        <Route path="/passports" element={<PassportDirectory />} />
        <Route path="/devices/:deviceId" element={<Passport />} />
        <Route path="/orphans" element={<OrphanCenter />} />
        <Route path="/patches" element={<PatchMarketplace />} />
        <Route path="/patches/submit" element={<RoleGate roles={["security_researcher"]}><SubmitPatch /></RoleGate>} />
        <Route path="/patches/:patchId/tests" element={<PatchTestingResults />} />
        <Route path="/patches/:patchId" element={<PatchDetails />} />
        <Route path="/patch-lab" element={<PatchLaboratory />} />
        <Route path="/researchers" element={<ResearcherDirectory />} />
        <Route path="/researchers/:researcherId" element={<ResearcherProfilePage />} />
        <Route path="/patch-review" element={<RoleGate roles={["administrator", "independent_reviewer"]}><ReviewerApproval /></RoleGate>} />
        <Route path="/blockchain" element={<BlockchainExplorer />} />
        <Route path="/guardian" element={<GuardianShield />} />
        <Route path="/analytics" element={<RiskAnalytics />} />
        <Route path="/demo" element={<DemoScenario />} />
        <Route path="/settings" element={<RoleGate roles={["administrator"]}><Settings /></RoleGate>} />
        <Route path="*" element={
          <div className="flex flex-col items-center justify-center min-h-[50vh] gap-4">
            <div className="text-[10px] font-bold tracking-widest text-ink-muted">404 NOT FOUND</div>
            <h1 className="text-xl font-bold text-ink">Page not found</h1>
            <Link to="/" className="btn btn-secondary btn-sm">Return to Command Center</Link>
          </div>
        } />
      </Routes>
    </Shell>
  );
}
