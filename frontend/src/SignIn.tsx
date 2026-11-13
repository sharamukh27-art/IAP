import { FormEvent, useState } from "react";
import { Fingerprint, FlaskConical, LockKeyhole, Shield, User } from "lucide-react";
import { useAuth } from "./AuthContext";

const capabilities = [
  {
    icon: Fingerprint,
    title: "Device identity",
    detail: "Passports for firmware, support lifecycle, and security posture.",
  },
  {
    icon: Shield,
    title: "Evidence-led detection",
    detail: "Lifecycle decisions grounded in support data and corroborating signals.",
  },
  {
    icon: FlaskConical,
    title: "Controlled recovery",
    detail: "Compatibility checks and reviewer gates before patch release.",
  },
];

export default function SignIn() {
  const { signIn, error } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    try {
      await signIn(username.trim(), password);
    } catch {
      setPassword("");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="signin-shell">
      <aside className="signin-aside">
        <div className="signin-aside-mark">IAP / SECURITY OPERATIONS</div>
        <div className="signin-aside-content">
          <div className="signin-logo">
            <div className="sidebar-logo-icon"><Shield size={15} /></div>
            <div><div className="sidebar-logo-name">IoT AFTERLIFE</div><div className="sidebar-logo-sub">PROTOCOL · SECURITY</div></div>
          </div>
          <div className="signin-aside-copy">
            <div className="signin-kicker"><span className="page-eyebrow-dot" />DEVICE SECURITY WORKSPACE</div>
            <h2>Keep connected devices in the security conversation.</h2>
            <p>Bring identity, support evidence, patch review, and recovery readiness into one governed workspace.</p>
          </div>
          <div className="signin-capabilities" aria-label="Platform capabilities">
            {capabilities.map(({ icon: Icon, title, detail }, index) => (
              <div className="signin-capability" key={title}>
                <Icon size={15} aria-hidden="true" />
                <div>
                  <strong>{title}</strong>
                  <span>{detail}</span>
                </div>
                <span className="signin-capability-index">{String(index + 1).padStart(2, "0")}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="signin-aside-mark">VIRTUAL FLEET · DEVICE AND NETWORK ACTIVITY ARE SIMULATED</div>
      </aside>
      <main className="signin-main">
        <div className="signin-card">
          <div className="signin-logo signin-card-logo">
            <div className="sidebar-logo-icon"><Shield size={15} /></div>
            <div><div className="sidebar-logo-name">IoT AFTERLIFE</div><div className="sidebar-logo-sub">PROTOCOL · SECURITY</div></div>
          </div>
          <div className="signin-card-kicker">WORKSPACE ACCESS <span>ROLE-BASED</span></div>
          <h1 className="signin-card-title">Sign in</h1>
          <p className="signin-card-desc">Use an account provisioned by your platform administrator.</p>

          {error && (
            <div className="alert alert-error mb-4" role="alert">
              <LockKeyhole size={13} className="mt-0.5 shrink-0" />
              {error}
            </div>
          )}

          <form onSubmit={submit} className="space-y-4">
            <div>
              <label className="form-label" htmlFor="username">Username</label>
              <label className="field">
                <User size={13} className="shrink-0 text-ink-muted" />
                <input id="username" required autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="your-username" />
              </label>
            </div>
            <div>
              <label className="form-label" htmlFor="password">Password</label>
              <label className="field">
                <LockKeyhole size={13} className="shrink-0 text-ink-muted" />
                <input id="password" required type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Enter your password" />
              </label>
            </div>
            <button disabled={submitting} type="submit" className="btn btn-primary w-full mt-2">
              {submitting ? <><span className="spinner" />Verifying credentials…</> : "Sign in"}
            </button>
          </form>

          <div className="signin-access-note">
            <LockKeyhole size={13} aria-hidden="true" />
            <span>Role-based access is enforced by the API.</span>
          </div>
          <p className="signin-footer">Your session token stays in this browser tab and is removed when you sign out.</p>
        </div>
      </main>
    </div>
  );
}
