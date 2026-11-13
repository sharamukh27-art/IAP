import { FormEvent, useCallback, useEffect, useState } from "react";
import { CircleAlert, Plus, RefreshCw, ShieldCheck, UserRound } from "lucide-react";
import {
  createManagedUser,
  listManagedUsers,
  setManagedUserActive,
  type AuthUser,
  type ManagedUserInput,
} from "./api";
import { useAuth } from "./AuthContext";

const roles: Array<{ value: AuthUser["role"]; label: string }> = [
  { value: "manufacturer", label: "Manufacturer" },
  { value: "security_researcher", label: "Security researcher" },
  { value: "independent_reviewer", label: "Independent reviewer" },
  { value: "device_owner", label: "Device owner" },
  { value: "administrator", label: "Administrator" },
];

export default function Settings() {
  const { user: current } = useAuth();
  const [users, setUsers] = useState<AuthUser[]>([]);
  const [role, setRole] = useState<ManagedUserInput["role"]>("security_researcher");
  const [form, setForm] = useState({ user_id: "", display_name: "", password: "", manufacturer: "", device_ids: "" });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try { setUsers(await listManagedUsers()); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Could not load user accounts."); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError("");
    setNotice("");
    try {
      await createManagedUser({
        user_id: form.user_id.trim(),
        display_name: form.display_name.trim(),
        role,
        password: form.password,
        manufacturer: role === "manufacturer" ? form.manufacturer.trim() : undefined,
        device_ids: role === "device_owner" ? form.device_ids.split(",").map((id) => id.trim()).filter(Boolean) : [],
      });
      setForm({ user_id: "", display_name: "", password: "", manufacturer: "", device_ids: "" });
      setNotice("Account created. The new user can sign in with the supplied password.");
      await load();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not create account.");
    } finally { setSaving(false); }
  }

  async function toggleActive(account: AuthUser) {
    setError("");
    setNotice("");
    try {
      await setManagedUserActive(account.user_id, !account.active);
      setNotice(`${account.user_id} ${account.active ? "disabled" : "enabled"}.`);
      await load();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not update account.");
    }
  }

  return (
    <div>
      <header className="page-header">
        <div>
        <div className="eyebrow"><span className="eyebrow-dot" /> ADMINISTRATION</div>
        <h1 className="page-title">Settings &amp; users</h1>
        <p className="page-desc">Provision role-scoped accounts and manage access. Authorization is enforced by the API.</p>
        </div>
      </header>
      {error && <div role="alert" className="portal-alert error mb-3"><CircleAlert size={14} />{error}</div>}
      {notice && <div role="status" className="portal-alert success mb-3"><ShieldCheck size={14} />{notice}</div>}
      <div className="grid items-start gap-4 xl:grid-cols-[340px_minmax(0,1fr)]">
        <form onSubmit={submit} className="panel p-4 space-y-4">
          <div className="section-title"><div className="mini-icon"><Plus size={15} /></div><div><h2>Create platform user</h2><p>Passwords are scrypt-hashed by the API.</p></div></div>
          <label className="block text-[10px] font-semibold">Username
            <input required minLength={3} maxLength={64} value={form.user_id} onChange={(event) => setForm({ ...form, user_id: event.target.value })} className="filter-field mt-1.5" />
          </label>
          <label className="block text-[10px] font-semibold">Display name
            <input required minLength={2} value={form.display_name} onChange={(event) => setForm({ ...form, display_name: event.target.value })} className="filter-field mt-1.5" />
          </label>
          <label className="block text-[10px] font-semibold">Role
            <select value={role} onChange={(event) => setRole(event.target.value as ManagedUserInput["role"])} className="filter-field mt-1.5">
              {roles.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
            </select>
          </label>
          {role === "manufacturer" && <label className="block text-[10px] font-semibold">Manufacturer scope
            <input required value={form.manufacturer} onChange={(event) => setForm({ ...form, manufacturer: event.target.value })} className="filter-field mt-1.5" placeholder="Fictional manufacturer name" />
          </label>}
          {role === "device_owner" && <label className="block text-[10px] font-semibold">Assigned device IDs
            <input required value={form.device_ids} onChange={(event) => setForm({ ...form, device_ids: event.target.value })} className="filter-field mt-1.5" placeholder="CAM-A-001, LOCK-003" />
          </label>}
          <label className="block text-[10px] font-semibold">Temporary password (12+ characters)
            <input required minLength={12} type="password" autoComplete="new-password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} className="filter-field mt-1.5" />
          </label>
          <button disabled={saving} className="btn btn-primary">
            <Plus size={14} />{saving ? "Creating…" : "Create account"}
          </button>
        </form>

        <section className="panel">
          <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
            <div className="section-title mb-0"><div className="mini-icon"><UserRound size={15} /></div><div><h2>Registered accounts</h2><p>Current access state and scoped roles.</p></div></div>
            <button onClick={() => void load()} disabled={loading} className="btn btn-secondary btn-sm">
              <RefreshCw size={12} className={loading ? "animate-spin" : ""} /> Refresh
            </button>
          </div>
          {loading && users.length === 0 ? <div className="portal-empty">Loading accounts…</div> : users.length ? (
            <div className="overflow-x-auto">
              <table className="data-table min-w-[640px]">
                <thead><tr><th>ACCOUNT</th><th>ROLE</th><th>SCOPE</th><th>STATE</th><th></th></tr></thead>
                <tbody>{users.map((account) => (
                  <tr key={account.user_id}>
                    <td><strong className="text-ink">{account.display_name}</strong><div className="mono mt-1">{account.user_id}</div></td>
                    <td className="capitalize">{account.role.replace(/_/g, " ")}</td>
                    <td className="text-[9px]">{account.manufacturer ?? (account.device_ids.length ? account.device_ids.join(", ") : "Platform")}</td>
                    <td><span className={`badge ${account.active ? "badge-green" : "badge-ruby"}`}>{account.active ? "Active" : "Disabled"}</span></td>
                    <td>{current?.user_id !== account.user_id && <button onClick={() => void toggleActive(account)} className="btn btn-secondary btn-sm">{account.active ? "Disable" : "Enable"}</button>}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          ) : <div className="portal-empty">No user accounts found.</div>}
        </section>
      </div>
    </div>
  );
}
