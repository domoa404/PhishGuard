import { useEffect, useState } from 'react';
import { Lock, Shield, UserCheck } from 'lucide-react';
import { apiFetch } from '../lib/api.ts';
import { getT } from '../i18n/translations.ts';
import type { Language, UserAccount, UserRole } from '../types/phishguard.ts';

interface Props {
  lang: Language;
  activeActor: string;
  activeRole: UserRole;
  onChangePersona: (actor: string, role: UserRole) => void;
}

interface ProviderStatus {
  id: string;
  name: string;
  configured: boolean;
  envVar: string;
  capability: string;
}

export function SettingsView({ lang, activeActor, activeRole, onChangePersona }: Props) {
  const t = getT(lang);
  const [users, setUsers] = useState<UserAccount[]>([]);
  const [providers, setProviders] = useState<ProviderStatus[]>([]);
  const [lowMax, setLowMax] = useState(4);
  const [mediumMax, setMediumMax] = useState(9);
  const [highMax, setHighMax] = useState(16);

  // Create User
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<UserRole>('Security Analyst');
  const [password, setPassword] = useState('');

  // Verify credentials
  const [authUser, setAuthUser] = useState('t.haddad');
  const [authPass, setAuthPass] = useState('');
  const [error, setError] = useState('');
  const [feedback, setFeedback] = useState('');

  const loadSettings = async () => {
    const res = await apiFetch<{
      users: UserAccount[];
      thresholds: { lowMax: number; mediumMax: number; highMax: number };
      providers: ProviderStatus[];
    }>('/api/settings');
    setUsers(res.users);
    setProviders(res.providers);
    setLowMax(res.thresholds.lowMax);
    setMediumMax(res.thresholds.mediumMax);
    setHighMax(res.thresholds.highMax);
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const handleSaveThresholds = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setFeedback('');
    try {
      await apiFetch('/api/settings/thresholds', {
        method: 'PATCH',
        body: JSON.stringify({ lowMax, mediumMax, highMax }),
      });
      setFeedback('Risk matrix thresholds updated.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to save thresholds');
    }
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setFeedback('');
    try {
      await apiFetch('/api/users', {
        method: 'POST',
        body: JSON.stringify({ username, displayName, email, role, password }),
      });
      setUsername('');
      setDisplayName('');
      setEmail('');
      setPassword('');
      setFeedback('User account provisioned with scrypt password hashing.');
      await loadSettings();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to create user');
    }
  };

  const handleVerifyLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setFeedback('');
    try {
      const user = await apiFetch<UserAccount>('/api/auth/verify', {
        method: 'POST',
        body: JSON.stringify({ username: authUser, password: authPass }),
      });
      onChangePersona(user.displayName, user.role);
      setAuthPass('');
      setFeedback(`Authenticated as ${user.displayName} (${user.role}).`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed');
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-[#17212B]">{t.settings.title}</h1>
        <p className="text-sm text-slate-500 mt-1">{t.settings.subtitle}</p>
      </div>

      {error && <div className="p-3 bg-[#FF3B5C]/10 border border-[#FF3B5C]/30 rounded-lg text-xs text-[#FF3B5C]">{error}</div>}
      {feedback && <div className="p-3 bg-[#39FF88]/15 border border-[#39FF88]/40 rounded-lg text-xs text-[#137A3E]">{feedback}</div>}

      {/* Active Role Switcher & Credential Verification */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        <div className="lg:col-span-6 bg-white border border-slate-200 rounded-xl p-5 space-y-4">
          <h2 className="text-sm font-semibold text-[#17212B] flex items-center gap-2">
            <Shield className="w-4 h-4" />
            {t.settings.activeSession}
          </h2>
          <p className="text-xs text-slate-500">
            Active: <strong className="text-[#17212B]">{activeActor}</strong> · Role:{' '}
            <strong className="text-[#17212B]">{activeRole}</strong>
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
            {users.slice(0, 3).map((u) => {
              const selected = activeActor === u.displayName && activeRole === u.role;
              return (
                <button
                  key={u.id}
                  type="button"
                  onClick={() => onChangePersona(u.displayName, u.role)}
                  className={`p-3 rounded-lg border text-start transition-all ${
                    selected ? 'bg-[#B7FF00] border-[#17212B]' : 'bg-[#F7F9FA] border-slate-200 hover:border-slate-300'
                  }`}
                >
                  <div className="text-xs font-bold text-[#17212B]">{u.role}</div>
                  <div className="text-xs text-slate-700 mt-0.5">{u.displayName}</div>
                  <div className="font-mono text-[10px] text-slate-500 mt-1">{u.username}</div>
                </button>
              );
            })}
          </div>
          {activeRole === 'Viewer' && (
            <p className="text-xs text-[#FF9F1C] font-medium">{t.common.readOnlyNotice}</p>
          )}
        </div>

        <form onSubmit={handleVerifyLogin} className="lg:col-span-6 bg-white border border-slate-200 rounded-xl p-5 space-y-3">
          <h2 className="text-sm font-semibold text-[#17212B] flex items-center gap-2">
            <Lock className="w-4 h-4" />
            Verify Account Credentials (scrypt)
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <input
              value={authUser}
              onChange={(e) => setAuthUser(e.target.value)}
              placeholder="Username (e.g. n.almansoor)"
              className="px-3 py-2 font-mono text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            />
            <input
              type="password"
              value={authPass}
              onChange={(e) => setAuthPass(e.target.value)}
              placeholder="Password"
              className="px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            />
          </div>
          <div className="flex items-center justify-between gap-3">
            <span className="text-[11px] text-slate-400">
              Demo credentials: n.almansoor / AdminSOC#2026 · t.haddad / AnalystSOC#2026
            </span>
            <button
              type="submit"
              className="px-4 py-2 bg-[#17212B] text-white text-xs font-semibold rounded-lg whitespace-nowrap"
            >
              Verify & Switch
            </button>
          </div>
        </form>
      </div>

      {/* Risk Thresholds & Create User */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        <form onSubmit={handleSaveThresholds} className="lg:col-span-5 bg-white border border-slate-200 rounded-xl p-5 space-y-3">
          <h2 className="text-sm font-semibold text-[#17212B]">{t.settings.thresholdsTitle}</h2>
          <p className="text-xs text-slate-500">Administrator role required to persist threshold changes.</p>
          <div className="grid grid-cols-3 gap-3 text-xs">
            <div>
              <label className="block text-slate-600 mb-1">Low Max</label>
              <input
                type="number"
                min={1}
                max={10}
                value={lowMax}
                onChange={(e) => setLowMax(Number(e.target.value))}
                className="w-full px-3 py-2 font-mono bg-[#F7F9FA] border border-slate-200 rounded-lg"
              />
            </div>
            <div>
              <label className="block text-slate-600 mb-1">Medium Max</label>
              <input
                type="number"
                min={5}
                max={18}
                value={mediumMax}
                onChange={(e) => setMediumMax(Number(e.target.value))}
                className="w-full px-3 py-2 font-mono bg-[#F7F9FA] border border-slate-200 rounded-lg"
              />
            </div>
            <div>
              <label className="block text-slate-600 mb-1">High Max</label>
              <input
                type="number"
                min={10}
                max={24}
                value={highMax}
                onChange={(e) => setHighMax(Number(e.target.value))}
                className="w-full px-3 py-2 font-mono bg-[#F7F9FA] border border-slate-200 rounded-lg"
              />
            </div>
          </div>
          <button
            type="submit"
            className="px-4 py-2 bg-[#B7FF00] text-[#17212B] text-xs font-bold rounded-lg"
          >
            {t.common.save}
          </button>
        </form>

        <form onSubmit={handleCreateUser} className="lg:col-span-7 bg-white border border-slate-200 rounded-xl p-5 space-y-3">
          <h2 className="text-sm font-semibold text-[#17212B] flex items-center gap-2">
            <UserCheck className="w-4 h-4" />
            {t.settings.createUser}
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <input
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Username"
              className="px-3 py-2 font-mono text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            />
            <input
              required
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="Full Name"
              className="px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            />
            <input
              required
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Email"
              className="px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as UserRole)}
              className="px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            >
              <option value="Administrator">Administrator</option>
              <option value="Security Analyst">Security Analyst</option>
              <option value="Viewer">Viewer</option>
            </select>
            <input
              required
              type="password"
              minLength={8}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password (min 8 chars)"
              className="px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            />
            <button
              type="submit"
              className="px-4 py-2 bg-[#17212B] text-white text-xs font-semibold rounded-lg"
            >
              {t.common.create}
            </button>
          </div>
        </form>
      </div>

      {/* Users Table & API Status */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-100">
          <h2 className="text-sm font-semibold text-[#17212B]">{t.settings.usersTitle}</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-start border-collapse text-xs">
            <thead>
              <tr className="bg-[#F7F9FA] border-b border-slate-200 text-slate-500">
                <th className="py-2.5 px-4 text-start font-semibold">ID</th>
                <th className="py-2.5 px-4 text-start font-semibold">Username</th>
                <th className="py-2.5 px-4 text-start font-semibold">Display Name</th>
                <th className="py-2.5 px-4 text-start font-semibold">Email</th>
                <th className="py-2.5 px-4 text-start font-semibold">Role</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {users.map((u) => (
                <tr key={u.id}>
                  <td className="py-2.5 px-4 font-mono">{u.id}</td>
                  <td className="py-2.5 px-4 font-mono font-semibold text-[#17212B]">{u.username}</td>
                  <td className="py-2.5 px-4">{u.displayName}</td>
                  <td className="py-2.5 px-4 text-slate-500">{u.email}</td>
                  <td className="py-2.5 px-4 font-semibold">{u.role}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="bg-white border border-slate-200 rounded-xl p-5 space-y-3">
        <h2 className="text-sm font-semibold text-[#17212B]">{t.settings.apiReadinessTitle}</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          {providers.map((p) => (
            <div key={p.id} className="p-3 bg-[#F7F9FA] rounded-lg">
              <div className="font-bold text-[#17212B]">{p.name}</div>
              <div className="font-mono text-[11px] text-slate-500 mt-1">{p.envVar}</div>
              <div className={`mt-1.5 font-semibold ${p.configured ? 'text-[#137A3E]' : 'text-slate-500'}`}>
                {p.configured ? t.intel.configured : t.intel.notConfigured}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
