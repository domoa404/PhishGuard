import { useEffect, useState } from 'react';
import {
  Activity,
  BarChart3,
  Bell,
  FileSearch,
  FlaskConical,
  Globe,
  History,
  LayoutDashboard,
  MailWarning,
  Menu,
  Radar,
  Search,
  Settings,
  ShieldAlert,
  ShieldCheck,
  X,
} from 'lucide-react';
import { apiFetch, setApiActor } from './lib/api.ts';
import { getT } from './i18n/translations.ts';
import { DashboardView } from './views/DashboardView.tsx';
import { EmailAnalysisView } from './views/EmailAnalysisView.tsx';
import { UrlScannerView } from './views/UrlScannerView.tsx';
import { ThreatIntelView } from './views/ThreatIntelView.tsx';
import { RiskAssessmentView } from './views/RiskAssessmentView.tsx';
import { IncidentResponseView } from './views/IncidentResponseView.tsx';
import { ForensicsView } from './views/ForensicsView.tsx';
import { SimulationLabView } from './views/SimulationLabView.tsx';
import { ReportsView } from './views/ReportsView.tsx';
import { ScanHistoryView } from './views/ScanHistoryView.tsx';
import { SettingsView } from './views/SettingsView.tsx';
import type {
  IncidentRecord,
  Language,
  NavSection,
  NotificationItem,
  RiskRecord,
  ScanRecord,
  ThreatIntelRecord,
  UserRole,
} from './types/phishguard.ts';

interface SearchResults {
  scans: ScanRecord[];
  incidents: IncidentRecord[];
  risks: RiskRecord[];
  intel: ThreatIntelRecord[];
}

const NAV_ITEMS: Array<{ id: NavSection; icon: typeof LayoutDashboard }> = [
  { id: 'dashboard', icon: LayoutDashboard },
  { id: 'email', icon: MailWarning },
  { id: 'url', icon: Globe },
  { id: 'intel', icon: Radar },
  { id: 'risk', icon: Activity },
  { id: 'incidents', icon: ShieldAlert },
  { id: 'forensics', icon: FileSearch },
  { id: 'simulation', icon: FlaskConical },
  { id: 'reports', icon: BarChart3 },
  { id: 'history', icon: History },
  { id: 'settings', icon: Settings },
];

export default function App() {
  const [lang, setLang] = useState<Language>('en');
  const [section, setSection] = useState<NavSection>('dashboard');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Active RBAC persona
  const [activeActor, setActiveActor] = useState('Tariq Haddad');
  const [activeRole, setActiveRole] = useState<UserRole>('Security Analyst');

  // Header widgets
  const [healthOk, setHealthOk] = useState(true);
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [notifOpen, setNotifOpen] = useState(false);

  const [globalQuery, setGlobalQuery] = useState('');
  const [searchResults, setSearchResults] = useState<SearchResults | null>(null);

  const t = getT(lang);

  useEffect(() => {
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
  }, [lang]);

  useEffect(() => {
    setApiActor(activeActor, activeRole);
  }, [activeActor, activeRole]);

  const refreshHeaderStatus = async () => {
    try {
      const [h, n] = await Promise.all([
        apiFetch<{ status: string }>('/api/health'),
        apiFetch<NotificationItem[]>('/api/notifications'),
      ]);
      setHealthOk(h.status === 'operational');
      setNotifications(n);
    } catch {
      setHealthOk(false);
    }
  };

  useEffect(() => {
    refreshHeaderStatus();
  }, [section]);

  useEffect(() => {
    const q = globalQuery.trim();
    if (!q) {
      setSearchResults(null);
      return;
    }
    const timer = setTimeout(() => {
      apiFetch<SearchResults>(`/api/search?q=${encodeURIComponent(q)}`)
        .then(setSearchResults)
        .catch(() => setSearchResults(null));
    }, 220);
    return () => clearTimeout(timer);
  }, [globalQuery]);

  const handleMarkAllRead = async () => {
    await apiFetch('/api/notifications/read-all', { method: 'POST' });
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  };

  const unreadCount = notifications.filter((n) => !n.read).length;

  const navigateTo = (target: NavSection) => {
    setSection(target);
    setMobileMenuOpen(false);
    setSearchResults(null);
    setGlobalQuery('');
    setNotifOpen(false);
  };

  return (
    <div className="min-h-screen bg-[#F7F9FA] text-[#17212B] flex">
      {/* Mobile Sidebar Backdrop */}
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 bg-[#17212B]/40 z-30 lg:hidden"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      {/* Sidebar Navigation */}
      <aside
        className={`fixed lg:sticky top-0 start-0 z-40 h-screen w-[264px] shrink-0 bg-white border-e border-slate-200 flex flex-col transition-transform duration-200 ${
          mobileMenuOpen
            ? 'translate-x-0'
            : lang === 'ar'
              ? 'translate-x-full lg:translate-x-0'
              : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Brand Block */}
        <div className="h-16 px-5 border-b border-slate-200 flex items-center justify-between gap-2">
          <button
            type="button"
            onClick={() => navigateTo('dashboard')}
            className="flex items-center gap-2.5 text-start"
          >
            <div className="w-8 h-8 rounded-lg bg-[#17212B] flex items-center justify-center shrink-0">
              <ShieldCheck className="w-4 h-4 text-[#B7FF00]" />
            </div>
            <span className="text-lg font-bold tracking-tight text-[#17212B] whitespace-nowrap">
              {t.brandName}
            </span>
          </button>
          <button
            type="button"
            onClick={() => setMobileMenuOpen(false)}
            className="lg:hidden p-1.5 text-slate-500"
            aria-label="Close navigation"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Navigation Links */}
        <nav className="flex-1 overflow-y-auto p-3 space-y-1">
          {NAV_ITEMS.map(({ id, icon: Icon }) => {
            const active = section === id;
            return (
              <button
                key={id}
                type="button"
                onClick={() => navigateTo(id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-semibold transition-colors text-start ${
                  active
                    ? 'bg-[#17212B] text-white'
                    : 'text-slate-600 hover:bg-[#F7F9FA] hover:text-[#17212B]'
                }`}
              >
                <Icon className={`w-4 h-4 shrink-0 ${active ? 'text-[#B7FF00]' : 'text-slate-400'}`} />
                <span className="truncate">{t.nav[id]}</span>
              </button>
            );
          })}
        </nav>

        {/* Quiet Brand Tagline Footer */}
        <div className="p-4 border-t border-slate-100 text-[11px] text-slate-400">
          {t.brandTagline}
        </div>
      </aside>

      {/* Main Column */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Top Header */}
        <header className="sticky top-0 z-20 h-16 bg-white/95 backdrop-blur border-b border-slate-200 px-4 sm:px-6 flex items-center justify-between gap-4 no-print">
          <div className="flex items-center gap-3 flex-1 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden p-2 rounded-lg border border-slate-200 text-[#17212B]"
              aria-label="Open menu"
            >
              <Menu className="w-4 h-4" />
            </button>

            {/* Global Search */}
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 text-slate-400 absolute start-3 top-2.5" />
              <input
                type="search"
                value={globalQuery}
                onChange={(e) => setGlobalQuery(e.target.value)}
                placeholder={t.header.searchPlaceholder}
                className="w-full ps-9 pe-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg focus:outline-none focus:border-[#17212B]"
              />
              {searchResults && (
                <div className="absolute start-0 end-0 top-11 bg-white border border-slate-200 rounded-xl shadow-lg p-3 z-50 space-y-2 max-h-80 overflow-y-auto text-xs">
                  {searchResults.incidents.length === 0 &&
                  searchResults.scans.length === 0 &&
                  searchResults.risks.length === 0 &&
                  searchResults.intel.length === 0 ? (
                    <div className="text-slate-400 py-2 text-center">{t.header.noResults}</div>
                  ) : (
                    <>
                      {searchResults.incidents.map((i) => (
                        <button
                          key={i.id}
                          type="button"
                          onClick={() => navigateTo('incidents')}
                          className="w-full text-start p-2 rounded-lg hover:bg-[#F7F9FA] flex justify-between gap-2"
                        >
                          <span className="font-medium truncate">{i.title}</span>
                          <span className="font-mono text-slate-400 shrink-0">{i.id}</span>
                        </button>
                      ))}
                      {searchResults.scans.map((s) => (
                        <button
                          key={s.id}
                          type="button"
                          onClick={() => navigateTo('history')}
                          className="w-full text-start p-2 rounded-lg hover:bg-[#F7F9FA] flex justify-between gap-2"
                        >
                          <span className="truncate">{s.submittedObject}</span>
                          <span className="font-mono text-slate-400 shrink-0">{s.id}</span>
                        </button>
                      ))}
                      {searchResults.intel.map((ioc) => (
                        <button
                          key={ioc.id}
                          type="button"
                          onClick={() => navigateTo('intel')}
                          className="w-full text-start p-2 rounded-lg hover:bg-[#F7F9FA] flex justify-between gap-2"
                        >
                          <span className="font-mono truncate">{ioc.indicator}</span>
                          <span className="text-slate-400 shrink-0">{ioc.iocType}</span>
                        </button>
                      ))}
                      {searchResults.risks.map((r) => (
                        <button
                          key={r.id}
                          type="button"
                          onClick={() => navigateTo('risk')}
                          className="w-full text-start p-2 rounded-lg hover:bg-[#F7F9FA] flex justify-between gap-2"
                        >
                          <span className="truncate">{r.assetAffected}</span>
                          <span className="font-mono text-slate-400 shrink-0">{r.id}</span>
                        </button>
                      ))}
                    </>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Right Header Controls */}
          <div className="flex items-center gap-2.5 sm:gap-3 shrink-0">
            {/* Real Database Health Indicator */}
            <div className="hidden md:flex items-center gap-1.5 text-xs text-slate-600 px-2.5 py-1.5 bg-[#F7F9FA] border border-slate-200 rounded-lg whitespace-nowrap">
              <span
                className={`w-2 h-2 rounded-full ${healthOk ? 'bg-[#16A34A]' : 'bg-[#FF3B5C]'}`}
                aria-hidden="true"
              />
              <span>{healthOk ? t.header.systemOperational : t.header.systemDegraded}</span>
            </div>

            {/* Language Switcher (Preserves Session & Data) */}
            <button
              type="button"
              onClick={() => setLang((l) => (l === 'en' ? 'ar' : 'en'))}
              className="px-3 py-1.5 bg-[#B7FF00] text-[#17212B] text-xs font-bold rounded-lg hover:brightness-95 transition-all whitespace-nowrap shrink-0"
            >
              {t.header.languageLabel}
            </button>

            {/* Notifications */}
            <div className="relative">
              <button
                type="button"
                onClick={() => setNotifOpen((o) => !o)}
                className="relative p-2 bg-white border border-slate-200 rounded-lg text-[#17212B] hover:border-slate-300"
                aria-label={t.header.notifications}
              >
                <Bell className="w-4 h-4" />
                {unreadCount > 0 && (
                  <span className="absolute -top-1 -end-1 w-4 h-4 rounded-full bg-[#FF3B5C] text-white text-[10px] font-mono font-bold flex items-center justify-center">
                    {unreadCount}
                  </span>
                )}
              </button>

              {notifOpen && (
                <div className="absolute end-0 top-11 w-80 bg-white border border-slate-200 rounded-xl shadow-lg p-3 z-50 space-y-2">
                  <div className="flex items-center justify-between pb-2 border-b border-slate-100">
                    <span className="text-xs font-bold text-[#17212B]">{t.header.notifications}</span>
                    <button
                      type="button"
                      onClick={handleMarkAllRead}
                      className="text-[11px] font-semibold text-slate-500 hover:text-[#17212B]"
                    >
                      {t.header.markAllRead}
                    </button>
                  </div>
                  <div className="divide-y divide-slate-100 max-h-64 overflow-y-auto">
                    {notifications.map((n) => (
                      <button
                        key={n.id}
                        type="button"
                        onClick={() => navigateTo(n.targetSection)}
                        className={`w-full text-start py-2 px-1.5 rounded hover:bg-[#F7F9FA] text-xs ${
                          n.read ? 'opacity-60' : 'font-semibold'
                        }`}
                      >
                        <div className="text-[#17212B]">{lang === 'ar' ? n.titleAr : n.title}</div>
                        <div className="font-mono text-[10px] text-slate-400 mt-0.5">
                          {n.severity} · {n.createdAt.slice(0, 16).replace('T', ' ')}
                        </div>
                      </button>
                    ))}
                    {notifications.length === 0 && (
                      <div className="py-4 text-center text-xs text-slate-400">{t.header.noNotifications}</div>
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Analyst Profile Button */}
            <button
              type="button"
              onClick={() => navigateTo('settings')}
              className="flex items-center gap-2.5 ps-1 pe-2.5 py-1 bg-[#F7F9FA] border border-slate-200 rounded-lg hover:border-slate-300 transition-colors"
            >
              <img
                src="/src/assets/images/avatar_soc_analyst_1795110584320.jpg"
                alt={activeActor}
                referrerPolicy="no-referrer"
                className="w-7 h-7 rounded-md object-cover bg-slate-200 shrink-0"
              />
              <div className="hidden sm:block text-start leading-tight">
                <div className="text-xs font-semibold text-[#17212B] whitespace-nowrap">{activeActor}</div>
                <div className="text-[10px] text-slate-500 whitespace-nowrap">{activeRole}</div>
              </div>
            </button>
          </div>
        </header>

        {/* Active Module Viewport */}
        <main className="flex-1 p-4 sm:p-6 max-w-[1440px] w-full mx-auto">
          {section === 'dashboard' && <DashboardView lang={lang} onNavigate={navigateTo} />}
          {section === 'email' && <EmailAnalysisView lang={lang} onNavigate={navigateTo} />}
          {section === 'url' && <UrlScannerView lang={lang} onNavigate={navigateTo} />}
          {section === 'intel' && <ThreatIntelView lang={lang} />}
          {section === 'risk' && <RiskAssessmentView lang={lang} />}
          {section === 'incidents' && <IncidentResponseView lang={lang} />}
          {section === 'forensics' && <ForensicsView lang={lang} />}
          {section === 'simulation' && <SimulationLabView lang={lang} />}
          {section === 'reports' && <ReportsView lang={lang} />}
          {section === 'history' && <ScanHistoryView lang={lang} />}
          {section === 'settings' && (
            <SettingsView
              lang={lang}
              activeActor={activeActor}
              activeRole={activeRole}
              onChangePersona={(actor, role) => {
                setActiveActor(actor);
                setActiveRole(role);
              }}
            />
          )}
        </main>
      </div>
    </div>
  );
}
