import { useEffect, useState } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { ArrowUpRight, RefreshCw } from 'lucide-react';
import { apiFetch } from '../lib/api.ts';
import { getT } from '../i18n/translations.ts';
import { ClassificationMarker, ScoreBar, SeverityMarker } from '../components/StatusText.tsx';
import type { DashboardSummary, Language, NavSection } from '../types/phishguard.ts';

interface Props {
  lang: Language;
  onNavigate: (section: NavSection) => void;
}

const DIST_COLORS: Record<string, string> = {
  Legitimate: '#39FF88',
  Suspicious: '#00E5FF',
  Phishing: '#FF9F1C',
  'High-Risk Phishing': '#FF3B5C',
};

const RISK_COLORS: Record<string, string> = {
  Low: '#39FF88',
  Medium: '#00E5FF',
  High: '#FF9F1C',
  Critical: '#FF3B5C',
};

export function DashboardView({ lang, onNavigate }: Props) {
  const t = getT(lang);
  const [period, setPeriod] = useState<'daily' | 'weekly' | 'monthly'>('daily');
  const [data, setData] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadData = async (selectedPeriod: 'daily' | 'weekly' | 'monthly') => {
    setLoading(true);
    setError('');
    try {
      const res = await apiFetch<DashboardSummary>(`/api/dashboard?period=${selectedPeriod}`);
      setData(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load dashboard');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData(period);
  }, [period]);

  const kpis = data
    ? [
        { label: t.dashboard.kpiTotalEmails, value: data.metrics.totalEmailsAnalyzed, accent: '#17212B', target: 'email' as NavSection },
        { label: t.dashboard.kpiPhishingEmails, value: data.metrics.phishingEmailsDetected, accent: '#FF3B5C', target: 'email' as NavSection },
        { label: t.dashboard.kpiMaliciousUrls, value: data.metrics.maliciousUrlsIdentified, accent: '#FF9F1C', target: 'url' as NavSection },
        { label: t.dashboard.kpiSuspiciousDomains, value: data.metrics.suspiciousDomains, accent: '#00E5FF', target: 'intel' as NavSection },
        { label: t.dashboard.kpiActiveIncidents, value: data.metrics.activeSecurityIncidents, accent: '#FF9F1C', target: 'incidents' as NavSection },
        { label: t.dashboard.kpiCriticalRisks, value: data.metrics.criticalRiskEvents, accent: '#FF3B5C', target: 'risk' as NavSection },
        { label: t.dashboard.kpiResolvedIncidents, value: data.metrics.resolvedIncidents, accent: '#16A34A', target: 'incidents' as NavSection },
      ]
    : [];

  return (
    <div className="space-y-6">
      {/* Page Title & Period Selector */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#17212B]">{t.dashboard.title}</h1>
          <p className="text-sm text-slate-500 mt-1">{t.dashboard.subtitle}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <div className="flex items-center gap-1 p-1 bg-white border border-slate-200 rounded-lg">
            {(['daily', 'weekly', 'monthly'] as const).map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => setPeriod(p)}
                className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap ${
                  period === p
                    ? 'bg-[#B7FF00] text-[#17212B]'
                    : 'text-slate-600 hover:text-[#17212B] hover:bg-[#F7F9FA]'
                }`}
              >
                {p === 'daily'
                  ? t.dashboard.periodDaily
                  : p === 'weekly'
                    ? t.dashboard.periodWeekly
                    : t.dashboard.periodMonthly}
              </button>
            ))}
          </div>
          <button
            type="button"
            onClick={() => loadData(period)}
            className="p-2 bg-white border border-slate-200 rounded-lg text-slate-600 hover:text-[#17212B] hover:border-slate-300 transition-colors"
            title={t.common.refresh}
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-white border border-[#FF3B5C]/40 rounded-xl text-sm text-[#FF3B5C]">
          {error}
        </div>
      )}

      {/* 7 KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7 gap-3">
        {loading && !data
          ? Array.from({ length: 7 }).map((_, idx) => (
              <div key={idx} className="bg-white border border-slate-200 rounded-xl p-4 h-24 animate-pulse" />
            ))
          : kpis.map((kpi) => (
              <button
                key={kpi.label}
                type="button"
                onClick={() => onNavigate(kpi.target)}
                className="group text-start bg-white border border-slate-200 rounded-xl p-4 hover:border-[#17212B]/30 hover:shadow-sm transition-all flex flex-col justify-between"
              >
                <div className="flex items-start justify-between gap-2">
                  <span className="text-xs font-medium text-slate-500 leading-snug">{kpi.label}</span>
                  <ArrowUpRight className="w-3.5 h-3.5 text-slate-300 group-hover:text-[#17212B] transition-colors shrink-0" />
                </div>
                <div className="mt-3 flex items-baseline justify-between">
                  <span className="text-2xl font-bold font-mono tabular-nums text-[#17212B]">
                    {kpi.value}
                  </span>
                  <span
                    className="w-2.5 h-2.5 rounded-sm shrink-0"
                    style={{ backgroundColor: kpi.accent }}
                    aria-hidden="true"
                  />
                </div>
              </button>
            ))}
      </div>

      {/* Charts Row */}
      {data && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Trend Chart */}
          <div className="lg:col-span-6 bg-white border border-slate-200 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-[#17212B]">{t.dashboard.chartTrend}</h2>
              <div className="flex items-center gap-3 text-xs text-slate-500">
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-xs bg-[#FF3B5C]" />
                  {t.dashboard.legendPhishing}
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-xs bg-[#00E5FF]" />
                  {t.dashboard.legendSuspicious}
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-xs bg-[#B7FF00]" />
                  {t.dashboard.legendLegitimate}
                </span>
              </div>
            </div>
            <div className="h-64 w-full" dir="ltr">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data.trendSeries} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" vertical={false} />
                  <XAxis dataKey="bucket" tick={{ fontSize: 11, fill: '#64748B' }} axisLine={false} tickLine={false} />
                  <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: '#64748B' }} axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#FFFFFF',
                      borderColor: '#E2E8F0',
                      borderRadius: '10px',
                      fontSize: '12px',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="phishing"
                    name={t.dashboard.legendPhishing}
                    stroke="#FF3B5C"
                    fill="#FF3B5C"
                    fillOpacity={0.14}
                    strokeWidth={2}
                  />
                  <Area
                    type="monotone"
                    dataKey="suspicious"
                    name={t.dashboard.legendSuspicious}
                    stroke="#00E5FF"
                    fill="#00E5FF"
                    fillOpacity={0.14}
                    strokeWidth={2}
                  />
                  <Area
                    type="monotone"
                    dataKey="legitimate"
                    name={t.dashboard.legendLegitimate}
                    stroke="#16A34A"
                    fill="#B7FF00"
                    fillOpacity={0.25}
                    strokeWidth={2}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Email Classification Distribution */}
          <div className="lg:col-span-3 bg-white border border-slate-200 rounded-xl p-5 flex flex-col">
            <h2 className="text-sm font-semibold text-[#17212B] mb-2">{t.dashboard.chartEmailDist}</h2>
            <div className="h-48 w-full" dir="ltr">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={data.emailDistribution}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={44}
                    outerRadius={70}
                    paddingAngle={3}
                  >
                    {data.emailDistribution.map((entry) => (
                      <Cell key={entry.key} fill={DIST_COLORS[entry.key] || '#94A3B8'} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="mt-auto space-y-1.5 pt-2 border-t border-slate-100">
              {data.emailDistribution.map((item) => (
                <div key={item.key} className="flex items-center justify-between text-xs">
                  <span className="flex items-center gap-2 text-slate-600">
                    <span
                      className="w-2.5 h-2.5 rounded-xs"
                      style={{ backgroundColor: DIST_COLORS[item.key] }}
                    />
                    {t.classifications[item.key as keyof typeof t.classifications] || item.name}
                  </span>
                  <span className="font-mono font-semibold text-[#17212B] tabular-nums">{item.value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Risk Severity Distribution */}
          <div className="lg:col-span-3 bg-white border border-slate-200 rounded-xl p-5 flex flex-col">
            <h2 className="text-sm font-semibold text-[#17212B] mb-4">{t.dashboard.chartRiskSeverity}</h2>
            <div className="h-56 w-full" dir="ltr">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.riskDistribution} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" vertical={false} />
                  <XAxis dataKey="level" tick={{ fontSize: 11, fill: '#64748B' }} axisLine={false} tickLine={false} />
                  <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: '#64748B' }} axisLine={false} tickLine={false} />
                  <Tooltip />
                  <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                    {data.riskDistribution.map((entry) => (
                      <Cell key={entry.level} fill={RISK_COLORS[entry.level] || '#17212B'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* Operational Lists Row */}
      {data && (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
          {/* Recent Security Incidents */}
          <div className="xl:col-span-5 bg-white border border-slate-200 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-[#17212B]">{t.dashboard.recentIncidents}</h2>
              <button
                type="button"
                onClick={() => onNavigate('incidents')}
                className="text-xs font-semibold text-[#17212B] hover:underline"
              >
                {t.common.viewDetails}
              </button>
            </div>
            <div className="divide-y divide-slate-100">
              {data.recentIncidents.map((inc) => (
                <div
                  key={inc.id}
                  onClick={() => onNavigate('incidents')}
                  className="py-3 first:pt-0 last:pb-0 cursor-pointer hover:bg-[#F7F9FA] -mx-2 px-2 rounded-lg transition-colors"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-semibold text-[#17212B] truncate">{inc.title}</span>
                    <SeverityMarker severity={inc.severity} label={t.severities[inc.severity]} />
                  </div>
                  <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-500">
                    <span className="font-mono text-[#17212B]">{inc.id}</span>
                    <span aria-hidden="true">·</span>
                    <span>{inc.nistStage}</span>
                    <span aria-hidden="true">·</span>
                    <span>{inc.assignedAnalyst}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Latest Scan Activities */}
          <div className="xl:col-span-4 bg-white border border-slate-200 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-[#17212B]">{t.dashboard.latestScans}</h2>
              <button
                type="button"
                onClick={() => onNavigate('history')}
                className="text-xs font-semibold text-[#17212B] hover:underline"
              >
                {t.common.viewDetails}
              </button>
            </div>
            <div className="divide-y divide-slate-100">
              {data.latestScans.map((scan) => (
                <div key={scan.id} className="py-2.5 first:pt-0 last:pb-0">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-[#17212B] truncate">{scan.submittedObject}</span>
                    <ClassificationMarker
                      classification={scan.classification}
                      label={t.classifications[scan.classification]}
                    />
                  </div>
                  <div className="mt-1.5 flex items-center justify-between gap-3">
                    <span className="text-xs text-slate-500 font-mono">
                      {scan.id} · {scan.analysisType.toUpperCase()}
                    </span>
                    <ScoreBar score={scan.riskScore} />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Recent Suspicious Domains */}
          <div className="xl:col-span-3 bg-white border border-slate-200 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-[#17212B]">{t.dashboard.suspiciousDomains}</h2>
              <button
                type="button"
                onClick={() => onNavigate('url')}
                className="text-xs font-semibold text-[#17212B] hover:underline"
              >
                {t.common.viewDetails}
              </button>
            </div>
            <div className="divide-y divide-slate-100">
              {data.recentSuspiciousDomains.map((d, idx) => (
                <div key={`${d.domain}-${idx}`} className="py-2.5 first:pt-0 last:pb-0">
                  <div className="font-mono text-xs font-semibold text-[#17212B] truncate">{d.domain}</div>
                  <div className="mt-1 flex items-center justify-between text-xs text-slate-500">
                    <span className="truncate">{d.source}</span>
                    <span className="font-mono font-semibold text-[#FF3B5C] tabular-nums">{d.riskScore}/100</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
