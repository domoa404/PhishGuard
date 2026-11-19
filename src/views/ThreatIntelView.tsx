import { useEffect, useState } from 'react';
import { Database, Plus, Search } from 'lucide-react';
import { apiFetch } from '../lib/api.ts';
import { getT } from '../i18n/translations.ts';
import { ScoreBar, SeverityMarker } from '../components/StatusText.tsx';
import type { Language, ThreatIntelRecord } from '../types/phishguard.ts';

interface ProviderStatus {
  id: string;
  name: string;
  configured: boolean;
  envVar: string;
  capability: string;
}

interface LookupResponse {
  indicator: string;
  localMatches: ThreatIntelRecord[];
  external: {
    provider: string;
    verifiedExternal: boolean;
    reputationScore: number | null;
    category: string | null;
    notes: string;
    timestamp: string;
  };
}

export function ThreatIntelView({ lang }: { lang: Language }) {
  const t = getT(lang);
  const [iocs, setIocs] = useState<ThreatIntelRecord[]>([]);
  const [providers, setProviders] = useState<ProviderStatus[]>([]);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');

  const [lookupInput, setLookupInput] = useState('');
  const [lookupType, setLookupType] = useState<'Domain' | 'IP' | 'URL' | 'SHA-256' | 'MD5'>('Domain');
  const [lookupResult, setLookupResult] = useState<LookupResponse | null>(null);

  const [newIndicator, setNewIndicator] = useState('');
  const [newType, setNewType] = useState<'IP' | 'Domain' | 'URL' | 'MD5' | 'SHA-1' | 'SHA-256'>('Domain');
  const [newCategory, setNewCategory] = useState('Credential Phishing');
  const [newScore, setNewScore] = useState(85);
  const [newNotes, setNewNotes] = useState('');
  const [error, setError] = useState('');
  const [feedback, setFeedback] = useState('');

  const loadIntel = async () => {
    const res = await apiFetch<{ iocs: ThreatIntelRecord[]; providers: ProviderStatus[] }>('/api/threat-intel');
    setIocs(res.iocs);
    setProviders(res.providers);
  };

  useEffect(() => {
    loadIntel();
  }, []);

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!lookupInput.trim()) return;
    const res = await apiFetch<LookupResponse>('/api/threat-intel/lookup', {
      method: 'POST',
      body: JSON.stringify({ indicator: lookupInput.trim(), iocType: lookupType }),
    });
    setLookupResult(res);
  };

  const handleAddIoc = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setFeedback('');
    try {
      await apiFetch('/api/threat-intel', {
        method: 'POST',
        body: JSON.stringify({
          indicator: newIndicator,
          iocType: newType,
          category: newCategory,
          reputationScore: Number(newScore),
          notes: newNotes,
        }),
      });
      setNewIndicator('');
      setNewNotes('');
      setFeedback('IOC stored in Threat Intelligence database.');
      await loadIntel();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to add IOC');
    }
  };

  const filtered = iocs.filter((i) => {
    const matchType = typeFilter === 'all' || i.iocType === typeFilter;
    const matchSearch =
      !search.trim() ||
      i.indicator.toLowerCase().includes(search.toLowerCase()) ||
      i.category.toLowerCase().includes(search.toLowerCase()) ||
      i.source.toLowerCase().includes(search.toLowerCase());
    return matchType && matchSearch;
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-[#17212B]">{t.intel.title}</h1>
        <p className="text-sm text-slate-500 mt-1">{t.intel.subtitle}</p>
      </div>

      {/* External Provider Status Strip */}
      <div className="bg-white border border-slate-200 rounded-xl p-5">
        <h2 className="text-xs font-semibold text-[#17212B] mb-3">{t.intel.providersTitle}</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {providers.map((p) => (
            <div key={p.id} className="p-3 bg-[#F7F9FA] rounded-lg space-y-1">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-bold text-[#17212B]">{p.name}</span>
                <span className={`text-[11px] font-semibold ${p.configured ? 'text-[#137A3E]' : 'text-slate-500'}`}>
                  {p.configured ? t.intel.configured : t.intel.notConfigured}
                </span>
              </div>
              <p className="text-[11px] text-slate-500">{p.capability}</p>
              <div className="font-mono text-[10px] text-slate-400">ENV: {p.envVar}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Live Lookup & Add IOC */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        <div className="lg:col-span-7 bg-white border border-slate-200 rounded-xl p-5 space-y-4">
          <h2 className="text-sm font-semibold text-[#17212B]">{t.intel.lookupTitle}</h2>
          <form onSubmit={handleLookup} className="flex flex-col sm:flex-row gap-2.5">
            <select
              value={lookupType}
              onChange={(e) => setLookupType(e.target.value as typeof lookupType)}
              className="px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            >
              <option value="Domain">Domain</option>
              <option value="IP">IP</option>
              <option value="URL">URL</option>
              <option value="SHA-256">SHA-256</option>
              <option value="MD5">MD5</option>
            </select>
            <input
              type="text"
              value={lookupInput}
              onChange={(e) => setLookupInput(e.target.value)}
              placeholder={t.intel.lookupPlaceholder}
              className="flex-1 px-3 py-2 font-mono text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg focus:outline-none focus:border-[#17212B]"
            />
            <button
              type="submit"
              className="px-4 py-2 bg-[#B7FF00] text-[#17212B] text-xs font-bold rounded-lg whitespace-nowrap"
            >
              {t.intel.lookupBtn}
            </button>
          </form>

          {lookupResult && (
            <div className="p-4 bg-[#F7F9FA] rounded-lg space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-mono font-bold text-[#17212B]">{lookupResult.indicator}</span>
                <span className="font-mono text-[11px] text-slate-500">{lookupResult.external.timestamp}</span>
              </div>
              <div className="text-slate-700">
                <strong>{lookupResult.external.provider}:</strong> {lookupResult.external.notes}
              </div>
              <div className="pt-1">
                {lookupResult.localMatches.length > 0 ? (
                  <div className="text-[#FF3B5C] font-semibold">
                    Matched {lookupResult.localMatches.length} local IOC record(s) — Score{' '}
                    {lookupResult.localMatches[0].reputationScore}/100 ({lookupResult.localMatches[0].source})
                  </div>
                ) : (
                  <div className="text-slate-600">No matches in local IOC repository.</div>
                )}
              </div>
            </div>
          )}
        </div>

        <form onSubmit={handleAddIoc} className="lg:col-span-5 bg-white border border-slate-200 rounded-xl p-5 space-y-3">
          <h2 className="text-sm font-semibold text-[#17212B] flex items-center gap-1.5">
            <Plus className="w-4 h-4" />
            {t.intel.addTitle}
          </h2>
          <div className="grid grid-cols-2 gap-2.5">
            <select
              value={newType}
              onChange={(e) => setNewType(e.target.value as typeof newType)}
              className="px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            >
              <option value="Domain">Domain</option>
              <option value="IP">IP</option>
              <option value="URL">URL</option>
              <option value="MD5">MD5</option>
              <option value="SHA-1">SHA-1</option>
              <option value="SHA-256">SHA-256</option>
            </select>
            <input
              type="number"
              min={0}
              max={100}
              value={newScore}
              onChange={(e) => setNewScore(Number(e.target.value))}
              placeholder="Score 0-100"
              className="px-3 py-2 font-mono text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            />
          </div>
          <input
            type="text"
            required
            value={newIndicator}
            onChange={(e) => setNewIndicator(e.target.value)}
            placeholder="Indicator value (domain, IP, hash...)"
            className="w-full px-3 py-2 font-mono text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
          />
          <input
            type="text"
            required
            value={newCategory}
            onChange={(e) => setNewCategory(e.target.value)}
            placeholder="Threat category"
            className="w-full px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
          />
          <input
            type="text"
            value={newNotes}
            onChange={(e) => setNewNotes(e.target.value)}
            placeholder="Analyst notes"
            className="w-full px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
          />
          {error && <p className="text-xs text-[#FF3B5C]">{error}</p>}
          {feedback && <p className="text-xs text-[#137A3E]">{feedback}</p>}
          <button
            type="submit"
            className="w-full py-2 bg-[#17212B] text-white text-xs font-semibold rounded-lg hover:bg-slate-800"
          >
            {t.common.create}
          </button>
        </form>
      </div>

      {/* IOC Table */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="relative flex-1 max-w-sm">
            <Search className="w-4 h-4 text-slate-400 absolute start-3 top-2.5" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={t.common.search}
              className="w-full ps-9 pe-3 py-1.5 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg focus:outline-none focus:border-[#17212B]"
            />
          </div>
          <div className="flex flex-wrap gap-1">
            {['all', 'IP', 'Domain', 'URL', 'MD5', 'SHA-1', 'SHA-256'].map((tp) => (
              <button
                key={tp}
                type="button"
                onClick={() => setTypeFilter(tp)}
                className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors ${
                  typeFilter === tp ? 'bg-[#17212B] text-white' : 'text-slate-600 hover:bg-[#F7F9FA]'
                }`}
              >
                {tp === 'all' ? t.intel.allTypes : tp}
              </button>
            ))}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-start border-collapse text-xs">
            <thead>
              <tr className="bg-[#F7F9FA] border-b border-slate-200 text-slate-500">
                <th className="py-2.5 px-4 text-start font-semibold">IOC</th>
                <th className="py-2.5 px-4 text-start font-semibold">Type</th>
                <th className="py-2.5 px-4 text-start font-semibold">Category</th>
                <th className="py-2.5 px-4 text-start font-semibold">{t.common.score}</th>
                <th className="py-2.5 px-4 text-start font-semibold">{t.common.severity}</th>
                <th className="py-2.5 px-4 text-start font-semibold">Source & Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filtered.map((item) => (
                <tr key={item.id} className="hover:bg-[#F7F9FA]">
                  <td className="py-3 px-4 font-mono font-medium text-[#17212B] max-w-[260px] truncate">
                    {item.indicator}
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-600">{item.iocType}</td>
                  <td className="py-3 px-4 text-slate-700">{item.category}</td>
                  <td className="py-3 px-4">
                    <ScoreBar score={item.reputationScore} />
                  </td>
                  <td className="py-3 px-4">
                    <SeverityMarker severity={item.severity} label={t.severities[item.severity]} />
                  </td>
                  <td className="py-3 px-4 text-slate-500">
                    <div>{item.source}</div>
                    <div className="font-mono text-[11px] text-slate-400">{item.lastUpdated.slice(0, 16).replace('T', ' ')}</div>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-slate-400">
                    <Database className="w-6 h-6 mx-auto mb-1 opacity-40" />
                    {t.common.noData}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
