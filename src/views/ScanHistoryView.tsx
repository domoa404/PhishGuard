import { useEffect, useState } from 'react';
import { Search } from 'lucide-react';
import { apiFetch } from '../lib/api.ts';
import { getT } from '../i18n/translations.ts';
import { ClassificationMarker, ScoreBar, SeverityMarker } from '../components/StatusText.tsx';
import type { AuditLogRecord, Language, ScanRecord } from '../types/phishguard.ts';

export function ScanHistoryView({ lang }: { lang: Language }) {
  const t = getT(lang);
  const [tab, setTab] = useState<'scans' | 'audit'>('scans');
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [audits, setAudits] = useState<AuditLogRecord[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanRecord | null>(null);

  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [resultFilter, setResultFilter] = useState('all');
  const [fromDate, setFromDate] = useState('');

  useEffect(() => {
    Promise.all([
      apiFetch<ScanRecord[]>('/api/scans'),
      apiFetch<AuditLogRecord[]>('/api/audit-logs'),
    ]).then(([s, a]) => {
      setScans(s);
      setAudits(a);
    });
  }, []);

  const filteredScans = scans.filter((s) => {
    const matchType = typeFilter === 'all' || s.analysisType === typeFilter;
    const matchSev = severityFilter === 'all' || s.severity === severityFilter;
    const matchRes = resultFilter === 'all' || s.classification === resultFilter;
    const matchDate = !fromDate || s.createdAt.slice(0, 10) >= fromDate;
    const matchSearch =
      !search.trim() ||
      s.submittedObject.toLowerCase().includes(search.toLowerCase()) ||
      s.id.toLowerCase().includes(search.toLowerCase()) ||
      s.analyst.toLowerCase().includes(search.toLowerCase());
    return matchType && matchSev && matchRes && matchDate && matchSearch;
  });

  const filteredAudits = audits.filter((a) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      a.action.toLowerCase().includes(q) ||
      a.actor.toLowerCase().includes(q) ||
      a.target.toLowerCase().includes(q) ||
      a.details.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#17212B]">{t.history.title}</h1>
          <p className="text-sm text-slate-500 mt-1">{t.history.subtitle}</p>
        </div>
        <div className="flex items-center gap-1 p-1 bg-white border border-slate-200 rounded-lg shrink-0">
          <button
            type="button"
            onClick={() => setTab('scans')}
            className={`px-3.5 py-1.5 text-xs font-semibold rounded-md ${
              tab === 'scans' ? 'bg-[#B7FF00] text-[#17212B]' : 'text-slate-600'
            }`}
          >
            {t.history.tabScans} ({scans.length})
          </button>
          <button
            type="button"
            onClick={() => setTab('audit')}
            className={`px-3.5 py-1.5 text-xs font-semibold rounded-md ${
              tab === 'audit' ? 'bg-[#B7FF00] text-[#17212B]' : 'text-slate-600'
            }`}
          >
            {t.history.tabAudit} ({audits.length})
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white border border-slate-200 rounded-xl p-4 flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="w-4 h-4 text-slate-400 absolute start-3 top-2.5" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t.common.search}
            className="w-full ps-9 pe-3 py-1.5 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
          />
        </div>
        {tab === 'scans' && (
          <>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              aria-label={t.history.filterType}
              className="px-3 py-1.5 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            >
              <option value="all">{t.history.filterType}: {t.common.all}</option>
              <option value="email">Email</option>
              <option value="url">URL</option>
            </select>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              aria-label={t.history.filterSeverity}
              className="px-3 py-1.5 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            >
              <option value="all">{t.history.filterSeverity}: {t.common.all}</option>
              <option value="Low">Low</option>
              <option value="Medium">Medium</option>
              <option value="High">High</option>
              <option value="Critical">Critical</option>
            </select>
            <select
              value={resultFilter}
              onChange={(e) => setResultFilter(e.target.value)}
              aria-label={t.history.filterResult}
              className="px-3 py-1.5 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            >
              <option value="all">{t.history.filterResult}: {t.common.all}</option>
              <option value="Legitimate">Legitimate</option>
              <option value="Suspicious">Suspicious</option>
              <option value="Phishing">Phishing</option>
              <option value="High-Risk Phishing">High-Risk Phishing</option>
            </select>
            <input
              type="date"
              value={fromDate}
              onChange={(e) => setFromDate(e.target.value)}
              aria-label={t.history.filterDate}
              className="px-3 py-1.5 text-xs font-mono bg-[#F7F9FA] border border-slate-200 rounded-lg"
            />
          </>
        )}
      </div>

      {tab === 'scans' ? (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
          <div className={`${selectedScan ? 'lg:col-span-7' : 'lg:col-span-12'} bg-white border border-slate-200 rounded-xl overflow-hidden`}>
            <div className="overflow-x-auto">
              <table className="w-full text-start border-collapse text-xs">
                <thead>
                  <tr className="bg-[#F7F9FA] border-b border-slate-200 text-slate-500">
                    <th className="py-2.5 px-4 text-start font-semibold">Scan ID</th>
                    <th className="py-2.5 px-4 text-start font-semibold">Type</th>
                    <th className="py-2.5 px-4 text-start font-semibold">Submitted Object</th>
                    <th className="py-2.5 px-4 text-start font-semibold">{t.common.classification}</th>
                    <th className="py-2.5 px-4 text-start font-semibold">{t.common.score}</th>
                    <th className="py-2.5 px-4 text-start font-semibold">{t.common.analyst}</th>
                    <th className="py-2.5 px-4 text-start font-semibold">{t.common.timestamp}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filteredScans.map((s) => (
                    <tr
                      key={s.id}
                      onClick={() => setSelectedScan(s)}
                      className={`cursor-pointer hover:bg-[#F7F9FA] ${selectedScan?.id === s.id ? 'bg-[#F7F9FA]' : ''}`}
                    >
                      <td className="py-3 px-4 font-mono font-bold text-[#17212B]">
                        {s.id}
                        {s.incidentId && <div className="text-[10px] text-[#FF3B5C]">{s.incidentId}</div>}
                      </td>
                      <td className="py-3 px-4 font-mono uppercase text-slate-600">{s.analysisType}</td>
                      <td className="py-3 px-4 text-[#17212B] max-w-[240px] truncate">{s.submittedObject}</td>
                      <td className="py-3 px-4">
                        <ClassificationMarker classification={s.classification} label={t.classifications[s.classification]} />
                      </td>
                      <td className="py-3 px-4">
                        <ScoreBar score={s.riskScore} />
                      </td>
                      <td className="py-3 px-4 text-slate-600">{s.analyst}</td>
                      <td className="py-3 px-4 font-mono text-slate-400 whitespace-nowrap">
                        {s.createdAt.slice(0, 16).replace('T', ' ')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {selectedScan && (
            <div className="lg:col-span-5 bg-white border border-slate-200 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-[#17212B]">{selectedScan.id}</span>
                <button
                  type="button"
                  onClick={() => setSelectedScan(null)}
                  className="text-xs text-slate-500 hover:text-[#17212B]"
                >
                  {t.common.cancel}
                </button>
              </div>
              <div className="flex items-center gap-2">
                <SeverityMarker severity={selectedScan.severity} label={t.severities[selectedScan.severity]} />
                <ClassificationMarker
                  classification={selectedScan.classification}
                  label={t.classifications[selectedScan.classification]}
                />
              </div>
              <div className="text-xs font-mono text-slate-700 break-all bg-[#F7F9FA] p-3 rounded-lg">
                {selectedScan.submittedObject}
              </div>
              <div className="space-y-1.5 text-xs">
                <div className="font-semibold text-[#17212B]">Findings ({selectedScan.details.findings.length})</div>
                {selectedScan.details.findings.map((f) => (
                  <div key={f.id} className="p-2 border border-slate-100 rounded-lg">
                    <div className="font-semibold text-[#17212B]">{lang === 'ar' ? f.titleAr : f.title}</div>
                    <div className="text-slate-600">{lang === 'ar' ? f.detailAr : f.detail}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-start border-collapse text-xs">
              <thead>
                <tr className="bg-[#F7F9FA] border-b border-slate-200 text-slate-500">
                  <th className="py-2.5 px-4 text-start font-semibold">{t.common.timestamp}</th>
                  <th className="py-2.5 px-4 text-start font-semibold">Actor & Role</th>
                  <th className="py-2.5 px-4 text-start font-semibold">Action</th>
                  <th className="py-2.5 px-4 text-start font-semibold">Target</th>
                  <th className="py-2.5 px-4 text-start font-semibold">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredAudits.map((a) => (
                  <tr key={a.id} className="hover:bg-[#F7F9FA]">
                    <td className="py-2.5 px-4 font-mono text-slate-500 whitespace-nowrap">
                      {a.timestamp.slice(0, 19).replace('T', ' ')}
                    </td>
                    <td className="py-2.5 px-4">
                      <span className="font-semibold text-[#17212B]">{a.actor}</span>
                      <span className="text-slate-400"> · {a.role}</span>
                    </td>
                    <td className="py-2.5 px-4 font-mono font-semibold text-[#17212B]">
                      {a.action}
                      {a.simulated && <span className="ms-2 text-[#007D8C]">({t.common.simulationOnly})</span>}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-600">{a.target}</td>
                    <td className="py-2.5 px-4 text-slate-600">{a.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
