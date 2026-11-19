import { useEffect, useState } from 'react';
import { Fingerprint } from 'lucide-react';
import { apiFetch } from '../lib/api.ts';
import { getT } from '../i18n/translations.ts';
import type { EvidenceRecord, IncidentRecord, Language, TimelineEventRecord } from '../types/phishguard.ts';

export function ForensicsView({ lang }: { lang: Language }) {
  const t = getT(lang);
  const [evidence, setEvidence] = useState<EvidenceRecord[]>([]);
  const [timeline, setTimeline] = useState<TimelineEventRecord[]>([]);
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);

  // Header Tracer
  const [rawHeaders, setRawHeaders] = useState(
    `Received: from mx-out.micros0ft-auth-verify.top (185.220.101.47) by mx1.enterprise.local with ESMTPS\nReceived: from internal-mailer (10.8.4.12) by mx-out.micros0ft-auth-verify.top\nAuthentication-Results: spf=fail smtp.mailfrom=micros0ft-auth-verify.top; dkim=fail; dmarc=fail\nFrom: "Microsoft Security" <security@micros0ft-auth-verify.top>\nReply-To: audit@proton.me`,
  );
  const [parsedHops, setParsedHops] = useState<Array<{ key: string; value: string }>>([]);

  // Evidence Collection
  const [incidentId, setIncidentId] = useState('INC-2026-001');
  const [source, setSource] = useState('Mail Gateway Quarantine Export');
  const [evidenceType, setEvidenceType] = useState<EvidenceRecord['evidenceType']>('Email Header');
  const [contentPreview, setContentPreview] = useState('');

  // Timeline
  const [tlIncidentId, setTlIncidentId] = useState('INC-2026-001');
  const [tlPhase, setTlPhase] = useState('Containment');
  const [tlDesc, setTlDesc] = useState('');

  const [error, setError] = useState('');
  const [feedback, setFeedback] = useState('');

  const loadForensics = async () => {
    const [f, incs] = await Promise.all([
      apiFetch<{ evidence: EvidenceRecord[]; timeline: TimelineEventRecord[] }>('/api/forensics'),
      apiFetch<IncidentRecord[]>('/api/incidents'),
    ]);
    setEvidence(f.evidence);
    setTimeline(f.timeline);
    setIncidents(incs);
    if (incs.length > 0 && !incs.some((i) => i.id === incidentId)) {
      setIncidentId(incs[0].id);
      setTlIncidentId(incs[0].id);
    }
  };

  useEffect(() => {
    loadForensics();
    handleParseHeaders();
  }, []);

  const handleParseHeaders = () => {
    const lines = rawHeaders.split(/\r?\n/).filter((l) => l.includes(':'));
    setParsedHops(
      lines.map((l) => {
        const idx = l.indexOf(':');
        return { key: l.slice(0, idx).trim(), value: l.slice(idx + 1).trim() };
      }),
    );
  };

  const handleCollectEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setFeedback('');
    try {
      const res = await apiFetch<{ id: string; sha256Hash: string }>('/api/forensics/evidence', {
        method: 'POST',
        body: JSON.stringify({ incidentId, source, evidenceType, contentPreview }),
      });
      setContentPreview('');
      setFeedback(`Evidence ${res.id} sealed · SHA-256: ${res.sha256Hash}`);
      await loadForensics();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to seal evidence');
    }
  };

  const handleAddTimeline = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    try {
      await apiFetch('/api/forensics/timeline', {
        method: 'POST',
        body: JSON.stringify({ incidentId: tlIncidentId, phase: tlPhase, description: tlDesc }),
      });
      setTlDesc('');
      await loadForensics();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to add timeline event');
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-[#17212B]">{t.forensics.title}</h1>
        <p className="text-sm text-slate-500 mt-1">{t.forensics.subtitle}</p>
      </div>

      {/* Header Tracer & Evidence Collector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        <div className="lg:col-span-6 bg-white border border-slate-200 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-[#17212B]">{t.forensics.headerParserTitle}</h2>
            <button
              type="button"
              onClick={handleParseHeaders}
              className="px-3 py-1.5 bg-[#B7FF00] text-[#17212B] text-xs font-bold rounded-lg"
            >
              {t.forensics.parseHeadersBtn}
            </button>
          </div>
          <textarea
            value={rawHeaders}
            onChange={(e) => setRawHeaders(e.target.value)}
            rows={5}
            placeholder={t.forensics.headerPlaceholder}
            className="w-full p-2.5 font-mono text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
          />
          <div className="divide-y divide-slate-100 border border-slate-200 rounded-lg">
            {parsedHops.map((h, i) => (
              <div key={i} className="p-2.5 text-xs flex flex-col sm:flex-row sm:items-start gap-2">
                <span className="font-mono font-bold text-[#17212B] min-w-[160px] shrink-0">{h.key}</span>
                <span className="font-mono text-slate-600 break-all">{h.value}</span>
              </div>
            ))}
          </div>
        </div>

        <form onSubmit={handleCollectEvidence} className="lg:col-span-6 bg-white border border-slate-200 rounded-xl p-5 space-y-3">
          <h2 className="text-sm font-semibold text-[#17212B] flex items-center gap-2">
            <Fingerprint className="w-4 h-4" />
            {t.forensics.collectTitle}
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <select
              value={incidentId}
              onChange={(e) => setIncidentId(e.target.value)}
              className="px-3 py-2 font-mono text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            >
              {incidents.map((inc) => (
                <option key={inc.id} value={inc.id}>
                  {inc.id} — {inc.title.slice(0, 32)}
                </option>
              ))}
            </select>
            <select
              value={evidenceType}
              onChange={(e) => setEvidenceType(e.target.value as EvidenceRecord['evidenceType'])}
              className="px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            >
              <option value="Email Header">Email Header</option>
              <option value="Raw EML">Raw EML</option>
              <option value="URL Artifact">URL Artifact</option>
              <option value="Auth Log">Auth Log</option>
              <option value="Attachment Metadata">Attachment Metadata</option>
            </select>
          </div>
          <input
            required
            value={source}
            onChange={(e) => setSource(e.target.value)}
            placeholder="Evidence Source"
            className="w-full px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
          />
          <textarea
            required
            value={contentPreview}
            onChange={(e) => setContentPreview(e.target.value)}
            rows={4}
            placeholder="Paste raw header, URL log, or artifact snippet to hash (SHA-256) and seal..."
            className="w-full p-2.5 font-mono text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
          />
          {error && <p className="text-xs text-[#FF3B5C]">{error}</p>}
          {feedback && <p className="text-xs font-mono text-[#137A3E] break-all">{feedback}</p>}
          <button
            type="submit"
            className="w-full py-2 bg-[#17212B] text-white text-xs font-semibold rounded-lg hover:bg-slate-800"
          >
            {t.common.submit}
          </button>
        </form>
      </div>

      {/* Chain of Custody Table */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-100">
          <h2 className="text-sm font-semibold text-[#17212B]">{t.forensics.custodyTable}</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-start border-collapse text-xs">
            <thead>
              <tr className="bg-[#F7F9FA] border-b border-slate-200 text-slate-500">
                <th className="py-2.5 px-4 text-start font-semibold">Evidence ID</th>
                <th className="py-2.5 px-4 text-start font-semibold">Incident</th>
                <th className="py-2.5 px-4 text-start font-semibold">Source & Type</th>
                <th className="py-2.5 px-4 text-start font-semibold">SHA-256 Integrity Hash</th>
                <th className="py-2.5 px-4 text-start font-semibold">Collected By</th>
                <th className="py-2.5 px-4 text-start font-semibold">{t.common.status}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {evidence.map((ev) => (
                <tr key={ev.id} className="hover:bg-[#F7F9FA]">
                  <td className="py-3 px-4 font-mono font-bold text-[#17212B]">{ev.id}</td>
                  <td className="py-3 px-4 font-mono text-slate-600">{ev.incidentId}</td>
                  <td className="py-3 px-4">
                    <div className="font-semibold text-[#17212B]">{ev.source}</div>
                    <div className="text-[11px] text-slate-500">{ev.evidenceType}</div>
                  </td>
                  <td className="py-3 px-4 font-mono text-[11px] text-slate-700 max-w-[260px] break-all">
                    {ev.sha256Hash}
                  </td>
                  <td className="py-3 px-4 text-slate-600">
                    <div>{ev.collectedBy}</div>
                    <div className="font-mono text-[11px] text-slate-400">{ev.collectedAt.slice(0, 16).replace('T', ' ')}</div>
                  </td>
                  <td className="py-3 px-4 font-semibold text-[#137A3E]">{ev.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Attack Timeline */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 space-y-4">
        <h2 className="text-sm font-semibold text-[#17212B]">{t.forensics.timelineTitle}</h2>
        <form onSubmit={handleAddTimeline} className="flex flex-col sm:flex-row gap-2.5">
          <select
            value={tlIncidentId}
            onChange={(e) => setTlIncidentId(e.target.value)}
            className="px-3 py-2 font-mono text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
          >
            {incidents.map((inc) => (
              <option key={inc.id} value={inc.id}>
                {inc.id}
              </option>
            ))}
          </select>
          <input
            value={tlPhase}
            onChange={(e) => setTlPhase(e.target.value)}
            placeholder="Phase (e.g. Initial Delivery, Containment)"
            className="px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg sm:w-48"
          />
          <input
            required
            value={tlDesc}
            onChange={(e) => setTlDesc(e.target.value)}
            placeholder="Chronological event description..."
            className="flex-1 px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
          />
          <button
            type="submit"
            className="px-4 py-2 bg-[#B7FF00] text-[#17212B] text-xs font-bold rounded-lg whitespace-nowrap"
          >
            {t.forensics.addTimelineBtn}
          </button>
        </form>

        <div className="divide-y divide-slate-100 border border-slate-200 rounded-lg">
          {timeline.map((ev) => (
            <div key={ev.id} className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
              <div className="space-y-0.5">
                <div className="flex items-center gap-2">
                  <span className="font-mono font-bold text-[#17212B]">{ev.incidentId}</span>
                  <span aria-hidden="true">·</span>
                  <span className="font-semibold text-[#007D8C]">{ev.phase}</span>
                  <span aria-hidden="true">·</span>
                  <span className="text-slate-500">{ev.actor}</span>
                </div>
                <p className="text-slate-700">{ev.description}</p>
              </div>
              <span className="font-mono text-[11px] text-slate-400 whitespace-nowrap">
                {ev.timestamp.slice(0, 19).replace('T', ' ')}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
