import { useEffect, useState } from 'react';
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { Download, FileSpreadsheet, Printer } from 'lucide-react';
import { apiFetch } from '../lib/api.ts';
import { getT } from '../i18n/translations.ts';
import { ClassificationMarker, SeverityMarker } from '../components/StatusText.tsx';
import type {
  DashboardSummary,
  EvidenceRecord,
  IncidentRecord,
  Language,
  RiskRecord,
  ScanRecord,
  ThreatIntelRecord,
  TimelineEventRecord,
} from '../types/phishguard.ts';

interface ReportBundle {
  generatedAt: string;
  dashboard: DashboardSummary;
  scans: ScanRecord[];
  incidents: IncidentRecord[];
  risks: RiskRecord[];
  threatIntel: ThreatIntelRecord[];
  evidence: EvidenceRecord[];
  timeline: TimelineEventRecord[];
}

export function ReportsView({ lang }: { lang: Language }) {
  const t = getT(lang);
  const [bundle, setBundle] = useState<ReportBundle | null>(null);
  const [scope, setScope] = useState<'full' | string>('full');

  useEffect(() => {
    apiFetch<ReportBundle>('/api/reports/summary').then(setBundle);
  }, []);

  if (!bundle) {
    return <div className="p-8 text-sm text-slate-500">{t.common.loading}</div>;
  }

  const selectedIncident = scope === 'full' ? null : bundle.incidents.find((i) => i.id === scope) || null;
  const emailScans = bundle.scans.filter((s) => s.analysisType === 'email');
  const urlScans = bundle.scans.filter((s) => s.analysisType === 'url');
  const relevantTimeline = selectedIncident
    ? bundle.timeline.filter((ev) => ev.incidentId === selectedIncident.id)
    : bundle.timeline;

  const handleExportPdf = () => {
    const doc = new jsPDF({ orientation: 'portrait', unit: 'pt', format: 'a4' });
    doc.setFontSize(16);
    doc.text('PhishGuard Security & Incident Response Report', 40, 48);
    doc.setFontSize(9);
    doc.text(`Generated: ${bundle.generatedAt} | Scope: ${selectedIncident ? selectedIncident.id : 'Full Platform'}`, 40, 66);

    autoTable(doc, {
      startY: 84,
      head: [['Metric', 'Value']],
      body: [
        ['Total Emails Analyzed', String(bundle.dashboard.metrics.totalEmailsAnalyzed)],
        ['Phishing Emails Detected', String(bundle.dashboard.metrics.phishingEmailsDetected)],
        ['Malicious URLs Identified', String(bundle.dashboard.metrics.maliciousUrlsIdentified)],
        ['Active Security Incidents', String(bundle.dashboard.metrics.activeSecurityIncidents)],
        ['Critical Risk Events', String(bundle.dashboard.metrics.criticalRiskEvents)],
        ['Resolved Incidents', String(bundle.dashboard.metrics.resolvedIncidents)],
      ],
      headStyles: { fillColor: [23, 33, 43] },
    });

    const afterMetricsY = (doc as unknown as { lastAutoTable?: { finalY: number } }).lastAutoTable?.finalY || 220;

    autoTable(doc, {
      startY: afterMetricsY + 18,
      head: [['Incident ID', 'Title', 'Severity', 'NIST Stage', 'Status', 'Score']],
      body: (selectedIncident ? [selectedIncident] : bundle.incidents).map((i) => [
        i.id,
        i.title,
        i.severity,
        i.nistStage,
        i.status,
        `${i.riskScore}/100`,
      ]),
      headStyles: { fillColor: [23, 33, 43] },
    });

    const afterIncY = (doc as unknown as { lastAutoTable?: { finalY: number } }).lastAutoTable?.finalY || 380;

    autoTable(doc, {
      startY: afterIncY + 18,
      head: [['Risk ID', 'Asset', 'Inherent', 'Residual', 'Strategy', 'Status']],
      body: bundle.risks.map((r) => [
        r.id,
        r.assetAffected,
        `${r.inherentRisk} (${r.inherentLevel})`,
        `${r.residualRisk} (${r.residualLevel})`,
        r.treatmentStrategy,
        r.treatmentStatus,
      ]),
      headStyles: { fillColor: [23, 33, 43] },
    });

    doc.save(`PhishGuard_Report_${selectedIncident ? selectedIncident.id : 'Full'}_${new Date().toISOString().slice(0, 10)}.pdf`);
  };

  const handleExportCsv = () => {
    const rows = [
      ['RecordType', 'ID', 'Summary', 'Severity/Level', 'Score', 'Status/Classification', 'Timestamp'],
      ...bundle.scans.map((s) => [
        `SCAN_${s.analysisType.toUpperCase()}`,
        s.id,
        s.submittedObject,
        s.severity,
        String(s.riskScore),
        s.classification,
        s.createdAt,
      ]),
      ...bundle.incidents.map((i) => [
        'INCIDENT',
        i.id,
        i.title,
        i.severity,
        String(i.riskScore),
        `${i.status} (${i.nistStage})`,
        i.detectedAt,
      ]),
      ...bundle.risks.map((r) => [
        'RISK',
        r.id,
        `${r.assetAffected} - ${r.threatDescription}`,
        r.inherentLevel,
        `${r.inherentRisk}/25 (Res ${r.residualRisk}/25)`,
        `${r.treatmentStrategy} (${r.treatmentStatus})`,
        r.updatedAt,
      ]),
    ];

    const csv = '\uFEFF' + rows.map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `PhishGuard_Export_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 no-print">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#17212B]">{t.reports.title}</h1>
          <p className="text-sm text-slate-500 mt-1">{t.reports.subtitle}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <select
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            aria-label={t.reports.scopeLabel}
            className="px-3 py-2 text-xs bg-white border border-slate-200 rounded-lg font-medium"
          >
            <option value="full">{t.reports.fullPlatform}</option>
            {bundle.incidents.map((inc) => (
              <option key={inc.id} value={inc.id}>
                {inc.id} — {inc.title.slice(0, 34)}
              </option>
            ))}
          </select>
          <button
            type="button"
            onClick={handleExportPdf}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-[#B7FF00] text-[#17212B] text-xs font-bold rounded-lg neon-glow-lime"
          >
            <Download className="w-3.5 h-3.5" />
            {t.common.exportPdf}
          </button>
          <button
            type="button"
            onClick={handleExportCsv}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-slate-200 text-[#17212B] text-xs font-semibold rounded-lg"
          >
            <FileSpreadsheet className="w-3.5 h-3.5" />
            {t.common.exportCsv}
          </button>
          <button
            type="button"
            onClick={() => window.print()}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-[#17212B] text-white text-xs font-semibold rounded-lg"
          >
            <Printer className="w-3.5 h-3.5" />
            {t.common.printReport}
          </button>
        </div>
      </div>

      {/* Printable / Preview Report Document */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 sm:p-8 space-y-8">
        <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 pb-5 border-b border-slate-200">
          <div>
            <div className="text-xs font-mono text-slate-500">PhishGuard · Risk Management & Incident Response</div>
            <h2 className="text-xl font-bold text-[#17212B] mt-1">
              {selectedIncident ? `${selectedIncident.id}: ${selectedIncident.title}` : t.reports.fullPlatform}
            </h2>
          </div>
          <div className="font-mono text-xs text-slate-500">
            {bundle.generatedAt.slice(0, 19).replace('T', ' ')} UTC
          </div>
        </div>

        {/* Executive Summary */}
        <section className="space-y-3">
          <h3 className="text-sm font-bold text-[#17212B]">{t.reports.executiveSummary}</h3>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            {[
              [t.dashboard.kpiTotalEmails, bundle.dashboard.metrics.totalEmailsAnalyzed],
              [t.dashboard.kpiPhishingEmails, bundle.dashboard.metrics.phishingEmailsDetected],
              [t.dashboard.kpiMaliciousUrls, bundle.dashboard.metrics.maliciousUrlsIdentified],
              [t.dashboard.kpiActiveIncidents, bundle.dashboard.metrics.activeSecurityIncidents],
              [t.dashboard.kpiCriticalRisks, bundle.dashboard.metrics.criticalRiskEvents],
              [t.dashboard.kpiResolvedIncidents, bundle.dashboard.metrics.resolvedIncidents],
            ].map(([label, val]) => (
              <div key={String(label)} className="p-3 bg-[#F7F9FA] rounded-lg">
                <div className="text-[11px] text-slate-500">{label}</div>
                <div className="text-xl font-mono font-bold text-[#17212B] mt-1 tabular-nums">{val}</div>
              </div>
            ))}
          </div>
        </section>

        {/* Email & URL Findings */}
        <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="space-y-2">
            <h3 className="text-sm font-bold text-[#17212B]">{t.reports.emailFindings}</h3>
            <div className="divide-y divide-slate-100 border border-slate-200 rounded-lg text-xs">
              {emailScans.slice(0, 5).map((s) => (
                <div key={s.id} className="p-3 flex items-center justify-between gap-3">
                  <div className="truncate">
                    <span className="font-mono font-semibold text-[#17212B] me-2">{s.id}</span>
                    <span className="text-slate-700">{s.submittedObject}</span>
                  </div>
                  <ClassificationMarker classification={s.classification} label={t.classifications[s.classification]} />
                </div>
              ))}
            </div>
          </div>
          <div className="space-y-2">
            <h3 className="text-sm font-bold text-[#17212B]">{t.reports.urlFindings}</h3>
            <div className="divide-y divide-slate-100 border border-slate-200 rounded-lg text-xs">
              {urlScans.slice(0, 5).map((s) => (
                <div key={s.id} className="p-3 flex items-center justify-between gap-3">
                  <div className="truncate font-mono">
                    <span className="font-semibold text-[#17212B] me-2">{s.id}</span>
                    <span className="text-slate-600">{s.submittedObject}</span>
                  </div>
                  <ClassificationMarker classification={s.classification} label={t.classifications[s.classification]} />
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Incident Summary & Timeline */}
        <section className="space-y-3">
          <h3 className="text-sm font-bold text-[#17212B]">{t.reports.incidentSummary}</h3>
          <div className="overflow-x-auto border border-slate-200 rounded-lg">
            <table className="w-full text-start border-collapse text-xs">
              <thead>
                <tr className="bg-[#F7F9FA] border-b border-slate-200 text-slate-500">
                  <th className="py-2 px-3 text-start">ID</th>
                  <th className="py-2 px-3 text-start">Incident</th>
                  <th className="py-2 px-3 text-start">{t.common.severity}</th>
                  <th className="py-2 px-3 text-start">NIST Stage</th>
                  <th className="py-2 px-3 text-start">{t.common.status}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {(selectedIncident ? [selectedIncident] : bundle.incidents).map((i) => (
                  <tr key={i.id}>
                    <td className="py-2.5 px-3 font-mono font-semibold">{i.id}</td>
                    <td className="py-2.5 px-3 text-[#17212B]">{i.title}</td>
                    <td className="py-2.5 px-3">
                      <SeverityMarker severity={i.severity} label={t.severities[i.severity]} />
                    </td>
                    <td className="py-2.5 px-3">{i.nistStage}</td>
                    <td className="py-2.5 px-3 font-semibold">{i.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {relevantTimeline.length > 0 && (
            <div className="divide-y divide-slate-100 border border-slate-200 rounded-lg text-xs">
              {relevantTimeline.map((ev) => (
                <div key={ev.id} className="p-2.5 flex items-center justify-between gap-4">
                  <div>
                    <span className="font-mono font-bold me-2">{ev.incidentId}</span>
                    <span className="font-semibold text-[#007D8C] me-2">{ev.phase}</span>
                    <span className="text-slate-700">{ev.description}</span>
                  </div>
                  <span className="font-mono text-[11px] text-slate-400 whitespace-nowrap">
                    {ev.timestamp.slice(0, 16).replace('T', ' ')}
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Risk & Recommendations */}
        <section className="space-y-3">
          <h3 className="text-sm font-bold text-[#17212B]">{t.reports.riskSummary}</h3>
          <div className="divide-y divide-slate-100 border border-slate-200 rounded-lg text-xs">
            {bundle.risks.map((r) => (
              <div key={r.id} className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <span className="font-mono font-bold me-2">{r.id}</span>
                  <span className="font-semibold text-[#17212B]">{r.assetAffected}</span>
                  <div className="text-slate-600 mt-0.5">{r.recommendations}</div>
                </div>
                <div className="font-mono font-semibold whitespace-nowrap">
                  {r.inherentRisk} → {r.residualRisk}/25 ({r.treatmentStrategy})
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
