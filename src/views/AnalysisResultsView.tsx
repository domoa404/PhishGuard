import { Download, Printer, Trash2 } from 'lucide-react';
import {
  downloadCombinedPdfReport,
  downloadEmailPdfReport,
  downloadUrlPdfReport,
} from '../lib/pdfReport.ts';
import { getT } from '../i18n/translations.ts';
import { ClassificationMarker, ScoreBar, SeverityMarker } from '../components/StatusText.tsx';
import type {
  EmailAnalysisResult,
  Language,
  RiskAssessmentResult,
  UrlAnalysisResult,
} from '../types/phishguard.ts';

interface Props {
  lang: Language;
  emailResult: EmailAnalysisResult | null;
  urlResult: UrlAnalysisResult | null;
  riskResult: RiskAssessmentResult | null;
  onClearSession: () => void;
}

export function AnalysisResultsView({
  lang,
  emailResult,
  urlResult,
  riskResult,
  onClearSession,
}: Props) {
  const t = getT(lang);
  const hasAny = Boolean(emailResult || urlResult || riskResult);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 no-print">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#17212B]">{t.results.title}</h1>
          <p className="text-sm text-slate-500 mt-1 max-w-3xl">{t.results.subtitle}</p>
        </div>

        {hasAny && (
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => downloadCombinedPdfReport(emailResult, urlResult, riskResult)}
              className="inline-flex items-center gap-1.5 px-4 py-2 bg-[#B7FF00] text-[#17212B] text-xs font-bold rounded-lg neon-glow-lime"
            >
              <Download className="w-3.5 h-3.5" />
              {t.results.downloadCombined}
            </button>
            <button
              type="button"
              onClick={() => window.print()}
              className="inline-flex items-center gap-1.5 px-4 py-2 bg-[#17212B] text-white text-xs font-semibold rounded-lg"
            >
              <Printer className="w-3.5 h-3.5" />
              {t.common.printReport}
            </button>
            <button
              type="button"
              onClick={onClearSession}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-slate-200 text-[#FF3B5C] text-xs font-semibold rounded-lg hover:border-[#FF3B5C]/40"
            >
              <Trash2 className="w-3.5 h-3.5" />
              {t.common.clearSession}
            </button>
          </div>
        )}
      </div>

      {!hasAny ? (
        <div className="bg-white border border-slate-200 rounded-xl py-16 text-center text-sm text-slate-500">
          {t.results.emptySession}
        </div>
      ) : (
        <div className="space-y-5">
          {/* Email Summary Card */}
          {emailResult && (
            <div className="bg-white border border-slate-200 rounded-xl p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
                <div>
                  <div className="text-xs font-mono text-slate-500">
                    {t.results.latestEmail} · {emailResult.id}
                  </div>
                  <h2 className="text-base font-bold text-[#17212B] mt-0.5">{emailResult.subject}</h2>
                  <div className="text-xs font-mono text-slate-500 mt-0.5">{emailResult.senderEmail}</div>
                </div>
                <div className="flex flex-wrap items-center gap-3 shrink-0">
                  <ClassificationMarker
                    classification={emailResult.classification}
                    label={t.classifications[emailResult.classification]}
                  />
                  <button
                    type="button"
                    onClick={() => downloadEmailPdfReport(emailResult)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#F7F9FA] border border-slate-200 text-xs font-semibold rounded-lg hover:border-slate-300 no-print"
                  >
                    <Download className="w-3.5 h-3.5" />
                    {t.common.downloadPdf}
                  </button>
                </div>
              </div>

              <ScoreBar score={emailResult.riskScore} />
              <p className="text-xs text-slate-700 leading-relaxed">
                {lang === 'ar' ? emailResult.explanationAr : emailResult.explanation}
              </p>

              {emailResult.findings.length > 0 && (
                <div className="divide-y divide-slate-100 border border-slate-200 rounded-lg text-xs">
                  {emailResult.findings.map((f) => (
                    <div key={f.id} className="p-2.5 flex items-center justify-between gap-3">
                      <span className="font-medium text-[#17212B]">{lang === 'ar' ? f.titleAr : f.title}</span>
                      <span className="font-mono text-slate-500 shrink-0">+{f.weight} pts</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* URL Summary Card */}
          {urlResult && (
            <div className="bg-white border border-slate-200 rounded-xl p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
                <div className="min-w-0">
                  <div className="text-xs font-mono text-slate-500">
                    {t.results.latestUrl} · {urlResult.id}
                  </div>
                  <h2 className="text-sm font-mono font-bold text-[#17212B] mt-0.5 break-all">
                    {urlResult.normalizedUrl}
                  </h2>
                </div>
                <div className="flex flex-wrap items-center gap-3 shrink-0">
                  <ClassificationMarker
                    classification={urlResult.classification}
                    label={t.classifications[urlResult.classification]}
                  />
                  <button
                    type="button"
                    onClick={() => downloadUrlPdfReport(urlResult)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#F7F9FA] border border-slate-200 text-xs font-semibold rounded-lg hover:border-slate-300 no-print"
                  >
                    <Download className="w-3.5 h-3.5" />
                    {t.common.downloadPdf}
                  </button>
                </div>
              </div>

              <ScoreBar score={urlResult.riskScore} />
              <p className="text-xs text-slate-700 leading-relaxed">
                {lang === 'ar' ? urlResult.explanationAr : urlResult.explanation}
              </p>
              <p className="text-[11px] font-medium text-[#007D8C]">
                {lang === 'ar' ? urlResult.externalIntelStatusAr : urlResult.externalIntelStatus}
              </p>
            </div>
          )}

          {/* Risk Summary Card */}
          {riskResult && (
            <div className="bg-white border border-slate-200 rounded-xl p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
                <div>
                  <div className="text-xs font-mono text-slate-500">
                    {t.results.latestRisk} · {riskResult.id}
                  </div>
                  <h2 className="text-base font-bold text-[#17212B] mt-0.5">{riskResult.assetName}</h2>
                  <div className="text-xs text-slate-500">{riskResult.threatScenario}</div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <SeverityMarker
                    severity={riskResult.inherentLevel}
                    label={`${t.risk.inherent}: ${riskResult.inherentScore}/25`}
                  />
                  <SeverityMarker
                    severity={riskResult.residualLevel}
                    label={`${t.risk.residual}: ${riskResult.residualScore}/25`}
                  />
                </div>
              </div>

              <ul className="space-y-1 text-xs text-slate-700 list-disc list-inside">
                {(lang === 'ar' ? riskResult.recommendationsAr : riskResult.recommendationsEn).map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
