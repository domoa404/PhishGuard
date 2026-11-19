import { useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { AlertTriangle, Download, Globe, Info, ShieldAlert, ShieldCheck } from 'lucide-react';
import { analyzeUrlClient } from '../engine/phishingAnalyzer.ts';
import { downloadUrlPdfReport } from '../lib/pdfReport.ts';
import { getT } from '../i18n/translations.ts';
import { ClassificationMarker, ScoreBar } from '../components/StatusText.tsx';
import type { Language, UrlAnalysisResult } from '../types/phishguard.ts';

interface Props {
  lang: Language;
  result: UrlAnalysisResult | null;
  onResult: (res: UrlAnalysisResult) => void;
  onSendToRisk: (asset: string, threat: string, score: number) => void;
}

export function UrlScannerTool({ lang, result, onResult, onSendToRisk }: Props) {
  const t = getT(lang);
  const [urlInput, setUrlInput] = useState(
    'https://micros0ft-auth-verify.top/oauth2/authorize?redirect=https://evil-collector.xyz',
  );
  const [error, setError] = useState('');

  const handleScan = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    try {
      const res = analyzeUrlClient(urlInput);
      onResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to parse URL');
    }
  };

  const chartData =
    result?.scoreBreakdown.map((b) => ({
      name: lang === 'ar' ? b.categoryAr : b.category,
      points: b.points,
    })) || [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-[#17212B]">{t.url.title}</h1>
        <p className="text-sm text-slate-500 mt-1 max-w-3xl">{t.url.subtitle}</p>
      </div>

      {/* Input Card */}
      <form onSubmit={handleScan} className="bg-white border border-slate-200 rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() =>
              setUrlInput('https://micros0ft-auth-verify.top/oauth2/authorize?redirect=https://evil-collector.xyz')
            }
            className="px-2.5 py-1.5 text-xs font-medium bg-[#F7F9FA] border border-slate-200 rounded-lg hover:border-slate-300"
          >
            {t.url.sampleLookalike}
          </button>
          <button
            type="button"
            onClick={() => setUrlInput('http://185.220.101.47/owa/login.php')}
            className="px-2.5 py-1.5 text-xs font-medium bg-[#F7F9FA] border border-slate-200 rounded-lg hover:border-slate-300"
          >
            {t.url.sampleIp}
          </button>
          <button
            type="button"
            onClick={() => setUrlInput('https://bit.ly/3xUpdateMfa')}
            className="px-2.5 py-1.5 text-xs font-medium bg-[#F7F9FA] border border-slate-200 rounded-lg hover:border-slate-300"
          >
            {t.url.sampleShortener}
          </button>
          <button
            type="button"
            onClick={() => setUrlInput('https://learn.microsoft.com/en-us/security/zero-trust')}
            className="px-2.5 py-1.5 text-xs font-medium bg-[#F7F9FA] border border-slate-200 rounded-lg hover:border-slate-300"
          >
            {t.url.sampleSafe}
          </button>
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            placeholder={t.url.inputPlaceholder}
            aria-label={t.url.inputLabel}
            className="flex-1 px-3.5 py-2.5 font-mono text-sm bg-[#F7F9FA] border border-slate-200 rounded-lg focus:outline-none focus:border-[#17212B]"
          />
          <button
            type="submit"
            className="px-5 py-2.5 bg-[#B7FF00] text-[#17212B] text-sm font-bold rounded-lg neon-glow-lime hover:brightness-95 transition-all whitespace-nowrap shrink-0"
          >
            {t.url.scanBtn}
          </button>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
          <span>{t.url.safetyNotice}</span>
        </div>
        {error && <p className="text-xs font-medium text-[#FF3B5C]">{error}</p>}
      </form>

      {!result ? (
        <div className="bg-white border border-slate-200 rounded-xl py-16 text-center space-y-2">
          <Globe className="w-10 h-10 text-slate-300 mx-auto" />
          <p className="text-sm font-semibold text-[#17212B]">{t.url.emptyTitle}</p>
          <p className="text-xs text-slate-500 max-w-md mx-auto">{t.url.emptyBody}</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
          {/* Left Structure & Attribution */}
          <div className="lg:col-span-5 bg-white border border-slate-200 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between gap-2 pb-3 border-b border-slate-100">
              <span className="font-mono text-xs font-bold text-[#17212B]">{result.id}</span>
              <ClassificationMarker
                classification={result.classification}
                label={t.classifications[result.classification]}
              />
            </div>

            <div>
              <div className="text-xs text-slate-500 mb-1">{t.common.score}</div>
              <ScoreBar score={result.riskScore} />
            </div>

            {/* Clear Heuristic vs External Intel Distinction */}
            <div className="p-3 bg-[#00E5FF]/10 border border-[#00E5FF]/35 rounded-lg space-y-1 text-xs">
              <div className="font-bold text-[#17212B]">{t.url.intelDistinction}</div>
              <p className="text-slate-700">
                {lang === 'ar' ? result.externalIntelStatusAr : result.externalIntelStatus}
              </p>
            </div>

            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => downloadUrlPdfReport(result)}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-[#B7FF00] text-[#17212B] text-xs font-bold rounded-lg neon-glow-lime"
              >
                <Download className="w-3.5 h-3.5" />
                {t.common.downloadPdf}
              </button>
              <button
                type="button"
                onClick={() =>
                  onSendToRisk(
                    `Web Access (${result.hostname})`,
                    `${result.classification}: ${result.normalizedUrl}`,
                    result.riskScore,
                  )
                }
                className="px-3.5 py-2 bg-[#17212B] text-white text-xs font-semibold rounded-lg"
              >
                {t.common.sendToRisk}
              </button>
            </div>

            <h2 className="text-xs font-semibold text-[#17212B] pt-2">{t.url.structureTitle}</h2>
            <dl className="divide-y divide-slate-100 text-xs">
              {[
                ['Hostname', result.hostname],
                ['Root Domain', result.domain],
                ['Subdomain', result.subdomain || '—'],
                ['TLD', result.tld ? `.${result.tld}` : '—'],
                ['Protocol / Port', `${result.protocol.toUpperCase()} : ${result.port}`],
                ['HTTPS Enabled', result.isHttps ? 'Yes (TLS)' : 'No (HTTP)'],
                ['IP-Based URL', result.isIpBased ? 'Yes' : 'No'],
                ['Typosquat Target', result.typosquatTarget || 'None'],
                ['Punycode / IDN', result.hasPunycode ? 'Detected' : 'None'],
                ['URL Length', `${result.urlLength} chars`],
              ].map(([k, v]) => (
                <div key={k} className="py-2 flex items-center justify-between gap-4">
                  <dt className="text-slate-500">{k}</dt>
                  <dd className="font-mono font-medium text-[#17212B] truncate max-w-[200px]">{v}</dd>
                </div>
              ))}
            </dl>
          </div>

          {/* Right Findings & Chart */}
          <div className="lg:col-span-7 bg-white border border-slate-200 rounded-xl p-5 space-y-5">
            <div className="p-4 bg-[#F7F9FA] rounded-lg space-y-1">
              <div className="text-xs font-bold text-[#17212B]">{t.email.whyTitle}</div>
              <p className="text-sm text-slate-700 leading-relaxed">
                {lang === 'ar' ? result.explanationAr : result.explanation}
              </p>
            </div>

            {chartData.length > 0 && (
              <div className="h-44 w-full" dir="ltr">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={chartData} layout="vertical" margin={{ top: 4, right: 20, left: 10, bottom: 4 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" horizontal={false} />
                    <XAxis type="number" tick={{ fontSize: 11, fill: '#64748B' }} axisLine={false} tickLine={false} />
                    <YAxis
                      type="category"
                      dataKey="name"
                      width={130}
                      tick={{ fontSize: 11, fill: '#17212B' }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Tooltip />
                    <Bar dataKey="points" radius={[0, 6, 6, 0]}>
                      {chartData.map((_, idx) => (
                        <Cell key={idx} fill={idx === 0 ? '#FF3B5C' : idx === 1 ? '#FF9F1C' : '#00E5FF'} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}

            <div>
              <h2 className="text-xs font-semibold text-[#17212B] mb-2.5">{t.url.indicatorsTitle}</h2>
              {result.findings.length === 0 ? (
                <div className="flex items-center gap-2 text-xs text-[#137A3E] p-3 bg-[#39FF88]/15 rounded-lg">
                  <ShieldCheck className="w-4 h-4" />
                  <span>{t.common.noFindings}</span>
                </div>
              ) : (
                <div className="divide-y divide-slate-100 border border-slate-200 rounded-lg">
                  {result.findings.map((f) => {
                    const Icon =
                      f.level === 'confirmed_malicious'
                        ? ShieldAlert
                        : f.level === 'suspicious'
                          ? AlertTriangle
                          : Info;
                    const color =
                      f.level === 'confirmed_malicious'
                        ? 'text-[#FF3B5C]'
                        : f.level === 'suspicious'
                          ? 'text-[#FF9F1C]'
                          : 'text-[#0891B2]';
                    return (
                      <div key={f.id} className="p-3.5 space-y-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="flex items-center gap-2 text-xs font-semibold text-[#17212B]">
                            <Icon className={`w-4 h-4 ${color} shrink-0`} />
                            {lang === 'ar' ? f.titleAr : f.title}
                          </span>
                          <span className="font-mono text-[11px] font-semibold text-slate-500 tabular-nums">
                            +{f.weight} pts
                          </span>
                        </div>
                        <p className="text-xs text-slate-600">{lang === 'ar' ? f.detailAr : f.detail}</p>
                        {f.evidenceSnippet && (
                          <div className="px-2 py-1 bg-[#F7F9FA] rounded font-mono text-[11px] text-[#17212B] break-all">
                            {f.evidenceSnippet}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {result.queryParams.length > 0 && (
              <div className="pt-2 border-t border-slate-100">
                <h3 className="text-xs font-semibold text-[#17212B] mb-2">{t.url.queryTitle}</h3>
                <div className="divide-y divide-slate-100 border border-slate-200 rounded-lg text-xs">
                  {result.queryParams.map((q, idx) => (
                    <div key={idx} className="px-3 py-2 flex items-center justify-between gap-4">
                      <span className="font-mono font-semibold text-[#17212B]">{q.key}</span>
                      <span className="font-mono text-slate-600 truncate max-w-xs">{q.value}</span>
                      <span className={`font-semibold ${q.suspicious ? 'text-[#FF3B5C]' : 'text-slate-400'}`}>
                        {q.suspicious ? 'Suspicious' : 'Standard'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="pt-2 border-t border-slate-100">
              <h3 className="text-xs font-semibold text-[#17212B] mb-2">{t.common.recommendations}</h3>
              <ul className="space-y-1.5 text-xs text-slate-700 list-disc list-inside">
                {(lang === 'ar' ? result.recommendedActionsAr : result.recommendedActions).map((act, i) => (
                  <li key={i}>{act}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
