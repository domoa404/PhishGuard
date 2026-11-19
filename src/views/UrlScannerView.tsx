import { useState } from 'react';
import { Globe, ShieldAlert, AlertTriangle, Info } from 'lucide-react';
import { apiFetch } from '../lib/api.ts';
import { getT } from '../i18n/translations.ts';
import { ClassificationMarker, ScoreBar } from '../components/StatusText.tsx';
import type { Language, NavSection, ScanRecord, UrlAnalysisResult } from '../types/phishguard.ts';

interface Props {
  lang: Language;
  onNavigate: (section: NavSection) => void;
}

export function UrlScannerView({ lang, onNavigate }: Props) {
  const t = getT(lang);
  const [urlInput, setUrlInput] = useState('https://micros0ft-auth-verify.top/oauth2/authorize?redirect=https://evil-drop.xyz');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [feedback, setFeedback] = useState('');
  const [scanRecord, setScanRecord] = useState<ScanRecord | null>(null);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setFeedback('');
    try {
      const record = await apiFetch<ScanRecord>('/api/analyze/url', {
        method: 'POST',
        body: JSON.stringify({ url: urlInput }),
      });
      setScanRecord(record);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'URL scan failed');
    } finally {
      setLoading(false);
    }
  };

  const result = scanRecord?.details as UrlAnalysisResult | undefined;

  const handleAddToIntel = async () => {
    if (!result) return;
    setError('');
    try {
      await apiFetch('/api/threat-intel', {
        method: 'POST',
        body: JSON.stringify({
          indicator: result.hostname,
          iocType: result.isIpBased ? 'IP' : 'Domain',
          category: result.classification,
          reputationScore: result.riskScore,
          notes: `Submitted from URL Scanner (${scanRecord?.id}).`,
        }),
      });
      setFeedback(`Indicator "${result.hostname}" added to Threat Intelligence.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not add IOC');
    }
  };

  const handleCreateIncident = async () => {
    if (!scanRecord || !result) return;
    setError('');
    try {
      const res = await apiFetch<{ id: string }>('/api/incidents', {
        method: 'POST',
        body: JSON.stringify({
          title: `Malicious URL Detected: ${result.hostname}`,
          category: 'Malicious URL',
          severity: scanRecord.severity,
          affectedAsset: 'Secure Web Gateway & End-User Browsers',
          threatSource: result.normalizedUrl,
          riskScore: result.riskScore,
          assignedAnalyst: scanRecord.analyst,
          evidenceSummary: `${result.findings.length} structural/reputation anomalies identified.`,
          linkedScanId: scanRecord.id,
        }),
      });
      setFeedback(`Incident ${res.id} opened and linked to scan ${scanRecord.id}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create incident');
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-[#17212B]">{t.url.title}</h1>
        <p className="text-sm text-slate-500 mt-1">{t.url.subtitle}</p>
      </div>

      {/* Submission Bar */}
      <form onSubmit={handleScan} className="bg-white border border-slate-200 rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => setUrlInput('https://micros0ft-auth-verify.top/oauth2/authorize?redirect=https://evil-drop.xyz')}
            className="px-2.5 py-1.5 text-xs font-medium bg-[#F7F9FA] border border-slate-200 rounded-lg hover:border-slate-300"
          >
            {t.url.samplePhish}
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
            disabled={loading}
            className="px-5 py-2.5 bg-[#B7FF00] text-[#17212B] text-sm font-bold rounded-lg neon-glow-lime hover:brightness-95 transition-all whitespace-nowrap shrink-0"
          >
            {loading ? t.common.loading : t.url.scanBtn}
          </button>
        </div>
        {error && <p className="text-xs font-medium text-[#FF3B5C]">{error}</p>}
      </form>

      {/* Analysis Result */}
      {!result || !scanRecord ? (
        <div className="bg-white border border-slate-200 rounded-xl py-16 text-center space-y-2">
          <Globe className="w-10 h-10 text-slate-300 mx-auto" />
          <p className="text-sm font-semibold text-[#17212B]">{t.url.domainInfo}</p>
          <p className="text-xs text-slate-500">{t.url.subtitle}</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
          {/* Left Structural Breakdown */}
          <div className="lg:col-span-5 bg-white border border-slate-200 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between gap-2 pb-3 border-b border-slate-100">
              <span className="font-mono text-xs text-slate-500">{scanRecord.id}</span>
              <ClassificationMarker
                classification={result.classification}
                label={t.classifications[result.classification]}
              />
            </div>

            <div>
              <div className="text-xs text-slate-500 mb-1">{t.common.score}</div>
              <ScoreBar score={result.riskScore} />
            </div>

            <div className="p-3 bg-[#F7F9FA] rounded-lg space-y-1 text-xs">
              <div className="font-semibold text-[#17212B]">{t.url.sourceBanner}</div>
              <div className="text-slate-600">{result.intelligenceSource}</div>
              <div className="font-mono text-[11px] text-slate-400">{result.checkedAt}</div>
            </div>

            <h2 className="text-xs font-semibold text-[#17212B] pt-2">{t.url.domainInfo}</h2>
            <dl className="divide-y divide-slate-100 text-xs">
              {[
                ['Hostname', result.hostname],
                ['Root Domain', result.domain],
                ['Subdomain', result.subdomain || '—'],
                ['TLD', result.tld ? `.${result.tld}` : '—'],
                ['Protocol / Port', `${result.protocol.toUpperCase()} : ${result.port}`],
                ['HTTPS Enabled', result.isHttps ? 'Yes (TLS)' : 'No (Plaintext HTTP)'],
                ['IP-Based Host', result.isIpBased ? 'Yes' : 'No'],
                ['Punycode / IDN', result.hasPunycode ? 'Detected' : 'None'],
                ['Typosquat Target', result.typosquatTarget || 'None detected'],
                ['URL Length', `${result.urlLength} chars`],
              ].map(([k, v]) => (
                <div key={k} className="py-2 flex items-center justify-between gap-4">
                  <dt className="text-slate-500">{k}</dt>
                  <dd className="font-mono font-medium text-[#17212B] truncate max-w-[210px]">{v}</dd>
                </div>
              ))}
            </dl>

            <div className="flex flex-wrap gap-2 pt-2">
              <button
                type="button"
                onClick={handleCreateIncident}
                className="px-3.5 py-2 bg-[#17212B] text-white text-xs font-semibold rounded-lg hover:bg-slate-800"
              >
                {t.common.createIncident}
              </button>
              <button
                type="button"
                onClick={handleAddToIntel}
                className="px-3.5 py-2 bg-white border border-slate-200 text-[#17212B] text-xs font-semibold rounded-lg hover:border-slate-300"
              >
                {t.intel.addTitle}
              </button>
              <button
                type="button"
                onClick={() => onNavigate('incidents')}
                className="px-3 py-2 text-xs font-semibold text-slate-600 hover:text-[#17212B]"
              >
                {t.nav.incidents}
              </button>
            </div>
            {feedback && (
              <div className="p-2.5 bg-[#39FF88]/15 border border-[#39FF88]/40 rounded-lg text-xs text-[#137A3E]">
                {feedback}
              </div>
            )}
          </div>

          {/* Right Findings & Query Params */}
          <div className="lg:col-span-7 bg-white border border-slate-200 rounded-xl p-5 space-y-5">
            <div>
              <h2 className="text-sm font-semibold text-[#17212B] mb-3">{t.url.findingsTitle}</h2>
              {result.findings.length === 0 ? (
                <p className="text-xs text-[#137A3E] bg-[#39FF88]/15 p-3 rounded-lg">
                  No structural anomalies or phishing signatures identified locally.
                </p>
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
                        <div className="flex items-center gap-2 text-xs font-semibold text-[#17212B]">
                          <Icon className={`w-4 h-4 ${color} shrink-0`} />
                          <span>{lang === 'ar' ? f.titleAr : f.title}</span>
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
              <div className="pt-4 border-t border-slate-100">
                <h3 className="text-xs font-semibold text-[#17212B] mb-2">{t.url.queryTitle}</h3>
                <div className="divide-y divide-slate-100 border border-slate-200 rounded-lg">
                  {result.queryParams.map((q, idx) => (
                    <div key={`${q.key}-${idx}`} className="px-3 py-2 flex items-center justify-between gap-4 text-xs">
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

            <div className="pt-4 border-t border-slate-100">
              <h3 className="text-xs font-semibold text-[#17212B] mb-2">{t.email.recommendations}</h3>
              <ul className="space-y-1.5 text-xs text-slate-600 list-disc list-inside">
                {(lang === 'ar' ? result.recommendedActionsAr : result.recommendedActions).map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
