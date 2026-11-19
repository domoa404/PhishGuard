import { useState } from 'react';
import { FileUp, MailCheck, ShieldAlert, ShieldCheck, AlertTriangle, Info, ArrowRight } from 'lucide-react';
import { apiFetch } from '../lib/api.ts';
import { getT } from '../i18n/translations.ts';
import { ClassificationMarker, ScoreBar, SeverityMarker } from '../components/StatusText.tsx';
import type { Language, NavSection, ScanRecord, EmailAnalysisResult } from '../types/phishguard.ts';

interface Props {
  lang: Language;
  onNavigate: (section: NavSection) => void;
  onOpenIncidentModal?: (prefill: {
    title: string;
    category: string;
    severity: 'Low' | 'Medium' | 'High' | 'Critical';
    affectedAsset: string;
    threatSource: string;
    riskScore: number;
    evidenceSummary: string;
    linkedScanId: string;
  }) => void;
}

const SAMPLE_PHISH_RAW = `From: "Microsoft 365 Account Team" <security@micros0ft-auth-verify.top>
Reply-To: verify-recovery@proton.me
To: finance-director@enterprise.local
Subject: URGENT: Your Microsoft 365 Mailbox Will Be Suspended Within 24 Hours
Authentication-Results: spf=fail smtp.mailfrom=micros0ft-auth-verify.top; dkim=fail; dmarc=fail
Received: from relay9.micros0ft-auth-verify.top (185.220.101.47) by mx1.enterprise.local
Content-Disposition: attachment; filename="Security_Verification_Form.pdf.exe"

Dear User,
Unusual sign-in activity was detected on your account. Immediate action required within 24 hours to avoid permanent deactivation.
Verify your password and MFA settings immediately:
https://micros0ft-auth-verify.top/oauth/login?redirect=https://capture.top/m365`;

const SAMPLE_BEC_RAW = `From: "Chief Executive Officer" <ceo.desk.urgent@gmail.com>
Reply-To: wire-approvals@yandex.com
To: accounts-payable@enterprise.local
Subject: Confidential Wire Transfer - Immediate Vendor Settlement
Authentication-Results: spf=pass; dkim=pass; dmarc=none

I am currently in an executive board session and unreachable by phone. Please arrange an urgent confidential payment of $42,500 for our acquisition vendor today. Reply directly to confirm bank details.`;

const SAMPLE_CLEAN_RAW = `From: "Enterprise IT Security" <security-awareness@enterprise.local>
To: all-employees@enterprise.local
Subject: Monthly Phishing Awareness Briefing Schedule
Authentication-Results: spf=pass; dkim=pass; dmarc=pass
Received: from internal-smtp.enterprise.local (10.10.2.20) by mx1.enterprise.local

Hello everyone,
Our monthly security awareness workshop takes place Thursday at 10:00 AM. You can review the slide deck on our internal portal: https://learn.microsoft.com/en-us/security/`;

export function EmailAnalysisView({ lang, onNavigate }: Props) {
  const t = getT(lang);
  const [mode, setMode] = useState<'raw' | 'structured'>('raw');
  const [rawEmail, setRawEmail] = useState(SAMPLE_PHISH_RAW);
  const [uploadedFilename, setUploadedFilename] = useState('');

  // Structured fields
  const [senderDisplayName, setSenderDisplayName] = useState('');
  const [senderEmail, setSenderEmail] = useState('');
  const [replyTo, setReplyTo] = useState('');
  const [subject, setSubject] = useState('');
  const [headersText, setHeadersText] = useState('');
  const [attachmentsInput, setAttachmentsInput] = useState('');
  const [body, setBody] = useState('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [feedback, setFeedback] = useState('');
  const [scanResult, setScanResult] = useState<ScanRecord | null>(null);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    setError('');
    const file = e.target.files?.[0];
    if (!file) return;
    if (!/\.(eml|txt)$/i.test(file.name)) {
      setError('Only .eml and .txt files are allowed for static inspection.');
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      setError('File exceeds 2 MB maximum limit.');
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setRawEmail(String(reader.result || ''));
      setUploadedFilename(file.name);
      setMode('raw');
    };
    reader.readAsText(file);
  };

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setFeedback('');
    try {
      const payload =
        mode === 'raw'
          ? { rawEmail, filename: uploadedFilename || undefined }
          : {
              senderDisplayName,
              senderEmail,
              replyTo,
              subject,
              headersText,
              body,
              attachmentNames: attachmentsInput
                .split(',')
                .map((s) => s.trim())
                .filter(Boolean),
            };
      const record = await apiFetch<ScanRecord>('/api/analyze/email', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      setScanResult(record);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateIncident = async () => {
    if (!scanResult) return;
    const details = scanResult.details as EmailAnalysisResult;
    setError('');
    try {
      const res = await apiFetch<{ id: string }>('/api/incidents', {
        method: 'POST',
        body: JSON.stringify({
          title: `Phishing Alert: ${details.subject}`,
          category: 'Email Phishing',
          severity: scanResult.severity,
          affectedAsset: 'Corporate Email Gateway & Recipients',
          threatSource: details.senderEmail,
          riskScore: scanResult.riskScore,
          assignedAnalyst: scanResult.analyst,
          evidenceSummary: details.explanation,
          linkedScanId: scanResult.id,
        }),
      });
      setFeedback(`Incident ${res.id} created and linked to scan ${scanResult.id}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to create incident');
    }
  };

  const handlePreserveForensics = async () => {
    if (!scanResult) return;
    const details = scanResult.details as EmailAnalysisResult;
    setError('');
    try {
      const res = await apiFetch<{ id: string; sha256Hash: string }>('/api/forensics/evidence', {
        method: 'POST',
        body: JSON.stringify({
          incidentId: scanResult.incidentId || 'INC-2026-001',
          source: `Email Scan ${scanResult.id}`,
          evidenceType: 'Raw EML',
          contentPreview: `Subject: ${details.subject}\nFrom: ${details.senderEmail}\nReply-To: ${details.replyTo}\n\n${details.sanitizedBodyPreview}`,
          status: 'Verified',
        }),
      });
      setFeedback(`Evidence ${res.id} sealed with SHA-256 ${res.sha256Hash.slice(0, 16)}...`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to seal evidence');
    }
  };

  const details = scanResult?.details as EmailAnalysisResult | undefined;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-[#17212B]">{t.email.title}</h1>
        <p className="text-sm text-slate-500 mt-1">{t.email.subtitle}</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Input Column */}
        <form onSubmit={handleAnalyze} className="lg:col-span-5 bg-white border border-slate-200 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-1 p-1 bg-[#F7F9FA] border border-slate-200 rounded-lg">
            <button
              type="button"
              onClick={() => setMode('raw')}
              className={`flex-1 py-1.5 px-3 text-xs font-semibold rounded-md transition-colors ${
                mode === 'raw' ? 'bg-white text-[#17212B] shadow-xs' : 'text-slate-600'
              }`}
            >
              {t.email.modeRaw}
            </button>
            <button
              type="button"
              onClick={() => setMode('structured')}
              className={`flex-1 py-1.5 px-3 text-xs font-semibold rounded-md transition-colors ${
                mode === 'structured' ? 'bg-white text-[#17212B] shadow-xs' : 'text-slate-600'
              }`}
            >
              {t.email.modeStructured}
            </button>
          </div>

          {mode === 'raw' ? (
            <>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setRawEmail(SAMPLE_PHISH_RAW);
                    setUploadedFilename('');
                  }}
                  className="px-2.5 py-1.5 text-xs font-medium bg-[#F7F9FA] border border-slate-200 rounded-lg hover:border-slate-300 text-[#17212B]"
                >
                  {t.email.loadSamplePhish}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setRawEmail(SAMPLE_BEC_RAW);
                    setUploadedFilename('');
                  }}
                  className="px-2.5 py-1.5 text-xs font-medium bg-[#F7F9FA] border border-slate-200 rounded-lg hover:border-slate-300 text-[#17212B]"
                >
                  {t.email.loadSampleBec}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setRawEmail(SAMPLE_CLEAN_RAW);
                    setUploadedFilename('');
                  }}
                  className="px-2.5 py-1.5 text-xs font-medium bg-[#F7F9FA] border border-slate-200 rounded-lg hover:border-slate-300 text-[#17212B]"
                >
                  {t.email.loadSampleClean}
                </button>
              </div>

              <label className="flex items-center justify-between gap-3 p-3 border border-dashed border-slate-300 rounded-lg bg-[#F7F9FA] cursor-pointer hover:border-[#17212B] transition-colors">
                <span className="flex items-center gap-2 text-xs font-medium text-slate-700">
                  <FileUp className="w-4 h-4 text-[#17212B]" />
                  {uploadedFilename || t.email.uploadLabel}
                </span>
                <input
                  type="file"
                  accept=".eml,.txt,text/plain,message/rfc822"
                  onChange={handleFileUpload}
                  className="sr-only"
                />
              </label>

              <textarea
                value={rawEmail}
                onChange={(e) => setRawEmail(e.target.value)}
                rows={13}
                placeholder={t.email.rawPlaceholder}
                className="w-full p-3 font-mono text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg focus:outline-none focus:border-[#17212B]"
              />
            </>
          ) : (
            <div className="space-y-3">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">{t.email.senderName}</label>
                  <input
                    type="text"
                    value={senderDisplayName}
                    onChange={(e) => setSenderDisplayName(e.target.value)}
                    placeholder="Microsoft Security"
                    className="w-full px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg focus:outline-none focus:border-[#17212B]"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">{t.email.senderEmail}</label>
                  <input
                    type="email"
                    value={senderEmail}
                    onChange={(e) => setSenderEmail(e.target.value)}
                    placeholder="alerts@micros0ft-auth.top"
                    className="w-full px-3 py-2 text-xs font-mono bg-[#F7F9FA] border border-slate-200 rounded-lg focus:outline-none focus:border-[#17212B]"
                  />
                </div>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">{t.email.replyTo}</label>
                  <input
                    type="text"
                    value={replyTo}
                    onChange={(e) => setReplyTo(e.target.value)}
                    placeholder="reply@external-drop.xyz"
                    className="w-full px-3 py-2 text-xs font-mono bg-[#F7F9FA] border border-slate-200 rounded-lg focus:outline-none focus:border-[#17212B]"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">{t.email.attachmentsLabel}</label>
                  <input
                    type="text"
                    value={attachmentsInput}
                    onChange={(e) => setAttachmentsInput(e.target.value)}
                    placeholder="invoice.pdf.exe, form.html"
                    className="w-full px-3 py-2 text-xs font-mono bg-[#F7F9FA] border border-slate-200 rounded-lg focus:outline-none focus:border-[#17212B]"
                  />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">{t.email.subject}</label>
                <input
                  type="text"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  placeholder="URGENT: Verify Account Within 24 Hours"
                  className="w-full px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg focus:outline-none focus:border-[#17212B]"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">{t.email.headersOptional}</label>
                <textarea
                  value={headersText}
                  onChange={(e) => setHeadersText(e.target.value)}
                  rows={3}
                  placeholder="Authentication-Results: spf=fail; dkim=fail; dmarc=fail"
                  className="w-full p-2.5 font-mono text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg focus:outline-none focus:border-[#17212B]"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">{t.email.bodyLabel}</label>
                <textarea
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  rows={5}
                  placeholder="Paste email message text and any embedded links..."
                  className="w-full p-2.5 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg focus:outline-none focus:border-[#17212B]"
                />
              </div>
            </div>
          )}

          {error && <p className="text-xs font-medium text-[#FF3B5C]">{error}</p>}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 px-4 bg-[#B7FF00] text-[#17212B] text-sm font-bold rounded-lg neon-glow-lime hover:brightness-95 transition-all disabled:opacity-60"
          >
            {loading ? t.email.analyzing : t.email.analyzeBtn}
          </button>
        </form>

        {/* Results Column */}
        <div className="lg:col-span-7 bg-white border border-slate-200 rounded-xl p-5">
          {!details || !scanResult ? (
            <div className="py-20 text-center space-y-2">
              <MailCheck className="w-10 h-10 text-slate-300 mx-auto" />
              <p className="text-sm font-semibold text-[#17212B]">{t.email.resultHeading}</p>
              <p className="text-xs text-slate-500 max-w-md mx-auto">{t.email.subtitle}</p>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Summary Header */}
              <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4 pb-5 border-b border-slate-100">
                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
                    <span className="font-mono font-semibold text-[#17212B]">{scanResult.id}</span>
                    <span aria-hidden="true">·</span>
                    <span>{details.analysisMode}</span>
                  </div>
                  <h2 className="text-lg font-bold text-[#17212B]">{details.subject}</h2>
                  <p className="text-xs font-mono text-slate-600">
                    From: {details.senderDisplayName ? `"${details.senderDisplayName}" ` : ''}
                    &lt;{details.senderEmail}&gt;
                    {details.replyTo ? ` · Reply-To: ${details.replyTo}` : ''}
                  </p>
                </div>
                <div className="flex flex-col sm:items-end gap-2 shrink-0">
                  <ClassificationMarker
                    classification={details.classification}
                    label={t.classifications[details.classification]}
                  />
                  <div className="flex items-center gap-4 text-xs">
                    <span className="text-slate-500">
                      {t.common.score}:{' '}
                      <strong className="font-mono text-[#17212B] tabular-nums">{details.riskScore}/100</strong>
                    </span>
                    <span className="text-slate-500">
                      {t.common.confidence}:{' '}
                      <strong className="font-mono text-[#17212B] tabular-nums">{details.confidence}%</strong>
                    </span>
                  </div>
                </div>
              </div>

              <ScoreBar score={details.riskScore} />

              {/* Explanation */}
              <div className="p-4 bg-[#F7F9FA] rounded-lg space-y-2">
                <p className="text-sm text-[#17212B] leading-relaxed">
                  {lang === 'ar' ? details.explanationAr : details.explanation}
                </p>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap items-center gap-3">
                <button
                  type="button"
                  onClick={handleCreateIncident}
                  className="px-4 py-2 bg-[#17212B] text-white text-xs font-semibold rounded-lg hover:bg-slate-800 transition-colors"
                >
                  {t.common.createIncident}
                </button>
                <button
                  type="button"
                  onClick={handlePreserveForensics}
                  className="px-4 py-2 bg-white border border-slate-200 text-[#17212B] text-xs font-semibold rounded-lg hover:border-slate-300 transition-colors"
                >
                  {t.email.sendToForensics}
                </button>
                <button
                  type="button"
                  onClick={() => onNavigate('incidents')}
                  className="inline-flex items-center gap-1 px-3 py-2 text-xs font-semibold text-slate-600 hover:text-[#17212B]"
                >
                  {t.nav.incidents}
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>

              {feedback && (
                <div className="p-3 bg-[#39FF88]/15 border border-[#39FF88]/40 rounded-lg text-xs font-medium text-[#137A3E]">
                  {feedback}
                </div>
              )}

              {/* SPF / DKIM / DMARC Telemetry */}
              <div className="pt-4 border-t border-slate-100 space-y-2">
                <h3 className="text-xs font-semibold text-[#17212B]">{t.email.authHeading}</h3>
                <div className="grid grid-cols-3 gap-3">
                  {(['spf', 'dkim', 'dmarc'] as const).map((proto) => {
                    const val = details.auth[proto];
                    const style =
                      val === 'pass'
                        ? 'text-[#137A3E] bg-[#39FF88]/15 border-[#39FF88]/40'
                        : val === 'fail' || val === 'softfail'
                          ? 'text-[#FF3B5C] bg-[#FF3B5C]/10 border-[#FF3B5C]/30'
                          : 'text-slate-600 bg-[#F7F9FA] border-slate-200';
                    return (
                      <div key={proto} className={`p-2.5 rounded-lg border text-xs flex items-center justify-between ${style}`}>
                        <span className="font-mono font-bold uppercase">{proto}</span>
                        <span className="font-mono font-semibold">{val}</span>
                      </div>
                    );
                  })}
                </div>
                <p className="text-xs text-slate-500">
                  {lang === 'ar' ? details.auth.noteAr : details.auth.note}
                </p>
              </div>

              {/* Findings Breakdown (Distinguishing Confirmed Malicious vs Suspicious) */}
              <div className="pt-4 border-t border-slate-100 space-y-3">
                {(['confirmed_malicious', 'suspicious', 'informational'] as const).map((lvl) => {
                  const items = details.findings.filter((f) => f.level === lvl);
                  if (items.length === 0) return null;
                  const heading =
                    lvl === 'confirmed_malicious'
                      ? t.email.confirmedMalicious
                      : lvl === 'suspicious'
                        ? t.email.suspiciousIndicators
                        : t.email.informationalNotes;
                  const Icon = lvl === 'confirmed_malicious' ? ShieldAlert : lvl === 'suspicious' ? AlertTriangle : Info;
                  const iconColor =
                    lvl === 'confirmed_malicious'
                      ? 'text-[#FF3B5C]'
                      : lvl === 'suspicious'
                        ? 'text-[#FF9F1C]'
                        : 'text-[#0891B2]';

                  return (
                    <div key={lvl} className="space-y-2">
                      <h3 className="text-xs font-semibold text-[#17212B] flex items-center gap-1.5">
                        <Icon className={`w-3.5 h-3.5 ${iconColor}`} />
                        {heading} ({items.length})
                      </h3>
                      <div className="divide-y divide-slate-100 border border-slate-200 rounded-lg">
                        {items.map((f) => (
                          <div key={f.id} className="p-3 space-y-1">
                            <div className="text-xs font-semibold text-[#17212B]">
                              {lang === 'ar' ? f.titleAr : f.title}
                            </div>
                            <p className="text-xs text-slate-600">{lang === 'ar' ? f.detailAr : f.detail}</p>
                            {f.evidenceSnippet && (
                              <div className="mt-1 px-2 py-1 bg-[#F7F9FA] rounded font-mono text-[11px] text-[#17212B] break-all">
                                {f.evidenceSnippet}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
                {details.findings.length === 0 && (
                  <div className="flex items-center gap-2 text-xs text-[#137A3E]">
                    <ShieldCheck className="w-4 h-4" />
                    <span>{lang === 'ar' ? details.explanationAr : details.explanation}</span>
                  </div>
                )}
              </div>

              {/* Extracted URLs & Attachments */}
              {(details.extractedUrls.length > 0 || details.attachments.length > 0) && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4 border-t border-slate-100">
                  <div>
                    <h3 className="text-xs font-semibold text-[#17212B] mb-2">{t.email.extractedUrls}</h3>
                    <div className="space-y-1.5">
                      {details.extractedUrls.map((u) => (
                        <div key={u} className="p-2 bg-[#F7F9FA] rounded font-mono text-[11px] text-slate-700 break-all">
                          {u}
                        </div>
                      ))}
                      {details.extractedUrls.length === 0 && (
                        <p className="text-xs text-slate-400">—</p>
                      )}
                    </div>
                  </div>
                  <div>
                    <h3 className="text-xs font-semibold text-[#17212B] mb-2">{t.email.attachmentsTitle}</h3>
                    <div className="space-y-1.5">
                      {details.attachments.map((att) => (
                        <div key={att.filename} className="p-2 bg-[#F7F9FA] rounded flex items-center justify-between gap-2 text-xs">
                          <span className="font-mono text-[#17212B] truncate">{att.filename}</span>
                          <SeverityMarker severity={att.riskLevel} label={t.severities[att.riskLevel]} />
                        </div>
                      ))}
                      {details.attachments.length === 0 && (
                        <p className="text-xs text-slate-400">—</p>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* Recommended Actions */}
              <div className="pt-4 border-t border-slate-100">
                <h3 className="text-xs font-semibold text-[#17212B] mb-2">{t.email.recommendations}</h3>
                <ul className="space-y-1.5 text-xs text-slate-600 list-disc list-inside">
                  {(lang === 'ar' ? details.recommendedActionsAr : details.recommendedActions).map((act, idx) => (
                    <li key={idx}>{act}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
