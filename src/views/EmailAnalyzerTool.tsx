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
import {
  AlertTriangle,
  Download,
  FileUp,
  Info,
  MailCheck,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { analyzeEmailClient } from '../engine/phishingAnalyzer.ts';
import { downloadEmailPdfReport } from '../lib/pdfReport.ts';
import { getT } from '../i18n/translations.ts';
import { ClassificationMarker, ScoreBar, SeverityMarker } from '../components/StatusText.tsx';
import type { EmailAnalysisResult, Language } from '../types/phishguard.ts';

interface Props {
  lang: Language;
  result: EmailAnalysisResult | null;
  onResult: (res: EmailAnalysisResult) => void;
  onSendToRisk: (asset: string, threat: string, score: number) => void;
}

const SAMPLE_PHISH_RAW = `From: "Microsoft 365 Account Team" <security@micros0ft-auth-verify.top>
Reply-To: verify-recovery@proton.me
To: finance-team@company.example
Subject: URGENT: Your Microsoft 365 Account Will Be Suspended Within 24 Hours
Authentication-Results: spf=fail smtp.mailfrom=micros0ft-auth-verify.top; dkim=fail; dmarc=fail
Received: from relay9.micros0ft-auth-verify.top (185.220.101.47) by mx1.company.example
Content-Disposition: attachment; filename="Security_Verification_Form.pdf.exe"

Dear Employee,
Unusual sign-in activity was detected on your mailbox. Immediate action required within 24 hours to avoid permanent deactivation.
Verify your password and MFA settings now:
https://micros0ft-auth-verify.top/oauth/login?redirect=https://evil-collector.xyz`;

const SAMPLE_BEC_RAW = `From: "Chief Executive Officer" <ceo.desk.urgent@gmail.com>
Reply-To: wire-approvals@yandex.com
To: accounts-payable@company.example
Subject: Confidential Wire Transfer - Immediate Vendor Settlement
Authentication-Results: spf=pass; dkim=pass; dmarc=none

I am in a board meeting and cannot take calls. Please arrange an urgent confidential payment of $42,500 for our acquisition vendor today. Reply with confirmation once bank details are updated.`;

const SAMPLE_CLEAN_RAW = `From: "IT Security Awareness" <awareness@company.example>
To: staff@company.example
Subject: Quarterly Security Briefing Agenda
Authentication-Results: spf=pass; dkim=pass; dmarc=pass
Received: from mail-internal.company.example (10.10.2.20) by mx1.company.example

Hello team,
Our quarterly cybersecurity awareness briefing will take place Thursday at 10:00 AM. You can review reference guides at https://learn.microsoft.com/en-us/security/zero-trust`;

export function EmailAnalyzerTool({ lang, result, onResult, onSendToRisk }: Props) {
  const t = getT(lang);
  const [mode, setMode] = useState<'raw' | 'structured'>('raw');
  const [rawEmail, setRawEmail] = useState(SAMPLE_PHISH_RAW);
  const [uploadedFilename, setUploadedFilename] = useState('');

  const [senderDisplayName, setSenderDisplayName] = useState('');
  const [senderEmail, setSenderEmail] = useState('');
  const [replyTo, setReplyTo] = useState('');
  const [subject, setSubject] = useState('');
  const [headersText, setHeadersText] = useState('');
  const [attachmentsInput, setAttachmentsInput] = useState('');
  const [body, setBody] = useState('');
  const [error, setError] = useState('');

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    setError('');
    const file = e.target.files?.[0];
    if (!file) return;
    if (!/\.(eml|txt)$/i.test(file.name)) {
      setError('Only .eml and .txt files are supported.');
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      setError('File exceeds 2 MB size limit.');
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

  const handleAnalyze = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (mode === 'raw' && !rawEmail.trim()) {
      setError('Paste raw email content or upload an .eml/.txt file.');
      return;
    }
    if (mode === 'structured' && !senderEmail.trim() && !subject.trim() && !body.trim()) {
      setError('Enter at least sender email, subject, or message body.');
      return;
    }

    const analysis = analyzeEmailClient(
      mode === 'raw'
        ? { rawEmail }
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
          },
    );
    onResult(analysis);
  };

  const barData =
    result?.scoreBreakdown.map((b) => ({
      name: lang === 'ar' ? b.categoryAr : b.category,
      points: b.points,
    })) || [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-[#17212B]">{t.email.title}</h1>
        <p className="text-sm text-slate-500 mt-1 max-w-3xl">{t.email.subtitle}</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Input Panel */}
        <form onSubmit={handleAnalyze} className="lg:col-span-5 bg-white border border-slate-200 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-1 p-1 bg-[#F7F9FA] border border-slate-200 rounded-lg">
            <button
              type="button"
              onClick={() => setMode('raw')}
              className={`flex-1 py-1.5 px-3 text-xs font-semibold rounded-md transition-colors whitespace-nowrap ${
                mode === 'raw' ? 'bg-white text-[#17212B] shadow-xs' : 'text-slate-600'
              }`}
            >
              {t.email.modeRaw}
            </button>
            <button
              type="button"
              onClick={() => setMode('structured')}
              className={`flex-1 py-1.5 px-3 text-xs font-semibold rounded-md transition-colors whitespace-nowrap ${
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
                  className="px-2.5 py-1.5 text-xs font-medium bg-[#F7F9FA] border border-slate-200 rounded-lg hover:border-slate-300"
                >
                  {t.email.samplePhish}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setRawEmail(SAMPLE_BEC_RAW);
                    setUploadedFilename('');
                  }}
                  className="px-2.5 py-1.5 text-xs font-medium bg-[#F7F9FA] border border-slate-200 rounded-lg hover:border-slate-300"
                >
                  {t.email.sampleBec}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setRawEmail(SAMPLE_CLEAN_RAW);
                    setUploadedFilename('');
                  }}
                  className="px-2.5 py-1.5 text-xs font-medium bg-[#F7F9FA] border border-slate-200 rounded-lg hover:border-slate-300"
                >
                  {t.email.sampleClean}
                </button>
              </div>

              <label className="flex items-center justify-between gap-3 p-3 border border-dashed border-slate-300 rounded-lg bg-[#F7F9FA] cursor-pointer hover:border-[#17212B] transition-colors">
                <span className="flex items-center gap-2 text-xs font-medium text-slate-700 truncate">
                  <FileUp className="w-4 h-4 text-[#17212B] shrink-0" />
                  <span className="truncate">{uploadedFilename || t.email.uploadLabel}</span>
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
                    value={senderDisplayName}
                    onChange={(e) => setSenderDisplayName(e.target.value)}
                    placeholder="Microsoft Security"
                    className="w-full px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">{t.email.senderEmail}</label>
                  <input
                    type="email"
                    value={senderEmail}
                    onChange={(e) => setSenderEmail(e.target.value)}
                    placeholder="alerts@micros0ft-auth.top"
                    className="w-full px-3 py-2 font-mono text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
                  />
                </div>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">{t.email.replyTo}</label>
                  <input
                    value={replyTo}
                    onChange={(e) => setReplyTo(e.target.value)}
                    placeholder="reply@external-drop.xyz"
                    className="w-full px-3 py-2 font-mono text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">{t.email.attachmentsLabel}</label>
                  <input
                    value={attachmentsInput}
                    onChange={(e) => setAttachmentsInput(e.target.value)}
                    placeholder="invoice.pdf.exe"
                    className="w-full px-3 py-2 font-mono text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
                  />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">{t.email.subject}</label>
                <input
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  placeholder="URGENT: Verify Account Within 24 Hours"
                  className="w-full px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">{t.email.headersOptional}</label>
                <textarea
                  value={headersText}
                  onChange={(e) => setHeadersText(e.target.value)}
                  rows={3}
                  placeholder="Authentication-Results: spf=fail; dkim=fail; dmarc=fail"
                  className="w-full p-2.5 font-mono text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">{t.email.bodyLabel}</label>
                <textarea
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  rows={5}
                  placeholder="Paste email body and links..."
                  className="w-full p-2.5 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
                />
              </div>
            </div>
          )}

          {error && <p className="text-xs font-medium text-[#FF3B5C]">{error}</p>}

          <button
            type="submit"
            className="w-full py-2.5 px-4 bg-[#B7FF00] text-[#17212B] text-sm font-bold rounded-lg neon-glow-lime hover:brightness-95 transition-all"
          >
            {t.email.analyzeBtn}
          </button>
        </form>

        {/* Right Results Panel */}
        <div className="lg:col-span-7 bg-white border border-slate-200 rounded-xl p-5">
          {!result ? (
            <div className="py-20 text-center space-y-2">
              <MailCheck className="w-10 h-10 text-slate-300 mx-auto" />
              <p className="text-sm font-semibold text-[#17212B]">{t.email.emptyTitle}</p>
              <p className="text-xs text-slate-500 max-w-md mx-auto">{t.email.emptyBody}</p>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Header & Classification */}
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 pb-5 border-b border-slate-100">
                <div className="space-y-1.5 min-w-0">
                  <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
                    <span className="font-mono font-bold text-[#17212B]">{result.id}</span>
                    <span aria-hidden="true">·</span>
                    <span>{t.common.heuristicOnly}</span>
                  </div>
                  <h2 className="text-lg font-bold text-[#17212B] break-words">{result.subject}</h2>
                  <p className="text-xs font-mono text-slate-600 break-all">
                    From: {result.senderDisplayName ? `"${result.senderDisplayName}" ` : ''}&lt;{result.senderEmail}&gt;
                    {result.replyTo ? ` · Reply-To: ${result.replyTo}` : ''}
                  </p>
                </div>
                <div className="flex flex-col sm:items-end gap-2 shrink-0">
                  <ClassificationMarker
                    classification={result.classification}
                    label={t.classifications[result.classification]}
                  />
                  <div className="flex items-center gap-4 text-xs">
                    <span className="text-slate-500">
                      {t.common.score}:{' '}
                      <strong className="font-mono text-[#17212B] tabular-nums">{result.riskScore}/100</strong>
                    </span>
                    <span className="text-slate-500">
                      {t.common.confidence}:{' '}
                      <strong className="font-mono text-[#17212B] tabular-nums">{result.confidence}%</strong>
                    </span>
                  </div>
                </div>
              </div>

              <ScoreBar score={result.riskScore} />

              {/* Action Buttons */}
              <div className="flex flex-wrap items-center gap-2.5">
                <button
                  type="button"
                  onClick={() => downloadEmailPdfReport(result)}
                  className="inline-flex items-center gap-1.5 px-4 py-2 bg-[#B7FF00] text-[#17212B] text-xs font-bold rounded-lg neon-glow-lime whitespace-nowrap"
                >
                  <Download className="w-3.5 h-3.5" />
                  {t.common.downloadPdf}
                </button>
                <button
                  type="button"
                  onClick={() =>
                    onSendToRisk(
                      `Email Mailbox (${result.senderEmail})`,
                      `${result.classification}: ${result.subject}`,
                      result.riskScore,
                    )
                  }
                  className="px-4 py-2 bg-[#17212B] text-white text-xs font-semibold rounded-lg hover:bg-slate-800 whitespace-nowrap"
                >
                  {t.common.sendToRisk}
                </button>
              </div>

              {/* Explanation */}
              <div className="p-4 bg-[#F7F9FA] rounded-lg space-y-1.5">
                <h3 className="text-xs font-bold text-[#17212B]">{t.email.whyTitle}</h3>
                <p className="text-sm text-slate-700 leading-relaxed">
                  {lang === 'ar' ? result.explanationAr : result.explanation}
                </p>
              </div>

              {/* Score Contribution Chart */}
              {barData.length > 0 && (
                <div className="pt-2 space-y-2">
                  <h3 className="text-xs font-semibold text-[#17212B]">{t.email.scoreChartTitle}</h3>
                  <div className="h-44 w-full" dir="ltr">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={barData} layout="vertical" margin={{ top: 4, right: 20, left: 10, bottom: 4 }}>
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
                          {barData.map((_, idx) => (
                            <Cell key={idx} fill={idx === 0 ? '#FF3B5C' : idx === 1 ? '#FF9F1C' : '#00E5FF'} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              )}

              {/* Auth Alignment */}
              <div className="pt-4 border-t border-slate-100 space-y-2">
                <h3 className="text-xs font-semibold text-[#17212B]">{t.email.authTitle}</h3>
                <div className="grid grid-cols-3 gap-3">
                  {(['spf', 'dkim', 'dmarc'] as const).map((proto) => {
                    const val = result.auth[proto];
                    const cls =
                      val === 'pass'
                        ? 'text-[#137A3E] bg-[#39FF88]/15 border-[#39FF88]/40'
                        : val === 'fail' || val === 'softfail'
                          ? 'text-[#FF3B5C] bg-[#FF3B5C]/10 border-[#FF3B5C]/30'
                          : 'text-slate-600 bg-[#F7F9FA] border-slate-200';
                    return (
                      <div key={proto} className={`p-2.5 rounded-lg border text-xs flex items-center justify-between ${cls}`}>
                        <span className="font-mono font-bold uppercase">{proto}</span>
                        <span className="font-mono font-semibold">{val}</span>
                      </div>
                    );
                  })}
                </div>
                <p className="text-xs text-slate-500">{lang === 'ar' ? result.auth.noteAr : result.auth.note}</p>
              </div>

              {/* Indicators */}
              <div className="pt-4 border-t border-slate-100 space-y-3">
                <h3 className="text-xs font-semibold text-[#17212B]">
                  {t.email.indicatorsTitle} ({result.findings.length})
                </h3>
                {result.findings.length === 0 ? (
                  <div className="flex items-center gap-2 text-xs text-[#137A3E]">
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
                      const iconCls =
                        f.level === 'confirmed_malicious'
                          ? 'text-[#FF3B5C]'
                          : f.level === 'suspicious'
                            ? 'text-[#FF9F1C]'
                            : 'text-[#0891B2]';
                      return (
                        <div key={f.id} className="p-3.5 space-y-1">
                          <div className="flex items-center justify-between gap-2">
                            <span className="flex items-center gap-2 text-xs font-semibold text-[#17212B]">
                              <Icon className={`w-4 h-4 ${iconCls} shrink-0`} />
                              {lang === 'ar' ? f.titleAr : f.title}
                            </span>
                            <span className="font-mono text-[11px] font-semibold text-slate-500 tabular-nums shrink-0">
                              +{f.weight} pts
                            </span>
                          </div>
                          <p className="text-xs text-slate-600">{lang === 'ar' ? f.detailAr : f.detail}</p>
                          {f.evidenceSnippet && (
                            <div className="px-2.5 py-1 bg-[#F7F9FA] rounded font-mono text-[11px] text-[#17212B] break-all">
                              {f.evidenceSnippet}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Extracted URLs & Attachments */}
              {(result.extractedUrls.length > 0 || result.attachments.length > 0) && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4 border-t border-slate-100">
                  <div>
                    <h3 className="text-xs font-semibold text-[#17212B] mb-2">{t.email.urlsTitle}</h3>
                    <div className="space-y-1.5">
                      {result.extractedUrls.map((u) => (
                        <div key={u.url} className="p-2.5 bg-[#F7F9FA] rounded-lg space-y-1">
                          <div className="font-mono text-[11px] text-[#17212B] break-all">{u.url}</div>
                          <div className="flex items-center justify-between text-[11px]">
                            <ClassificationMarker
                              classification={u.classification}
                              label={t.classifications[u.classification]}
                            />
                            <span className="font-mono font-semibold text-slate-600">{u.riskScore}/100</span>
                          </div>
                        </div>
                      ))}
                      {result.extractedUrls.length === 0 && <p className="text-xs text-slate-400">—</p>}
                    </div>
                  </div>
                  <div>
                    <h3 className="text-xs font-semibold text-[#17212B] mb-2">{t.email.attachmentsTitle}</h3>
                    <div className="space-y-1.5">
                      {result.attachments.map((att) => (
                        <div key={att.filename} className="p-2.5 bg-[#F7F9FA] rounded-lg flex items-center justify-between gap-2 text-xs">
                          <div className="min-w-0">
                            <div className="font-mono font-semibold text-[#17212B] truncate">{att.filename}</div>
                            <div className="text-[11px] text-slate-500">
                              {lang === 'ar' ? att.reasonAr : att.reason}
                            </div>
                          </div>
                          <SeverityMarker severity={att.riskLevel} label={t.severities[att.riskLevel]} />
                        </div>
                      ))}
                      {result.attachments.length === 0 && <p className="text-xs text-slate-400">—</p>}
                    </div>
                  </div>
                </div>
              )}

              {/* Headers Snapshot */}
              {result.headers.length > 0 && (
                <div className="pt-4 border-t border-slate-100 space-y-2">
                  <h3 className="text-xs font-semibold text-[#17212B]">{t.email.headersTitle}</h3>
                  <div className="max-h-40 overflow-y-auto divide-y divide-slate-100 border border-slate-200 rounded-lg text-[11px] font-mono">
                    {result.headers.map((h, i) => (
                      <div key={i} className="px-3 py-1.5 flex gap-3">
                        <span className="font-bold text-[#17212B] min-w-[130px] shrink-0">{h.key}</span>
                        <span className="text-slate-600 break-all">{h.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommended Actions */}
              <div className="pt-4 border-t border-slate-100">
                <h3 className="text-xs font-semibold text-[#17212B] mb-2">{t.common.recommendations}</h3>
                <ul className="space-y-1.5 text-xs text-slate-700 list-disc list-inside">
                  {(lang === 'ar' ? result.recommendedActionsAr : result.recommendedActions).map((act, idx) => (
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
