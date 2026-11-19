import { useEffect, useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { getT } from './i18n/translations.ts';
import { EmailAnalyzerTool } from './views/EmailAnalyzerTool.tsx';
import { UrlScannerTool } from './views/UrlScannerTool.tsx';
import { RiskCalculatorTool } from './views/RiskCalculatorTool.tsx';
import { AnalysisResultsView } from './views/AnalysisResultsView.tsx';
import type {
  EmailAnalysisResult,
  Language,
  RiskAssessmentResult,
  ToolTab,
  UrlAnalysisResult,
} from './types/phishguard.ts';

export default function App() {
  const [lang, setLang] = useState<Language>('en');
  const [activeTab, setActiveTab] = useState<ToolTab>('email');

  // Temporary in-memory session state only (never written to localStorage/sessionStorage)
  const [emailResult, setEmailResult] = useState<EmailAnalysisResult | null>(null);
  const [urlResult, setUrlResult] = useState<UrlAnalysisResult | null>(null);
  const [riskResult, setRiskResult] = useState<RiskAssessmentResult | null>(null);
  const [riskPrefill, setRiskPrefill] = useState<{
    asset: string;
    threat: string;
    likelihood: number;
    impact: number;
  } | null>(null);

  const t = getT(lang);

  useEffect(() => {
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
  }, [lang]);

  const handleSendToRisk = (asset: string, threat: string, score: number) => {
    const likelihood = score >= 75 ? 5 : score >= 50 ? 4 : score >= 25 ? 3 : 2;
    const impact = score >= 75 ? 5 : score >= 50 ? 4 : 3;
    setRiskPrefill({ asset, threat, likelihood, impact });
    setActiveTab('risk');
  };

  const handleClearSession = () => {
    setEmailResult(null);
    setUrlResult(null);
    setRiskResult(null);
    setRiskPrefill(null);
  };

  const tabOrder: ToolTab[] = ['email', 'url', 'risk', 'results'];

  return (
    <div className="min-h-screen bg-[#F7F9FA] text-[#17212B] flex flex-col">
      {/* Clean 3-Zone Top Bar */}
      <header className="sticky top-0 z-20 bg-white border-b border-slate-200 px-4 sm:px-8 h-16 flex items-center justify-between gap-6 no-print">
        {/* Zone 1: Brand Wordmark */}
        <button
          type="button"
          onClick={() => setActiveTab('email')}
          className="flex items-center gap-2.5 whitespace-nowrap shrink-0"
        >
          <span className="w-8 h-8 rounded-lg bg-[#17212B] flex items-center justify-center shrink-0">
            <ShieldCheck className="w-4 h-4 text-[#B7FF00]" />
          </span>
          <span className="text-lg font-bold tracking-tight text-[#17212B]">{t.brandName}</span>
        </button>

        {/* Zone 2: 4 Core Tool Links */}
        <nav className="hidden md:flex items-center gap-6">
          {tabOrder.map((tab) => {
            const active = activeTab === tab;
            return (
              <button
                key={tab}
                type="button"
                onClick={() => setActiveTab(tab)}
                className={`py-1 text-sm font-semibold transition-colors whitespace-nowrap shrink-0 border-b-2 ${
                  active
                    ? 'text-[#17212B] border-[#B7FF00]'
                    : 'text-slate-500 border-transparent hover:text-[#17212B]'
                }`}
              >
                {t.tabs[tab]}
              </button>
            );
          })}
        </nav>

        {/* Zone 3: Primary Language Action */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={() => setLang((l) => (l === 'en' ? 'ar' : 'en'))}
            className="px-4 py-2 bg-[#B7FF00] text-[#17212B] text-xs font-bold rounded-lg hover:brightness-95 transition-all whitespace-nowrap shrink-0"
          >
            {t.langSwitch}
          </button>
        </div>
      </header>

      {/* Mobile Tab Bar */}
      <div className="md:hidden bg-white border-b border-slate-200 px-3 py-2 flex items-center gap-1 overflow-x-auto no-print">
        {tabOrder.map((tab) => (
          <button
            key={tab}
            type="button"
            onClick={() => setActiveTab(tab)}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md whitespace-nowrap shrink-0 ${
              activeTab === tab ? 'bg-[#17212B] text-white' : 'text-slate-600'
            }`}
          >
            {t.tabs[tab]}
          </button>
        ))}
      </div>

      {/* Main Content */}
      <main className="flex-1 w-full max-w-[1280px] mx-auto px-4 sm:px-8 py-6 space-y-5">
        {/* Quiet Session-Only Context Bar */}
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 pb-3 border-b border-slate-200/80 no-print">
          <span>{t.brandTagline}</span>
          <span className="font-mono text-[#007D8C]">{t.privacyNote}</span>
        </div>

        {activeTab === 'email' && (
          <EmailAnalyzerTool
            lang={lang}
            result={emailResult}
            onResult={setEmailResult}
            onSendToRisk={handleSendToRisk}
          />
        )}

        {activeTab === 'url' && (
          <UrlScannerTool
            lang={lang}
            result={urlResult}
            onResult={setUrlResult}
            onSendToRisk={handleSendToRisk}
          />
        )}

        {activeTab === 'risk' && (
          <RiskCalculatorTool lang={lang} prefill={riskPrefill} onResult={setRiskResult} />
        )}

        {activeTab === 'results' && (
          <AnalysisResultsView
            lang={lang}
            emailResult={emailResult}
            urlResult={urlResult}
            riskResult={riskResult}
            onClearSession={handleClearSession}
          />
        )}
      </main>
    </div>
  );
}
