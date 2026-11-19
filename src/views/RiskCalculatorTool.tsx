import { useEffect, useState } from 'react';
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
import { evaluateRiskMatrix } from '../engine/phishingAnalyzer.ts';
import { getT } from '../i18n/translations.ts';
import { SeverityMarker } from '../components/StatusText.tsx';
import type { Language, RiskAssessmentResult, RiskTreatment, ThreatSeverity } from '../types/phishguard.ts';

interface Props {
  lang: Language;
  prefill?: { asset: string; threat: string; likelihood: number; impact: number } | null;
  onResult: (res: RiskAssessmentResult) => void;
}

export function RiskCalculatorTool({ lang, prefill, onResult }: Props) {
  const t = getT(lang);
  const [assetName, setAssetName] = useState(prefill?.asset || 'Corporate Email & SSO Identity');
  const [threatScenario, setThreatScenario] = useState(
    prefill?.threat || 'Credential Phishing via Lookalike Domain',
  );
  const [likelihood, setLikelihood] = useState(prefill?.likelihood || 4);
  const [impact, setImpact] = useState(prefill?.impact || 5);
  const [controlEffectiveness, setControlEffectiveness] = useState(35);
  const [strategy, setStrategy] = useState<RiskTreatment>('Mitigate');

  useEffect(() => {
    if (prefill) {
      setAssetName(prefill.asset);
      setThreatScenario(prefill.threat);
      setLikelihood(prefill.likelihood);
      setImpact(prefill.impact);
    }
  }, [prefill]);

  const evaluation = evaluateRiskMatrix({
    assetName,
    threatScenario,
    likelihood,
    impact,
    controlEffectiveness,
    strategy,
  });

  useEffect(() => {
    onResult(evaluation);
  }, [assetName, threatScenario, likelihood, impact, controlEffectiveness, strategy]);

  const toLevel = (score: number): ThreatSeverity => {
    if (score >= 17) return 'Critical';
    if (score >= 10) return 'High';
    if (score >= 5) return 'Medium';
    return 'Low';
  };

  const cellStyle = (score: number) => {
    const lvl = toLevel(score);
    if (lvl === 'Critical') return 'bg-[#FF3B5C]/15 border-[#FF3B5C]/40 text-[#FF3B5C]';
    if (lvl === 'High') return 'bg-[#FF9F1C]/18 border-[#FF9F1C]/45 text-[#9C5200]';
    if (lvl === 'Medium') return 'bg-[#00E5FF]/15 border-[#00E5FF]/40 text-[#006B78]';
    return 'bg-[#39FF88]/18 border-[#39FF88]/45 text-[#137A3E]';
  };

  const chartData = [
    { name: t.risk.inherent, score: evaluation.inherentScore, level: evaluation.inherentLevel },
    { name: t.risk.residual, score: evaluation.residualScore, level: evaluation.residualLevel },
  ];

  const barColor = (lvl: ThreatSeverity) =>
    lvl === 'Critical' ? '#FF3B5C' : lvl === 'High' ? '#FF9F1C' : lvl === 'Medium' ? '#00E5FF' : '#39FF88';

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-[#17212B]">{t.risk.title}</h1>
        <p className="text-sm text-slate-500 mt-1 max-w-3xl">{t.risk.subtitle}</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Interactive 5x5 Matrix */}
        <div className="lg:col-span-6 bg-white border border-slate-200 rounded-xl p-5 space-y-4">
          <div>
            <h2 className="text-sm font-semibold text-[#17212B]">{t.risk.matrixTitle}</h2>
            <p className="text-xs text-slate-500 mt-0.5">{t.risk.matrixHint}</p>
          </div>

          <div className="overflow-x-auto">
            <div className="min-w-[400px]">
              <div className="grid grid-cols-6 gap-1.5 text-center text-[11px] font-semibold text-slate-500 mb-1.5">
                <div className="py-1 text-start">L × I</div>
                {t.risk.impactLevels.map((lbl, idx) => (
                  <div key={idx} className="py-1 truncate">
                    {lbl}
                  </div>
                ))}
              </div>

              {[5, 4, 3, 2, 1].map((lVal) => (
                <div key={lVal} className="grid grid-cols-6 gap-1.5 mb-1.5">
                  <div className="flex items-center text-[11px] font-semibold text-slate-600 pe-2 truncate">
                    {t.risk.likelihoodLevels[lVal - 1]}
                  </div>
                  {[1, 2, 3, 4, 5].map((iVal) => {
                    const score = lVal * iVal;
                    const active = likelihood === lVal && impact === iVal;
                    return (
                      <button
                        key={iVal}
                        type="button"
                        onClick={() => {
                          setLikelihood(lVal);
                          setImpact(iVal);
                        }}
                        className={`h-14 rounded-lg border flex flex-col items-center justify-center transition-all ${cellStyle(
                          score,
                        )} ${active ? 'ring-2 ring-[#17212B] scale-[1.03]' : 'hover:scale-[1.02]'}`}
                      >
                        <span className="font-mono text-sm font-bold tabular-nums">{score}</span>
                        <span className="text-[10px] font-semibold">{t.severities[toLevel(score)]}</span>
                      </button>
                    );
                  })}
                </div>
              ))}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-4 pt-2 border-t border-slate-100 text-xs text-slate-600">
            <span>{t.severities.Low}: 1–4</span>
            <span>{t.severities.Medium}: 5–9</span>
            <span>{t.severities.High}: 10–16</span>
            <span>{t.severities.Critical}: 17–25</span>
          </div>
        </div>

        {/* Inputs, Visual Indicator & Recommendations */}
        <div className="lg:col-span-6 bg-white border border-slate-200 rounded-xl p-5 space-y-5">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1">{t.risk.assetLabel}</label>
              <input
                value={assetName}
                onChange={(e) => setAssetName(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1">{t.risk.strategyLabel}</label>
              <select
                value={strategy}
                onChange={(e) => setStrategy(e.target.value as RiskTreatment)}
                className="w-full px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
              >
                {(['Avoid', 'Mitigate', 'Transfer', 'Accept'] as const).map((s) => (
                  <option key={s} value={s}>
                    {t.risk.strategies[s]}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-600 mb-1">{t.risk.threatLabel}</label>
            <input
              value={threatScenario}
              onChange={(e) => setThreatScenario(e.target.value)}
              className="w-full px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1">{t.risk.likelihoodLabel}</label>
              <select
                value={likelihood}
                onChange={(e) => setLikelihood(Number(e.target.value))}
                className="w-full px-2.5 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
              >
                {[1, 2, 3, 4, 5].map((n) => (
                  <option key={n} value={n}>
                    {t.risk.likelihoodLevels[n - 1]}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1">{t.risk.impactLabel}</label>
              <select
                value={impact}
                onChange={(e) => setImpact(Number(e.target.value))}
                className="w-full px-2.5 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
              >
                {[1, 2, 3, 4, 5].map((n) => (
                  <option key={n} value={n}>
                    {t.risk.impactLevels[n - 1]}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1">
                {t.risk.controlsLabel}: <span className="font-mono">{controlEffectiveness}%</span>
              </label>
              <input
                type="range"
                min={0}
                max={90}
                step={5}
                value={controlEffectiveness}
                onChange={(e) => setControlEffectiveness(Number(e.target.value))}
                className="w-full accent-[#17212B] mt-2"
              />
            </div>
          </div>

          {/* Visual Risk Indicator Summary */}
          <div className="grid grid-cols-2 gap-3 p-4 bg-[#F7F9FA] rounded-xl">
            <div>
              <div className="text-xs text-slate-500">{t.risk.inherent}</div>
              <div className="mt-1 flex items-center gap-2.5">
                <span className="text-2xl font-mono font-bold text-[#17212B] tabular-nums">
                  {evaluation.inherentScore}/25
                </span>
                <SeverityMarker severity={evaluation.inherentLevel} label={t.severities[evaluation.inherentLevel]} />
              </div>
            </div>
            <div>
              <div className="text-xs text-slate-500">{t.risk.residual}</div>
              <div className="mt-1 flex items-center gap-2.5">
                <span className="text-2xl font-mono font-bold text-[#17212B] tabular-nums">
                  {evaluation.residualScore}/25
                </span>
                <SeverityMarker severity={evaluation.residualLevel} label={t.severities[evaluation.residualLevel]} />
              </div>
            </div>
          </div>

          {/* Comparison Chart */}
          <div className="space-y-2">
            <h3 className="text-xs font-semibold text-[#17212B]">{t.risk.gaugeTitle}</h3>
            <div className="h-36 w-full" dir="ltr">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} layout="vertical" margin={{ top: 4, right: 24, left: 10, bottom: 4 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" horizontal={false} />
                  <XAxis type="number" domain={[0, 25]} tick={{ fontSize: 11, fill: '#64748B' }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="name" width={110} tick={{ fontSize: 11, fill: '#17212B' }} axisLine={false} tickLine={false} />
                  <Tooltip />
                  <Bar dataKey="score" radius={[0, 6, 6, 0]}>
                    {chartData.map((entry, idx) => (
                      <Cell key={idx} fill={barColor(entry.level)} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Recommendations */}
          <div className="pt-3 border-t border-slate-100">
            <h3 className="text-xs font-semibold text-[#17212B] mb-2">{t.risk.recsTitle}</h3>
            <ul className="space-y-1.5 text-xs text-slate-700 list-disc list-inside">
              {(lang === 'ar' ? evaluation.recommendationsAr : evaluation.recommendationsEn).map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
