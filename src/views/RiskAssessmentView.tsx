import { useEffect, useState } from 'react';
import { apiFetch } from '../lib/api.ts';
import { getT } from '../i18n/translations.ts';
import { SeverityMarker } from '../components/StatusText.tsx';
import type { Language, RiskRecord, RiskTreatment, ThreatSeverity } from '../types/phishguard.ts';

interface Thresholds {
  lowMax: number;
  mediumMax: number;
  highMax: number;
}

export function RiskAssessmentView({ lang }: { lang: Language }) {
  const t = getT(lang);
  const [risks, setRisks] = useState<RiskRecord[]>([]);
  const [thresholds, setThresholds] = useState<Thresholds>({ lowMax: 4, mediumMax: 9, highMax: 16 });
  const [selectedCell, setSelectedCell] = useState<{ l: number; i: number } | null>(null);

  // New Risk Form
  const [assetAffected, setAssetAffected] = useState('');
  const [threatDescription, setThreatDescription] = useState('');
  const [vulnerability, setVulnerability] = useState('');
  const [likelihood, setLikelihood] = useState(4);
  const [impact, setImpact] = useState(4);
  const [existingControls, setExistingControls] = useState('');
  const [controlEffectiveness, setControlEffectiveness] = useState(35);
  const [riskOwner, setRiskOwner] = useState('Security Operations');
  const [treatmentStrategy, setTreatmentStrategy] = useState<RiskTreatment>('Mitigate');
  const [mitigationPlan, setMitigationPlan] = useState('');
  const [error, setError] = useState('');
  const [feedback, setFeedback] = useState('');

  const loadRisks = async () => {
    const res = await apiFetch<{ risks: RiskRecord[]; thresholds: Thresholds }>('/api/risks');
    setRisks(res.risks);
    setThresholds(res.thresholds);
  };

  useEffect(() => {
    loadRisks();
  }, []);

  const scoreToLevel = (score: number): ThreatSeverity => {
    if (score > thresholds.highMax) return 'Critical';
    if (score > thresholds.mediumMax) return 'High';
    if (score > thresholds.lowMax) return 'Medium';
    return 'Low';
  };

  const cellStyle = (score: number) => {
    const lvl = scoreToLevel(score);
    if (lvl === 'Critical') return 'bg-[#FF3B5C]/15 border-[#FF3B5C]/40 text-[#FF3B5C]';
    if (lvl === 'High') return 'bg-[#FF9F1C]/18 border-[#FF9F1C]/45 text-[#9C5200]';
    if (lvl === 'Medium') return 'bg-[#00E5FF]/15 border-[#00E5FF]/40 text-[#006B78]';
    return 'bg-[#39FF88]/18 border-[#39FF88]/45 text-[#137A3E]';
  };

  const previewInherent = likelihood * impact;
  const previewResidual = Math.max(1, Math.round(previewInherent * (1 - controlEffectiveness / 100)));

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setFeedback('');
    try {
      const res = await apiFetch<{ id: string }>('/api/risks', {
        method: 'POST',
        body: JSON.stringify({
          assetAffected,
          threatDescription,
          vulnerability,
          likelihood,
          impact,
          existingControls,
          controlEffectiveness,
          riskOwner,
          treatmentStrategy,
          mitigationPlan,
        }),
      });
      setFeedback(`Risk assessment ${res.id} recorded.`);
      setAssetAffected('');
      setThreatDescription('');
      setVulnerability('');
      setExistingControls('');
      setMitigationPlan('');
      await loadRisks();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to save risk');
    }
  };

  const handleUpdateStatus = async (id: string, treatmentStatus: RiskRecord['treatmentStatus']) => {
    setError('');
    try {
      await apiFetch(`/api/risks/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ treatmentStatus }),
      });
      await loadRisks();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to update risk');
    }
  };

  const visibleRisks = selectedCell
    ? risks.filter((r) => r.likelihood === selectedCell.l && r.impact === selectedCell.i)
    : risks;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-[#17212B]">{t.risk.title}</h1>
        <p className="text-sm text-slate-500 mt-1">{t.risk.subtitle}</p>
      </div>

      {/* 5x5 Matrix + New Risk Form */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
        {/* Interactive 5x5 Risk Matrix */}
        <div className="xl:col-span-6 bg-white border border-slate-200 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-[#17212B]">{t.risk.matrixTitle}</h2>
              <p className="text-xs text-slate-500 mt-0.5">{t.risk.matrixHint}</p>
            </div>
            {selectedCell && (
              <button
                type="button"
                onClick={() => setSelectedCell(null)}
                className="px-3 py-1.5 text-xs font-semibold bg-[#F7F9FA] border border-slate-200 rounded-lg hover:border-slate-300"
              >
                {t.risk.clearCellFilter}
              </button>
            )}
          </div>

          <div className="overflow-x-auto">
            <div className="min-w-[420px]">
              <div className="grid grid-cols-6 gap-1.5 text-center text-[11px] font-semibold text-slate-500 mb-1.5">
                <div className="py-1 text-start">L \ I</div>
                {t.risk.impactLabels.map((lbl, idx) => (
                  <div key={idx} className="py-1 truncate">
                    {lbl}
                  </div>
                ))}
              </div>

              {[5, 4, 3, 2, 1].map((lVal) => (
                <div key={lVal} className="grid grid-cols-6 gap-1.5 mb-1.5">
                  <div className="flex items-center text-[11px] font-semibold text-slate-600 pe-2 truncate">
                    {t.risk.likelihoodLabels[lVal - 1]}
                  </div>
                  {[1, 2, 3, 4, 5].map((iVal) => {
                    const score = lVal * iVal;
                    const countInCell = risks.filter((r) => r.likelihood === lVal && r.impact === iVal).length;
                    const isSelected = selectedCell?.l === lVal && selectedCell?.i === iVal;
                    return (
                      <button
                        key={iVal}
                        type="button"
                        onClick={() => {
                          setLikelihood(lVal);
                          setImpact(iVal);
                          setSelectedCell(isSelected ? null : { l: lVal, i: iVal });
                        }}
                        className={`h-14 rounded-lg border flex flex-col items-center justify-center transition-all ${cellStyle(
                          score,
                        )} ${isSelected ? 'ring-2 ring-[#17212B]' : 'hover:scale-[1.02]'}`}
                      >
                        <span className="font-mono text-sm font-bold tabular-nums">{score}</span>
                        {countInCell > 0 && (
                          <span className="text-[10px] font-semibold opacity-90">
                            {countInCell} {countInCell === 1 ? 'risk' : 'risks'}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              ))}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-4 pt-2 border-t border-slate-100 text-xs text-slate-600">
            <span>Low: 1–{thresholds.lowMax}</span>
            <span>Medium: {thresholds.lowMax + 1}–{thresholds.mediumMax}</span>
            <span>High: {thresholds.mediumMax + 1}–{thresholds.highMax}</span>
            <span>Critical: {thresholds.highMax + 1}–25</span>
          </div>
        </div>

        {/* New Risk Assessment Form */}
        <form onSubmit={handleCreate} className="xl:col-span-6 bg-white border border-slate-200 rounded-xl p-5 space-y-3.5">
          <div className="flex items-center justify-between gap-2">
            <h2 className="text-sm font-semibold text-[#17212B]">{t.risk.newRiskTitle}</h2>
            <div className="flex items-center gap-3 text-xs font-mono">
              <span>
                {t.risk.inherent}: <strong>{previewInherent}</strong> ({scoreToLevel(previewInherent)})
              </span>
              <span>
                {t.risk.residual}: <strong>{previewResidual}</strong> ({scoreToLevel(previewResidual)})
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1">{t.risk.asset}</label>
              <input
                required
                value={assetAffected}
                onChange={(e) => setAssetAffected(e.target.value)}
                placeholder="Identity Provider / Email Gateway"
                className="w-full px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1">{t.risk.owner}</label>
              <input
                required
                value={riskOwner}
                onChange={(e) => setRiskOwner(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1">{t.risk.threat}</label>
              <input
                required
                value={threatDescription}
                onChange={(e) => setThreatDescription(e.target.value)}
                placeholder="Spear-phishing credential capture"
                className="w-full px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1">{t.risk.vulnerability}</label>
              <input
                required
                value={vulnerability}
                onChange={(e) => setVulnerability(e.target.value)}
                placeholder="Legacy SMTP auth enabled"
                className="w-full px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
              />
            </div>
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1">{t.risk.likelihood}</label>
              <select
                value={likelihood}
                onChange={(e) => setLikelihood(Number(e.target.value))}
                className="w-full px-2.5 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
              >
                {[1, 2, 3, 4, 5].map((n) => (
                  <option key={n} value={n}>
                    {t.risk.likelihoodLabels[n - 1]}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1">{t.risk.impact}</label>
              <select
                value={impact}
                onChange={(e) => setImpact(Number(e.target.value))}
                className="w-full px-2.5 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
              >
                {[1, 2, 3, 4, 5].map((n) => (
                  <option key={n} value={n}>
                    {t.risk.impactLabels[n - 1]}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1">{t.risk.effectiveness}</label>
              <input
                type="number"
                min={0}
                max={90}
                value={controlEffectiveness}
                onChange={(e) => setControlEffectiveness(Number(e.target.value))}
                className="w-full px-2.5 py-2 font-mono text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1">{t.risk.controls}</label>
              <input
                required
                value={existingControls}
                onChange={(e) => setExistingControls(e.target.value)}
                placeholder="DMARC p=quarantine, MFA"
                className="w-full px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1">{t.risk.strategy}</label>
              <select
                value={treatmentStrategy}
                onChange={(e) => setTreatmentStrategy(e.target.value as RiskTreatment)}
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
            <label className="block text-xs font-medium text-slate-600 mb-1">{t.risk.mitigation}</label>
            <input
              required
              value={mitigationPlan}
              onChange={(e) => setMitigationPlan(e.target.value)}
              placeholder="Enforce FIDO2 hardware MFA and disable legacy auth protocols"
              className="w-full px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            />
          </div>

          {error && <p className="text-xs text-[#FF3B5C]">{error}</p>}
          {feedback && <p className="text-xs text-[#137A3E]">{feedback}</p>}

          <button
            type="submit"
            className="w-full py-2.5 bg-[#B7FF00] text-[#17212B] text-xs font-bold rounded-lg neon-glow-lime hover:brightness-95"
          >
            {t.common.create}
          </button>
        </form>
      </div>

      {/* Risk Register Table */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-100 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-[#17212B]">
            Risk Register ({visibleRisks.length})
          </h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-start border-collapse text-xs">
            <thead>
              <tr className="bg-[#F7F9FA] border-b border-slate-200 text-slate-500">
                <th className="py-2.5 px-4 text-start font-semibold">Risk ID</th>
                <th className="py-2.5 px-4 text-start font-semibold">{t.risk.asset}</th>
                <th className="py-2.5 px-4 text-start font-semibold">{t.risk.threat}</th>
                <th className="py-2.5 px-4 text-start font-semibold">L × I</th>
                <th className="py-2.5 px-4 text-start font-semibold">{t.risk.inherent}</th>
                <th className="py-2.5 px-4 text-start font-semibold">{t.risk.residual}</th>
                <th className="py-2.5 px-4 text-start font-semibold">{t.risk.strategy}</th>
                <th className="py-2.5 px-4 text-start font-semibold">{t.common.status}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {visibleRisks.map((r) => (
                <tr key={r.id} className="hover:bg-[#F7F9FA] align-top">
                  <td className="py-3 px-4 font-mono font-bold text-[#17212B] whitespace-nowrap">
                    {r.id}
                    {r.linkedIncidentId && (
                      <div className="text-[10px] font-normal text-slate-400">{r.linkedIncidentId}</div>
                    )}
                  </td>
                  <td className="py-3 px-4 font-medium text-[#17212B]">
                    <div>{r.assetAffected}</div>
                    <div className="text-[11px] text-slate-500 mt-0.5">{r.riskOwner}</div>
                  </td>
                  <td className="py-3 px-4 max-w-xs space-y-1">
                    <div className="text-[#17212B] font-medium">{r.threatDescription}</div>
                    <div className="text-[11px] text-slate-500">{r.recommendations}</div>
                  </td>
                  <td className="py-3 px-4 font-mono tabular-nums whitespace-nowrap">
                    {r.likelihood} × {r.impact}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold tabular-nums">{r.inherentRisk}</span>
                      <SeverityMarker severity={r.inherentLevel} label={t.severities[r.inherentLevel]} />
                    </div>
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold tabular-nums">{r.residualRisk}</span>
                      <SeverityMarker severity={r.residualLevel} label={t.severities[r.residualLevel]} />
                    </div>
                  </td>
                  <td className="py-3 px-4 font-medium">{t.risk.strategies[r.treatmentStrategy]}</td>
                  <td className="py-3 px-4">
                    <select
                      value={r.treatmentStatus}
                      onChange={(e) =>
                        handleUpdateStatus(r.id, e.target.value as RiskRecord['treatmentStatus'])
                      }
                      className="px-2 py-1 text-xs bg-[#F7F9FA] border border-slate-200 rounded"
                    >
                      <option value="Open">Open</option>
                      <option value="In Progress">In Progress</option>
                      <option value="Controlled">Controlled</option>
                      <option value="Accepted">Accepted</option>
                    </select>
                  </td>
                </tr>
              ))}
              {visibleRisks.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-10 text-center text-slate-400">
                    {t.common.noData}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
