import { useEffect, useState } from 'react';
import { Award, CheckCircle2, XCircle } from 'lucide-react';
import { apiFetch } from '../lib/api.ts';
import { getT } from '../i18n/translations.ts';
import { SIMULATION_SCENARIOS } from '../data/simulations.ts';
import type { Language, SimulationAttempt } from '../types/phishguard.ts';

export function SimulationLabView({ lang }: { lang: Language }) {
  const t = getT(lang);
  const [activeId, setActiveId] = useState(SIMULATION_SCENARIOS[0].id);
  const [selectedThreat, setSelectedThreat] = useState('');
  const [selectedActions, setSelectedActions] = useState<string[]>([]);
  const [evaluated, setEvaluated] = useState<{
    score: number;
    passed: boolean;
    threatCorrect: boolean;
    missedActions: string[];
    wrongActions: string[];
  } | null>(null);
  const [attempts, setAttempts] = useState<SimulationAttempt[]>([]);

  const loadAttempts = async () => {
    const res = await apiFetch<SimulationAttempt[]>('/api/simulations');
    setAttempts(res);
  };

  useEffect(() => {
    loadAttempts();
  }, []);

  const scenario = SIMULATION_SCENARIOS.find((s) => s.id === activeId) || SIMULATION_SCENARIOS[0];

  const handleSelectScenario = (id: string) => {
    setActiveId(id);
    setSelectedThreat('');
    setSelectedActions([]);
    setEvaluated(null);
  };

  const toggleAction = (actionId: string) => {
    setSelectedActions((prev) =>
      prev.includes(actionId) ? prev.filter((a) => a !== actionId) : [...prev, actionId],
    );
  };

  const handleEvaluate = async () => {
    if (!selectedThreat) return;
    const threatCorrect = selectedThreat === scenario.correctThreatId;
    const missedActions = scenario.correctActionIds.filter((id) => !selectedActions.includes(id));
    const wrongActions = selectedActions.filter((id) => !scenario.correctActionIds.includes(id));

    let score = threatCorrect ? 40 : 0;
    const perAction = 60 / scenario.correctActionIds.length;
    const correctSelected = selectedActions.filter((id) => scenario.correctActionIds.includes(id)).length;
    score += Math.round(correctSelected * perAction - wrongActions.length * 15);
    score = Math.max(0, Math.min(100, score));
    const passed = score >= 70;

    setEvaluated({ score, passed, threatCorrect, missedActions, wrongActions });

    await apiFetch('/api/simulations', {
      method: 'POST',
      body: JSON.stringify({
        scenarioId: scenario.id,
        scenarioTitle: scenario.titleEn,
        score,
        maxScore: 100,
        selectedThreat,
        selectedActions,
        passed,
      }),
    });
    await loadAttempts();
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-[#17212B]">{t.simulation.title}</h1>
        <p className="text-sm text-slate-500 mt-1">{t.simulation.subtitle}</p>
      </div>

      {/* Scenario Selector Tabs */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5">
        {SIMULATION_SCENARIOS.map((sc) => {
          const isActive = sc.id === scenario.id;
          return (
            <button
              key={sc.id}
              type="button"
              onClick={() => handleSelectScenario(sc.id)}
              className={`p-3.5 rounded-xl border text-start transition-all ${
                isActive
                  ? 'bg-[#17212B] border-[#17212B] text-white'
                  : 'bg-white border-slate-200 text-[#17212B] hover:border-slate-300'
              }`}
            >
              <div className={`text-[11px] font-mono font-semibold ${isActive ? 'text-[#B7FF00]' : 'text-slate-500'}`}>
                {sc.code}
              </div>
              <div className="text-xs font-semibold mt-1 line-clamp-2">
                {lang === 'ar' ? sc.categoryAr : sc.categoryEn}
              </div>
            </button>
          );
        })}
      </div>

      {/* Active Scenario Lab */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Scenario Brief & Evidence */}
        <div className="lg:col-span-5 bg-white border border-slate-200 rounded-xl p-5 space-y-4">
          <div>
            <div className="text-xs font-mono text-slate-500">{scenario.code}</div>
            <h2 className="text-base font-bold text-[#17212B] mt-1">
              {lang === 'ar' ? scenario.titleAr : scenario.titleEn}
            </h2>
            <p className="text-xs text-slate-600 mt-2 leading-relaxed">
              {lang === 'ar' ? scenario.briefAr : scenario.briefEn}
            </p>
          </div>

          <div className="pt-3 border-t border-slate-100 space-y-2">
            <h3 className="text-xs font-semibold text-[#17212B]">Evidence & Telemetry Clues</h3>
            <div className="space-y-1.5">
              {(lang === 'ar' ? scenario.evidenceLinesAr : scenario.evidenceLinesEn).map((line, i) => (
                <div key={i} className="p-2.5 bg-[#F7F9FA] rounded-lg font-mono text-[11px] text-[#17212B]">
                  {line}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Interactive Decision Panel */}
        <div className="lg:col-span-7 bg-white border border-slate-200 rounded-xl p-5 space-y-5">
          {/* Step 1 */}
          <div className="space-y-2.5">
            <h3 className="text-xs font-semibold text-[#17212B]">{t.simulation.stepIdentify}</h3>
            <div className="space-y-2">
              {scenario.threatOptions.map((opt) => (
                <label
                  key={opt.id}
                  className={`flex items-center gap-3 p-3 rounded-lg border cursor-pointer text-xs transition-colors ${
                    selectedThreat === opt.id
                      ? 'bg-[#B7FF00]/20 border-[#17212B] font-semibold'
                      : 'bg-[#F7F9FA] border-slate-200 hover:border-slate-300'
                  }`}
                >
                  <input
                    type="radio"
                    name="threat"
                    checked={selectedThreat === opt.id}
                    onChange={() => setSelectedThreat(opt.id)}
                  />
                  <span>{lang === 'ar' ? opt.labelAr : opt.labelEn}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Step 2 */}
          <div className="space-y-2.5 pt-3 border-t border-slate-100">
            <h3 className="text-xs font-semibold text-[#17212B]">{t.simulation.stepActions}</h3>
            <div className="space-y-2">
              {scenario.actionOptions.map((act) => (
                <label
                  key={act.id}
                  className={`flex items-center gap-3 p-3 rounded-lg border cursor-pointer text-xs transition-colors ${
                    selectedActions.includes(act.id)
                      ? 'bg-[#00E5FF]/12 border-[#0891B2] font-semibold'
                      : 'bg-[#F7F9FA] border-slate-200 hover:border-slate-300'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={selectedActions.includes(act.id)}
                    onChange={() => toggleAction(act.id)}
                  />
                  <span>{lang === 'ar' ? act.labelAr : act.labelEn}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              type="button"
              disabled={!selectedThreat || selectedActions.length === 0}
              onClick={handleEvaluate}
              className="px-5 py-2.5 bg-[#B7FF00] text-[#17212B] text-xs font-bold rounded-lg neon-glow-lime disabled:opacity-50"
            >
              {t.simulation.evaluateBtn}
            </button>
            {evaluated && (
              <button
                type="button"
                onClick={() => handleSelectScenario(scenario.id)}
                className="px-4 py-2.5 bg-white border border-slate-200 text-xs font-semibold rounded-lg"
              >
                {t.simulation.retryBtn}
              </button>
            )}
          </div>

          {/* Evaluation Result */}
          {evaluated && (
            <div className="pt-4 border-t border-slate-100 space-y-4">
              <div className="flex items-center justify-between p-4 rounded-xl bg-[#F7F9FA]">
                <div className="flex items-center gap-3">
                  {evaluated.passed ? (
                    <CheckCircle2 className="w-6 h-6 text-[#137A3E]" />
                  ) : (
                    <XCircle className="w-6 h-6 text-[#FF3B5C]" />
                  )}
                  <div>
                    <div className="text-sm font-bold text-[#17212B]">
                      {evaluated.passed ? t.simulation.passed : t.simulation.needsReview}
                    </div>
                    <div className="text-xs text-slate-500">
                      {evaluated.missedActions.length > 0 && `Missed ${evaluated.missedActions.length} key action(s). `}
                      {evaluated.wrongActions.length > 0 && `Selected ${evaluated.wrongActions.length} unsafe action(s).`}
                    </div>
                  </div>
                </div>
                <div className="text-end">
                  <div className="text-[11px] text-slate-500">{t.simulation.scoreLabel}</div>
                  <div className="text-2xl font-mono font-bold text-[#17212B] tabular-nums">
                    {evaluated.score}/100
                  </div>
                </div>
              </div>

              <div className="space-y-1.5">
                <h4 className="text-xs font-semibold text-[#17212B]">{t.simulation.mistakeReview}</h4>
                <p className="text-xs text-slate-600 leading-relaxed">
                  {lang === 'ar' ? scenario.explanationAr : scenario.explanationEn}
                </p>
              </div>

              <div className="space-y-1.5">
                <h4 className="text-xs font-semibold text-[#17212B]">{t.simulation.correctWorkflow}</h4>
                <ol className="list-decimal list-inside space-y-1 text-xs text-slate-700">
                  {(lang === 'ar' ? scenario.workflowAr : scenario.workflowEn).map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ol>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Completion Report */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-100 flex items-center gap-2">
          <Award className="w-4 h-4 text-[#17212B]" />
          <h2 className="text-sm font-semibold text-[#17212B]">{t.simulation.completionReport}</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-start border-collapse text-xs">
            <thead>
              <tr className="bg-[#F7F9FA] border-b border-slate-200 text-slate-500">
                <th className="py-2.5 px-4 text-start font-semibold">ID</th>
                <th className="py-2.5 px-4 text-start font-semibold">Scenario</th>
                <th className="py-2.5 px-4 text-start font-semibold">{t.common.analyst}</th>
                <th className="py-2.5 px-4 text-start font-semibold">{t.simulation.scoreLabel}</th>
                <th className="py-2.5 px-4 text-start font-semibold">{t.common.status}</th>
                <th className="py-2.5 px-4 text-start font-semibold">{t.common.timestamp}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {attempts.map((a) => (
                <tr key={a.id} className="hover:bg-[#F7F9FA]">
                  <td className="py-2.5 px-4 font-mono font-semibold">{a.id}</td>
                  <td className="py-2.5 px-4 text-[#17212B]">{a.scenarioTitle}</td>
                  <td className="py-2.5 px-4 text-slate-600">{a.analyst}</td>
                  <td className="py-2.5 px-4 font-mono font-bold tabular-nums">
                    {a.score}/{a.maxScore}
                  </td>
                  <td className={`py-2.5 px-4 font-semibold ${a.passed ? 'text-[#137A3E]' : 'text-[#FF3B5C]'}`}>
                    {a.passed ? t.simulation.passed : t.simulation.needsReview}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-slate-400">
                    {a.completedAt.slice(0, 16).replace('T', ' ')}
                  </td>
                </tr>
              ))}
              {attempts.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-400">
                    Complete any scenario above to record your SOC simulation score.
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
