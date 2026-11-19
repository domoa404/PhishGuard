import { useEffect, useState } from 'react';
import { CheckCircle2, Plus, ShieldAlert } from 'lucide-react';
import { apiFetch } from '../lib/api.ts';
import { getT } from '../i18n/translations.ts';
import { ScoreBar, SeverityMarker } from '../components/StatusText.tsx';
import type { IncidentRecord, Language, NistStage, RiskRecord, ThreatSeverity } from '../types/phishguard.ts';

const STAGES: NistStage[] = [
  'Preparation',
  'Detection & Analysis',
  'Containment',
  'Eradication',
  'Recovery',
  'Post-Incident Review',
];

const RESPONSE_ACTIONS = [
  'quarantine_email',
  'block_url',
  'flag_sender',
  'disable_account',
  'isolate_endpoint',
  'remove_indicators',
  'verify_recovery',
  'close_incident',
] as const;

export function IncidentResponseView({ lang }: { lang: Language }) {
  const t = getT(lang);
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [risks, setRisks] = useState<RiskRecord[]>([]);
  const [selectedId, setSelectedId] = useState<string>('');
  const [notesDraft, setNotesDraft] = useState('');
  const [showNewForm, setShowNewForm] = useState(false);

  // Create form
  const [title, setTitle] = useState('');
  const [category, setCategory] = useState('Credential Phishing');
  const [severity, setSeverity] = useState<ThreatSeverity>('High');
  const [affectedAsset, setAffectedAsset] = useState('');
  const [threatSource, setThreatSource] = useState('');
  const [riskScore, setRiskScore] = useState(75);
  const [assignedAnalyst, setAssignedAnalyst] = useState('Tariq Haddad');
  const [evidenceSummary, setEvidenceSummary] = useState('');

  const [error, setError] = useState('');
  const [feedback, setFeedback] = useState('');

  const loadData = async () => {
    const [incs, rsk] = await Promise.all([
      apiFetch<IncidentRecord[]>('/api/incidents'),
      apiFetch<{ risks: RiskRecord[] }>('/api/risks'),
    ]);
    setIncidents(incs);
    setRisks(rsk.risks);
    if (!selectedId && incs.length > 0) {
      setSelectedId(incs[0].id);
      setNotesDraft(incs[0].investigationNotes);
    } else if (selectedId) {
      const current = incs.find((i) => i.id === selectedId);
      if (current) setNotesDraft(current.investigationNotes);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const activeIncident = incidents.find((i) => i.id === selectedId) || incidents[0];

  const handleSelectIncident = (inc: IncidentRecord) => {
    setSelectedId(inc.id);
    setNotesDraft(inc.investigationNotes);
    setFeedback('');
    setError('');
  };

  const handleStageChange = async (nistStage: NistStage) => {
    if (!activeIncident) return;
    setError('');
    try {
      await apiFetch(`/api/incidents/${activeIncident.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ nistStage }),
      });
      setFeedback(`Moved ${activeIncident.id} to stage: ${nistStage}`);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to update stage');
    }
  };

  const handleLinkRisk = async (linkedRiskId: string) => {
    if (!activeIncident) return;
    setError('');
    try {
      await apiFetch(`/api/incidents/${activeIncident.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ linkedRiskId: linkedRiskId || null }),
      });
      setFeedback(`Updated risk linkage for ${activeIncident.id}.`);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to link risk');
    }
  };

  const handleSaveNotes = async () => {
    if (!activeIncident) return;
    setError('');
    try {
      await apiFetch(`/api/incidents/${activeIncident.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ investigationNotes: notesDraft }),
      });
      setFeedback('Investigation notes saved.');
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to save notes');
    }
  };

  const handleExecuteSimAction = async (actionKey: (typeof RESPONSE_ACTIONS)[number]) => {
    if (!activeIncident) return;
    setError('');
    setFeedback('');
    try {
      const label = t.incidents.actionLabels[actionKey];
      await apiFetch(`/api/incidents/${activeIncident.id}/actions`, {
        method: 'POST',
        body: JSON.stringify({
          actionKey,
          label,
          notes: `Executed simulated SOC control "${label}" on ${activeIncident.affectedAsset}.`,
        }),
      });
      setFeedback(`[${t.common.simulationOnly}] ${label} logged to audit trail.`);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed');
    }
  };

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    try {
      const res = await apiFetch<{ id: string }>('/api/incidents', {
        method: 'POST',
        body: JSON.stringify({
          title,
          category,
          severity,
          affectedAsset,
          threatSource,
          riskScore,
          assignedAnalyst,
          evidenceSummary,
        }),
      });
      setShowNewForm(false);
      setTitle('');
      setAffectedAsset('');
      setThreatSource('');
      setEvidenceSummary('');
      setSelectedId(res.id);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to create incident');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#17212B]">{t.incidents.title}</h1>
          <p className="text-sm text-slate-500 mt-1">{t.incidents.subtitle}</p>
        </div>
        <button
          type="button"
          onClick={() => setShowNewForm((s) => !s)}
          className="inline-flex items-center gap-2 px-4 py-2 bg-[#B7FF00] text-[#17212B] text-xs font-bold rounded-lg neon-glow-lime whitespace-nowrap shrink-0"
        >
          <Plus className="w-4 h-4" />
          {t.incidents.newIncident}
        </button>
      </div>

      {showNewForm && (
        <form onSubmit={handleCreateIncident} className="bg-white border border-slate-200 rounded-xl p-5 space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <input
              required
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Incident Title"
              className="sm:col-span-2 px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            />
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value as ThreatSeverity)}
              className="px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            >
              <option value="Low">Low</option>
              <option value="Medium">Medium</option>
              <option value="High">High</option>
              <option value="Critical">Critical</option>
            </select>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
            <input
              required
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              placeholder="Category"
              className="px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            />
            <input
              required
              value={affectedAsset}
              onChange={(e) => setAffectedAsset(e.target.value)}
              placeholder="Affected Asset"
              className="px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            />
            <input
              required
              value={threatSource}
              onChange={(e) => setThreatSource(e.target.value)}
              placeholder="Threat Source (Email/URL/IP)"
              className="px-3 py-2 font-mono text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            />
            <input
              type="number"
              min={0}
              max={100}
              value={riskScore}
              onChange={(e) => setRiskScore(Number(e.target.value))}
              className="px-3 py-2 font-mono text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <input
              required
              value={assignedAnalyst}
              onChange={(e) => setAssignedAnalyst(e.target.value)}
              placeholder="Assigned Analyst"
              className="px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            />
            <input
              required
              value={evidenceSummary}
              onChange={(e) => setEvidenceSummary(e.target.value)}
              placeholder="Initial Evidence Summary"
              className="sm:col-span-2 px-3 py-2 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg"
            />
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setShowNewForm(false)}
              className="px-4 py-2 text-xs font-semibold text-slate-600"
            >
              {t.common.cancel}
            </button>
            <button
              type="submit"
              className="px-4 py-2 bg-[#17212B] text-white text-xs font-semibold rounded-lg"
            >
              {t.common.create}
            </button>
          </div>
        </form>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Incident Queue */}
        <div className="lg:col-span-4 bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 overflow-hidden">
          {incidents.map((inc) => {
            const active = activeIncident?.id === inc.id;
            return (
              <button
                key={inc.id}
                type="button"
                onClick={() => handleSelectIncident(inc)}
                className={`w-full text-start p-4 transition-colors ${
                  active ? 'bg-[#F7F9FA]' : 'hover:bg-[#F7F9FA]/60'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-bold text-[#17212B]">{inc.id}</span>
                  <SeverityMarker severity={inc.severity} label={t.severities[inc.severity]} />
                </div>
                <div className="mt-1.5 text-sm font-semibold text-[#17212B] line-clamp-2">{inc.title}</div>
                <div className="mt-2 flex items-center justify-between text-xs text-slate-500">
                  <span>{inc.status}</span>
                  <span>{inc.nistStage}</span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Incident Inspector */}
        {activeIncident && (
          <div className="lg:col-span-8 bg-white border border-slate-200 rounded-xl p-5 space-y-6">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4 pb-4 border-b border-slate-100">
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
                  <span className="font-mono font-bold text-[#17212B]">{activeIncident.id}</span>
                  <span aria-hidden="true">·</span>
                  <span>{activeIncident.category}</span>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono">{activeIncident.detectedAt.slice(0, 16).replace('T', ' ')}</span>
                </div>
                <h2 className="text-lg font-bold text-[#17212B]">{activeIncident.title}</h2>
                <p className="text-xs text-slate-600">{activeIncident.evidenceSummary}</p>
              </div>
              <div className="flex flex-col sm:items-end gap-2 shrink-0">
                <SeverityMarker severity={activeIncident.severity} label={t.severities[activeIncident.severity]} />
                <ScoreBar score={activeIncident.riskScore} />
              </div>
            </div>

            {/* Metadata Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
              <div>
                <div className="text-slate-500">Affected Asset</div>
                <div className="font-semibold text-[#17212B] mt-0.5">{activeIncident.affectedAsset}</div>
              </div>
              <div>
                <div className="text-slate-500">Threat Source</div>
                <div className="font-mono font-semibold text-[#17212B] mt-0.5 break-all">
                  {activeIncident.threatSource}
                </div>
              </div>
              <div>
                <label className="block text-slate-500 mb-1">{t.incidents.linkRisk}</label>
                <select
                  value={activeIncident.linkedRiskId || ''}
                  onChange={(e) => handleLinkRisk(e.target.value)}
                  className="w-full px-2.5 py-1.5 text-xs font-mono bg-[#F7F9FA] border border-slate-200 rounded-lg"
                >
                  <option value="">— None —</option>
                  {risks.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.id} ({r.assetAffected})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* NIST SP 800-61 Lifecycle Stepper */}
            <div className="space-y-2.5 pt-2 border-t border-slate-100">
              <h3 className="text-xs font-semibold text-[#17212B]">{t.incidents.lifecycleTitle}</h3>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
                {STAGES.map((stage) => {
                  const isCurrent = activeIncident.nistStage === stage;
                  return (
                    <button
                      key={stage}
                      type="button"
                      onClick={() => handleStageChange(stage)}
                      className={`p-2.5 rounded-lg border text-xs font-semibold text-start transition-all ${
                        isCurrent
                          ? 'bg-[#B7FF00] border-[#17212B] text-[#17212B]'
                          : 'bg-[#F7F9FA] border-slate-200 text-slate-600 hover:border-slate-300'
                      }`}
                    >
                      {t.incidents.stages[stage]}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Simulated Response Actions */}
            <div className="space-y-3 pt-2 border-t border-slate-100">
              <div className="flex items-center justify-between gap-2">
                <h3 className="text-xs font-semibold text-[#17212B]">{t.incidents.responseActionsTitle}</h3>
                <span className="text-[11px] font-semibold text-[#007D8C]">{t.common.simulationOnly}</span>
              </div>
              <p className="text-xs text-slate-500">{t.incidents.simBanner}</p>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
                {RESPONSE_ACTIONS.map((key) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => handleExecuteSimAction(key)}
                    className="px-3 py-2 text-xs font-medium bg-[#F7F9FA] border border-slate-200 rounded-lg text-start hover:bg-[#17212B] hover:text-white transition-colors"
                  >
                    {t.incidents.actionLabels[key]}
                  </button>
                ))}
              </div>
            </div>

            {error && <p className="text-xs font-medium text-[#FF3B5C]">{error}</p>}
            {feedback && (
              <p className="text-xs font-medium text-[#137A3E] bg-[#39FF88]/15 p-2.5 rounded-lg">{feedback}</p>
            )}

            {/* Executed Actions Log */}
            {activeIncident.actions.length > 0 && (
              <div className="space-y-2 pt-2 border-t border-slate-100">
                <h3 className="text-xs font-semibold text-[#17212B]">Response Action History</h3>
                <div className="divide-y divide-slate-100 border border-slate-200 rounded-lg">
                  {activeIncident.actions.map((act) => (
                    <div key={act.id} className="p-2.5 flex items-center justify-between gap-4 text-xs">
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="w-3.5 h-3.5 text-[#137A3E] shrink-0" />
                        <span className="font-semibold text-[#17212B]">{act.label}</span>
                        <span className="text-slate-500">· {act.notes}</span>
                      </div>
                      <span className="font-mono text-[11px] text-slate-400 whitespace-nowrap">
                        {act.executedBy} · {t.common.simulationOnly}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Investigation Notes */}
            <div className="space-y-2 pt-2 border-t border-slate-100">
              <h3 className="text-xs font-semibold text-[#17212B]">{t.incidents.notesTitle}</h3>
              <textarea
                value={notesDraft}
                onChange={(e) => setNotesDraft(e.target.value)}
                rows={3}
                className="w-full p-3 text-xs bg-[#F7F9FA] border border-slate-200 rounded-lg focus:outline-none focus:border-[#17212B]"
              />
              <button
                type="button"
                onClick={handleSaveNotes}
                className="px-4 py-2 bg-[#17212B] text-white text-xs font-semibold rounded-lg hover:bg-slate-800"
              >
                {t.incidents.saveNotes}
              </button>
            </div>
          </div>
        )}
        {!activeIncident && (
          <div className="lg:col-span-8 bg-white border border-slate-200 rounded-xl py-16 text-center text-slate-400">
            <ShieldAlert className="w-8 h-8 mx-auto mb-2 opacity-40" />
            {t.common.noData}
          </div>
        )}
      </div>
    </div>
  );
}
