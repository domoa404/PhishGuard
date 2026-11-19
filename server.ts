import express from 'express';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { z } from 'zod';
import {
  addAuditLog,
  buildDashboardSummary,
  db,
  getKnownBadIocs,
  getRiskThresholds,
  hashPassword,
  initDatabase,
  listAuditLogs,
  listEvidence,
  listIncidents,
  listNotifications,
  listRisks,
  listScans,
  listSimulationAttempts,
  listThreatIntel,
  listTimelineEvents,
  listUsers,
  riskScoreToLevel,
  setRiskThresholds,
  sha256Hex,
  verifyPassword,
} from './src/server/db.ts';
import { analyzeEmailHeuristic, analyzeUrlHeuristic, scoreToSeverity } from './src/server/analyzers.ts';
import { getThreatIntelProviderStatuses, queryExternalThreatIntel } from './src/server/threatIntel.ts';
import type { NistStage, UserRole } from './src/types/phishguard.ts';

dotenv.config();
initDatabase();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);

app.use(express.json({ limit: '3mb' }));

// Extract active actor & role from headers (defaults to Security Analyst for interactive demo session)
function getActor(req: express.Request): { actor: string; role: UserRole } {
  const actor = String(req.header('x-phishguard-actor') || 'Tariq Haddad').slice(0, 80);
  const rawRole = String(req.header('x-phishguard-role') || 'Security Analyst');
  const role: UserRole =
    rawRole === 'Administrator' || rawRole === 'Security Analyst' || rawRole === 'Viewer'
      ? rawRole
      : 'Security Analyst';
  return { actor, role };
}

function requireWriteRole(req: express.Request, res: express.Response, allowed: UserRole[]): { actor: string; role: UserRole } | null {
  const current = getActor(req);
  if (!allowed.includes(current.role)) {
    res.status(403).json({
      error: `Role "${current.role}" has read-only permissions for this operation. Switch to Security Analyst or Administrator in Settings.`,
    });
    return null;
  }
  return current;
}

// Health check
app.get('/api/health', (_req, res) => {
  try {
    db.prepare('SELECT 1').get();
    res.json({ status: 'operational', database: 'sqlite', timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ status: 'degraded', error: String(err) });
  }
});

// Dashboard summary
app.get('/api/dashboard', (req, res) => {
  const periodParam = String(req.query.period || 'daily');
  const period = periodParam === 'weekly' || periodParam === 'monthly' ? periodParam : 'daily';
  res.json(buildDashboardSummary(period));
});

// Global Search across scans, incidents, IOCs, risks
app.get('/api/search', (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  if (!q) {
    res.json({ scans: [], incidents: [], risks: [], intel: [] });
    return;
  }
  const scans = listScans()
    .filter((s) => s.submittedObject.toLowerCase().includes(q) || s.id.toLowerCase().includes(q) || s.classification.toLowerCase().includes(q))
    .slice(0, 5);
  const incidents = listIncidents()
    .filter((i) => i.title.toLowerCase().includes(q) || i.id.toLowerCase().includes(q) || i.threatSource.toLowerCase().includes(q))
    .slice(0, 5);
  const risks = listRisks()
    .filter((r) => r.assetAffected.toLowerCase().includes(q) || r.id.toLowerCase().includes(q) || r.threatDescription.toLowerCase().includes(q))
    .slice(0, 5);
  const intel = listThreatIntel()
    .filter((t) => t.indicator.toLowerCase().includes(q) || t.category.toLowerCase().includes(q))
    .slice(0, 5);
  res.json({ scans, incidents, risks, intel });
});

// Email Phishing Analysis
const emailScanSchema = z.object({
  rawEmail: z.string().max(1_800_000).optional(),
  senderEmail: z.string().max(320).optional(),
  senderDisplayName: z.string().max(240).optional(),
  replyTo: z.string().max(320).optional(),
  subject: z.string().max(500).optional(),
  body: z.string().max(1_500_000).optional(),
  headersText: z.string().max(500_000).optional(),
  attachmentNames: z.array(z.string().max(260)).max(25).optional(),
  filename: z.string().max(260).optional(),
});

app.post('/api/analyze/email', (req, res) => {
  const auth = requireWriteRole(req, res, ['Administrator', 'Security Analyst']);
  if (!auth) return;

  const parsed = emailScanSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid email analysis payload', issues: parsed.error.issues });
    return;
  }

  const data = parsed.data;
  if (data.filename && !/\.(eml|txt)$/i.test(data.filename)) {
    res.status(400).json({ error: 'Only .eml and .txt email files are permitted.' });
    return;
  }

  if (!data.rawEmail && !data.body && !data.senderEmail && !data.subject) {
    res.status(400).json({ error: 'Provide raw email content, .eml/.txt file, or email fields to analyze.' });
    return;
  }

  const knownBad = getKnownBadIocs();
  const result = analyzeEmailHeuristic(data, knownBad);
  const scanId = `SCN-${Date.now().toString().slice(-6)}`;
  const severity = scoreToSeverity(result.riskScore);
  const now = new Date().toISOString();
  const submittedObject = `${result.subject} (${result.senderEmail})`;

  db.prepare(
    `INSERT INTO scans (id, analysis_type, submitted_object, classification, severity, risk_score, confidence, analyst, incident_id, created_at, details_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    scanId,
    'email',
    submittedObject,
    result.classification,
    severity,
    result.riskScore,
    result.confidence,
    auth.actor,
    null,
    now,
    JSON.stringify(result),
  );

  if (result.riskScore >= 60) {
    db.prepare(
      `INSERT INTO notifications (id, title, title_ar, severity, created_at, read, target_section) VALUES (?, ?, ?, ?, ?, 0, 'email')`,
    ).run(
      `NTF-${Date.now()}`,
      `${result.classification} detected in ${scanId} (${result.riskScore}/100)`,
      `تم اكتشاف ${result.classification} في الفحص ${scanId} (${result.riskScore}/100)`,
      severity,
      now,
    );
  }

  addAuditLog({
    actor: auth.actor,
    role: auth.role,
    action: 'EMAIL_SCAN_EXECUTED',
    target: scanId,
    category: 'scan',
    simulated: false,
    details: `Analyzed email "${result.subject}" -> ${result.classification} (${result.riskScore}/100).`,
  });

  res.status(201).json({
    id: scanId,
    analysisType: 'email',
    submittedObject,
    classification: result.classification,
    severity,
    riskScore: result.riskScore,
    confidence: result.confidence,
    analyst: auth.actor,
    incidentId: null,
    createdAt: now,
    details: result,
  });
});

// URL & Domain Scanner
const urlScanSchema = z.object({
  url: z.string().min(3).max(2048),
});

app.post('/api/analyze/url', async (req, res) => {
  const auth = requireWriteRole(req, res, ['Administrator', 'Security Analyst']);
  if (!auth) return;

  const parsed = urlScanSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Please provide a valid URL or domain name.' });
    return;
  }

  try {
    const knownBad = getKnownBadIocs();
    const matchedLocal = knownBad.filter((k) =>
      parsed.data.url.toLowerCase().includes(k.indicator.toLowerCase()),
    );
    const result = analyzeUrlHeuristic(parsed.data.url, matchedLocal);

    // Query external threat intelligence ONLY if configured via server env vars
    const ext = await queryExternalThreatIntel(result.hostname, 'Domain');
    if (ext.verifiedExternal && ext.reputationScore !== null) {
      result.intelligenceSource = ext.provider;
      result.intelligenceVerified = true;
      result.riskScore = Math.max(result.riskScore, ext.reputationScore);
    }

    const scanId = `SCN-${Date.now().toString().slice(-6)}`;
    const severity = scoreToSeverity(result.riskScore);
    const now = new Date().toISOString();

    db.prepare(
      `INSERT INTO scans (id, analysis_type, submitted_object, classification, severity, risk_score, confidence, analyst, incident_id, created_at, details_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      scanId,
      'url',
      result.normalizedUrl,
      result.classification,
      severity,
      result.riskScore,
      result.confidence,
      auth.actor,
      null,
      now,
      JSON.stringify(result),
    );

    addAuditLog({
      actor: auth.actor,
      role: auth.role,
      action: 'URL_SCAN_EXECUTED',
      target: scanId,
      category: 'scan',
      simulated: false,
      details: `Scanned URL ${result.hostname} -> ${result.classification} (${result.riskScore}/100).`,
    });

    res.status(201).json({
      id: scanId,
      analysisType: 'url',
      submittedObject: result.normalizedUrl,
      classification: result.classification,
      severity,
      riskScore: result.riskScore,
      confidence: result.confidence,
      analyst: auth.actor,
      incidentId: null,
      createdAt: now,
      details: result,
    });
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Unable to parse URL' });
  }
});

// Scans list
app.get('/api/scans', (_req, res) => {
  res.json(listScans());
});

// Threat Intelligence
app.get('/api/threat-intel', (_req, res) => {
  res.json({
    iocs: listThreatIntel(),
    providers: getThreatIntelProviderStatuses(),
  });
});

const iocSchema = z.object({
  indicator: z.string().min(3).max(500),
  iocType: z.enum(['IP', 'Domain', 'URL', 'MD5', 'SHA-1', 'SHA-256']),
  category: z.string().min(2).max(120),
  reputationScore: z.number().min(0).max(100),
  notes: z.string().max(600).optional(),
});

app.post('/api/threat-intel', (req, res) => {
  const auth = requireWriteRole(req, res, ['Administrator', 'Security Analyst']);
  if (!auth) return;

  const parsed = iocSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid IOC fields', issues: parsed.error.issues });
    return;
  }

  const d = parsed.data;
  const now = new Date().toISOString();
  const id = `IOC-${Date.now().toString().slice(-5)}`;
  const severity = scoreToSeverity(d.reputationScore);

  try {
    db.prepare(
      `INSERT INTO threat_intel (id, indicator, ioc_type, category, reputation_score, severity, source, verified_external, first_seen, last_updated, notes)
       VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
    ).run(id, d.indicator.trim(), d.iocType, d.category.trim(), d.reputationScore, severity, 'Analyst Submission (Local Store)', now, now, d.notes || 'Added manually during SOC investigation.');

    addAuditLog({
      actor: auth.actor,
      role: auth.role,
      action: 'IOC_ADDED',
      target: id,
      category: 'intel',
      simulated: false,
      details: `Added ${d.iocType} indicator "${d.indicator}" (${severity}).`,
    });

    res.status(201).json({ ok: true, id });
  } catch {
    res.status(409).json({ error: 'Indicator already exists in Threat Intelligence repository.' });
  }
});

app.post('/api/threat-intel/lookup', async (req, res) => {
  const indicator = String(req.body?.indicator || '').trim();
  const iocType = String(req.body?.iocType || 'Domain');
  if (!indicator) {
    res.status(400).json({ error: 'Indicator is required for lookup.' });
    return;
  }

  const localMatches = listThreatIntel().filter(
    (i) => i.indicator.toLowerCase() === indicator.toLowerCase() || i.indicator.toLowerCase().includes(indicator.toLowerCase()),
  );
  const external = await queryExternalThreatIntel(indicator, iocType);
  res.json({ indicator, localMatches, external });
});

// Cyber Risk Assessment Engine
app.get('/api/risks', (_req, res) => {
  res.json({
    risks: listRisks(),
    thresholds: getRiskThresholds(),
  });
});

const riskSchema = z.object({
  assetAffected: z.string().min(2).max(200),
  threatDescription: z.string().min(3).max(400),
  vulnerability: z.string().min(3).max(400),
  likelihood: z.number().int().min(1).max(5),
  impact: z.number().int().min(1).max(5),
  existingControls: z.string().max(400),
  controlEffectiveness: z.number().int().min(0).max(90),
  riskOwner: z.string().min(2).max(120),
  treatmentStrategy: z.enum(['Avoid', 'Mitigate', 'Transfer', 'Accept']),
  treatmentStatus: z.enum(['Open', 'In Progress', 'Controlled', 'Accepted']).optional(),
  mitigationPlan: z.string().min(3).max(600),
  linkedIncidentId: z.string().nullable().optional(),
});

function generateRiskRecommendation(inherent: number, residual: number, strategy: string): string {
  if (inherent >= 17) {
    return `Critical inherent exposure (${inherent}/25). Enforce immediate technical controls (${strategy}), mandate FIDO2 MFA, and schedule executive risk review.`;
  }
  if (residual >= 10) {
    return `Elevated residual risk (${residual}/25). Strengthen gateway filtering, verify control effectiveness quarterly, and test incident playbook.`;
  }
  return `Risk within manageable tolerance (${residual}/25) under ${strategy} strategy. Maintain continuous monitoring and periodic reassessment.`;
}

app.post('/api/risks', (req, res) => {
  const auth = requireWriteRole(req, res, ['Administrator', 'Security Analyst']);
  if (!auth) return;

  const parsed = riskSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid risk assessment data', issues: parsed.error.issues });
    return;
  }

  const d = parsed.data;
  const inherentRisk = d.likelihood * d.impact;
  const residualRisk = Math.max(1, Math.round(inherentRisk * (1 - d.controlEffectiveness / 100)));
  const thresholds = getRiskThresholds();
  const inherentLevel = riskScoreToLevel(inherentRisk, thresholds);
  const residualLevel = riskScoreToLevel(residualRisk, thresholds);
  const recommendations = generateRiskRecommendation(inherentRisk, residualRisk, d.treatmentStrategy);
  const id = `RSK-${String(Math.floor(Math.random() * 900 + 100))}`;
  const now = new Date().toISOString();

  db.prepare(
    `INSERT INTO risks (id, asset_affected, threat_description, vulnerability, likelihood, impact, inherent_risk, inherent_level, existing_controls, control_effectiveness, residual_risk, residual_level, risk_owner, treatment_strategy, treatment_status, mitigation_plan, recommendations, linked_incident_id, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    id,
    d.assetAffected,
    d.threatDescription,
    d.vulnerability,
    d.likelihood,
    d.impact,
    inherentRisk,
    inherentLevel,
    d.existingControls,
    d.controlEffectiveness,
    residualRisk,
    residualLevel,
    d.riskOwner,
    d.treatmentStrategy,
    d.treatmentStatus || 'Open',
    d.mitigationPlan,
    recommendations,
    d.linkedIncidentId || null,
    now,
  );

  addAuditLog({
    actor: auth.actor,
    role: auth.role,
    action: 'RISK_CREATED',
    target: id,
    category: 'risk',
    simulated: false,
    details: `Created risk assessment for "${d.assetAffected}" (Inherent: ${inherentRisk}, Residual: ${residualRisk}).`,
  });

  res.status(201).json({ ok: true, id });
});

app.patch('/api/risks/:id', (req, res) => {
  const auth = requireWriteRole(req, res, ['Administrator', 'Security Analyst']);
  if (!auth) return;

  const existing = listRisks().find((r) => r.id === req.params.id);
  if (!existing) {
    res.status(404).json({ error: 'Risk record not found' });
    return;
  }

  const likelihood = Number(req.body.likelihood ?? existing.likelihood);
  const impact = Number(req.body.impact ?? existing.impact);
  const controlEffectiveness = Number(req.body.controlEffectiveness ?? existing.controlEffectiveness);
  const treatmentStrategy = String(req.body.treatmentStrategy ?? existing.treatmentStrategy);
  const treatmentStatus = String(req.body.treatmentStatus ?? existing.treatmentStatus);
  const mitigationPlan = String(req.body.mitigationPlan ?? existing.mitigationPlan);
  const linkedIncidentId = req.body.linkedIncidentId !== undefined ? req.body.linkedIncidentId : existing.linkedIncidentId;

  const inherentRisk = likelihood * impact;
  const residualRisk = Math.max(1, Math.round(inherentRisk * (1 - controlEffectiveness / 100)));
  const thresholds = getRiskThresholds();
  const inherentLevel = riskScoreToLevel(inherentRisk, thresholds);
  const residualLevel = riskScoreToLevel(residualRisk, thresholds);
  const recommendations = generateRiskRecommendation(inherentRisk, residualRisk, treatmentStrategy);
  const now = new Date().toISOString();

  db.prepare(
    `UPDATE risks SET likelihood = ?, impact = ?, inherent_risk = ?, inherent_level = ?, control_effectiveness = ?, residual_risk = ?, residual_level = ?, treatment_strategy = ?, treatment_status = ?, mitigation_plan = ?, recommendations = ?, linked_incident_id = ?, updated_at = ? WHERE id = ?`,
  ).run(
    likelihood,
    impact,
    inherentRisk,
    inherentLevel,
    controlEffectiveness,
    residualRisk,
    residualLevel,
    treatmentStrategy,
    treatmentStatus,
    mitigationPlan,
    recommendations,
    linkedIncidentId,
    now,
    req.params.id,
  );

  addAuditLog({
    actor: auth.actor,
    role: auth.role,
    action: 'RISK_UPDATED',
    target: req.params.id,
    category: 'risk',
    simulated: false,
    details: `Updated treatment status to ${treatmentStatus}, strategy ${treatmentStrategy}, residual ${residualRisk}/25.`,
  });

  res.json({ ok: true });
});

// Incident Response Center
app.get('/api/incidents', (_req, res) => {
  res.json(listIncidents());
});

const incidentSchema = z.object({
  title: z.string().min(3).max(240),
  category: z.string().min(2).max(120),
  severity: z.enum(['Low', 'Medium', 'High', 'Critical']),
  affectedAsset: z.string().min(2).max(200),
  threatSource: z.string().min(2).max(240),
  riskScore: z.number().int().min(0).max(100),
  assignedAnalyst: z.string().min(2).max(120),
  evidenceSummary: z.string().max(1000),
  investigationNotes: z.string().max(2000).optional(),
  linkedScanId: z.string().nullable().optional(),
  linkedRiskId: z.string().nullable().optional(),
});

app.post('/api/incidents', (req, res) => {
  const auth = requireWriteRole(req, res, ['Administrator', 'Security Analyst']);
  if (!auth) return;

  const parsed = incidentSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid incident payload', issues: parsed.error.issues });
    return;
  }

  const d = parsed.data;
  const id = `INC-2026-${String(Math.floor(Math.random() * 900 + 100))}`;
  const now = new Date().toISOString();

  db.prepare(
    `INSERT INTO incidents (id, title, category, severity, detected_at, affected_asset, threat_source, risk_score, assigned_analyst, status, nist_stage, evidence_summary, investigation_notes, linked_scan_id, linked_risk_id, actions_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open', 'Detection & Analysis', ?, ?, ?, ?, '[]')`,
  ).run(
    id,
    d.title,
    d.category,
    d.severity,
    now,
    d.affectedAsset,
    d.threatSource,
    d.riskScore,
    d.assignedAnalyst,
    d.evidenceSummary,
    d.investigationNotes || '',
    d.linkedScanId || null,
    d.linkedRiskId || null,
  );

  if (d.linkedScanId) {
    db.prepare('UPDATE scans SET incident_id = ? WHERE id = ?').run(id, d.linkedScanId);
  }

  db.prepare(
    `INSERT INTO timeline_events (id, incident_id, timestamp, phase, actor, description) VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(`TL-${Date.now()}`, id, now, 'Detection & Analysis', auth.actor, `Incident opened: ${d.title}`);

  db.prepare(
    `INSERT INTO notifications (id, title, title_ar, severity, created_at, read, target_section) VALUES (?, ?, ?, ?, ?, 0, 'incidents')`,
  ).run(`NTF-${Date.now()}`, `New Incident Opened: ${id}`, `تم فتح حادث أمني جديد: ${id}`, d.severity, now);

  addAuditLog({
    actor: auth.actor,
    role: auth.role,
    action: 'INCIDENT_CREATED',
    target: id,
    category: 'incident',
    simulated: false,
    details: `Created incident "${d.title}" (${d.severity})${d.linkedScanId ? ` linked to scan ${d.linkedScanId}` : ''}.`,
  });

  res.status(201).json({ ok: true, id });
});

const NIST_STAGES: NistStage[] = [
  'Preparation',
  'Detection & Analysis',
  'Containment',
  'Eradication',
  'Recovery',
  'Post-Incident Review',
];

app.patch('/api/incidents/:id', (req, res) => {
  const auth = requireWriteRole(req, res, ['Administrator', 'Security Analyst']);
  if (!auth) return;

  const inc = listIncidents().find((i) => i.id === req.params.id);
  if (!inc) {
    res.status(404).json({ error: 'Incident not found' });
    return;
  }

  const nistStage = NIST_STAGES.includes(req.body.nistStage) ? req.body.nistStage : inc.nistStage;
  const status = ['Open', 'Investigating', 'Contained', 'Closed'].includes(req.body.status)
    ? req.body.status
    : inc.status;
  const assignedAnalyst = String(req.body.assignedAnalyst || inc.assignedAnalyst);
  const investigationNotes =
    req.body.investigationNotes !== undefined ? String(req.body.investigationNotes) : inc.investigationNotes;
  const linkedRiskId = req.body.linkedRiskId !== undefined ? req.body.linkedRiskId : inc.linkedRiskId;

  db.prepare(
    `UPDATE incidents SET nist_stage = ?, status = ?, assigned_analyst = ?, investigation_notes = ?, linked_risk_id = ? WHERE id = ?`,
  ).run(nistStage, status, assignedAnalyst, investigationNotes, linkedRiskId, req.params.id);

  if (req.body.nistStage && req.body.nistStage !== inc.nistStage) {
    db.prepare(
      `INSERT INTO timeline_events (id, incident_id, timestamp, phase, actor, description) VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(`TL-${Date.now()}`, req.params.id, new Date().toISOString(), nistStage, auth.actor, `Lifecycle transitioned from ${inc.nistStage} to ${nistStage}.`);
  }

  addAuditLog({
    actor: auth.actor,
    role: auth.role,
    action: 'INCIDENT_UPDATED',
    target: req.params.id,
    category: 'incident',
    simulated: false,
    details: `Updated stage=${nistStage}, status=${status}, analyst=${assignedAnalyst}.`,
  });

  res.json({ ok: true });
});

app.post('/api/incidents/:id/actions', (req, res) => {
  const auth = requireWriteRole(req, res, ['Administrator', 'Security Analyst']);
  if (!auth) return;

  const inc = listIncidents().find((i) => i.id === req.params.id);
  if (!inc) {
    res.status(404).json({ error: 'Incident not found' });
    return;
  }

  const actionKey = String(req.body.actionKey || '');
  const label = String(req.body.label || actionKey);
  const notes = String(req.body.notes || 'Executed within PhishGuard simulated incident response environment.');
  const now = new Date().toISOString();

  const newAction = {
    id: `ACT-${Date.now()}`,
    actionKey,
    label,
    simulated: true,
    executedBy: auth.actor,
    executedAt: now,
    notes,
  };

  const updatedActions = [...inc.actions, newAction];
  let nextStatus = inc.status;
  let nextStage = inc.nistStage;

  if (actionKey === 'quarantine_email' || actionKey === 'block_url' || actionKey === 'isolate_endpoint' || actionKey === 'disable_account') {
    if (inc.status === 'Open' || inc.status === 'Investigating') nextStatus = 'Contained';
    if (inc.nistStage === 'Preparation' || inc.nistStage === 'Detection & Analysis') nextStage = 'Containment';
  } else if (actionKey === 'remove_indicators') {
    nextStage = 'Eradication';
  } else if (actionKey === 'verify_recovery') {
    nextStage = 'Recovery';
  } else if (actionKey === 'close_incident') {
    nextStatus = 'Closed';
    nextStage = 'Post-Incident Review';
  }

  db.prepare('UPDATE incidents SET actions_json = ?, status = ?, nist_stage = ? WHERE id = ?').run(
    JSON.stringify(updatedActions),
    nextStatus,
    nextStage,
    req.params.id,
  );

  db.prepare(
    `INSERT INTO timeline_events (id, incident_id, timestamp, phase, actor, description) VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(`TL-${Date.now()}`, req.params.id, now, nextStage, auth.actor, `[SIMULATED RESPONSE] ${label}: ${notes}`);

  addAuditLog({
    actor: auth.actor,
    role: auth.role,
    action: `SIM_ACTION_${actionKey.toUpperCase()}`,
    target: req.params.id,
    category: 'incident',
    simulated: true,
    details: `${label} — ${notes}`,
  });

  res.status(201).json({ ok: true, action: newAction, status: nextStatus, nistStage: nextStage });
});

// Digital Forensics & Evidence Chain of Custody
app.get('/api/forensics', (_req, res) => {
  res.json({
    evidence: listEvidence(),
    timeline: listTimelineEvents(),
  });
});

const evidenceSchema = z.object({
  incidentId: z.string().min(3),
  source: z.string().min(2).max(200),
  evidenceType: z.enum(['Email Header', 'Raw EML', 'URL Artifact', 'Auth Log', 'Attachment Metadata']),
  contentPreview: z.string().min(2).max(20000),
  status: z.enum(['Verified', 'Quarantined', 'Archived']).optional(),
});

app.post('/api/forensics/evidence', (req, res) => {
  const auth = requireWriteRole(req, res, ['Administrator', 'Security Analyst']);
  if (!auth) return;

  const parsed = evidenceSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid evidence submission', issues: parsed.error.issues });
    return;
  }

  const d = parsed.data;
  const id = `EVD-${Date.now().toString().slice(-5)}`;
  const now = new Date().toISOString();
  const sha256Hash = sha256Hex(d.contentPreview);

  db.prepare(
    `INSERT INTO evidence (id, incident_id, source, evidence_type, collected_at, collected_by, sha256_hash, status, content_preview)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(id, d.incidentId, d.source, d.evidenceType, now, auth.actor, sha256Hash, d.status || 'Verified', d.contentPreview);

  addAuditLog({
    actor: auth.actor,
    role: auth.role,
    action: 'EVIDENCE_COLLECTED',
    target: id,
    category: 'forensics',
    simulated: false,
    details: `Sealed ${d.evidenceType} for ${d.incidentId} with SHA-256 ${sha256Hash.slice(0, 16)}...`,
  });

  res.status(201).json({ ok: true, id, sha256Hash });
});

app.post('/api/forensics/timeline', (req, res) => {
  const auth = requireWriteRole(req, res, ['Administrator', 'Security Analyst']);
  if (!auth) return;

  const incidentId = String(req.body.incidentId || '');
  const phase = String(req.body.phase || 'Investigation');
  const description = String(req.body.description || '').trim();
  const timestamp = String(req.body.timestamp || new Date().toISOString());

  if (!incidentId || !description) {
    res.status(400).json({ error: 'Incident ID and description are required.' });
    return;
  }

  const id = `TL-${Date.now()}`;
  db.prepare(
    `INSERT INTO timeline_events (id, incident_id, timestamp, phase, actor, description) VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(id, incidentId, timestamp, phase, auth.actor, description);

  addAuditLog({
    actor: auth.actor,
    role: auth.role,
    action: 'TIMELINE_EVENT_ADDED',
    target: incidentId,
    category: 'forensics',
    simulated: false,
    details: `${phase}: ${description}`,
  });

  res.status(201).json({ ok: true, id });
});

// Attack Simulation Lab
app.get('/api/simulations', (_req, res) => {
  res.json(listSimulationAttempts());
});

app.post('/api/simulations', (req, res) => {
  const auth = getActor(req); // All roles including Viewer can complete educational labs!
  const schema = z.object({
    scenarioId: z.string(),
    scenarioTitle: z.string(),
    score: z.number().int().min(0).max(100),
    maxScore: z.number().int().min(1).max(100),
    selectedThreat: z.string(),
    selectedActions: z.array(z.string()),
    passed: z.boolean(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid simulation submission' });
    return;
  }

  const d = parsed.data;
  const id = `SIM-${Date.now().toString().slice(-6)}`;
  const now = new Date().toISOString();

  db.prepare(
    `INSERT INTO simulation_attempts (id, scenario_id, scenario_title, analyst, score, max_score, selected_threat, selected_actions_json, passed, completed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(id, d.scenarioId, d.scenarioTitle, auth.actor, d.score, d.maxScore, d.selectedThreat, JSON.stringify(d.selectedActions), d.passed ? 1 : 0, now);

  addAuditLog({
    actor: auth.actor,
    role: auth.role,
    action: 'SIMULATION_COMPLETED',
    target: d.scenarioId,
    category: 'simulation',
    simulated: true,
    details: `Completed "${d.scenarioTitle}" with score ${d.score}/${d.maxScore}.`,
  });

  res.status(201).json({ ok: true, id });
});

// Audit Logs & Notifications
app.get('/api/audit-logs', (_req, res) => {
  res.json(listAuditLogs());
});

app.get('/api/notifications', (_req, res) => {
  res.json(listNotifications());
});

app.post('/api/notifications/read-all', (_req, res) => {
  db.prepare('UPDATE notifications SET read = 1').run();
  res.json({ ok: true });
});

// Settings, Users & RBAC
app.get('/api/settings', (_req, res) => {
  res.json({
    users: listUsers(),
    thresholds: getRiskThresholds(),
    providers: getThreatIntelProviderStatuses(),
  });
});

app.patch('/api/settings/thresholds', (req, res) => {
  const auth = requireWriteRole(req, res, ['Administrator']);
  if (!auth) return;

  const schema = z.object({
    lowMax: z.number().int().min(1).max(10),
    mediumMax: z.number().int().min(5).max(18),
    highMax: z.number().int().min(10).max(24),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid risk threshold parameters' });
    return;
  }
  setRiskThresholds(parsed.data);

  addAuditLog({
    actor: auth.actor,
    role: auth.role,
    action: 'RISK_THRESHOLDS_UPDATED',
    target: 'risk_thresholds',
    category: 'settings',
    simulated: false,
    details: `Updated matrix thresholds: Low<=${parsed.data.lowMax}, Medium<=${parsed.data.mediumMax}, High<=${parsed.data.highMax}.`,
  });

  res.json({ ok: true, thresholds: parsed.data });
});

app.post('/api/users', (req, res) => {
  const auth = requireWriteRole(req, res, ['Administrator']);
  if (!auth) return;

  const schema = z.object({
    username: z.string().min(3).max(60),
    displayName: z.string().min(2).max(120),
    email: z.string().email(),
    role: z.enum(['Administrator', 'Security Analyst', 'Viewer']),
    password: z.string().min(8).max(128),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid user account parameters (password min 8 chars).' });
    return;
  }
  const d = parsed.data;
  const id = `USR-${Date.now().toString().slice(-4)}`;
  const now = new Date().toISOString();
  try {
    db.prepare(
      `INSERT INTO users (id, username, display_name, email, role, password_hash, active, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?)`,
    ).run(id, d.username.trim(), d.displayName.trim(), d.email.trim(), d.role, hashPassword(d.password), now);

    addAuditLog({
      actor: auth.actor,
      role: auth.role,
      action: 'USER_CREATED',
      target: d.username,
      category: 'settings',
      simulated: false,
      details: `Provisioned user ${d.displayName} with role ${d.role} (scrypt hashed credentials).`,
    });
    res.status(201).json({ ok: true, id });
  } catch {
    res.status(409).json({ error: 'Username already exists.' });
  }
});

app.post('/api/auth/verify', (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  const row = db
    .prepare('SELECT id, username, display_name, email, role, password_hash, active FROM users WHERE username = ?')
    .get(username) as Record<string, unknown> | undefined;

  if (!row || !verifyPassword(password, String(row.password_hash))) {
    res.status(401).json({ error: 'Invalid username or password.' });
    return;
  }

  addAuditLog({
    actor: String(row.display_name),
    role: row.role as UserRole,
    action: 'USER_SESSION_VERIFIED',
    target: String(row.username),
    category: 'settings',
    simulated: false,
    details: 'Verified credentials via scrypt password hash.',
  });

  res.json({
    id: String(row.id),
    username: String(row.username),
    displayName: String(row.display_name),
    email: String(row.email),
    role: row.role as UserRole,
  });
});

// Full dataset export for Reports & Analytics
app.get('/api/reports/summary', (_req, res) => {
  res.json({
    generatedAt: new Date().toISOString(),
    dashboard: buildDashboardSummary('daily'),
    scans: listScans(),
    incidents: listIncidents(),
    risks: listRisks(),
    threatIntel: listThreatIntel(),
    evidence: listEvidence(),
    timeline: listTimelineEvents(),
  });
});

// Vite dev middleware or static production build
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    if (fs.existsSync(distDir)) {
      app.use(express.static(distDir));
      app.get('*', (_req, res) => {
        res.sendFile(path.join(distDir, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`PhishGuard server listening on http://localhost:${PORT}`);
  });
}

startServer();
