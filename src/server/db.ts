import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import type {
  AuditLogRecord,
  DashboardSummary,
  EvidenceRecord,
  IncidentRecord,
  IncidentResponseAction,
  NotificationItem,
  RiskRecord,
  ScanRecord,
  SimulationAttempt,
  ThreatIntelRecord,
  ThreatSeverity,
  TimelineEventRecord,
  UserAccount,
  UserRole,
} from '../types/phishguard.ts';
import { analyzeEmailHeuristic, analyzeUrlHeuristic } from './analyzers.ts';

const DB_PATH = path.resolve(process.cwd(), 'phishguard.db');
export const db = new DatabaseSync(DB_PATH);

export function hashPassword(password: string): string {
  const salt = randomBytes(16).toString('hex');
  const derived = scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  const [salt, keyHex] = storedHash.split(':');
  if (!salt || !keyHex) return false;
  const derived = scryptSync(password, salt, 64);
  const keyBuf = Buffer.from(keyHex, 'hex');
  if (derived.length !== keyBuf.length) return false;
  return timingSafeEqual(derived, keyBuf);
}

export function sha256Hex(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

export function riskScoreToLevel(score: number, thresholds?: { lowMax: number; mediumMax: number; highMax: number }): ThreatSeverity {
  const t = thresholds || getRiskThresholds();
  if (score > t.highMax) return 'Critical';
  if (score > t.mediumMax) return 'High';
  if (score > t.lowMax) return 'Medium';
  return 'Low';
}

export function initDatabase() {
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      display_name TEXT NOT NULL,
      email TEXT NOT NULL,
      role TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      analysis_type TEXT NOT NULL,
      submitted_object TEXT NOT NULL,
      classification TEXT NOT NULL,
      severity TEXT NOT NULL,
      risk_score INTEGER NOT NULL,
      confidence INTEGER NOT NULL,
      analyst TEXT NOT NULL,
      incident_id TEXT,
      created_at TEXT NOT NULL,
      details_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS threat_intel (
      id TEXT PRIMARY KEY,
      indicator TEXT UNIQUE NOT NULL,
      ioc_type TEXT NOT NULL,
      category TEXT NOT NULL,
      reputation_score INTEGER NOT NULL,
      severity TEXT NOT NULL,
      source TEXT NOT NULL,
      verified_external INTEGER NOT NULL DEFAULT 0,
      first_seen TEXT NOT NULL,
      last_updated TEXT NOT NULL,
      notes TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS risks (
      id TEXT PRIMARY KEY,
      asset_affected TEXT NOT NULL,
      threat_description TEXT NOT NULL,
      vulnerability TEXT NOT NULL,
      likelihood INTEGER NOT NULL,
      impact INTEGER NOT NULL,
      inherent_risk INTEGER NOT NULL,
      inherent_level TEXT NOT NULL,
      existing_controls TEXT NOT NULL,
      control_effectiveness INTEGER NOT NULL,
      residual_risk INTEGER NOT NULL,
      residual_level TEXT NOT NULL,
      risk_owner TEXT NOT NULL,
      treatment_strategy TEXT NOT NULL,
      treatment_status TEXT NOT NULL,
      mitigation_plan TEXT NOT NULL,
      recommendations TEXT NOT NULL,
      linked_incident_id TEXT,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      category TEXT NOT NULL,
      severity TEXT NOT NULL,
      detected_at TEXT NOT NULL,
      affected_asset TEXT NOT NULL,
      threat_source TEXT NOT NULL,
      risk_score INTEGER NOT NULL,
      assigned_analyst TEXT NOT NULL,
      status TEXT NOT NULL,
      nist_stage TEXT NOT NULL,
      evidence_summary TEXT NOT NULL,
      investigation_notes TEXT NOT NULL,
      linked_scan_id TEXT,
      linked_risk_id TEXT,
      actions_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS evidence (
      id TEXT PRIMARY KEY,
      incident_id TEXT NOT NULL,
      source TEXT NOT NULL,
      evidence_type TEXT NOT NULL,
      collected_at TEXT NOT NULL,
      collected_by TEXT NOT NULL,
      sha256_hash TEXT NOT NULL,
      status TEXT NOT NULL,
      content_preview TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS timeline_events (
      id TEXT PRIMARY KEY,
      incident_id TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      phase TEXT NOT NULL,
      actor TEXT NOT NULL,
      description TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS simulation_attempts (
      id TEXT PRIMARY KEY,
      scenario_id TEXT NOT NULL,
      scenario_title TEXT NOT NULL,
      analyst TEXT NOT NULL,
      score INTEGER NOT NULL,
      max_score INTEGER NOT NULL,
      selected_threat TEXT NOT NULL,
      selected_actions_json TEXT NOT NULL,
      passed INTEGER NOT NULL,
      completed_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      actor TEXT NOT NULL,
      role TEXT NOT NULL,
      action TEXT NOT NULL,
      target TEXT NOT NULL,
      category TEXT NOT NULL,
      simulated INTEGER NOT NULL DEFAULT 0,
      details TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      title_ar TEXT NOT NULL,
      severity TEXT NOT NULL,
      created_at TEXT NOT NULL,
      read INTEGER NOT NULL DEFAULT 0,
      target_section TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value_json TEXT NOT NULL
    );
  `);

  seedInitialData();
}

export function getRiskThresholds(): { lowMax: number; mediumMax: number; highMax: number } {
  const row = db.prepare('SELECT value_json FROM app_settings WHERE key = ?').get('risk_thresholds') as
    | { value_json: string }
    | undefined;
  if (!row) return { lowMax: 4, mediumMax: 9, highMax: 16 };
  return JSON.parse(row.value_json);
}

export function setRiskThresholds(thresholds: { lowMax: number; mediumMax: number; highMax: number }) {
  db.prepare(
    'INSERT INTO app_settings (key, value_json) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json',
  ).run('risk_thresholds', JSON.stringify(thresholds));
}

export function addAuditLog(entry: Omit<AuditLogRecord, 'id' | 'timestamp'> & { timestamp?: string }) {
  const id = `AUD-${Date.now()}-${Math.floor(Math.random() * 900 + 100)}`;
  const timestamp = entry.timestamp || new Date().toISOString();
  db.prepare(
    `INSERT INTO audit_logs (id, timestamp, actor, role, action, target, category, simulated, details)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    id,
    timestamp,
    entry.actor,
    entry.role,
    entry.action,
    entry.target,
    entry.category,
    entry.simulated ? 1 : 0,
    entry.details,
  );
}

function seedInitialData() {
  const userCount = (db.prepare('SELECT COUNT(*) as c FROM users').get() as { c: number }).c;
  if (userCount > 0) return;

  const now = Date.now();
  const isoAgo = (hoursAgo: number) => new Date(now - hoursAgo * 3600 * 1000).toISOString();

  // 1. Settings
  setRiskThresholds({ lowMax: 4, mediumMax: 9, highMax: 16 });

  // 2. Users (RBAC demonstration accounts)
  const insertUser = db.prepare(
    `INSERT INTO users (id, username, display_name, email, role, password_hash, active, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  insertUser.run('USR-001', 'n.almansoor', 'Noura Al-Mansoor', 'n.almansoor@phishguard.edu', 'Administrator', hashPassword('AdminSOC#2026'), 1, isoAgo(720));
  insertUser.run('USR-002', 't.haddad', 'Tariq Haddad', 't.haddad@phishguard.edu', 'Security Analyst', hashPassword('AnalystSOC#2026'), 1, isoAgo(680));
  insertUser.run('USR-003', 'l.chen', 'Lina Chen', 'l.chen@phishguard.edu', 'Viewer', hashPassword('ViewerSOC#2026'), 1, isoAgo(600));

  // 3. Threat Intelligence IOCs
  const iocs: ThreatIntelRecord[] = [
    {
      id: 'IOC-101',
      indicator: 'micros0ft-auth-verify.top',
      iocType: 'Domain',
      category: 'Credential Harvesting',
      reputationScore: 94,
      severity: 'Critical',
      source: 'URLhaus / Local SOC Feed',
      verifiedExternal: false,
      firstSeen: isoAgo(160),
      lastUpdated: isoAgo(4),
      notes: 'Typosquatted Microsoft 365 OAuth consent phishing domain.',
    },
    {
      id: 'IOC-102',
      indicator: 'http://185.220.101.47/owa/login.php',
      iocType: 'URL',
      category: 'Phishing Kit Landing Page',
      reputationScore: 91,
      severity: 'Critical',
      source: 'Local Heuristic & SOC Telemetry',
      verifiedExternal: false,
      firstSeen: isoAgo(120),
      lastUpdated: isoAgo(8),
      notes: 'Direct IP-hosted Outlook Web App credential harvester.',
    },
    {
      id: 'IOC-103',
      indicator: '185.220.101.47',
      iocType: 'IP',
      category: 'Malicious Phishing Infrastructure',
      reputationScore: 88,
      severity: 'High',
      source: 'AbuseIPDB Seeded Intelligence',
      verifiedExternal: false,
      firstSeen: isoAgo(240),
      lastUpdated: isoAgo(12),
      notes: 'Repeatedly observed hosting credential capture pages.',
    },
    {
      id: 'IOC-104',
      indicator: 'dhl-express-clearance.click',
      iocType: 'Domain',
      category: 'Delivery Smishing / Phishing',
      reputationScore: 82,
      severity: 'High',
      source: 'AlienVault OTX Pulse (Cached)',
      verifiedExternal: false,
      firstSeen: isoAgo(96),
      lastUpdated: isoAgo(14),
      notes: 'Fake customs fee portal targeting corporate logistics staff.',
    },
    {
      id: 'IOC-105',
      indicator: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      iocType: 'SHA-256',
      category: 'Malicious Macro Payload',
      reputationScore: 96,
      severity: 'Critical',
      source: 'MalwareBazaar / SOC Sandbox',
      verifiedExternal: false,
      firstSeen: isoAgo(72),
      lastUpdated: isoAgo(2),
      notes: 'Weaponized invoice.docm dropper observed in finance department campaign.',
    },
    {
      id: 'IOC-106',
      indicator: 'paypa1-billing-security.xyz',
      iocType: 'Domain',
      category: 'Financial Phishing',
      reputationScore: 89,
      severity: 'High',
      source: 'Local SOC Watchlist',
      verifiedExternal: false,
      firstSeen: isoAgo(190),
      lastUpdated: isoAgo(18),
      notes: 'Lookalike payment domain with homoglyph numeral substitution.',
    },
    {
      id: 'IOC-107',
      indicator: '44d88612fea8a8f36de82e1278abb02f',
      iocType: 'MD5',
      category: 'Trojan Dropper',
      reputationScore: 85,
      severity: 'High',
      source: 'VirusTotal Cached Signature',
      verifiedExternal: false,
      firstSeen: isoAgo(300),
      lastUpdated: isoAgo(36),
      notes: 'Known archive loader distributed via HR policy update lures.',
    },
  ];
  const insertIoc = db.prepare(
    `INSERT INTO threat_intel (id, indicator, ioc_type, category, reputation_score, severity, source, verified_external, first_seen, last_updated, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  for (const ioc of iocs) {
    insertIoc.run(
      ioc.id,
      ioc.indicator,
      ioc.iocType,
      ioc.category,
      ioc.reputationScore,
      ioc.severity,
      ioc.source,
      ioc.verifiedExternal ? 1 : 0,
      ioc.firstSeen,
      ioc.lastUpdated,
      ioc.notes,
    );
  }

  const knownBad = iocs.map((i) => ({
    indicator: i.indicator,
    category: i.category,
    reputationScore: i.reputationScore,
    source: i.source,
  }));

  // 4. Sample Email & URL Scans (analyzed through the real engine!)
  const sampleEmails = [
    {
      id: 'SCN-1001',
      hoursAgo: 3,
      analyst: 'Tariq Haddad',
      incidentId: 'INC-2026-001',
      rawEmail: `From: "Microsoft 365 Security" <security@micros0ft-auth-verify.top>
Reply-To: audit-recovery@proton.me
To: finance-team@enterprise.local
Subject: URGENT: Your Microsoft 365 Account Will Be Suspended Within 24 Hours
Authentication-Results: spf=fail smtp.mailfrom=micros0ft-auth-verify.top; dkim=fail; dmarc=fail
Received: from mail.micros0ft-auth-verify.top (185.220.101.47) by mx1.enterprise.local

Dear Employee,
Unusual sign-in activity was detected. Immediate action required within 24 hours to prevent permanent mailbox deactivation.
Verify your account credentials now: https://micros0ft-auth-verify.top/oauth/login?redirect=https://evil-collector.xyz
`,
    },
    {
      id: 'SCN-1002',
      hoursAgo: 9,
      analyst: 'Noura Al-Mansoor',
      incidentId: 'INC-2026-002',
      rawEmail: `From: "Chief Executive Officer" <ceo.office.urgent@gmail.com>
Reply-To: wire-approvals@yandex.com
To: ap-payroll@enterprise.local
Subject: Confidential Wire Transfer - Immediate Vendor Settlement
Authentication-Results: spf=pass; dkim=pass; dmarc=none

I am in a board meeting and cannot take calls. Please process an urgent confidential payment for our acquisition partner today. Reply with confirmation once bank details are updated.
`,
    },
    {
      id: 'SCN-1003',
      hoursAgo: 26,
      analyst: 'Tariq Haddad',
      incidentId: 'INC-2026-003',
      rawEmail: `From: "Logistics Billing" <billing@dhl-express-clearance.click>
To: operations@enterprise.local
Subject: Final Notice: Shipment Customs Invoice Attached
Authentication-Results: spf=softfail; dkim=none; dmarc=fail
Content-Disposition: attachment; filename="Customs_Invoice_4491.pdf.exe"

Please open the attached Customs_Invoice_4491.pdf.exe or pay clearance fees at http://185.220.101.47/owa/login.php
`,
    },
    {
      id: 'SCN-1004',
      hoursAgo: 52,
      analyst: 'Tariq Haddad',
      incidentId: null,
      rawEmail: `From: "IT Helpdesk" <helpdesk@enterprise.local>
To: all-staff@enterprise.local
Subject: Scheduled Quarterly Security Awareness Workshop
Authentication-Results: spf=pass; dkim=pass; dmarc=pass
Received: from internal-relay.enterprise.local (10.20.4.12) by mx1.enterprise.local

Hello team,
Our quarterly cybersecurity awareness session will be held next Tuesday at 10:00 AM in Auditorium B. Please review the agenda on the intranet portal: https://intranet.enterprise.local/training
`,
    },
    {
      id: 'SCN-1005',
      hoursAgo: 78,
      analyst: 'Noura Al-Mansoor',
      incidentId: null,
      rawEmail: `From: "GitHub Notifications" <notifications@github.com>
To: devsecops@enterprise.local
Subject: [phishguard-core] Pull request #42 merged
Authentication-Results: spf=pass; dkim=pass; dmarc=pass

Pull request #42 has been merged into main. View build summary at https://github.com/enterprise/phishguard-core/pull/42
`,
    },
  ];

  const insertScan = db.prepare(
    `INSERT INTO scans (id, analysis_type, submitted_object, classification, severity, risk_score, confidence, analyst, incident_id, created_at, details_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );

  for (const s of sampleEmails) {
    const res = analyzeEmailHeuristic({ rawEmail: s.rawEmail }, knownBad);
    const sev: ThreatSeverity =
      res.riskScore >= 75 ? 'Critical' : res.riskScore >= 50 ? 'High' : res.riskScore >= 25 ? 'Medium' : 'Low';
    insertScan.run(
      s.id,
      'email',
      `${res.subject} (${res.senderEmail})`,
      res.classification,
      sev,
      res.riskScore,
      res.confidence,
      s.analyst,
      s.incidentId,
      isoAgo(s.hoursAgo),
      JSON.stringify(res),
    );
  }

  const sampleUrls = [
    { id: 'SCN-2001', hoursAgo: 5, url: 'https://micros0ft-auth-verify.top/oauth2/authorize?next=https://capture.top', incidentId: 'INC-2026-001' },
    { id: 'SCN-2002', hoursAgo: 15, url: 'http://185.220.101.47/owa/login.php', incidentId: 'INC-2026-003' },
    { id: 'SCN-2003', hoursAgo: 38, url: 'https://paypa1-billing-security.xyz/account/confirm?token=8921a', incidentId: null },
    { id: 'SCN-2004', hoursAgo: 96, url: 'https://bit.ly/3xUpdateMfa', incidentId: null },
    { id: 'SCN-2005', hoursAgo: 130, url: 'https://learn.microsoft.com/en-us/security/zero-trust', incidentId: null },
  ];

  for (const u of sampleUrls) {
    const matched = knownBad.filter((k) => u.url.toLowerCase().includes(k.indicator.toLowerCase()));
    const res = analyzeUrlHeuristic(u.url, matched);
    const sev: ThreatSeverity =
      res.riskScore >= 75 ? 'Critical' : res.riskScore >= 50 ? 'High' : res.riskScore >= 25 ? 'Medium' : 'Low';
    insertScan.run(
      u.id,
      'url',
      u.url,
      res.classification,
      sev,
      res.riskScore,
      res.confidence,
      'Tariq Haddad',
      u.incidentId,
      isoAgo(u.hoursAgo),
      JSON.stringify(res),
    );
  }

  // 5. Incidents (NIST SP 800-61 lifecycle)
  const incidents: IncidentRecord[] = [
    {
      id: 'INC-2026-001',
      title: 'Microsoft 365 OAuth Credential Harvesting Campaign',
      category: 'Credential Phishing',
      severity: 'Critical',
      detectedAt: isoAgo(3),
      affectedAsset: 'Corporate Email & Identity Tenant (SSO)',
      threatSource: 'security@micros0ft-auth-verify.top (185.220.101.47)',
      riskScore: 92,
      assignedAnalyst: 'Tariq Haddad',
      status: 'Contained',
      nistStage: 'Containment',
      evidenceSummary: 'Spoofed M365 suspension lure with SPF/DKIM/DMARC failure and lookalike domain.',
      investigationNotes: 'Identified 4 targeted finance users. Quarantined messages and blocked domain in simulated SWG policy.',
      linkedScanId: 'SCN-1001',
      linkedRiskId: 'RSK-001',
      actions: [
        {
          id: 'ACT-1',
          actionKey: 'quarantine_email',
          label: 'Quarantine suspicious email',
          simulated: true,
          executedBy: 'Tariq Haddad',
          executedAt: isoAgo(2.5),
          notes: 'Removed 4 copies from finance mailboxes (simulation).',
        },
        {
          id: 'ACT-2',
          actionKey: 'block_url',
          label: 'Block malicious URL',
          simulated: true,
          executedBy: 'Tariq Haddad',
          executedAt: isoAgo(2),
          notes: 'Added micros0ft-auth-verify.top to simulated DNS sinkhole.',
        },
      ],
    },
    {
      id: 'INC-2026-002',
      title: 'Executive Impersonation Wire Transfer Request (BEC)',
      category: 'Business Email Compromise',
      severity: 'High',
      detectedAt: isoAgo(9),
      affectedAsset: 'Accounts Payable Workflow',
      threatSource: 'ceo.office.urgent@gmail.com',
      riskScore: 76,
      assignedAnalyst: 'Noura Al-Mansoor',
      status: 'Investigating',
      nistStage: 'Detection & Analysis',
      evidenceSummary: 'Free webmail sender impersonating CEO with Reply-To mismatch to yandex.com.',
      investigationNotes: 'Verified with CFO via out-of-band phone call that no acquisition payment was authorized.',
      linkedScanId: 'SCN-1002',
      linkedRiskId: 'RSK-002',
      actions: [
        {
          id: 'ACT-3',
          actionKey: 'flag_sender',
          label: 'Flag suspicious sender',
          simulated: true,
          executedBy: 'Noura Al-Mansoor',
          executedAt: isoAgo(8),
          notes: 'Tagged external webmail impersonation pattern.',
        },
      ],
    },
    {
      id: 'INC-2026-003',
      title: 'Executable Double-Extension Attachment Delivery (.pdf.exe)',
      category: 'Malware Delivery',
      severity: 'Critical',
      detectedAt: isoAgo(26),
      affectedAsset: 'Operations Endpoint Workstation WS-FIN-14',
      threatSource: 'billing@dhl-express-clearance.click',
      riskScore: 95,
      assignedAnalyst: 'Tariq Haddad',
      status: 'Open',
      nistStage: 'Eradication',
      evidenceSummary: 'DHL customs lure delivering Customs_Invoice_4491.pdf.exe and IP phishing link.',
      investigationNotes: 'Endpoint WS-FIN-14 isolated in simulation mode pending EDR hash sweep.',
      linkedScanId: 'SCN-1003',
      linkedRiskId: 'RSK-003',
      actions: [],
    },
    {
      id: 'INC-2026-004',
      title: 'Suspicious OAuth Token Grant Following SMS Lure',
      category: 'Account Compromise',
      severity: 'Medium',
      detectedAt: isoAgo(140),
      affectedAsset: 'Sales Cloud Directory Account',
      threatSource: 'dhl-express-clearance.click',
      riskScore: 62,
      assignedAnalyst: 'Noura Al-Mansoor',
      status: 'Closed',
      nistStage: 'Post-Incident Review',
      evidenceSummary: 'Anomalous login from foreign ASN immediately after clicking shortened link.',
      investigationNotes: 'Sessions revoked, MFA re-enrolled, post-incident review completed.',
      linkedScanId: null,
      linkedRiskId: 'RSK-004',
      actions: [
        {
          id: 'ACT-4',
          actionKey: 'verify_recovery',
          label: 'Verify system recovery',
          simulated: true,
          executedBy: 'Noura Al-Mansoor',
          executedAt: isoAgo(125),
          notes: 'Confirmed clean sign-in telemetry for 24h.',
        },
        {
          id: 'ACT-5',
          actionKey: 'close_incident',
          label: 'Close incident',
          simulated: true,
          executedBy: 'Noura Al-Mansoor',
          executedAt: isoAgo(120),
          notes: 'Lessons learned documented in Risk Register.',
        },
      ],
    },
  ];

  const insertIncident = db.prepare(
    `INSERT INTO incidents (id, title, category, severity, detected_at, affected_asset, threat_source, risk_score, assigned_analyst, status, nist_stage, evidence_summary, investigation_notes, linked_scan_id, linked_risk_id, actions_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  for (const inc of incidents) {
    insertIncident.run(
      inc.id,
      inc.title,
      inc.category,
      inc.severity,
      inc.detectedAt,
      inc.affectedAsset,
      inc.threatSource,
      inc.riskScore,
      inc.assignedAnalyst,
      inc.status,
      inc.nistStage,
      inc.evidenceSummary,
      inc.investigationNotes,
      inc.linkedScanId,
      inc.linkedRiskId,
      JSON.stringify(inc.actions),
    );
  }

  // 6. Cyber Risk Assessments (5x5 Likelihood x Impact)
  const risks: RiskRecord[] = [
    {
      id: 'RSK-001',
      assetAffected: 'Enterprise SSO & Cloud Mailboxes',
      threatDescription: 'Credential theft via lookalike OAuth phishing domains',
      vulnerability: 'Absence of FIDO2 hardware MFA enforcement for remote logins',
      likelihood: 5,
      impact: 5,
      inherentRisk: 25,
      inherentLevel: 'Critical',
      existingControls: 'Standard TOTP MFA + Email gateway SPF/DMARC filtering',
      controlEffectiveness: 40,
      residualRisk: 15,
      residualLevel: 'High',
      riskOwner: 'CISO / Identity Team',
      treatmentStrategy: 'Mitigate',
      treatmentStatus: 'In Progress',
      mitigationPlan: 'Enforce phishing-resistant FIDO2/WebAuthn keys and restrict third-party OAuth app consent.',
      recommendations: 'Deploy Conditional Access policies blocking legacy auth and unverified app registrations.',
      linkedIncidentId: 'INC-2026-001',
      updatedAt: isoAgo(2),
    },
    {
      id: 'RSK-002',
      assetAffected: 'Accounts Payable & Treasury Systems',
      threatDescription: 'Fraudulent wire transfers via Executive Impersonation (BEC)',
      vulnerability: 'Single-channel email approval accepted for urgent vendor payments',
      likelihood: 4,
      impact: 5,
      inherentRisk: 20,
      inherentLevel: 'Critical',
      existingControls: 'External sender warning banner on incoming webmail',
      controlEffectiveness: 35,
      residualRisk: 13,
      residualLevel: 'High',
      riskOwner: 'VP of Finance',
      treatmentStrategy: 'Mitigate',
      treatmentStatus: 'Open',
      mitigationPlan: 'Mandate dual out-of-band voice verification for bank account changes above $5,000.',
      recommendations: 'Implement ERP payment hold workflow and DMARC p=reject enforcement.',
      linkedIncidentId: 'INC-2026-002',
      updatedAt: isoAgo(8),
    },
    {
      id: 'RSK-003',
      assetAffected: 'Corporate Endpoints & Workstations',
      threatDescription: 'Malware execution via disguised double-extension email attachments',
      vulnerability: 'Users allowed to extract unverified archive/executable attachments locally',
      likelihood: 4,
      impact: 4,
      inherentRisk: 16,
      inherentLevel: 'High',
      existingControls: 'Antivirus endpoint scanning + attachment extension warnings',
      controlEffectiveness: 50,
      residualRisk: 8,
      residualLevel: 'Medium',
      riskOwner: 'Endpoint Engineering Lead',
      treatmentStrategy: 'Avoid',
      treatmentStatus: 'In Progress',
      mitigationPlan: 'Block .exe, .scr, .iso, .hta attachments completely at mail gateway and enable Attack Surface Reduction.',
      recommendations: 'Disable Windows Script Host and enforce AppLocker allowlisting.',
      linkedIncidentId: 'INC-2026-003',
      updatedAt: isoAgo(20),
    },
    {
      id: 'RSK-004',
      assetAffected: 'Remote Sales SaaS Portal',
      threatDescription: 'Session hijacking via SMS/URL shortener phishing',
      vulnerability: 'Long-lived session tokens without IP/ASN anomaly revocation',
      likelihood: 3,
      impact: 3,
      inherentRisk: 9,
      inherentLevel: 'Medium',
      existingControls: 'TLS encryption + 8-hour session idle timeout',
      controlEffectiveness: 60,
      residualRisk: 4,
      residualLevel: 'Low',
      riskOwner: 'IAM Operations',
      treatmentStrategy: 'Mitigate',
      treatmentStatus: 'Controlled',
      mitigationPlan: 'Enable impossible-travel detection and continuous access evaluation.',
      recommendations: 'Continue periodic token hygiene audits.',
      linkedIncidentId: 'INC-2026-004',
      updatedAt: isoAgo(110),
    },
    {
      id: 'RSK-005',
      assetAffected: 'Public DNS & Brand Domains',
      threatDescription: 'Lookalike domain registration eroding customer trust',
      vulnerability: 'No automated domain typo-monitoring or takedown SLA',
      likelihood: 3,
      impact: 4,
      inherentRisk: 12,
      inherentLevel: 'High',
      existingControls: 'Manual quarterly WHOIS review',
      controlEffectiveness: 25,
      residualRisk: 9,
      residualLevel: 'Medium',
      riskOwner: 'Security Architecture',
      treatmentStrategy: 'Transfer',
      treatmentStatus: 'Open',
      mitigationPlan: 'Subscribe to registrar brand-protection takedown service and cyber insurance coverage.',
      recommendations: 'Publish BIMI and strict DMARC p=reject records.',
      linkedIncidentId: null,
      updatedAt: isoAgo(90),
    },
  ];

  const insertRisk = db.prepare(
    `INSERT INTO risks (id, asset_affected, threat_description, vulnerability, likelihood, impact, inherent_risk, inherent_level, existing_controls, control_effectiveness, residual_risk, residual_level, risk_owner, treatment_strategy, treatment_status, mitigation_plan, recommendations, linked_incident_id, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  for (const r of risks) {
    insertRisk.run(
      r.id,
      r.assetAffected,
      r.threatDescription,
      r.vulnerability,
      r.likelihood,
      r.impact,
      r.inherentRisk,
      r.inherentLevel,
      r.existingControls,
      r.controlEffectiveness,
      r.residualRisk,
      r.residualLevel,
      r.riskOwner,
      r.treatmentStrategy,
      r.treatmentStatus,
      r.mitigationPlan,
      r.recommendations,
      r.linkedIncidentId,
      r.updatedAt,
    );
  }

  // 7. Forensics Evidence Chain of Custody
  const rawSample1 = `From: "Microsoft 365 Security" <security@micros0ft-auth-verify.top>\nReply-To: audit-recovery@proton.me\nAuthentication-Results: spf=fail; dkim=fail; dmarc=fail`;
  const rawSample2 = `http://185.220.101.47/owa/login.php | ASN AS44907 | Observed 2026-11-19`;
  const insertEv = db.prepare(
    `INSERT INTO evidence (id, incident_id, source, evidence_type, collected_at, collected_by, sha256_hash, status, content_preview)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  insertEv.run('EVD-501', 'INC-2026-001', 'Mail Gateway Quarantine Export', 'Email Header', isoAgo(2.8), 'Tariq Haddad', sha256Hex(rawSample1), 'Verified', rawSample1);
  insertEv.run('EVD-502', 'INC-2026-003', 'SWG Proxy Intercept Log', 'URL Artifact', isoAgo(25), 'Tariq Haddad', sha256Hex(rawSample2), 'Quarantined', rawSample2);

  // 8. Forensics Timeline Events
  const insertTimeline = db.prepare(
    `INSERT INTO timeline_events (id, incident_id, timestamp, phase, actor, description) VALUES (?, ?, ?, ?, ?, ?)`,
  );
  insertTimeline.run('TL-01', 'INC-2026-001', isoAgo(3.2), 'Initial Delivery', 'External MTA (185.220.101.47)', 'Phishing email targeting 4 finance employees arrived with SPF/DKIM failure.');
  insertTimeline.run('TL-02', 'INC-2026-001', isoAgo(3.0), 'Detection & Analysis', 'PhishGuard Heuristic Engine', 'Flagged lookalike domain micros0ft-auth-verify.top (Risk Score: 92/100).');
  insertTimeline.run('TL-03', 'INC-2026-001', isoAgo(2.5), 'Containment', 'Tariq Haddad', 'Simulated mailbox quarantine and SWG URL block executed.');

  // 9. Notifications
  const insertNotif = db.prepare(
    `INSERT INTO notifications (id, title, title_ar, severity, created_at, read, target_section) VALUES (?, ?, ?, ?, ?, ?, ?)`,
  );
  insertNotif.run('NTF-01', 'Critical Phishing Campaign Detected (INC-2026-001)', 'تم اكتشاف حملة تصيد حرجة (INC-2026-001)', 'Critical', isoAgo(3), 0, 'incidents');
  insertNotif.run('NTF-02', 'Dangerous .pdf.exe Attachment Flagged in Scan SCN-1003', 'تم رصد مرفق خطير .pdf.exe في الفحص SCN-1003', 'Critical', isoAgo(26), 0, 'email');
  insertNotif.run('NTF-03', 'Risk RSK-002 Exceeds Residual Threshold (13/25)', 'المخاطرة RSK-002 تتجاوز الحد المتبقي المقبول (13/25)', 'High', isoAgo(8), 0, 'risk');

  // 10. Audit Logs
  addAuditLog({ timestamp: isoAgo(3), actor: 'Tariq Haddad', role: 'Security Analyst', action: 'EMAIL_SCAN_EXECUTED', target: 'SCN-1001', category: 'scan', simulated: false, details: 'Analyzed suspicious Microsoft 365 impersonation email (Score 92).' });
  addAuditLog({ timestamp: isoAgo(2.5), actor: 'Tariq Haddad', role: 'Security Analyst', action: 'QUARANTINE_EMAIL', target: 'INC-2026-001', category: 'incident', simulated: true, details: 'Quarantined 4 phishing email copies in simulation workspace.' });
  addAuditLog({ timestamp: isoAgo(8), actor: 'Noura Al-Mansoor', role: 'Administrator', action: 'RISK_ASSESSMENT_UPDATED', target: 'RSK-002', category: 'risk', simulated: false, details: 'Updated BEC risk residual score to 13 (High).' });
  addAuditLog({ timestamp: isoAgo(25), actor: 'Tariq Haddad', role: 'Security Analyst', action: 'EVIDENCE_HASH_SEALED', target: 'EVD-502', category: 'forensics', simulated: false, details: 'Captured URL artifact and generated SHA-256 chain-of-custody record.' });
}

export function getKnownBadIocs() {
  return db
    .prepare('SELECT indicator, category, reputation_score as reputationScore, source FROM threat_intel')
    .all() as Array<{ indicator: string; category: string; reputationScore: number; source: string }>;
}

export function listScans(): ScanRecord[] {
  const rows = db
    .prepare('SELECT * FROM scans ORDER BY created_at DESC')
    .all() as Array<Record<string, unknown>>;
  return rows.map((r) => ({
    id: String(r.id),
    analysisType: r.analysis_type as 'email' | 'url',
    submittedObject: String(r.submitted_object),
    classification: r.classification as ScanRecord['classification'],
    severity: r.severity as ThreatSeverity,
    riskScore: Number(r.risk_score),
    confidence: Number(r.confidence),
    analyst: String(r.analyst),
    incidentId: r.incident_id ? String(r.incident_id) : null,
    createdAt: String(r.created_at),
    details: JSON.parse(String(r.details_json)),
  }));
}

export function listIncidents(): IncidentRecord[] {
  const rows = db
    .prepare('SELECT * FROM incidents ORDER BY detected_at DESC')
    .all() as Array<Record<string, unknown>>;
  return rows.map((r) => ({
    id: String(r.id),
    title: String(r.title),
    category: String(r.category),
    severity: r.severity as ThreatSeverity,
    detectedAt: String(r.detected_at),
    affectedAsset: String(r.affected_asset),
    threatSource: String(r.threat_source),
    riskScore: Number(r.risk_score),
    assignedAnalyst: String(r.assigned_analyst),
    status: r.status as IncidentRecord['status'],
    nistStage: r.nist_stage as IncidentRecord['nistStage'],
    evidenceSummary: String(r.evidence_summary),
    investigationNotes: String(r.investigation_notes),
    linkedScanId: r.linked_scan_id ? String(r.linked_scan_id) : null,
    linkedRiskId: r.linked_risk_id ? String(r.linked_risk_id) : null,
    actions: JSON.parse(String(r.actions_json)) as IncidentResponseAction[],
  }));
}

export function listRisks(): RiskRecord[] {
  const rows = db
    .prepare('SELECT * FROM risks ORDER BY inherent_risk DESC, updated_at DESC')
    .all() as Array<Record<string, unknown>>;
  return rows.map((r) => ({
    id: String(r.id),
    assetAffected: String(r.asset_affected),
    threatDescription: String(r.threat_description),
    vulnerability: String(r.vulnerability),
    likelihood: Number(r.likelihood),
    impact: Number(r.impact),
    inherentRisk: Number(r.inherent_risk),
    inherentLevel: r.inherent_level as ThreatSeverity,
    existingControls: String(r.existing_controls),
    controlEffectiveness: Number(r.control_effectiveness),
    residualRisk: Number(r.residual_risk),
    residualLevel: r.residual_level as ThreatSeverity,
    riskOwner: String(r.risk_owner),
    treatmentStrategy: r.treatment_strategy as RiskRecord['treatmentStrategy'],
    treatmentStatus: r.treatment_status as RiskRecord['treatmentStatus'],
    mitigationPlan: String(r.mitigation_plan),
    recommendations: String(r.recommendations),
    linkedIncidentId: r.linked_incident_id ? String(r.linked_incident_id) : null,
    updatedAt: String(r.updated_at),
  }));
}

export function listThreatIntel(): ThreatIntelRecord[] {
  const rows = db
    .prepare('SELECT * FROM threat_intel ORDER BY last_updated DESC')
    .all() as Array<Record<string, unknown>>;
  return rows.map((r) => ({
    id: String(r.id),
    indicator: String(r.indicator),
    iocType: r.ioc_type as ThreatIntelRecord['iocType'],
    category: String(r.category),
    reputationScore: Number(r.reputation_score),
    severity: r.severity as ThreatSeverity,
    source: String(r.source),
    verifiedExternal: Boolean(r.verified_external),
    firstSeen: String(r.first_seen),
    lastUpdated: String(r.last_updated),
    notes: String(r.notes),
  }));
}

export function listEvidence(): EvidenceRecord[] {
  const rows = db
    .prepare('SELECT * FROM evidence ORDER BY collected_at DESC')
    .all() as Array<Record<string, unknown>>;
  return rows.map((r) => ({
    id: String(r.id),
    incidentId: String(r.incident_id),
    source: String(r.source),
    evidenceType: r.evidence_type as EvidenceRecord['evidenceType'],
    collectedAt: String(r.collected_at),
    collectedBy: String(r.collected_by),
    sha256Hash: String(r.sha256_hash),
    status: r.status as EvidenceRecord['status'],
    contentPreview: String(r.content_preview),
  }));
}

export function listTimelineEvents(): TimelineEventRecord[] {
  const rows = db
    .prepare('SELECT * FROM timeline_events ORDER BY timestamp ASC')
    .all() as Array<Record<string, unknown>>;
  return rows.map((r) => ({
    id: String(r.id),
    incidentId: String(r.incident_id),
    timestamp: String(r.timestamp),
    phase: String(r.phase),
    actor: String(r.actor),
    description: String(r.description),
  }));
}

export function listAuditLogs(): AuditLogRecord[] {
  const rows = db
    .prepare('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 250')
    .all() as Array<Record<string, unknown>>;
  return rows.map((r) => ({
    id: String(r.id),
    timestamp: String(r.timestamp),
    actor: String(r.actor),
    role: r.role as UserRole,
    action: String(r.action),
    target: String(r.target),
    category: r.category as AuditLogRecord['category'],
    simulated: Boolean(r.simulated),
    details: String(r.details),
  }));
}

export function listNotifications(): NotificationItem[] {
  const rows = db
    .prepare('SELECT * FROM notifications ORDER BY created_at DESC LIMIT 30')
    .all() as Array<Record<string, unknown>>;
  return rows.map((r) => ({
    id: String(r.id),
    title: String(r.title),
    titleAr: String(r.title_ar),
    severity: r.severity as ThreatSeverity,
    createdAt: String(r.created_at),
    read: Boolean(r.read),
    targetSection: r.target_section as NotificationItem['targetSection'],
  }));
}

export function listUsers(): UserAccount[] {
  const rows = db
    .prepare('SELECT id, username, display_name, email, role, active, created_at FROM users ORDER BY created_at ASC')
    .all() as Array<Record<string, unknown>>;
  return rows.map((r) => ({
    id: String(r.id),
    username: String(r.username),
    displayName: String(r.display_name),
    email: String(r.email),
    role: r.role as UserRole,
    active: Boolean(r.active),
    createdAt: String(r.created_at),
  }));
}

export function listSimulationAttempts(): SimulationAttempt[] {
  const rows = db
    .prepare('SELECT * FROM simulation_attempts ORDER BY completed_at DESC')
    .all() as Array<Record<string, unknown>>;
  return rows.map((r) => ({
    id: String(r.id),
    scenarioId: String(r.scenario_id),
    scenarioTitle: String(r.scenario_title),
    analyst: String(r.analyst),
    score: Number(r.score),
    maxScore: Number(r.max_score),
    selectedThreat: String(r.selected_threat),
    selectedActions: JSON.parse(String(r.selected_actions_json)),
    passed: Boolean(r.passed),
    completedAt: String(r.completed_at),
  }));
}

export function buildDashboardSummary(period: 'daily' | 'weekly' | 'monthly'): DashboardSummary {
  const scans = listScans();
  const incidents = listIncidents();
  const risks = listRisks();
  const intel = listThreatIntel();

  const emailScans = scans.filter((s) => s.analysisType === 'email');
  const urlScans = scans.filter((s) => s.analysisType === 'url');

  const phishingEmailsDetected = emailScans.filter(
    (s) => s.classification === 'Phishing' || s.classification === 'High-Risk Phishing',
  ).length;
  const maliciousUrlsIdentified = urlScans.filter(
    (s) => s.classification === 'Phishing' || s.classification === 'High-Risk Phishing',
  ).length;

  const suspiciousDomainsSet = new Set<string>();
  for (const i of intel) {
    if (i.iocType === 'Domain') suspiciousDomainsSet.add(i.indicator);
  }
  for (const s of urlScans) {
    if (s.riskScore >= 25 && 'domain' in s.details && s.details.domain) {
      suspiciousDomainsSet.add(s.details.domain);
    }
  }

  const activeSecurityIncidents = incidents.filter((i) => i.status !== 'Closed').length;
  const resolvedIncidents = incidents.filter((i) => i.status === 'Closed').length;
  const criticalRiskEvents =
    risks.filter((r) => r.inherentLevel === 'Critical' || r.residualLevel === 'Critical').length +
    incidents.filter((i) => i.severity === 'Critical' && i.status !== 'Closed').length;

  // Build real dynamic buckets from scan timestamps
  const bucketMap = new Map<string, { bucket: string; phishing: number; suspicious: number; legitimate: number; urls: number }>();
  const now = new Date();
  const bucketLabels: string[] = [];

  if (period === 'daily') {
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 86400000);
      const key = d.toISOString().slice(0, 10);
      bucketLabels.push(key);
      bucketMap.set(key, { bucket: key.slice(5), phishing: 0, suspicious: 0, legitimate: 0, urls: 0 });
    }
    for (const s of scans) {
      const key = s.createdAt.slice(0, 10);
      const entry = bucketMap.get(key);
      if (entry) {
        if (s.analysisType === 'url') entry.urls += 1;
        if (s.classification === 'Phishing' || s.classification === 'High-Risk Phishing') entry.phishing += 1;
        else if (s.classification === 'Suspicious') entry.suspicious += 1;
        else entry.legitimate += 1;
      }
    }
  } else if (period === 'weekly') {
    for (let w = 3; w >= 0; w--) {
      const label = `W-${w === 0 ? 'Current' : w}`;
      bucketLabels.push(label);
      bucketMap.set(label, { bucket: label, phishing: 0, suspicious: 0, legitimate: 0, urls: 0 });
    }
    for (const s of scans) {
      const daysDiff = Math.floor((now.getTime() - new Date(s.createdAt).getTime()) / 86400000);
      const weekIdx = Math.min(3, Math.max(0, Math.floor(daysDiff / 7)));
      const label = `W-${weekIdx === 0 ? 'Current' : weekIdx}`;
      const entry = bucketMap.get(label);
      if (entry) {
        if (s.analysisType === 'url') entry.urls += 1;
        if (s.classification === 'Phishing' || s.classification === 'High-Risk Phishing') entry.phishing += 1;
        else if (s.classification === 'Suspicious') entry.suspicious += 1;
        else entry.legitimate += 1;
      }
    }
  } else {
    for (let m = 5; m >= 0; m--) {
      const d = new Date(now.getFullYear(), now.getMonth() - m, 1);
      const key = d.toISOString().slice(0, 7);
      bucketLabels.push(key);
      bucketMap.set(key, { bucket: key, phishing: 0, suspicious: 0, legitimate: 0, urls: 0 });
    }
    for (const s of scans) {
      const key = s.createdAt.slice(0, 7);
      const entry = bucketMap.get(key);
      if (entry) {
        if (s.analysisType === 'url') entry.urls += 1;
        if (s.classification === 'Phishing' || s.classification === 'High-Risk Phishing') entry.phishing += 1;
        else if (s.classification === 'Suspicious') entry.suspicious += 1;
        else entry.legitimate += 1;
      }
    }
  }

  const trendSeries = bucketLabels.map((k) => bucketMap.get(k)!);

  const emailDistribution = [
    {
      name: 'Legitimate',
      key: 'Legitimate',
      value: emailScans.filter((e) => e.classification === 'Legitimate').length,
    },
    {
      name: 'Suspicious',
      key: 'Suspicious',
      value: emailScans.filter((e) => e.classification === 'Suspicious').length,
    },
    {
      name: 'Phishing',
      key: 'Phishing',
      value: emailScans.filter((e) => e.classification === 'Phishing').length,
    },
    {
      name: 'High-Risk Phishing',
      key: 'High-Risk Phishing',
      value: emailScans.filter((e) => e.classification === 'High-Risk Phishing').length,
    },
  ];

  const riskLevels: ThreatSeverity[] = ['Low', 'Medium', 'High', 'Critical'];
  const riskDistribution = riskLevels.map((level) => ({
    level,
    count: risks.filter((r) => r.inherentLevel === level).length,
  }));

  const recentSuspiciousDomains = [
    ...urlScans
      .filter((u) => u.riskScore >= 25 && 'domain' in u.details)
      .map((u) => ({
        domain: (u.details as { hostname: string }).hostname,
        riskScore: u.riskScore,
        classification: u.classification,
        source: 'URL Scanner',
        detectedAt: u.createdAt,
      })),
    ...intel
      .filter((i) => i.iocType === 'Domain')
      .map((i) => ({
        domain: i.indicator,
        riskScore: i.reputationScore,
        classification: (i.reputationScore >= 75 ? 'High-Risk Phishing' : 'Phishing') as ScanRecord['classification'],
        source: i.source,
        detectedAt: i.lastUpdated,
      })),
  ].slice(0, 6);

  return {
    metrics: {
      totalEmailsAnalyzed: emailScans.length,
      phishingEmailsDetected,
      maliciousUrlsIdentified,
      suspiciousDomains: suspiciousDomainsSet.size,
      activeSecurityIncidents,
      criticalRiskEvents,
      resolvedIncidents,
    },
    trendSeries,
    emailDistribution,
    riskDistribution,
    recentIncidents: incidents.slice(0, 5),
    latestScans: scans.slice(0, 6),
    recentSuspiciousDomains,
  };
}
