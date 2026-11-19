export type Language = 'en' | 'ar';

export type UserRole = 'Administrator' | 'Security Analyst' | 'Viewer';

export type NavSection =
  | 'dashboard'
  | 'email'
  | 'url'
  | 'intel'
  | 'risk'
  | 'incidents'
  | 'forensics'
  | 'simulation'
  | 'reports'
  | 'history'
  | 'settings';

export type EmailClassification =
  | 'Legitimate'
  | 'Suspicious'
  | 'Phishing'
  | 'High-Risk Phishing';

export type ThreatSeverity = 'Low' | 'Medium' | 'High' | 'Critical';

export type NistStage =
  | 'Preparation'
  | 'Detection & Analysis'
  | 'Containment'
  | 'Eradication'
  | 'Recovery'
  | 'Post-Incident Review';

export type RiskTreatment = 'Avoid' | 'Mitigate' | 'Transfer' | 'Accept';

export type IndicatorLevel = 'confirmed_malicious' | 'suspicious' | 'informational';

export interface FindingIndicator {
  id: string;
  level: IndicatorLevel;
  category: string;
  title: string;
  titleAr: string;
  detail: string;
  detailAr: string;
  evidenceSnippet?: string;
}

export interface EmailAuthResults {
  spf: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none';
  dkim: 'pass' | 'fail' | 'none';
  dmarc: 'pass' | 'fail' | 'none';
  note: string;
  noteAr: string;
}

export interface EmailAnalysisResult {
  senderEmail: string;
  senderDisplayName: string;
  replyTo: string;
  subject: string;
  sanitizedBodyPreview: string;
  extractedUrls: string[];
  attachments: Array<{
    filename: string;
    extension: string;
    riskLevel: ThreatSeverity;
    reason: string;
  }>;
  auth: EmailAuthResults;
  headers: Array<{ key: string; value: string }>;
  routingHops: string[];
  classification: EmailClassification;
  riskScore: number;
  confidence: number;
  findings: FindingIndicator[];
  iocs: Array<{ type: string; value: string; level: IndicatorLevel }>;
  explanation: string;
  explanationAr: string;
  recommendedActions: string[];
  recommendedActionsAr: string[];
  analysisMode: 'Local Heuristic Engine' | 'Heuristic + Threat Intelligence';
}

export interface UrlAnalysisResult {
  submittedInput: string;
  normalizedUrl: string;
  protocol: string;
  hostname: string;
  domain: string;
  subdomain: string;
  tld: string;
  port: string;
  path: string;
  queryParams: Array<{ key: string; value: string; suspicious: boolean }>;
  isIpBased: boolean;
  isHttps: boolean;
  hasPunycode: boolean;
  typosquatTarget: string | null;
  urlLength: number;
  encodingCount: number;
  classification: EmailClassification;
  riskScore: number;
  confidence: number;
  findings: FindingIndicator[];
  recommendedActions: string[];
  recommendedActionsAr: string[];
  intelligenceSource: string;
  intelligenceVerified: boolean;
  checkedAt: string;
}

export interface ScanRecord {
  id: string;
  analysisType: 'email' | 'url';
  submittedObject: string;
  classification: EmailClassification;
  severity: ThreatSeverity;
  riskScore: number;
  confidence: number;
  analyst: string;
  incidentId: string | null;
  createdAt: string;
  details: EmailAnalysisResult | UrlAnalysisResult;
}

export interface ThreatIntelRecord {
  id: string;
  indicator: string;
  iocType: 'IP' | 'Domain' | 'URL' | 'MD5' | 'SHA-1' | 'SHA-256';
  category: string;
  reputationScore: number;
  severity: ThreatSeverity;
  source: string;
  verifiedExternal: boolean;
  firstSeen: string;
  lastUpdated: string;
  notes: string;
}

export interface RiskRecord {
  id: string;
  assetAffected: string;
  threatDescription: string;
  vulnerability: string;
  likelihood: number;
  impact: number;
  inherentRisk: number;
  inherentLevel: ThreatSeverity;
  existingControls: string;
  controlEffectiveness: number;
  residualRisk: number;
  residualLevel: ThreatSeverity;
  riskOwner: string;
  treatmentStrategy: RiskTreatment;
  treatmentStatus: 'Open' | 'In Progress' | 'Controlled' | 'Accepted';
  mitigationPlan: string;
  recommendations: string;
  linkedIncidentId: string | null;
  updatedAt: string;
}

export interface IncidentResponseAction {
  id: string;
  actionKey: string;
  label: string;
  simulated: boolean;
  executedBy: string;
  executedAt: string;
  notes: string;
}

export interface IncidentRecord {
  id: string;
  title: string;
  category: string;
  severity: ThreatSeverity;
  detectedAt: string;
  affectedAsset: string;
  threatSource: string;
  riskScore: number;
  assignedAnalyst: string;
  status: 'Open' | 'Investigating' | 'Contained' | 'Closed';
  nistStage: NistStage;
  evidenceSummary: string;
  investigationNotes: string;
  linkedScanId: string | null;
  linkedRiskId: string | null;
  actions: IncidentResponseAction[];
}

export interface EvidenceRecord {
  id: string;
  incidentId: string;
  source: string;
  evidenceType: 'Email Header' | 'Raw EML' | 'URL Artifact' | 'Auth Log' | 'Attachment Metadata';
  collectedAt: string;
  collectedBy: string;
  sha256Hash: string;
  status: 'Verified' | 'Quarantined' | 'Archived';
  contentPreview: string;
}

export interface TimelineEventRecord {
  id: string;
  incidentId: string;
  timestamp: string;
  phase: string;
  actor: string;
  description: string;
}

export interface AuditLogRecord {
  id: string;
  timestamp: string;
  actor: string;
  role: UserRole;
  action: string;
  target: string;
  category: 'scan' | 'incident' | 'risk' | 'forensics' | 'simulation' | 'settings' | 'intel';
  simulated: boolean;
  details: string;
}

export interface NotificationItem {
  id: string;
  title: string;
  titleAr: string;
  severity: ThreatSeverity;
  createdAt: string;
  read: boolean;
  targetSection: NavSection;
}

export interface UserAccount {
  id: string;
  username: string;
  displayName: string;
  email: string;
  role: UserRole;
  active: boolean;
  createdAt: string;
}

export interface SimulationAttempt {
  id: string;
  scenarioId: string;
  scenarioTitle: string;
  analyst: string;
  score: number;
  maxScore: number;
  selectedThreat: string;
  selectedActions: string[];
  passed: boolean;
  completedAt: string;
}

export interface DashboardSummary {
  metrics: {
    totalEmailsAnalyzed: number;
    phishingEmailsDetected: number;
    maliciousUrlsIdentified: number;
    suspiciousDomains: number;
    activeSecurityIncidents: number;
    criticalRiskEvents: number;
    resolvedIncidents: number;
  };
  trendSeries: Array<{
    bucket: string;
    phishing: number;
    suspicious: number;
    legitimate: number;
    urls: number;
  }>;
  emailDistribution: Array<{ name: string; key: string; value: number }>;
  riskDistribution: Array<{ level: ThreatSeverity; count: number }>;
  recentIncidents: IncidentRecord[];
  latestScans: ScanRecord[];
  recentSuspiciousDomains: Array<{
    domain: string;
    riskScore: number;
    classification: EmailClassification;
    source: string;
    detectedAt: string;
  }>;
}
