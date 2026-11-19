export type Language = 'en' | 'ar';

export type ToolTab = 'email' | 'url' | 'risk' | 'results';

export type EmailClassification =
  | 'Legitimate'
  | 'Suspicious'
  | 'Phishing'
  | 'High-Risk Phishing';

export type ThreatSeverity = 'Low' | 'Medium' | 'High' | 'Critical';

export type RiskTreatment = 'Avoid' | 'Mitigate' | 'Transfer' | 'Accept';

export type IndicatorLevel = 'confirmed_malicious' | 'suspicious' | 'informational';

export interface FindingIndicator {
  id: string;
  level: IndicatorLevel;
  category: string;
  categoryAr: string;
  weight: number;
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
  id: string;
  analyzedAt: string;
  senderEmail: string;
  senderDisplayName: string;
  replyTo: string;
  returnPath: string;
  subject: string;
  sanitizedBodyPreview: string;
  extractedUrls: Array<{ url: string; riskScore: number; classification: EmailClassification }>;
  attachments: Array<{
    filename: string;
    extension: string;
    riskLevel: ThreatSeverity;
    reason: string;
    reasonAr: string;
  }>;
  auth: EmailAuthResults;
  headers: Array<{ key: string; value: string }>;
  routingHops: string[];
  classification: EmailClassification;
  severity: ThreatSeverity;
  riskScore: number;
  confidence: number;
  scoreBreakdown: Array<{ category: string; categoryAr: string; points: number }>;
  findings: FindingIndicator[];
  explanation: string;
  explanationAr: string;
  recommendedActions: string[];
  recommendedActionsAr: string[];
  intelligenceMode: 'heuristic_only';
}

export interface UrlAnalysisResult {
  id: string;
  analyzedAt: string;
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
  hasAtSymbol: boolean;
  typosquatTarget: string | null;
  isShortener: boolean;
  urlLength: number;
  encodingCount: number;
  classification: EmailClassification;
  severity: ThreatSeverity;
  riskScore: number;
  confidence: number;
  scoreBreakdown: Array<{ category: string; categoryAr: string; points: number }>;
  findings: FindingIndicator[];
  explanation: string;
  explanationAr: string;
  recommendedActions: string[];
  recommendedActionsAr: string[];
  intelligenceMode: 'heuristic_only';
  externalIntelStatus: string;
  externalIntelStatusAr: string;
}

export interface RiskAssessmentResult {
  id: string;
  evaluatedAt: string;
  assetName: string;
  threatScenario: string;
  likelihood: number;
  impact: number;
  inherentScore: number;
  inherentLevel: ThreatSeverity;
  controlEffectiveness: number;
  residualScore: number;
  residualLevel: ThreatSeverity;
  strategy: RiskTreatment;
  recommendationsEn: string[];
  recommendationsAr: string[];
}
