import type {
  EmailAnalysisResult,
  EmailAuthResults,
  EmailClassification,
  FindingIndicator,
  RiskAssessmentResult,
  RiskTreatment,
  ThreatSeverity,
  UrlAnalysisResult,
} from '../types/phishguard.ts';

const BRAND_DOMAINS = [
  'microsoft.com',
  'office365.com',
  'paypal.com',
  'google.com',
  'apple.com',
  'amazon.com',
  'dhl.com',
  'fedex.com',
  'linkedin.com',
  'github.com',
  'okta.com',
  'aramco.com',
  'alrajhibank.com.sa',
  'dropbox.com',
  'adobe.com',
  'stripe.com',
  'binance.com',
];

const FREE_MAIL_PROVIDERS = new Set([
  'gmail.com',
  'yahoo.com',
  'outlook.com',
  'hotmail.com',
  'proton.me',
  'protonmail.com',
  'yandex.com',
  'mail.ru',
]);

const SUSPICIOUS_TLDS = new Set([
  'zip',
  'mov',
  'top',
  'xyz',
  'click',
  'work',
  'tk',
  'ml',
  'ga',
  'cf',
  'gq',
  'rest',
  'cam',
  'cfd',
  'icu',
  'support',
  'security',
  'login',
]);

const URL_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'cutt.ly',
  'rb.gy',
  'rebrand.ly',
]);

const HIGH_RISK_EXTENSIONS = new Set([
  'exe',
  'scr',
  'bat',
  'cmd',
  'ps1',
  'vbs',
  'js',
  'jse',
  'hta',
  'iso',
  'img',
  'lnk',
  'msi',
  'dll',
]);

const MACRO_OR_SCRIPT_EXTENSIONS = new Set([
  'docm',
  'xlsm',
  'pptm',
  'html',
  'htm',
  'svg',
  'zip',
  'rar',
  '7z',
]);

const URGENCY_PATTERNS: Array<{ regex: RegExp; category: string; categoryAr: string; label: string; labelAr: string; weight: number }> = [
  {
    regex: /\b(urgent|immediate(?:ly)?|within 24 hours|suspend(?:ed|sion)?|locked|deactivat\w*|terminated|expire[sd]?|final notice|action required|verify your account)\b/i,
    category: 'Social Engineering',
    categoryAr: 'الهندسة الاجتماعية',
    label: 'Account suspension or deadline urgency pressure',
    labelAr: 'ضغط الاستعجال أو التهديد بتعليق الحساب',
    weight: 16,
  },
  {
    regex: /\b(wire transfer|invoice overdue|bank details|gift card|payroll update|chief executive|confidential payment|vendor settlement)\b/i,
    category: 'Financial Lure (BEC)',
    categoryAr: 'استدراج مالي (BEC)',
    label: 'Financial transfer or Business Email Compromise (BEC) lure',
    labelAr: 'مؤشرات احتيال مالي أو طلب تحويل عاجل',
    weight: 22,
  },
  {
    regex: /\b(password reset|confirm credentials|mfa reset|unusual sign-?in|security alert|click below to verify|re-?authenticate)\b/i,
    category: 'Credential Harvesting',
    categoryAr: 'سرقة بيانات الاعتماد',
    label: 'Credential or MFA verification prompt',
    labelAr: 'استدراج لإدخال بيانات الدخول أو رموز التحقق',
    weight: 18,
  },
  {
    regex: /(عاجل|تعليق الحساب|تحديث البيانات|كلمة المرور|تحويل مالي|خلال 24 ساعة|تأكيد الهوية|إيقاف الحساب)/i,
    category: 'Social Engineering',
    categoryAr: 'الهندسة الاجتماعية',
    label: 'Arabic social engineering urgency phrasing',
    labelAr: 'عبارات استعجال وهندسة اجتماعية باللغة العربية',
    weight: 18,
  },
];

export function sanitizeEmailText(input: string): string {
  return input
    .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '[script-removed]')
    .replace(/on\w+\s*=\s*(['"]).*?\1/gi, '')
    .replace(/<\/?[^>]+(>|$)/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

function normalizeHomoglyphs(domain: string): string {
  return domain
    .toLowerCase()
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/3/g, 'e')
    .replace(/5/g, 's')
    .replace(/@/g, 'a');
}

function extractRootDomain(hostname: string): { domain: string; subdomain: string; tld: string } {
  const clean = hostname.toLowerCase().replace(/\.$/, '');
  const parts = clean.split('.').filter(Boolean);
  if (parts.length <= 2) {
    return { domain: clean, subdomain: '', tld: parts[parts.length - 1] || '' };
  }
  return {
    domain: parts.slice(-2).join('.'),
    subdomain: parts.slice(0, -2).join('.'),
    tld: parts[parts.length - 1] || '',
  };
}

function detectTyposquatting(hostname: string): string | null {
  const { domain } = extractRootDomain(hostname);
  const normalized = normalizeHomoglyphs(domain);
  const normHostname = normalizeHomoglyphs(hostname);
  const baseLabel = domain.split('.')[0] || '';
  const normBase = normalized.split('.')[0] || '';

  for (const brand of BRAND_DOMAINS) {
    if (domain === brand) continue;
    const brandBase = brand.split('.')[0] || '';
    const distRaw = levenshtein(domain, brand);
    const distNorm = levenshtein(normalized, brand);
    const containsBrand =
      (hostname.toLowerCase().includes(brandBase) || normHostname.includes(brandBase)) &&
      !hostname.toLowerCase().endsWith(`.${brand}`) &&
      domain !== brand;

    if (distRaw <= 2 || distNorm <= 1 || containsBrand || (normBase === brandBase && domain !== brand)) {
      return brand;
    }
    if (baseLabel.length >= 5 && levenshtein(normBase, brandBase) <= 1 && domain !== brand) {
      return brand;
    }
  }
  return null;
}

export function classifyScore(score: number): EmailClassification {
  if (score >= 75) return 'High-Risk Phishing';
  if (score >= 50) return 'Phishing';
  if (score >= 25) return 'Suspicious';
  return 'Legitimate';
}

export function scoreToSeverity(score: number): ThreatSeverity {
  if (score >= 75) return 'Critical';
  if (score >= 50) return 'High';
  if (score >= 25) return 'Medium';
  return 'Low';
}

function buildScoreBreakdown(findings: FindingIndicator[]) {
  const map = new Map<string, { category: string; categoryAr: string; points: number }>();
  for (const f of findings) {
    const prev = map.get(f.category);
    if (prev) {
      prev.points += f.weight;
    } else {
      map.set(f.category, { category: f.category, categoryAr: f.categoryAr, points: f.weight });
    }
  }
  return Array.from(map.values()).sort((a, b) => b.points - a.points);
}

export function analyzeUrlClient(rawInput: string): UrlAnalysisResult {
  const trimmed = rawInput.trim();
  if (!trimmed || trimmed.length < 3 || !trimmed.includes('.')) {
    throw new Error('Please enter a valid URL or domain name (e.g. https://example.com).');
  }
  const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;

  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error('Invalid URL or domain syntax.');
  }

  const findings: FindingIndicator[] = [];
  let score = 0;

  const hostname = parsed.hostname.toLowerCase();
  const isIpBased = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':');
  const isHttps = parsed.protocol === 'https:';
  const hasPunycode = hostname.includes('xn--') || /[^\x20-\x7E]/.test(hostname);
  const hasAtSymbol = trimmed.includes('@');
  const { domain, subdomain, tld } = extractRootDomain(hostname);
  const typosquatTarget = isIpBased ? null : detectTyposquatting(hostname);
  const isShortener = URL_SHORTENERS.has(domain);
  const urlLength = trimmed.length;
  const encodingMatches = trimmed.match(/%[0-9a-fA-F]{2}/g) || [];
  const encodingCount = encodingMatches.length;

  const queryParams: Array<{ key: string; value: string; suspicious: boolean }> = [];
  parsed.searchParams.forEach((value, key) => {
    const suspiciousParam =
      /(redirect|next|url|dest|target|return|continue|token|session|login)/i.test(key) ||
      /^https?:\/\//i.test(value);
    queryParams.push({ key, value, suspicious: suspiciousParam });
  });

  if (typosquatTarget) {
    const weight = 42;
    score += weight;
    findings.push({
      id: `url-typo-${findings.length + 1}`,
      level: 'confirmed_malicious',
      category: 'Domain Spoofing',
      categoryAr: 'انتحال النطاق',
      weight,
      title: `Lookalike / typosquatted domain impersonating ${typosquatTarget}`,
      titleAr: `نطاق منتحل أو مشابه بصرياً للعلامة ${typosquatTarget}`,
      detail: `Hostname "${hostname}" closely resembles "${typosquatTarget}" using character substitution or brand-keyword injection.`,
      detailAr: `اسم النطاق "${hostname}" يحاكي "${typosquatTarget}" عبر استبدال أحرف أو حقن اسم العلامة التجارية.`,
      evidenceSnippet: hostname,
    });
  }

  if (isIpBased) {
    const weight = 34;
    score += weight;
    findings.push({
      id: `url-ip-${findings.length + 1}`,
      level: 'suspicious',
      category: 'IP Host Literal',
      categoryAr: 'عنوان IP مباشر',
      weight,
      title: 'Direct IP-based host instead of registered domain name',
      titleAr: 'استخدام عنوان IP مباشر بدلاً من اسم نطاق مسجل',
      detail: `Host "${hostname}" uses a raw IP address, commonly seen in temporary phishing kits to bypass domain reputation filters.`,
      detailAr: `المضيف "${hostname}" يستخدم عنوان IP مباشر، وهي تقنية شائعة لتجاوز فلاتر سمعة النطاقات.`,
      evidenceSnippet: hostname,
    });
  }

  if (hasAtSymbol) {
    const weight = 32;
    score += weight;
    findings.push({
      id: `url-at-${findings.length + 1}`,
      level: 'confirmed_malicious',
      category: 'Deceptive Syntax',
      categoryAr: 'بنية مضللة',
      weight,
      title: 'Credential-prefix "@" obfuscation in URL authority',
      titleAr: 'استخدام الرمز "@" لإخفاء الوجهة الحقيقية للرابط',
      detail: 'Browsers treat text before "@" as userinfo and navigate to the host after "@", masking the true destination.',
      detailAr: 'تتجاهل المتصفحات النص قبل "@" وتنتقل إلى المضيف بعده مما يخفي الوجهة الفعلية.',
      evidenceSnippet: trimmed.slice(0, 90),
    });
  }

  if (hasPunycode) {
    const weight = 26;
    score += weight;
    findings.push({
      id: `url-idn-${findings.length + 1}`,
      level: 'suspicious',
      category: 'Homograph Risk',
      categoryAr: 'خطر تشابه الأحرف',
      weight,
      title: 'Punycode / Internationalized Domain Name (IDN) detected',
      titleAr: 'اكتشاف ترميز Punycode أو أحرف دولية غير قياسية',
      detail: 'Presence of "xn--" or non-ASCII characters may indicate an IDN homograph impersonation attack.',
      detailAr: 'وجود ترميز xn-- أو أحرف غير قياسية قد يشير إلى هجوم تشابه الأحرف البصري.',
      evidenceSnippet: hostname,
    });
  }

  if (SUSPICIOUS_TLDS.has(tld)) {
    const weight = 20;
    score += weight;
    findings.push({
      id: `url-tld-${findings.length + 1}`,
      level: 'suspicious',
      category: 'TLD Risk',
      categoryAr: 'خطورة الامتداد',
      weight,
      title: `High-abuse top-level domain (.${tld})`,
      titleAr: `امتداد نطاق مرتفع الاستغلال (.${tld})`,
      detail: `The .${tld} TLD appears frequently in disposable phishing campaigns.`,
      detailAr: `الامتداد .${tld} يُستغل بكثرة في حملات التصيد المؤقتة.`,
      evidenceSnippet: `.${tld}`,
    });
  }

  if (isShortener) {
    const weight = 22;
    score += weight;
    findings.push({
      id: `url-short-${findings.length + 1}`,
      level: 'suspicious',
      category: 'Obfuscation',
      categoryAr: 'إخفاء الوجهة',
      weight,
      title: `URL shortener obscures final destination (${domain})`,
      titleAr: `خدمة اختصار روابط تخفي الوجهة النهائية (${domain})`,
      detail: 'Shortened links mask the true landing domain and should be expanded safely before trusting.',
      detailAr: 'الروابط المختصرة تخفي النطاق النهائي ويجب كشفها في بيئة معزولة قبل فتحها.',
      evidenceSnippet: domain,
    });
  }

  if (subdomain && subdomain.split('.').length >= 3) {
    const weight = 18;
    score += weight;
    findings.push({
      id: `url-sub-${findings.length + 1}`,
      level: 'suspicious',
      category: 'URL Structure',
      categoryAr: 'بنية الرابط',
      weight,
      title: 'Deeply nested subdomain chain',
      titleAr: 'سلسلة نطاقات فرعية متداخلة بشكل مريب',
      detail: `Detected ${subdomain.split('.').length} subdomain levels ("${subdomain}"), often crafted to place trusted keywords on the left.`,
      detailAr: `تم رصد عدة مستويات من النطاقات الفرعية ("${subdomain}") لإظهار كلمات موثوقة في بداية الرابط.`,
      evidenceSnippet: subdomain,
    });
  }

  const redirectParams = queryParams.filter((p) => p.suspicious);
  if (redirectParams.length > 0) {
    const weight = 20;
    score += weight;
    findings.push({
      id: `url-redir-${findings.length + 1}`,
      level: 'suspicious',
      category: 'Query Parameters',
      categoryAr: 'معاملات الاستعلام',
      weight,
      title: 'Suspicious redirect or token query parameters',
      titleAr: 'معاملات استعلام مريبة لإعادة التوجيه أو جمع الرموز',
      detail: `Detected sensitive parameter keys: ${redirectParams.map((p) => p.key).join(', ')}.`,
      detailAr: `تم رصد معاملات حساسة في الرابط: ${redirectParams.map((p) => p.key).join(', ')}.`,
      evidenceSnippet: parsed.search.slice(0, 90),
    });
  }

  if (urlLength > 100) {
    const weight = 12;
    score += weight;
    findings.push({
      id: `url-len-${findings.length + 1}`,
      level: 'suspicious',
      category: 'URL Structure',
      categoryAr: 'بنية الرابط',
      weight,
      title: `Excessive URL length (${urlLength} characters)`,
      titleAr: `طول رابط مفرط (${urlLength} حرفاً)`,
      detail: 'Overly long URLs often conceal redirect chains or encoded tracking payloads.',
      detailAr: 'الروابط الطويلة جداً تُستخدم لإخفاء سلاسل التوجيه أو البيانات المرمزة.',
    });
  }

  if (encodingCount >= 4) {
    const weight = 14;
    score += weight;
    findings.push({
      id: `url-enc-${findings.length + 1}`,
      level: 'suspicious',
      category: 'Encoding',
      categoryAr: 'الترميز',
      weight,
      title: `Heavy percent-encoding (${encodingCount} encoded sequences)`,
      titleAr: `نسبة ترميز مرتفعة (${encodingCount} تسلسل مرمز)`,
      detail: 'Repeated percent-encoding can hide keywords from simple filters.',
      detailAr: 'تكرار الترميز المئوي قد يهدف لإخفاء الكلمات عن مرشحات الأمان.',
    });
  }

  if (!isHttps) {
    const weight = 10;
    score += weight;
    findings.push({
      id: `url-http-${findings.length + 1}`,
      level: 'informational',
      category: 'Transport Security',
      categoryAr: 'أمان النقل',
      weight,
      title: 'Unencrypted HTTP scheme (no TLS)',
      titleAr: 'بروتوكول HTTP غير مشفر (بدون TLS)',
      detail: 'Unencrypted transport detected. Note that HTTPS alone does not prove safety, as phishing sites also deploy free certificates.',
      detailAr: 'الرابط غير مشفر، مع ملاحظة أن وجود HTTPS لا يعني الموثوقية لأن مواقع التصيد تستخدم شهادات مجانية أيضاً.',
    });
  }

  const riskScore = Math.min(100, Math.max(4, score));
  const classification = classifyScore(riskScore);
  const severity = scoreToSeverity(riskScore);
  const confidence = Math.min(95, 62 + findings.length * 7);

  const explanation =
    findings.length === 0
      ? `Local heuristic inspection found no structural phishing indicators, lookalike patterns, or deceptive query parameters in "${hostname}".`
      : `Classified as ${classification} (${riskScore}/100) by client-side heuristics due to ${findings.length} detected indicator(s): ${findings
          .slice(0, 3)
          .map((f) => f.title)
          .join('; ')}.`;

  const explanationAr =
    findings.length === 0
      ? `لم يرصد التحليل الاستدلالي المحلي أي مؤشرات تصيد أو انتحال أو معاملات مضللة في النطاق "${hostname}".`
      : `تم تصنيف الرابط (${classification}) بدرجة خطورة ${riskScore}/100 بناءً على ${findings.length} مؤشر(ات): ${findings
          .slice(0, 3)
          .map((f) => f.titleAr)
          .join('؛ ')}.`;

  const recommendedActions =
    riskScore >= 50
      ? [
          'Do not open or enter credentials on this URL.',
          'Block the hostname/domain in your web gateway or DNS filter.',
          'Verify external reputation via an authorized sandbox or threat feed before allowing access.',
        ]
      : riskScore >= 25
        ? [
            'Inspect destination inside an isolated sandbox browser before opening.',
            'Verify domain registration age and exact brand spelling.',
          ]
        : ['No local heuristic anomalies found; maintain standard browsing caution.'];

  const recommendedActionsAr =
    riskScore >= 50
      ? [
          'لا تفتح هذا الرابط ولا تُدخل أي بيانات اعتماد فيه.',
          'احظر النطاق أو المضيف عبر بوابة الويب أو مرشح DNS.',
          'تحقق من السمعة الخارجية عبر بيئة معزولة قبل السماح بالوصول.',
        ]
      : riskScore >= 25
        ? [
            'افحص الوجهة في متصفح معزول (Sandbox) قبل الفتح.',
            'تحقق من عمر النطاق والهجاء الدقيق لاسم العلامة التجارية.',
          ]
        : ['لم تُرصد شذوذات محلية؛ استمر في الحذر المعتاد عند التصفح.'];

  return {
    id: `URL-${Date.now().toString().slice(-6)}`,
    analyzedAt: new Date().toISOString(),
    submittedInput: trimmed,
    normalizedUrl: parsed.href,
    protocol: parsed.protocol.replace(':', ''),
    hostname,
    domain,
    subdomain,
    tld,
    port: parsed.port || (isHttps ? '443' : '80'),
    path: parsed.pathname || '/',
    queryParams,
    isIpBased,
    isHttps,
    hasPunycode,
    hasAtSymbol,
    typosquatTarget,
    isShortener,
    urlLength,
    encodingCount,
    classification,
    severity,
    riskScore,
    confidence,
    scoreBreakdown: buildScoreBreakdown(findings),
    findings,
    explanation,
    explanationAr,
    recommendedActions,
    recommendedActionsAr,
    intelligenceMode: 'heuristic_only',
    externalIntelStatus:
      'Client-Side Heuristic Analysis Only — No external threat intelligence API is queried from the browser.',
    externalIntelStatusAr:
      'تحليل استدلالي محلي فقط في المتصفح — لم يتم الاستعلام من قواعد استخبارات تهديدات خارجية.',
  };
}

export interface EmailClientInput {
  rawEmail?: string;
  senderEmail?: string;
  senderDisplayName?: string;
  replyTo?: string;
  subject?: string;
  headersText?: string;
  body?: string;
  attachmentNames?: string[];
}

function parseRawEmailClient(raw: string) {
  const splitIdx = raw.search(/\r?\n\r?\n/);
  const headerBlock = splitIdx >= 0 ? raw.slice(0, splitIdx) : raw;
  const bodyBlock = splitIdx >= 0 ? raw.slice(splitIdx).trim() : '';

  const unfolded = headerBlock.replace(/\r?\n[ \t]+/g, ' ');
  const headers: Array<{ key: string; value: string }> = [];
  for (const line of unfolded.split(/\r?\n/)) {
    const colon = line.indexOf(':');
    if (colon > 0) {
      headers.push({
        key: line.slice(0, colon).trim(),
        value: line.slice(colon + 1).trim(),
      });
    }
  }

  const getHeader = (name: string) =>
    headers.find((h) => h.key.toLowerCase() === name.toLowerCase())?.value || '';

  const fromRaw = getHeader('From');
  const fromMatch = fromRaw.match(/^(?:"?([^"<]*)"?\s*)?<([^>]+)>$/);
  const senderDisplayName = fromMatch ? fromMatch[1].trim() : '';
  const senderEmail = fromMatch
    ? fromMatch[2].trim()
    : (fromRaw.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i)?.[0] || fromRaw).trim();

  const replyToRaw = getHeader('Reply-To');
  const replyTo =
    replyToRaw.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i)?.[0] || replyToRaw.trim();

  const returnPathRaw = getHeader('Return-Path');
  const returnPath =
    returnPathRaw.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i)?.[0] || returnPathRaw.trim();

  const subject = getHeader('Subject');
  const routingHops = headers.filter((h) => h.key.toLowerCase() === 'received').map((h) => h.value);

  const mimeAttachments: string[] = [];
  const fnRegex = /filename\*?=(?:"([^"]+)"|([^\s;]+))/gi;
  let m: RegExpExecArray | null;
  while ((m = fnRegex.exec(raw)) !== null) {
    mimeAttachments.push((m[1] || m[2] || '').trim());
  }

  return {
    headers,
    senderDisplayName,
    senderEmail,
    replyTo,
    returnPath,
    subject,
    body: bodyBlock || raw,
    routingHops,
    mimeAttachments,
  };
}

function parseAuthenticationClient(headers: Array<{ key: string; value: string }>): EmailAuthResults {
  const authText = headers
    .filter((h) =>
      ['authentication-results', 'received-spf', 'dkim-signature', 'arc-authentication-results'].includes(
        h.key.toLowerCase(),
      ),
    )
    .map((h) => `${h.key}: ${h.value}`)
    .join('\n')
    .toLowerCase();

  const extractStatus = (proto: 'spf' | 'dkim' | 'dmarc') => {
    const m = authText.match(new RegExp(`${proto}=(pass|fail|softfail|neutral|none)`));
    return m ? m[1] : 'none';
  };

  const spf = extractStatus('spf') as EmailAuthResults['spf'];
  const dkimRaw = extractStatus('dkim');
  const dkim = (dkimRaw === 'pass' || dkimRaw === 'fail' ? dkimRaw : 'none') as EmailAuthResults['dkim'];
  const dmarcRaw = extractStatus('dmarc');
  const dmarc = (dmarcRaw === 'pass' || dmarcRaw === 'fail' ? dmarcRaw : 'none') as EmailAuthResults['dmarc'];

  return {
    spf,
    dkim,
    dmarc,
    note: 'SPF/DKIM/DMARC failures elevate suspicion when paired with lure or domain anomalies, but never prove phishing alone (forwarding or misconfiguration can break alignment).',
    noteAr: 'فشل SPF/DKIM/DMARC يرفع درجة الاشتباه عند اقترانه بمؤشرات أخرى، ولا يثبت التصيد بمفرده (قد ينتج عن إعادة التوجيه).',
  };
}

export function analyzeEmailClient(input: EmailClientInput): EmailAnalysisResult {
  const parsed = input.rawEmail ? parseRawEmailClient(input.rawEmail) : null;
  const headers = [...(parsed?.headers || [])];

  if (input.headersText) {
    for (const line of input.headersText.split(/\r?\n/)) {
      const idx = line.indexOf(':');
      if (idx > 0) {
        headers.push({ key: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() });
      }
    }
  }

  const senderEmail = (input.senderEmail || parsed?.senderEmail || '').trim();
  const senderDisplayName = (input.senderDisplayName || parsed?.senderDisplayName || '').trim();
  const replyTo = (input.replyTo || parsed?.replyTo || '').trim();
  const returnPath = (parsed?.returnPath || '').trim();
  const subject = (input.subject || parsed?.subject || '(No Subject)').trim();
  const rawBody = input.body || parsed?.body || '';
  const sanitizedBodyPreview = sanitizeEmailText(rawBody).slice(0, 1400);
  const routingHops =
    parsed?.routingHops ||
    headers.filter((h) => h.key.toLowerCase() === 'received').map((h) => h.value);

  const auth = parseAuthenticationClient(headers);
  const findings: FindingIndicator[] = [];
  let score = 0;

  const senderDomain = (senderEmail.split('@')[1] || '').toLowerCase();
  const replyDomain = (replyTo.split('@')[1] || '').toLowerCase();
  const returnDomain = (returnPath.split('@')[1] || '').toLowerCase();

  // 1. Sender lookalike domain check
  if (senderDomain) {
    const typo = detectTyposquatting(senderDomain);
    if (typo) {
      const weight = 38;
      score += weight;
      findings.push({
        id: 'em-sender-typo',
        level: 'confirmed_malicious',
        category: 'Sender Impersonation',
        categoryAr: 'انتحال المرسل',
        weight,
        title: `Sender domain "${senderDomain}" impersonates "${typo}"`,
        titleAr: `نطاق المرسل "${senderDomain}" ينتحل العلامة "${typo}"`,
        detail: 'Lookalike sender domain detected via homoglyph normalization and edit-distance matching.',
        detailAr: 'تم اكتشاف تشابه بصري مع علامة معروفة عبر تحليل استبدال الأحرف.',
        evidenceSnippet: senderEmail,
      });
    }
  }

  // 2. Display name inconsistency
  if (senderDisplayName && senderDomain) {
    const displayLower = senderDisplayName.toLowerCase();
    for (const brand of BRAND_DOMAINS) {
      const brandName = brand.split('.')[0];
      if (displayLower.includes(brandName) && !senderDomain.endsWith(brand)) {
        const weight = 24;
        score += weight;
        findings.push({
          id: 'em-display-mismatch',
          level: 'suspicious',
          category: 'Sender Impersonation',
          categoryAr: 'انتحال المرسل',
          weight,
          title: `Display name "${senderDisplayName}" mismatches sender domain "${senderDomain}"`,
          titleAr: `الاسم الظاهر "${senderDisplayName}" لا يتطابق مع نطاق المرسل "${senderDomain}"`,
          detail: `Sender display name references "${brandName}" while originating from "${senderDomain}".`,
          detailAr: `الاسم الظاهر يشير إلى "${brandName}" بينما الرسالة مرسلة من "${senderDomain}".`,
          evidenceSnippet: `${senderDisplayName} <${senderEmail}>`,
        });
        break;
      }
    }

    if (
      /\b(ceo|cfo|president|director|executive|it support|helpdesk|security team|hr)\b/i.test(displayLower) &&
      FREE_MAIL_PROVIDERS.has(senderDomain)
    ) {
      const weight = 24;
      score += weight;
      findings.push({
        id: 'em-exec-freemail',
        level: 'suspicious',
        category: 'BEC Impersonation',
        categoryAr: 'انتحال صفة تنفيذية',
        weight,
        title: `Corporate persona "${senderDisplayName}" using free webmail (${senderDomain})`,
        titleAr: `صفة مؤسسية "${senderDisplayName}" تستخدم بريداً مجانياً (${senderDomain})`,
        detail: 'Executive or IT roles sending from consumer webmail strongly indicate Business Email Compromise.',
        detailAr: 'انتحال الأدوار القيادية أو الدعم الفني عبر بريد مجاني مؤشر شائع لهجمات BEC.',
        evidenceSnippet: senderEmail,
      });
    }
  }

  // 3. Reply-To / Return-Path mismatch
  if (replyTo && senderDomain && replyDomain && replyDomain !== senderDomain) {
    const weight = 22;
    score += weight;
    findings.push({
      id: 'em-reply-mismatch',
      level: 'suspicious',
      category: 'Header Anomaly',
      categoryAr: 'شذوذ الترويسة',
      weight,
      title: `Reply-To domain (${replyDomain}) differs from From domain (${senderDomain})`,
      titleAr: `نطاق الرد (${replyDomain}) يختلف عن نطاق المرسل (${senderDomain})`,
      detail: 'Responses are silently redirected to a separate external domain.',
      detailAr: 'يتم توجيه الردود إلى نطاق خارجي مختلف عن النطاق الظاهر للمرسل.',
      evidenceSnippet: `From: ${senderEmail} | Reply-To: ${replyTo}`,
    });
  } else if (returnPath && senderDomain && returnDomain && returnDomain !== senderDomain) {
    const weight = 12;
    score += weight;
    findings.push({
      id: 'em-returnpath',
      level: 'informational',
      category: 'Header Anomaly',
      categoryAr: 'شذوذ الترويسة',
      weight,
      title: `Return-Path domain (${returnDomain}) differs from From domain (${senderDomain})`,
      titleAr: `مسار الإرجاع (${returnDomain}) يختلف عن نطاق المرسل (${senderDomain})`,
      detail: 'Bounce address domain does not match visible sender domain (may occur with bulk mailers or spoofing).',
      detailAr: 'عنوان الارتداد يختلف عن نطاق المرسل الظاهر (يحدث في القوائم البريدية أو الانتحال).',
      evidenceSnippet: returnPath,
    });
  }

  // 4. Email Authentication alignment
  const failedAuths: string[] = [];
  if (auth.spf === 'fail' || auth.spf === 'softfail') failedAuths.push(`SPF:${auth.spf}`);
  if (auth.dkim === 'fail') failedAuths.push('DKIM:fail');
  if (auth.dmarc === 'fail') failedAuths.push('DMARC:fail');
  if (failedAuths.length > 0) {
    const weight = Math.min(18, failedAuths.length * 7);
    score += weight;
    findings.push({
      id: 'em-auth-fail',
      level: 'suspicious',
      category: 'Email Authentication',
      categoryAr: 'مصادقة البريد',
      weight,
      title: `Authentication alignment failure (${failedAuths.join(', ')})`,
      titleAr: `فشل التحقق من مصادقة البريد (${failedAuths.join(', ')})`,
      detail: 'SPF/DKIM/DMARC failure raises suspicion alongside other cues, though forwarding can also cause failures.',
      detailAr: 'فشل المصادقة يزيد درجة الاشتباه عند اقترانه بقرائن أخرى، ولا يكفي وحده لإثبات التصيد.',
      evidenceSnippet: failedAuths.join(' · '),
    });
  }

  // 5. Urgency & social engineering keywords
  const combinedText = `${subject}\n${sanitizedBodyPreview}`;
  for (const pat of URGENCY_PATTERNS) {
    const match = combinedText.match(pat.regex);
    if (match) {
      score += pat.weight;
      findings.push({
        id: `em-se-${findings.length + 1}`,
        level: 'suspicious',
        category: pat.category,
        categoryAr: pat.categoryAr,
        weight: pat.weight,
        title: pat.label,
        titleAr: pat.labelAr,
        detail: `Matched social engineering indicator phrase: "${match[0]}".`,
        detailAr: `تم رصد عبارة استدراج أو ضغط نفسي: "${match[0]}".`,
        evidenceSnippet: match[0],
      });
    }
  }

  // 6. Embedded URL inspection
  const urlMatches = rawBody.match(/https?:\/\/[^\s"'<>)\]]+/gi) || [];
  const uniqueUrls = Array.from(new Set(urlMatches.map((u) => u.replace(/[.,;!?]+$/, '')))).slice(0, 15);
  const extractedUrls: EmailAnalysisResult['extractedUrls'] = [];

  for (const u of uniqueUrls) {
    try {
      const urlEval = analyzeUrlClient(u);
      extractedUrls.push({
        url: u,
        riskScore: urlEval.riskScore,
        classification: urlEval.classification,
      });
      if (urlEval.riskScore >= 50) {
        const weight = 30;
        score += weight;
        findings.push({
          id: `em-url-${findings.length + 1}`,
          level: urlEval.findings.some((f) => f.level === 'confirmed_malicious')
            ? 'confirmed_malicious'
            : 'suspicious',
          category: 'Embedded URL',
          categoryAr: 'الروابط المدمجة',
          weight,
          title: `High-risk embedded URL (${urlEval.hostname})`,
          titleAr: `رابط مدمج عالي الخطورة (${urlEval.hostname})`,
          detail: `URL heuristic score ${urlEval.riskScore}/100: ${urlEval.findings.map((f) => f.title).slice(0, 2).join('; ')}.`,
          detailAr: `درجة الرابط ${urlEval.riskScore}/100: ${urlEval.findings.map((f) => f.titleAr).slice(0, 2).join('؛ ')}.`,
          evidenceSnippet: u,
        });
      } else if (urlEval.riskScore >= 25) {
        const weight = 14;
        score += weight;
        findings.push({
          id: `em-url-${findings.length + 1}`,
          level: 'suspicious',
          category: 'Embedded URL',
          categoryAr: 'الروابط المدمجة',
          weight,
          title: `Suspicious embedded URL (${urlEval.hostname})`,
          titleAr: `رابط مدمج مريب (${urlEval.hostname})`,
          detail: `URL scored ${urlEval.riskScore}/100 under local heuristic checks.`,
          detailAr: `سجّل الرابط ${urlEval.riskScore}/100 في الفحص المحلي.`,
          evidenceSnippet: u,
        });
      }
    } catch {
      // Skip malformed URL string
    }
  }

  // 7. Attachment metadata inspection (never executed)
  const attachmentNames = Array.from(
    new Set([...(input.attachmentNames || []), ...(parsed?.mimeAttachments || [])].filter(Boolean)),
  );
  const attachments = attachmentNames.map((filename) => {
    const lower = filename.toLowerCase();
    const parts = lower.split('.');
    const extension = parts.length > 1 ? parts[parts.length - 1] : '';
    const hasDoubleExtension = parts.length >= 3 && HIGH_RISK_EXTENSIONS.has(extension);

    if (HIGH_RISK_EXTENSIONS.has(extension) || hasDoubleExtension) {
      const weight = 36;
      score += weight;
      findings.push({
        id: `em-att-${findings.length + 1}`,
        level: 'confirmed_malicious',
        category: 'Dangerous Attachment',
        categoryAr: 'مرفق خطير',
        weight,
        title: `Executable or script attachment "${filename}"`,
        titleAr: `مرفق تنفيذي أو برمجي خطير "${filename}"`,
        detail: hasDoubleExtension
          ? 'Double extension masquerading technique detected (e.g. .pdf.exe).'
          : `Executable/container extension .${extension} is commonly blocked by email security policy.`,
        detailAr: hasDoubleExtension
          ? 'تم رصد تقنية تمويه الامتداد المزدوج للملف.'
          : `الامتداد .${extension} يصنف ضمن المرفقات التنفيذية الخطيرة.`,
        evidenceSnippet: filename,
      });
      return {
        filename,
        extension,
        riskLevel: 'Critical' as ThreatSeverity,
        reason: hasDoubleExtension ? 'Double extension payload' : `Executable/script (.${extension})`,
        reasonAr: hasDoubleExtension ? 'تمويه امتداد مزدوج' : `ملف تنفيذي (.${extension})`,
      };
    }

    if (MACRO_OR_SCRIPT_EXTENSIONS.has(extension)) {
      const weight = 20;
      score += weight;
      findings.push({
        id: `em-att-${findings.length + 1}`,
        level: 'suspicious',
        category: 'Dangerous Attachment',
        categoryAr: 'مرفق خطير',
        weight,
        title: `Macro-enabled or active HTML attachment "${filename}"`,
        titleAr: `مرفق يحتوي على ماكرو أو صفحة HTML نشطة "${filename}"`,
        detail: `Format .${extension} is frequently abused for HTML smuggling or macro malware delivery.`,
        detailAr: `النوع .${extension} يُستخدم بكثرة في تهريب صفحات التصيد أو الماكرو الخبيث.`,
        evidenceSnippet: filename,
      });
      return {
        filename,
        extension,
        riskLevel: 'High' as ThreatSeverity,
        reason: `Active script/macro/archive (.${extension})`,
        reasonAr: `ملف نشط/ماكرو (.${extension})`,
      };
    }

    return {
      filename,
      extension,
      riskLevel: 'Low' as ThreatSeverity,
      reason: 'Standard document extension',
      reasonAr: 'امتداد مستند اعتيادي',
    };
  });

  // Safeguard: Authentication failure alone never proves phishing
  const nonAuthFindings = findings.filter((f) => f.category !== 'Email Authentication');
  if (nonAuthFindings.length === 0 && failedAuths.length > 0) {
    score = Math.min(score, 32);
  }

  const riskScore = Math.min(100, Math.max(3, score));
  const classification = classifyScore(riskScore);
  const severity = scoreToSeverity(riskScore);
  const confidence = Math.min(97, 60 + findings.length * 6);

  const explanation =
    findings.length === 0
      ? 'No phishing indicators, impersonation anomalies, suspicious URLs, or high-risk attachments were found by local browser heuristics.'
      : `Classified as ${classification} (${riskScore}/100) based on ${
          findings.filter((f) => f.level === 'confirmed_malicious').length
        } high-confidence malicious indicator(s) and ${
          findings.filter((f) => f.level === 'suspicious').length
        } suspicious indicator(s): ${findings
          .slice(0, 3)
          .map((f) => f.title)
          .join('; ')}.`;

  const explanationAr =
    findings.length === 0
      ? 'لم يتم رصد مؤشرات تصيد أو انتحال مرسل أو روابط مريبة في هذه الرسالة.'
      : `تم تصنيف البريد (${classification}) بدرجة خطورة ${riskScore}/100 استناداً إلى ${
          findings.filter((f) => f.level === 'confirmed_malicious').length
        } مؤشر عالي الخطورة و${
          findings.filter((f) => f.level === 'suspicious').length
        } مؤشر مريب: ${findings
          .slice(0, 3)
          .map((f) => f.titleAr)
          .join('؛ ')}.`;

  const recommendedActions =
    riskScore >= 50
      ? [
          'Do not click links, download attachments, or reply to this message.',
          'Report and quarantine the message in your email client or security team.',
          'If credentials were already entered, immediately change passwords and revoke active sessions.',
        ]
      : riskScore >= 25
        ? [
            'Verify the sender through a trusted phone number or separate communication channel.',
            'Inspect extracted links safely before navigating.',
          ]
        : ['Message passed local heuristic checks; remain attentive to unexpected requests.'];

  const recommendedActionsAr =
    riskScore >= 50
      ? [
          'لا تنقر على أي رابط ولا تفتح المرفقات ولا ترد على الرسالة.',
          'أبلغ عن الرسالة واعزلها عبر فريق الأمان أو بريدك الإلكتروني.',
          'إذا تم إدخال بيانات اعتماد، غيّر كلمة المرور فوراً وأبطل الجلسات النشطة.',
        ]
      : riskScore >= 25
        ? [
            'تحقق من هوية المرسل عبر رقم هاتف موثوق أو قناة اتصال بديلة.',
            'افحص الروابط المستخرجة بأمان قبل زيارتها.',
          ]
        : ['اجتازت الرسالة الفحص المحلي بنجاح؛ استمر في التحقق من الطلبات غير المتوقعة.'];

  return {
    id: `EML-${Date.now().toString().slice(-6)}`,
    analyzedAt: new Date().toISOString(),
    senderEmail: senderEmail || 'Not specified',
    senderDisplayName,
    replyTo,
    returnPath,
    subject,
    sanitizedBodyPreview,
    extractedUrls,
    attachments,
    auth,
    headers,
    routingHops,
    classification,
    severity,
    riskScore,
    confidence,
    scoreBreakdown: buildScoreBreakdown(findings),
    findings,
    explanation,
    explanationAr,
    recommendedActions,
    recommendedActionsAr,
    intelligenceMode: 'heuristic_only',
  };
}

export function evaluateRiskMatrix(params: {
  assetName: string;
  threatScenario: string;
  likelihood: number;
  impact: number;
  controlEffectiveness: number;
  strategy: RiskTreatment;
}): RiskAssessmentResult {
  const likelihood = Math.min(5, Math.max(1, Math.round(params.likelihood)));
  const impact = Math.min(5, Math.max(1, Math.round(params.impact)));
  const controlEffectiveness = Math.min(90, Math.max(0, Math.round(params.controlEffectiveness)));

  const inherentScore = likelihood * impact;
  const residualScore = Math.max(1, Math.round(inherentScore * (1 - controlEffectiveness / 100)));

  const toLevel = (s: number): ThreatSeverity => {
    if (s >= 17) return 'Critical';
    if (s >= 10) return 'High';
    if (s >= 5) return 'Medium';
    return 'Low';
  };

  const inherentLevel = toLevel(inherentScore);
  const residualLevel = toLevel(residualScore);

  const recommendationsEn: string[] = [];
  const recommendationsAr: string[] = [];

  if (inherentScore >= 17) {
    recommendationsEn.push('Critical inherent exposure: enforce phishing-resistant MFA (FIDO2/WebAuthn) immediately.');
    recommendationsEn.push('Block executable/script email attachments and enforce strict DMARC (p=reject).');
    recommendationsAr.push('تعرض حرج للمخاطر: فرض المصادقة متعددة العوامل المقاومة للتصيد (FIDO2) فوراً.');
    recommendationsAr.push('حظر المرفقات التنفيذية وتطبيق سياسة DMARC الصارمة (p=reject).');
  } else if (inherentScore >= 10) {
    recommendationsEn.push('High risk level: deploy external sender warning banners and URL link rewriting/isolation.');
    recommendationsEn.push('Require out-of-band verification for financial or credential-change requests.');
    recommendationsAr.push('مستوى مخاطرة مرتفع: تفعيل تنبيهات المرسل الخارجي وعزل الروابط المريبة.');
    recommendationsAr.push('اشتراط التحقق خارج نطاق البريد لأي طلبات مالية أو تغيير صلاحيات.');
  } else {
    recommendationsEn.push('Moderate/Low risk: maintain periodic security awareness drills and email gateway filtering.');
    recommendationsAr.push('مخاطرة منخفضة/متوسطة: مواصلة برامج التوعية الدورية وفلاتر بوابة البريد.');
  }

  if (params.strategy === 'Transfer') {
    recommendationsEn.push('Document cyber-insurance or third-party managed SOC SLA coverage for residual exposure.');
    recommendationsAr.push('توثيق التغطية التأمينية السيبرانية أو اتفاقيات خدمات الحماية المدارة للمخاطر المتبقية.');
  } else if (params.strategy === 'Avoid') {
    recommendationsEn.push('Decommission legacy authentication protocols (POP/IMAP/Basic Auth) to eliminate attack vector.');
    recommendationsAr.push('إيقاف بروتوكولات المصادقة القديمة للقضاء على مسار الهجوم تماماً.');
  } else if (params.strategy === 'Accept') {
    recommendationsEn.push('Obtain formal risk acceptance sign-off and monitor residual score quarterly.');
    recommendationsAr.push('توثيق قبول المخاطرة رسمياً ومراجعة المخاطرة المتبقية بشكل ربع سنوي.');
  }

  return {
    id: `RSK-${Date.now().toString().slice(-6)}`,
    evaluatedAt: new Date().toISOString(),
    assetName: params.assetName.trim() || 'Corporate Email & Identity',
    threatScenario: params.threatScenario.trim() || 'Phishing & Credential Compromise',
    likelihood,
    impact,
    inherentScore,
    inherentLevel,
    controlEffectiveness,
    residualScore,
    residualLevel,
    strategy: params.strategy,
    recommendationsEn,
    recommendationsAr,
  };
}
