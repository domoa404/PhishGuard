import type {
  EmailAnalysisResult,
  EmailAuthResults,
  EmailClassification,
  FindingIndicator,
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

const URGENCY_PATTERNS: Array<{ regex: RegExp; label: string; labelAr: string }> = [
  {
    regex: /\b(urgent|immediate(?:ly)?|within 24 hours|suspend(?:ed|sion)?|locked|deactivat\w*|terminated|expire[sd]?|final notice|action required|verify your account)\b/i,
    label: 'Account suspension or deadline urgency pressure',
    labelAr: 'ضغط الاستعجال أو التهديد بتعليق الحساب',
  },
  {
    regex: /\b(wire transfer|invoice overdue|bank details|gift card|payroll update|chief executive|confidential payment)\b/i,
    label: 'Financial / Business Email Compromise (BEC) lure',
    labelAr: 'مؤشرات احتيال مالي أو انتحال صفة تنفيذية (BEC)',
  },
  {
    regex: /\b(password reset|confirm credentials|mfa reset|unusual sign-?in|security alert|click below to verify)\b/i,
    label: 'Credential harvesting prompt',
    labelAr: 'استدراج لإدخال بيانات الاعتماد وكلمات المرور',
  },
  {
    regex: /(عاجل|تعليق الحساب|تحديث البيانات|كلمة المرور|تحويل مالي|خلال 24 ساعة|تأكيد الهوية)/i,
    label: 'Arabic social engineering urgency phrase',
    labelAr: 'عبارات هندسة اجتماعية واستعجال باللغة العربية',
  },
];

export function sanitizeText(input: string): string {
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
  const domain = parts.slice(-2).join('.');
  const subdomain = parts.slice(0, -2).join('.');
  const tld = parts[parts.length - 1] || '';
  return { domain, subdomain, tld };
}

function detectTyposquatting(hostname: string): string | null {
  const { domain } = extractRootDomain(hostname);
  const normalized = normalizeHomoglyphs(domain);
  const baseLabel = domain.split('.')[0] || '';
  const normBase = normalized.split('.')[0] || '';

  for (const brand of BRAND_DOMAINS) {
    if (domain === brand) continue;
    const brandBase = brand.split('.')[0] || '';
    const distRaw = levenshtein(domain, brand);
    const distNorm = levenshtein(normalized, brand);
    const normHostname = normalizeHomoglyphs(hostname);
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

export function analyzeUrlHeuristic(
  rawInput: string,
  knownBadMatches: Array<{ indicator: string; category: string; reputationScore: number; source: string }> = [],
): UrlAnalysisResult {
  const trimmed = rawInput.trim();
  const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;

  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error('Invalid URL or domain format');
  }

  const findings: FindingIndicator[] = [];
  let score = 0;

  const hostname = parsed.hostname.toLowerCase();
  const isIpBased = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':');
  const isHttps = parsed.protocol === 'https:';
  const hasPunycode = hostname.includes('xn--') || /[^\x20-\x7E]/.test(hostname);
  const { domain, subdomain, tld } = extractRootDomain(hostname);
  const typosquatTarget = isIpBased ? null : detectTyposquatting(hostname);
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

  // Check known malicious IOC matches
  for (const match of knownBadMatches) {
    score += 55;
    findings.push({
      id: `ioc-${findings.length + 1}`,
      level: 'confirmed_malicious',
      category: 'IOC Match',
      title: `Matched known malicious indicator (${match.category})`,
      titleAr: `مطابقة مع مؤشر اختراق خبيث معروف (${match.category})`,
      detail: `Matched ${match.indicator} in ${match.source} (reputation score ${match.reputationScore}/100).`,
      detailAr: `تمت مطابقة ${match.indicator} ضمن قاعدة ${match.source} (درجة السمعة ${match.reputationScore}/100).`,
      evidenceSnippet: match.indicator,
    });
  }

  if (isIpBased) {
    score += 28;
    findings.push({
      id: `ip-host-${findings.length + 1}`,
      level: 'suspicious',
      category: 'URL Structure',
      title: 'Direct IP-based host instead of domain name',
      titleAr: 'استخدام عنوان IP مباشر بدلاً من اسم نطاق',
      detail: `Host "${hostname}" uses a raw IP literal, a common evasion technique in phishing kits.`,
      detailAr: `المضيف "${hostname}" يستخدم عنوان IP مباشر، وهي تقنية شائعة لتجاوز فلاتر النطاقات.`,
      evidenceSnippet: hostname,
    });
  }

  if (typosquatTarget) {
    score += 36;
    findings.push({
      id: `typo-${findings.length + 1}`,
      level: 'confirmed_malicious',
      category: 'Impersonation',
      title: `Potential brand typosquatting / lookalike of ${typosquatTarget}`,
      titleAr: `انتحال محتمل أو تشابه بصري مع النطاق ${typosquatTarget}`,
      detail: `Hostname "${hostname}" closely mimics "${typosquatTarget}" via character substitution or brand keyword injection.`,
      detailAr: `اسم النطاق "${hostname}" يحاكي "${typosquatTarget}" عبر استبدال أحرف أو حقن اسم العلامة التجارية.`,
      evidenceSnippet: hostname,
    });
  }

  if (hasPunycode) {
    score += 25;
    findings.push({
      id: `idn-${findings.length + 1}`,
      level: 'suspicious',
      category: 'Homograph Risk',
      title: 'Punycode / Internationalized Domain Name (IDN) detected',
      titleAr: 'اكتشاف ترميز Punycode / نطاق دولي محتمل الخداع',
      detail: 'Non-ASCII or xn-- domain encoding may indicate an IDN homograph spoof.',
      detailAr: 'وجود ترميز xn-- أو أحرف غير قياسية قد يشير إلى هجوم تشابه الأحرف.',
      evidenceSnippet: hostname,
    });
  }

  if (trimmed.includes('@')) {
    score += 30;
    findings.push({
      id: `at-trick-${findings.length + 1}`,
      level: 'confirmed_malicious',
      category: 'Deceptive Syntax',
      title: 'Credential-prefix "@" obfuscation in URL authority',
      titleAr: 'استخدام الرمز "@" لخداع المستخدم في عنوان الرابط',
      detail: 'Browsers ignore text before "@" in the authority section, masking the true destination host.',
      detailAr: 'المتصفحات تتجاهل النص قبل "@" مما يخفي الوجهة الفعلية للرابط.',
      evidenceSnippet: trimmed.slice(0, 80),
    });
  }

  if (SUSPICIOUS_TLDS.has(tld)) {
    score += 18;
    findings.push({
      id: `tld-${findings.length + 1}`,
      level: 'suspicious',
      category: 'Domain Reputation',
      title: `High-abuse top-level domain (.${tld})`,
      titleAr: `نطاق مستوى أعلى مرتفع الخطورة (.${tld})`,
      detail: `The .${tld} TLD is disproportionately observed in disposable phishing infrastructure.`,
      detailAr: `الامتداد .${tld} يُستخدم بكثرة في البنية التحتية المؤقتة للتصيد.`,
      evidenceSnippet: `.${tld}`,
    });
  }

  if (URL_SHORTENERS.has(domain)) {
    score += 20;
    findings.push({
      id: `shortener-${findings.length + 1}`,
      level: 'suspicious',
      category: 'Obfuscation',
      title: `URL shortener obscures destination (${domain})`,
      titleAr: `خدمة اختصار روابط تخفي الوجهة النهائية (${domain})`,
      detail: 'Shortened links mask the final landing page and require out-of-band expansion before trust.',
      detailAr: 'الروابط المختصرة تخفي الصفحة النهائية وتتطلب فحصاً معزولاً قبل الوثوق بها.',
      evidenceSnippet: domain,
    });
  }

  if (subdomain && subdomain.split('.').length >= 3) {
    score += 16;
    findings.push({
      id: `sub-${findings.length + 1}`,
      level: 'suspicious',
      category: 'URL Structure',
      title: 'Deeply nested subdomain chain',
      titleAr: 'سلسلة نطاقات فرعية متداخلة بشكل غير معتاد',
      detail: `Detected ${subdomain.split('.').length} subdomain levels ("${subdomain}"), often used to push legitimate-looking words to the left.`,
      detailAr: `تم رصد عدة مستويات من النطاقات الفرعية ("${subdomain}") لإظهار كلمات موثوقة في بداية الرابط.`,
      evidenceSnippet: subdomain,
    });
  }

  if (!isHttps) {
    score += 12;
    findings.push({
      id: `tls-${findings.length + 1}`,
      level: 'informational',
      category: 'Transport Security',
      title: 'Unencrypted HTTP scheme (no TLS)',
      titleAr: 'اتصال غير مشفر عبر HTTP بدون شهادة TLS',
      detail: 'Traffic is unencrypted; note that HTTPS alone does not guarantee legitimacy since phishing sites also use free certificates.',
      detailAr: 'الرابط لا يستخدم التشفير، مع ملاحظة أن وجود HTTPS لا يثبت موثوقية الموقع.',
    });
  }

  if (urlLength > 100) {
    score += 12;
    findings.push({
      id: `len-${findings.length + 1}`,
      level: 'suspicious',
      category: 'URL Structure',
      title: `Excessive URL length (${urlLength} characters)`,
      titleAr: `طول رابط مفرط (${urlLength} حرفاً)`,
      detail: 'Long URLs frequently conceal redirect chains or Base64 tracking payloads.',
      detailAr: 'الروابط الطويلة جداً تُستخدم غالباً لإخفاء سلاسل إعادة التوجيه أو حمولات التتبع.',
    });
  }

  if (encodingCount >= 4) {
    score += 14;
    findings.push({
      id: `enc-${findings.length + 1}`,
      level: 'suspicious',
      category: 'Encoding',
      title: `Heavy percent-encoding (${encodingCount} encoded sequences)`,
      titleAr: `نسبة ترميز مرتفعة في الرابط (${encodingCount} تسلسل مرمز)`,
      detail: 'Multiple percent-encoded characters can evade naive keyword filters.',
      detailAr: 'كثرة الأحرف المرمزة قد تهدف للالتفاف على فلاتر الفحص البسيطة.',
    });
  }

  const redirectParams = queryParams.filter((p) => p.suspicious);
  if (redirectParams.length > 0) {
    score += 18;
    findings.push({
      id: `redir-${findings.length + 1}`,
      level: 'suspicious',
      category: 'Query Parameters',
      title: 'Potential open-redirect or token harvesting parameters',
      titleAr: 'معاملات استعلام مريبة (إعادة توجيه أو رموز جلسة)',
      detail: `Suspicious query keys detected: ${redirectParams.map((p) => p.key).join(', ')}.`,
      detailAr: `تم رصد معاملات مريبة في الرابط: ${redirectParams.map((p) => p.key).join(', ')}.`,
      evidenceSnippet: parsed.search.slice(0, 90),
    });
  }

  const riskScore = Math.min(100, Math.max(4, score));
  const classification = classifyScore(riskScore);
  const confidence = Math.min(96, 62 + findings.length * 7);

  const recommendedActions: string[] = [];
  const recommendedActionsAr: string[] = [];
  if (riskScore >= 50) {
    recommendedActions.push('Block domain/URL at Secure Web Gateway and DNS resolver (simulated response).');
    recommendedActions.push('Search proxy and email logs for other users who received or visited this URL.');
    recommendedActions.push('Create an Incident Response ticket and attach URL telemetry as evidence.');
    recommendedActionsAr.push('حظر النطاق والرابط في بوابة الويب الآمنة وخادم DNS (استجابة محاكاة).');
    recommendedActionsAr.push('البحث في سجلات البروكسي والبريد عن مستخدمين آخرين وصلهم هذا الرابط.');
    recommendedActionsAr.push('فتح تذكرة حادث أمني وإرفاق بيانات الرابط كدليل رقمي.');
  } else if (riskScore >= 25) {
    recommendedActions.push('Inspect destination inside an isolated browser sandbox before permitting access.');
    recommendedActions.push('Cross-check domain WHOIS age and certificate transparency logs.');
    recommendedActionsAr.push('فحص الوجهة داخل بيئة معزولة (Sandbox) قبل السماح بالوصول.');
    recommendedActionsAr.push('التحقق من عمر النطاق وسجلات الشهادات الرقمية.');
  } else {
    recommendedActions.push('No heuristic phishing indicators found; continue standard monitoring.');
    recommendedActionsAr.push('لم يتم رصد مؤشرات تصيد محلية؛ استمر في المراقبة الاعتيادية.');
  }

  return {
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
    typosquatTarget,
    urlLength,
    encodingCount,
    classification,
    riskScore,
    confidence,
    findings,
    recommendedActions,
    recommendedActionsAr,
    intelligenceSource: knownBadMatches.length > 0
      ? `Local Heuristic Engine + ${knownBadMatches[0].source}`
      : 'Local Heuristic Analysis (External APIs unconfigured or offline)',
    intelligenceVerified: knownBadMatches.length > 0,
    checkedAt: new Date().toISOString(),
  };
}

export interface EmailAnalysisInput {
  rawEmail?: string;
  senderEmail?: string;
  senderDisplayName?: string;
  replyTo?: string;
  subject?: string;
  body?: string;
  headersText?: string;
  attachmentNames?: string[];
}

function parseRawEmail(raw: string) {
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

  const subject = getHeader('Subject');
  const routingHops = headers
    .filter((h) => h.key.toLowerCase() === 'received')
    .map((h) => h.value);

  // Check Content-Disposition filenames in MIME body
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
    subject,
    body: bodyBlock || raw,
    routingHops,
    mimeAttachments,
  };
}

function parseAuthentication(headers: Array<{ key: string; value: string }>): EmailAuthResults {
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
    note: 'SPF/DKIM/DMARC failures increase suspicion (forwarding or misconfiguration can also cause failures), and never prove phishing alone without corroborating indicators.',
    noteAr: 'فشل SPF/DKIM/DMARC يرفع درجة الاشتباه لكنه لا يُثبت التصيد بمفرده دون قرائن داعمة (قد ينتج عن إعادة التوجيه أو خطأ إعداد).',
  };
}

export function analyzeEmailHeuristic(
  input: EmailAnalysisInput,
  knownBadIocs: Array<{ indicator: string; category: string; reputationScore: number; source: string }> = [],
): EmailAnalysisResult {
  const parsed = input.rawEmail ? parseRawEmail(input.rawEmail) : null;
  const headers = parsed?.headers || [];
  if (input.headersText && !input.rawEmail) {
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
  const subject = (input.subject || parsed?.subject || '(No Subject)').trim();
  const rawBody = input.body || parsed?.body || '';
  const sanitizedBodyPreview = sanitizeText(rawBody).slice(0, 1200);
  const routingHops = parsed?.routingHops || headers.filter((h) => h.key.toLowerCase() === 'received').map((h) => h.value);

  const auth = parseAuthentication(headers);
  const findings: FindingIndicator[] = [];
  const iocs: Array<{ type: string; value: string; level: FindingIndicator['level'] }> = [];
  let score = 0;

  const senderDomain = (senderEmail.split('@')[1] || '').toLowerCase();
  const replyDomain = (replyTo.split('@')[1] || '').toLowerCase();

  // 1. Sender domain inspection & typosquatting
  if (senderDomain) {
    const typo = detectTyposquatting(senderDomain);
    if (typo) {
      score += 38;
      findings.push({
        id: 'sender-typo',
        level: 'confirmed_malicious',
        category: 'Sender Spoofing',
        title: `Sender domain "${senderDomain}" impersonates "${typo}"`,
        titleAr: `نطاق المرسل "${senderDomain}" ينتحل النطاق "${typo}"`,
        detail: 'Lookalike sender domain detected via character-distance and homoglyph inspection.',
        detailAr: 'تم اكتشاف نطاق مرسل مشابه بصرياً لعلامة معروفة عبر فحص تشابه الأحرف.',
        evidenceSnippet: senderEmail,
      });
      iocs.push({ type: 'Domain', value: senderDomain, level: 'confirmed_malicious' });
    }
  }

  // 2. Display name inconsistency
  if (senderDisplayName && senderDomain) {
    const displayLower = senderDisplayName.toLowerCase();
    for (const brand of BRAND_DOMAINS) {
      const brandName = brand.split('.')[0];
      if (displayLower.includes(brandName) && !senderDomain.endsWith(brand)) {
        score += 24;
        findings.push({
          id: 'display-mismatch',
          level: 'suspicious',
          category: 'Display Name Impersonation',
          title: `Display name "${senderDisplayName}" mismatches sender domain "${senderDomain}"`,
          titleAr: `الاسم الظاهر "${senderDisplayName}" لا يتطابق مع نطاق المرسل "${senderDomain}"`,
          detail: `Sender claims to represent "${brandName}" while sending from "${senderDomain}".`,
          detailAr: `المرسل يدّعي تمثيل "${brandName}" لكنه يرسل من النطاق "${senderDomain}".`,
          evidenceSnippet: `${senderDisplayName} <${senderEmail}>`,
        });
        break;
      }
    }
    if (
      (displayLower.includes('ceo') ||
        displayLower.includes('cfo') ||
        displayLower.includes('director') ||
        displayLower.includes('it support') ||
        displayLower.includes('security team')) &&
      FREE_MAIL_PROVIDERS.has(senderDomain)
    ) {
      score += 24;
      findings.push({
        id: 'freemail-exec',
        level: 'suspicious',
        category: 'Executive Impersonation',
        title: `Corporate role "${senderDisplayName}" using free webmail (${senderDomain})`,
        titleAr: `منصب مؤسسي "${senderDisplayName}" يستخدم بريداً مجانياً (${senderDomain})`,
        detail: 'High-privilege personas sending from consumer webmail strongly correlate with BEC attacks.',
        detailAr: 'انتحال المناصب التنفيذية أو الدعم الفني عبر بريد مجاني مؤشر قوي على هجمات BEC.',
        evidenceSnippet: senderEmail,
      });
    }
  }

  // 3. Reply-To mismatch
  if (replyTo && senderEmail && replyDomain && senderDomain && replyDomain !== senderDomain) {
    score += 22;
    findings.push({
      id: 'reply-to-mismatch',
      level: 'suspicious',
      category: 'Header Anomaly',
      title: `Reply-To domain (${replyDomain}) differs from From domain (${senderDomain})`,
      titleAr: `نطاق الرد (${replyDomain}) يختلف عن نطاق المرسل (${senderDomain})`,
      detail: 'Replies are routed to an external domain not matching the claimed sender.',
      detailAr: 'الردود تُوجَّه إلى نطاق خارجي مختلف عن نطاق المرسل الظاهر.',
      evidenceSnippet: `From: ${senderEmail} | Reply-To: ${replyTo}`,
    });
    iocs.push({ type: 'Email', value: replyTo, level: 'suspicious' });
  }

  // 4. Authentication checks (never sole proof)
  const failedAuths: string[] = [];
  if (auth.spf === 'fail' || auth.spf === 'softfail') failedAuths.push(`SPF:${auth.spf}`);
  if (auth.dkim === 'fail') failedAuths.push('DKIM:fail');
  if (auth.dmarc === 'fail') failedAuths.push('DMARC:fail');
  if (failedAuths.length > 0) {
    score += Math.min(18, failedAuths.length * 7);
    findings.push({
      id: 'auth-fail',
      level: 'suspicious',
      category: 'Email Authentication',
      title: `Authentication alignment failure (${failedAuths.join(', ')})`,
      titleAr: `فشل التحقق من مصادقة البريد (${failedAuths.join(', ')})`,
      detail: 'Authentication failures elevate risk when combined with lure or URL anomalies, though forwarding can also break SPF.',
      detailAr: 'فشل المصادقة يزيد درجة الخطر عند اقترانه بمؤشرات أخرى، مع احتمال حدوثه بسبب إعادة التوجيه.',
      evidenceSnippet: failedAuths.join(' · '),
    });
  }

  // 5. Urgency & social engineering patterns
  const combinedText = `${subject}\n${sanitizedBodyPreview}`;
  for (const pat of URGENCY_PATTERNS) {
    const match = combinedText.match(pat.regex);
    if (match) {
      score += 14;
      findings.push({
        id: `se-${findings.length + 1}`,
        level: 'suspicious',
        category: 'Social Engineering',
        title: pat.label,
        titleAr: pat.labelAr,
        detail: `Matched social engineering cue: "${match[0]}".`,
        detailAr: `تم رصد عبارة استدراج أو ضغط نفسي: "${match[0]}".`,
        evidenceSnippet: match[0],
      });
    }
  }

  // 6. Embedded URL extraction & analysis
  const urlMatches = rawBody.match(/https?:\/\/[^\s"'<>)\]]+/gi) || [];
  const extractedUrls = Array.from(new Set(urlMatches.map((u) => u.replace(/[.,;!?]+$/, '')))).slice(0, 20);
  let hasMaliciousUrl = false;

  for (const u of extractedUrls) {
    const matchedKnown = knownBadIocs.filter(
      (k) => u.toLowerCase().includes(k.indicator.toLowerCase()),
    );
    const urlEval = analyzeUrlHeuristic(u, matchedKnown);
    if (urlEval.riskScore >= 50) {
      hasMaliciousUrl = true;
      score += 30;
      findings.push({
        id: `url-${findings.length + 1}`,
        level: urlEval.findings.some((f) => f.level === 'confirmed_malicious')
          ? 'confirmed_malicious'
          : 'suspicious',
        category: 'Embedded URL',
        title: `High-risk embedded URL (${urlEval.hostname})`,
        titleAr: `رابط مدمج عالي الخطورة (${urlEval.hostname})`,
        detail: `URL scored ${urlEval.riskScore}/100: ${urlEval.findings.map((f) => f.title).slice(0, 2).join('; ')}.`,
        detailAr: `سجّل الرابط ${urlEval.riskScore}/100: ${urlEval.findings.map((f) => f.titleAr).slice(0, 2).join('؛ ')}.`,
        evidenceSnippet: u,
      });
      iocs.push({
        type: 'URL',
        value: u,
        level: urlEval.riskScore >= 70 ? 'confirmed_malicious' : 'suspicious',
      });
    } else if (urlEval.riskScore >= 25) {
      score += 12;
      findings.push({
        id: `url-${findings.length + 1}`,
        level: 'suspicious',
        category: 'Embedded URL',
        title: `Suspicious embedded URL (${urlEval.hostname})`,
        titleAr: `رابط مدمج مريب (${urlEval.hostname})`,
        detail: `URL scored ${urlEval.riskScore}/100.`,
        detailAr: `سجّل الرابط ${urlEval.riskScore}/100.`,
        evidenceSnippet: u,
      });
      iocs.push({ type: 'URL', value: u, level: 'suspicious' });
    }
  }

  // 7. Attachments inspection (never execute!)
  const attachmentNames = Array.from(
    new Set([...(input.attachmentNames || []), ...(parsed?.mimeAttachments || [])].filter(Boolean)),
  );
  const attachments = attachmentNames.map((filename) => {
    const lower = filename.toLowerCase();
    const parts = lower.split('.');
    const extension = parts.length > 1 ? parts[parts.length - 1] : '';
    const hasDoubleExtension = parts.length >= 3 && HIGH_RISK_EXTENSIONS.has(extension);

    if (HIGH_RISK_EXTENSIONS.has(extension) || hasDoubleExtension) {
      score += 36;
      findings.push({
        id: `att-${findings.length + 1}`,
        level: 'confirmed_malicious',
        category: 'Malicious Attachment',
        title: `Dangerous executable/script attachment "${filename}"`,
        titleAr: `مرفق تنفيذي أو برمجي خطير "${filename}"`,
        detail: hasDoubleExtension
          ? 'Double file extension masquerading technique detected.'
          : `Executable or container extension .${extension} is blocked by standard email security policy.`,
        detailAr: hasDoubleExtension
          ? 'تم اكتشاف تقنية تمويه الامتداد المزدوج للملف.'
          : `الامتداد .${extension} يصنف ضمن المرفقات الخطيرة المحظورة.`,
        evidenceSnippet: filename,
      });
      iocs.push({ type: 'Attachment', value: filename, level: 'confirmed_malicious' });
      return {
        filename,
        extension,
        riskLevel: 'Critical' as ThreatSeverity,
        reason: hasDoubleExtension ? 'Double extension payload' : `Executable/script extension (.${extension})`,
      };
    }

    if (MACRO_OR_SCRIPT_EXTENSIONS.has(extension)) {
      score += 20;
      findings.push({
        id: `att-${findings.length + 1}`,
        level: 'suspicious',
        category: 'Attachment Risk',
        title: `Macro-enabled or active HTML attachment "${filename}"`,
        titleAr: `مرفق يحتوي على ماكرو أو صفحة HTML نشطة "${filename}"`,
        detail: `File type .${extension} is frequently abused for HTML smuggling or macro delivery.`,
        detailAr: `النوع .${extension} يُستخدم كثيراً في تهريب صفحات التصيد أو الماكرو الخبيث.`,
        evidenceSnippet: filename,
      });
      iocs.push({ type: 'Attachment', value: filename, level: 'suspicious' });
      return {
        filename,
        extension,
        riskLevel: 'High' as ThreatSeverity,
        reason: `Active script/macro/archive format (.${extension})`,
      };
    }

    return {
      filename,
      extension,
      riskLevel: 'Low' as ThreatSeverity,
      reason: 'Standard document format',
    };
  });

  // 8. Check known IOCs against sender / body
  for (const k of knownBadIocs) {
    if (
      (senderEmail && senderEmail.toLowerCase().includes(k.indicator.toLowerCase())) ||
      rawBody.toLowerCase().includes(k.indicator.toLowerCase())
    ) {
      if (!iocs.some((i) => i.value === k.indicator)) {
        score += 35;
        findings.push({
          id: `ioc-body-${findings.length + 1}`,
          level: 'confirmed_malicious',
          category: 'Threat Intelligence Match',
          title: `Confirmed IOC match: ${k.indicator}`,
          titleAr: `مطابقة مع مؤشر اختراق مؤكد: ${k.indicator}`,
          detail: `Matched ${k.category} IOC from ${k.source}.`,
          detailAr: `تمت مطابقة مؤشر (${k.category}) من مصدر ${k.source}.`,
          evidenceSnippet: k.indicator,
        });
        iocs.push({ type: 'IOC', value: k.indicator, level: 'confirmed_malicious' });
      }
    }
  }

  // Safeguard: Auth failure alone must never push classification into Phishing
  const nonAuthIndicators = findings.filter((f) => f.category !== 'Email Authentication');
  if (nonAuthIndicators.length === 0 && failedAuths.length > 0) {
    score = Math.min(score, 32); // Keep in Suspicious at most
  }

  const riskScore = Math.min(100, Math.max(3, score));
  const classification = classifyScore(riskScore);
  const confidence = Math.min(97, 60 + findings.length * 6 + (hasMaliciousUrl ? 6 : 0));

  const explanation =
    findings.length === 0
      ? 'No phishing indicators, deceptive sender patterns, or suspicious URLs were identified in this message.'
      : `Classified as ${classification} (Risk ${riskScore}/100) based on ${
          findings.filter((f) => f.level === 'confirmed_malicious').length
        } confirmed malicious indicator(s) and ${
          findings.filter((f) => f.level === 'suspicious').length
        } suspicious indicator(s): ${findings
          .slice(0, 3)
          .map((f) => f.title)
          .join('; ')}.`;

  const explanationAr =
    findings.length === 0
      ? 'لم يتم رصد مؤشرات تصيد أو انتحال مرسل أو روابط مريبة في هذه الرسالة.'
      : `تم تصنيف الرسالة (${classification}) بدرجة خطورة ${riskScore}/100 بناءً على ${
          findings.filter((f) => f.level === 'confirmed_malicious').length
        } مؤشر خبيث مؤكد و${
          findings.filter((f) => f.level === 'suspicious').length
        } مؤشر مريب: ${findings
          .slice(0, 3)
          .map((f) => f.titleAr)
          .join('؛ ')}.`;

  const recommendedActions: string[] = [];
  const recommendedActionsAr: string[] = [];

  if (riskScore >= 50) {
    recommendedActions.push('Quarantine message from recipient mailbox and purge matching copies across tenant.');
    recommendedActions.push('Flag sender domain and block extracted phishing URLs at web proxy.');
    recommendedActions.push('Escalate to Incident Response Center and preserve raw headers in Forensics.');
    recommendedActionsAr.push('عزل الرسالة من صندوق الوارد وحذف النسخ المطابقة على مستوى المؤسسة.');
    recommendedActionsAr.push('حظر نطاق المرسل والروابط المستخرجة في بوابة الويب.');
    recommendedActionsAr.push('تصعيد الحالة إلى مركز الاستجابة للحوادث وحفظ الترويسات في التحقيق الرقمي.');
  } else if (riskScore >= 25) {
    recommendedActions.push('Warn recipient with external sender banner and hold links for sandbox verification.');
    recommendedActions.push('Verify sender identity out-of-band before taking any requested action.');
    recommendedActionsAr.push('تنبيه المستلم وإخضاع الروابط للفحص المعزول قبل الفتح.');
    recommendedActionsAr.push('التحقق من هوية المرسل عبر قناة اتصال بديلة قبل تنفيذ أي طلب.');
  } else {
    recommendedActions.push('Message appears safe under local heuristic rules; retain standard audit record.');
    recommendedActionsAr.push('تبدو الرسالة سليمة وفق الفحص المحلي؛ يُحفظ السجل لأغراض المراجعة.');
  }

  return {
    senderEmail: senderEmail || 'unknown@unknown',
    senderDisplayName,
    replyTo,
    subject,
    sanitizedBodyPreview,
    extractedUrls,
    attachments,
    auth,
    headers,
    routingHops,
    classification,
    riskScore,
    confidence,
    findings,
    iocs,
    explanation,
    explanationAr,
    recommendedActions,
    recommendedActionsAr,
    analysisMode: knownBadIocs.length > 0 ? 'Heuristic + Threat Intelligence' : 'Local Heuristic Engine',
  };
}
