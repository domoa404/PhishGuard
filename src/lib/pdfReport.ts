import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import type { EmailAnalysisResult, RiskAssessmentResult, UrlAnalysisResult } from '../types/phishguard.ts';

export function downloadEmailPdfReport(email: EmailAnalysisResult) {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'pt', format: 'a4' });
  doc.setFontSize(16);
  doc.text('PhishGuard — Email Phishing Analysis Report', 40, 48);
  doc.setFontSize(9);
  doc.text(`Analysis ID: ${email.id}  |  Analyzed At: ${email.analyzedAt}`, 40, 66);
  doc.text('Analysis Mode: Client-Side Heuristic Inspection (No personal data stored)', 40, 80);

  autoTable(doc, {
    startY: 96,
    head: [['Attribute', 'Extracted Value']],
    body: [
      ['Classification', email.classification],
      ['Phishing Risk Score', `${email.riskScore} / 100 (Confidence ${email.confidence}%)`],
      ['Sender Email', email.senderEmail],
      ['Display Name', email.senderDisplayName || '—'],
      ['Reply-To', email.replyTo || '—'],
      ['Subject', email.subject],
      ['SPF / DKIM / DMARC', `SPF=${email.auth.spf} | DKIM=${email.auth.dkim} | DMARC=${email.auth.dmarc}`],
      ['Extracted URLs', String(email.extractedUrls.length)],
      ['Attachments', email.attachments.map((a) => a.filename).join(', ') || 'None'],
    ],
    headStyles: { fillColor: [23, 33, 43] },
  });

  const y1 = (doc as unknown as { lastAutoTable?: { finalY: number } }).lastAutoTable?.finalY || 300;
  doc.setFontSize(11);
  doc.text('Assessment Explanation', 40, y1 + 22);
  doc.setFontSize(9);
  const splitExp = doc.splitTextToSize(email.explanation, 515);
  doc.text(splitExp, 40, y1 + 38);

  const y2 = y1 + 42 + splitExp.length * 12;
  autoTable(doc, {
    startY: y2,
    head: [['Level', 'Category', 'Indicator & Explanation']],
    body:
      email.findings.length > 0
        ? email.findings.map((f) => [
            f.level === 'confirmed_malicious' ? 'Malicious' : f.level === 'suspicious' ? 'Suspicious' : 'Info',
            f.category,
            `${f.title} — ${f.detail}`,
          ])
        : [['Clean', 'Heuristic', 'No phishing indicators detected.']],
    headStyles: { fillColor: [23, 33, 43] },
  });

  const y3 = (doc as unknown as { lastAutoTable?: { finalY: number } }).lastAutoTable?.finalY || y2 + 120;
  autoTable(doc, {
    startY: y3 + 16,
    head: [['Recommended Security Actions']],
    body: email.recommendedActions.map((a) => [a]),
    headStyles: { fillColor: [23, 33, 43] },
  });

  doc.save(`PhishGuard_Email_Report_${email.id}.pdf`);
}

export function downloadUrlPdfReport(urlRes: UrlAnalysisResult) {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'pt', format: 'a4' });
  doc.setFontSize(16);
  doc.text('PhishGuard — URL Security Analysis Report', 40, 48);
  doc.setFontSize(9);
  doc.text(`Scan ID: ${urlRes.id}  |  Analyzed At: ${urlRes.analyzedAt}`, 40, 66);
  doc.text(urlRes.externalIntelStatus, 40, 80);

  autoTable(doc, {
    startY: 96,
    head: [['Attribute', 'Inspected Value']],
    body: [
      ['Submitted URL', urlRes.normalizedUrl],
      ['Classification', urlRes.classification],
      ['Risk Score', `${urlRes.riskScore} / 100 (Confidence ${urlRes.confidence}%)`],
      ['Hostname', urlRes.hostname],
      ['Root Domain / TLD', `${urlRes.domain} (.${urlRes.tld || '—'})`],
      ['Protocol / Port', `${urlRes.protocol.toUpperCase()} : ${urlRes.port}`],
      ['HTTPS / TLS', urlRes.isHttps ? 'Yes' : 'No (Plaintext HTTP)'],
      ['IP-Based URL', urlRes.isIpBased ? 'Yes' : 'No'],
      ['Typosquatting Match', urlRes.typosquatTarget || 'None detected'],
      ['Punycode / IDN', urlRes.hasPunycode ? 'Detected' : 'None'],
    ],
    headStyles: { fillColor: [23, 33, 43] },
  });

  const y1 = (doc as unknown as { lastAutoTable?: { finalY: number } }).lastAutoTable?.finalY || 320;
  autoTable(doc, {
    startY: y1 + 18,
    head: [['Level', 'Category', 'Detected Anomaly']],
    body:
      urlRes.findings.length > 0
        ? urlRes.findings.map((f) => [
            f.level === 'confirmed_malicious' ? 'Malicious' : f.level === 'suspicious' ? 'Suspicious' : 'Info',
            f.category,
            `${f.title} — ${f.detail}`,
          ])
        : [['Clean', 'Structure', 'No suspicious structural indicators found locally.']],
    headStyles: { fillColor: [23, 33, 43] },
  });

  const y2 = (doc as unknown as { lastAutoTable?: { finalY: number } }).lastAutoTable?.finalY || y1 + 140;
  autoTable(doc, {
    startY: y2 + 16,
    head: [['Recommended Actions']],
    body: urlRes.recommendedActions.map((a) => [a]),
    headStyles: { fillColor: [23, 33, 43] },
  });

  doc.save(`PhishGuard_URL_Report_${urlRes.id}.pdf`);
}

export function downloadCombinedPdfReport(
  email: EmailAnalysisResult | null,
  urlRes: UrlAnalysisResult | null,
  risk: RiskAssessmentResult | null,
) {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'pt', format: 'a4' });
  doc.setFontSize(16);
  doc.text('PhishGuard — Cybersecurity Analysis Summary Report', 40, 48);
  doc.setFontSize(9);
  doc.text(`Generated: ${new Date().toISOString()}  |  Mode: Temporary In-Memory Client Analysis`, 40, 66);

  let cursorY = 86;

  if (email) {
    autoTable(doc, {
      startY: cursorY,
      head: [['Email Analysis', 'Result']],
      body: [
        ['Subject / Sender', `${email.subject} (${email.senderEmail})`],
        ['Classification', `${email.classification} — Score ${email.riskScore}/100`],
        ['Explanation', email.explanation],
      ],
      headStyles: { fillColor: [23, 33, 43] },
    });
    cursorY = ((doc as unknown as { lastAutoTable?: { finalY: number } }).lastAutoTable?.finalY || cursorY + 80) + 18;
  }

  if (urlRes) {
    autoTable(doc, {
      startY: cursorY,
      head: [['URL Analysis', 'Result']],
      body: [
        ['Target URL', urlRes.normalizedUrl],
        ['Classification', `${urlRes.classification} — Score ${urlRes.riskScore}/100`],
        ['Intelligence Source', urlRes.externalIntelStatus],
        ['Explanation', urlRes.explanation],
      ],
      headStyles: { fillColor: [23, 33, 43] },
    });
    cursorY = ((doc as unknown as { lastAutoTable?: { finalY: number } }).lastAutoTable?.finalY || cursorY + 80) + 18;
  }

  if (risk) {
    autoTable(doc, {
      startY: cursorY,
      head: [['Risk Assessment', 'Score & Treatment']],
      body: [
        ['Asset / Threat', `${risk.assetName} — ${risk.threatScenario}`],
        ['Inherent Risk (L x I)', `${risk.likelihood} x ${risk.impact} = ${risk.inherentScore}/25 (${risk.inherentLevel})`],
        ['Residual Risk', `${risk.residualScore}/25 (${risk.residualLevel}) after ${risk.controlEffectiveness}% controls`],
        ['Strategy', risk.strategy],
        ['Recommendations', risk.recommendationsEn.join(' | ')],
      ],
      headStyles: { fillColor: [23, 33, 43] },
    });
  }

  doc.save(`PhishGuard_Summary_Report_${new Date().toISOString().slice(0, 10)}.pdf`);
}
