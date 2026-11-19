import type { EmailClassification, ThreatSeverity } from '../types/phishguard.ts';

const SEVERITY_STYLES: Record<ThreatSeverity, string> = {
  Critical: 'text-[#FF3B5C] bg-[#FF3B5C]/10 border-[#FF3B5C]/30',
  High: 'text-[#C26A00] bg-[#FF9F1C]/15 border-[#FF9F1C]/35',
  Medium: 'text-[#007D8C] bg-[#00E5FF]/12 border-[#00E5FF]/35',
  Low: 'text-[#137A3E] bg-[#39FF88]/18 border-[#39FF88]/40',
};

export function SeverityMarker({
  severity,
  label,
}: {
  severity: ThreatSeverity;
  label?: string;
}) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 text-xs font-semibold rounded border whitespace-nowrap shrink-0 tabular-nums ${
        SEVERITY_STYLES[severity] || SEVERITY_STYLES.Medium
      }`}
    >
      {label || severity}
    </span>
  );
}

export function ClassificationMarker({
  classification,
  label,
}: {
  classification: EmailClassification;
  label?: string;
}) {
  const styleMap: Record<EmailClassification, string> = {
    'High-Risk Phishing': 'text-[#FF3B5C] bg-[#FF3B5C]/10 border-[#FF3B5C]/30',
    Phishing: 'text-[#C26A00] bg-[#FF9F1C]/15 border-[#FF9F1C]/35',
    Suspicious: 'text-[#007D8C] bg-[#00E5FF]/12 border-[#00E5FF]/35',
    Legitimate: 'text-[#137A3E] bg-[#39FF88]/18 border-[#39FF88]/40',
  };
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 text-xs font-semibold rounded border whitespace-nowrap shrink-0 ${
        styleMap[classification]
      }`}
    >
      {label || classification}
    </span>
  );
}

export function ScoreBar({ score }: { score: number }) {
  const color =
    score >= 75
      ? '#FF3B5C'
      : score >= 50
        ? '#FF9F1C'
        : score >= 25
          ? '#00E5FF'
          : '#39FF88';

  return (
    <div className="flex items-center gap-2.5 min-w-[110px]">
      <div className="flex-1 h-1.5 bg-slate-100 rounded overflow-hidden">
        <div
          className="h-full transition-all duration-300"
          style={{ width: `${Math.min(100, Math.max(4, score))}%`, backgroundColor: color }}
        />
      </div>
      <span className="font-mono text-xs font-semibold text-[#17212B] tabular-nums w-8 text-end">
        {score}
      </span>
    </div>
  );
}
