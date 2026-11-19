export interface ProviderStatus {
  id: 'virustotal' | 'urlhaus' | 'abuseipdb' | 'otx';
  name: string;
  configured: boolean;
  envVar: string;
  capability: string;
}

export function getThreatIntelProviderStatuses(): ProviderStatus[] {
  return [
    {
      id: 'virustotal',
      name: 'VirusTotal v3',
      configured: Boolean(process.env.VIRUSTOTAL_API_KEY),
      envVar: 'VIRUSTOTAL_API_KEY',
      capability: 'URL, Domain, IP & File Hash reputation',
    },
    {
      id: 'urlhaus',
      name: 'URLhaus (abuse.ch)',
      configured: Boolean(process.env.URLHAUS_AUTH_KEY),
      envVar: 'URLHAUS_AUTH_KEY',
      capability: 'Malicious URL & payload distribution feeds',
    },
    {
      id: 'abuseipdb',
      name: 'AbuseIPDB',
      configured: Boolean(process.env.ABUSEIPDB_API_KEY),
      envVar: 'ABUSEIPDB_API_KEY',
      capability: 'IP abuse confidence & ASN telemetry',
    },
    {
      id: 'otx',
      name: 'AlienVault OTX',
      configured: Boolean(process.env.OTX_API_KEY),
      envVar: 'OTX_API_KEY',
      capability: 'Threat pulse IOC correlation',
    },
  ];
}

export async function queryExternalThreatIntel(indicator: string, iocType: string): Promise<{
  provider: string;
  verifiedExternal: boolean;
  reputationScore: number | null;
  category: string | null;
  notes: string;
  timestamp: string;
}> {
  const timestamp = new Date().toISOString();

  // VirusTotal URL/domain/IP lookup when server key is configured
  if (process.env.VIRUSTOTAL_API_KEY) {
    try {
      let endpoint = '';
      if (iocType === 'IP') {
        endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(indicator)}`;
      } else if (iocType === 'Domain') {
        endpoint = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(indicator)}`;
      } else if (iocType === 'MD5' || iocType === 'SHA-1' || iocType === 'SHA-256') {
        endpoint = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(indicator)}`;
      }
      if (endpoint) {
        const res = await fetch(endpoint, {
          headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY },
          signal: AbortSignal.timeout(5000),
        });
        if (res.ok) {
          const data = (await res.json()) as {
            data?: { attributes?: { last_analysis_stats?: { malicious?: number; suspicious?: number; harmless?: number } } };
          };
          const stats = data.data?.attributes?.last_analysis_stats;
          if (stats) {
            const mal = stats.malicious || 0;
            const susp = stats.suspicious || 0;
            const total = mal + susp + (stats.harmless || 0) || 1;
            const score = Math.min(100, Math.round(((mal * 1.2 + susp * 0.6) / total) * 100));
            return {
              provider: 'VirusTotal API v3',
              verifiedExternal: true,
              reputationScore: score,
              category: mal > 0 ? 'External Malicious Verdict' : 'Clean / Unflagged',
              notes: `VirusTotal stats: ${mal} malicious, ${susp} suspicious engines flagged indicator.`,
              timestamp,
            };
          }
        }
      }
    } catch {
      // Fall back cleanly with explicit attribution
    }
  }

  // AbuseIPDB check for IP indicators
  if (iocType === 'IP' && process.env.ABUSEIPDB_API_KEY) {
    try {
      const res = await fetch(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(indicator)}&maxAgeInDays=90`,
        {
          headers: {
            Key: process.env.ABUSEIPDB_API_KEY,
            Accept: 'application/json',
          },
          signal: AbortSignal.timeout(5000),
        },
      );
      if (res.ok) {
        const json = (await res.json()) as {
          data?: { abuseConfidenceScore?: number; totalReports?: number; isp?: string };
        };
        if (json.data) {
          return {
            provider: 'AbuseIPDB v2',
            verifiedExternal: true,
            reputationScore: json.data.abuseConfidenceScore ?? 0,
            category: (json.data.abuseConfidenceScore ?? 0) > 50 ? 'Abusive Infrastructure' : 'Low Abuse Reports',
            notes: `AbuseIPDB confidence ${json.data.abuseConfidenceScore}%, total reports: ${json.data.totalReports ?? 0}, ISP: ${json.data.isp ?? 'Unknown'}.`,
            timestamp,
          };
        }
      }
    } catch {
      // Fall back cleanly
    }
  }

  return {
    provider: 'Local IOC Repository & Heuristic Check',
    verifiedExternal: false,
    reputationScore: null,
    category: null,
    notes: 'External threat intelligence API keys are not configured on this server; result reflects local IOC store and heuristic inspection only.',
    timestamp,
  };
}
