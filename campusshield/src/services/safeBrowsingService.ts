const API_KEY = import.meta.env.VITE_SAFE_BROWSING_API_KEY;
if (API_KEY) {
  const masked = API_KEY.slice(0, 6) + '...' + API_KEY.slice(-4);
  console.log('🔒 Safe Browsing API key loaded:', masked);
}

const API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

const THREAT_TYPES = [
  'MALWARE',
  'SOCIAL_ENGINEERING',
  'UNWANTED_SOFTWARE',
  'POTENTIALLY_HARMFUL_APPLICATION',
] as const;

export interface SafeBrowsingResult {
  matched: boolean;
  threatType?: string;
  threatMessage?: string;
}

function mapThreatTypeToMessage(type: string): string {
  switch (type) {
    case 'MALWARE':
      return 'This URL is listed on Google Safe Browsing as hosting malware.';
    case 'SOCIAL_ENGINEERING':
      return 'This URL is listed on Google Safe Browsing as a phishing or social engineering site.';
    case 'UNWANTED_SOFTWARE':
      return 'This URL is listed on Google Safe Browsing for distributing unwanted software.';
    case 'POTENTIALLY_HARMFUL_APPLICATION':
      return 'This URL is listed on Google Safe Browsing for hosting potentially harmful applications.';
    default:
      return 'This URL matched a Google Safe Browsing threat list.';
  }
}

export async function checkUrlSafeBrowsing(url: string): Promise<SafeBrowsingResult | null> {
  if (!API_KEY) {
    console.log('⚠️ Safe Browsing API key not configured — skipping check');
    return null;
  }

  try {
    const response = await fetch(`${API_URL}?key=${API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: {
          clientId: 'campus-shield',
          clientVersion: '1.0.0',
        },
        threatInfo: {
          threatTypes: THREAT_TYPES,
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      }),
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error('❌ Safe Browsing API error:', response.status, errText);
      return null;
    }

    const data = await response.json();

    if (data.matches && data.matches.length > 0) {
      const match = data.matches[0];
      console.log('🚨 Safe Browsing match found:', match.threatType);
      return {
        matched: true,
        threatType: match.threatType,
        threatMessage: mapThreatTypeToMessage(match.threatType),
      };
    }

    console.log('✅ Safe Browsing: no threats found');
    return { matched: false };
  } catch (error) {
    console.error('❌ Safe Browsing request failed:', error);
    return null;
  }
}
