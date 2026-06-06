/**
 * Enhanced phishing URL feature extraction.
 *
 * Focus: detect URLs that use legitimate or trusted-looking domains
 * but have suspicious, random, or phishing-structured paths/queries.
 */

// ─── Utilities ─────────────────────────────────────────────────────────────────

export function normalizeUrl(raw: string): string {
  const s = raw.trim();
  if (/^https?:\/\//i.test(s)) return s;
  if (s.startsWith('//')) return `https:${s}`;
  return `https://${s}`;
}

/** Shannon entropy of a string — higher = more random. */
function shannonEntropy(s: string): number {
  const len = s.length;
  if (len < 2) return 0;
  const freq: Record<string, number> = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const ch in freq) {
    const p = freq[ch] / len;
    h -= p * Math.log2(p);
  }
  return Math.min(h / 4, 1); // normalise so ~4 is max (random string)
}

/** Does a segment look like gibberish? High entropy + consonant-heavy + no vowels. */
function isGibberish(segment: string): boolean {
  if (segment.length < 4) return false;
  const entropy = shannonEntropy(segment);
  if (entropy < 0.6) return false; // too structured
  const vowels = (segment.match(/[aeiou]/gi) || []).length;
  const letters = (segment.match(/[a-zA-Z]/g) || []).length;
  // Short segments (<12 chars) need stronger evidence to avoid false positives
  if (segment.length < 12) {
    if (vowels > 0) return false; // has readable characters
    return entropy > 0.7 && letters >= 4; // truly random-looking
  }
  // If >80% of letters are consonants AND high entropy, likely random
  if (letters > 0 && (letters - vowels) / letters > 0.8) return true;
  // Check for keyboard smashes (no vowels at all in a long segment)
  if (segment.length >= 6 && vowels === 0 && letters >= 4) return true;
  return false;
}

/** Does the path segment look like a base64 token? */
function looksLikeBase64(s: string): boolean {
  if (s.length < 16) return false;
  if (!/\d/.test(s)) return false; // base64 almost always has digits
  return /^[A-Za-z0-9+/=_\-]{16,}$/.test(s);
}

/** Check if string contains repeated runs of the same character (e.g., "aaaa", "1111"). */
function hasRepeatedRun(s: string): boolean {
  return /(.)\1{3,}/.test(s);
}

// ─── Static sets ───────────────────────────────────────────────────────────────

const SUSPICIOUS_TLDS = new Set([
  'tk','ml','ga','cf','gq','xyz','top','work','date','men','loan',
  'download','win','bid','trade','webcam','review','science','party',
  'racing','click','link',
]);

const SHORTENERS = new Set([
  'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly',
  'shorturl.at','rb.gy','tiny.cc','cutt.ly','s.id',
]);

const PHISHING_PATH_KW = [
  'login','signin','verify','secure','update','confirm','account',
  'password','credential','banking','paypal','refund','reward','prize',
  'winner','free','urgent','suspended','restrict','unlock','authenticate',
  'token','reset','recovery','authorize','auth','session','2fa','mfa',
  'verification','identity','validate','billing','invoice','payment',
];

const SUSPICIOUS_EXTENSIONS = new Set([
  'exe','scr','bat','cmd','msi','vbs','ps1','jar','apk','xapk',
  'dmg','pkg','zip','rar','7z','doc','docm','xlsm','pptm',
]);

const COMMON_TLDS = new Set([
  'com','org','net','edu','gov','mil','my','uk','jp','de','fr','au',
  'ca','in','br','kr','sg','hk','nz','th','ph','id','vn',
]);

const TRUSTED_DOMAINS = new Set([
  'youtube.com','www.youtube.com','m.youtube.com',
  'google.com','goo.gl','www.google.com','mail.google.com','drive.google.com',
  'docs.google.com','maps.google.com','photos.google.com','maps.app.goo.gl',
  'forms.gle','sites.google.com','classroom.google.com','meet.google.com',
  'calendar.google.com','sheets.google.com','slides.google.com','forms.google.com',
  'www.openlearning.com','openlearning.com',
  'www.padlet.com','padlet.com',
  'facebook.com','www.facebook.com','m.facebook.com',
  'twitter.com','www.twitter.com','x.com','www.x.com',
  'instagram.com','www.instagram.com',
  'linkedin.com','www.linkedin.com',
  'whatsapp.com','www.whatsapp.com',
  'amazon.com','www.amazon.com',
  'apple.com','www.apple.com',
  'microsoft.com','www.microsoft.com',
  'github.com','www.github.com',
  'stackoverflow.com','www.stackoverflow.com',
  'wikipedia.org','www.wikipedia.org','en.wikipedia.org',
  'netflix.com','www.netflix.com',
  'spotify.com','www.spotify.com',
  'telegram.org','www.telegram.org',
  'discord.com','www.discord.com',
  'reddit.com','www.reddit.com',
  'zoom.us','www.zoom.us',
  'canva.com','www.canva.com',
  'figma.com','www.figma.com',
  'npmjs.com','www.npmjs.com',
  'react.dev','www.react.dev',
  'uptm.edu.my','www.uptm.edu.my',
  'kptm.edu.my','www.kptm.edu.my',
  'lms.uptm.edu.my','mycms.kptm.edu.my',
  'epay.kptm.edu.my','edupage.org','uptm.edupage.org',
]);

// ─── Feature interface ─────────────────────────────────────────────────────────

export interface UrlFeatures {
  // Domain-level (16)
  urlLength: number;
  domainLength: number;
  isHttps: number;
  atSymbol: number;
  isIp: number;
  suspiciousTld: number;
  isShortener: number;
  hasPort: number;
  subdomainDepth: number;
  dotCount: number;
  dashCount: number;
  numericRatio: number;
  encodedChars: number;
  cyrillicChars: number;
  brandSpoof: number;
  isTrusted: number;

  // Path-level (13)
  pathLength: number;
  pathSegmentCount: number;
  maxPathSegmentEntropy: number;
  meanPathSegmentEntropy: number;
  pathNumericRatio: number;
  pathSpecialCharRatio: number;
  pathSuspiciousKwCount: number;
  lastSegmentGibberish: number;
  tldInPath: number;
  queryParamCount: number;
  doubleSlashInPath: number;
  repeatedCharsInPath: number;
  domainPathRatio: number;
}

export const FEATURE_COUNT = 29;
export const FEATURE_NAMES: (keyof UrlFeatures)[] = [
  'urlLength','domainLength','isHttps','atSymbol','isIp','suspiciousTld',
  'isShortener','hasPort','subdomainDepth','dotCount','dashCount','numericRatio',
  'encodedChars','cyrillicChars','brandSpoof','isTrusted',
  'pathLength','pathSegmentCount','maxPathSegmentEntropy','meanPathSegmentEntropy',
  'pathNumericRatio','pathSpecialCharRatio','pathSuspiciousKwCount',
  'lastSegmentGibberish','tldInPath','queryParamCount','doubleSlashInPath',
  'repeatedCharsInPath','domainPathRatio',
];

// ─── Main extraction ───────────────────────────────────────────────────────────

export function extractFeatures(url: string): UrlFeatures {
  let u: URL;
  try {
    u = new URL(normalizeUrl(url));
  } catch {
    return {
      urlLength: 1, domainLength: 1, isHttps: 0, atSymbol: 1, isIp: 0,
      suspiciousTld: 1, isShortener: 0, hasPort: 1, subdomainDepth: 0,
      dotCount: 0, dashCount: 0, numericRatio: 0, encodedChars: 1,
      cyrillicChars: 0, brandSpoof: 0, isTrusted: 0,
      pathLength: 1, pathSegmentCount: 1, maxPathSegmentEntropy: 1,
      meanPathSegmentEntropy: 1, pathNumericRatio: 1, pathSpecialCharRatio: 1,
      pathSuspiciousKwCount: 1, lastSegmentGibberish: 1, tldInPath: 1,
      queryParamCount: 1, doubleSlashInPath: 1, repeatedCharsInPath: 1,
      domainPathRatio: 1,
    };
  }

  const hostname = u.hostname.toLowerCase();
  const hostParts = hostname.split('.');
  const tld = hostParts[hostParts.length - 1];
  const regDomain = hostParts.length >= 2 ? hostParts.slice(-2).join('.') : hostname;
  const pathname = u.pathname;
  const query = u.search;

  // ── Domain features ───────────────────────────────────────────────────────

  // Brand spoof: catch subdomain-of-brand and embedded-brand-domain patterns
  const spoofBrands = ['paypal.com','facebook.com','instagram.com','twitter.com',
    'linkedin.com','whatsapp.com','amazon.com','apple.com','microsoft.com',
    'google.com','gmail.com','netflix.com'];
  const hasSpoof = spoofBrands.some(d => {
    if (hostname === d) return false;
    // Check 1: subdomain of brand — docs.google.com → endsWith('.google.com')
    const isSubdomain = hostname.endsWith('.' + d);
    // Check 2: embedded brand — google.com.evil.com → startsWith('google.com.') or contains '.google.com.'
    const isEmbedded = hostname.startsWith(d + '.') || hostname.includes('.' + d + '.');
    if (!isSubdomain && !isEmbedded) return false;
    const parts = hostname.split('.');
    const rd = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
    return !TRUSTED_DOMAINS.has(hostname) && !TRUSTED_DOMAINS.has(rd);
  });

  // ── Path features ─────────────────────────────────────────────────────────

  const path = pathname + query;
  const segments = pathname.split('/').filter(Boolean);

  // Path segment entropies
  const entropies = segments.map(s => shannonEntropy(s));
  const maxEntropy = entropies.length > 0 ? Math.max(...entropies) : 0;
  const meanEntropy = entropies.length > 0
    ? entropies.reduce((a, b) => a + b, 0) / entropies.length
    : 0;

  // Path numeric ratio
  const pathDigits = (pathname.match(/\d/g) || []).length;
  const pathNumericRatio = pathname.length > 0 ? pathDigits / pathname.length : 0;

  // Path special character ratio (non-alphanumeric except /)
  const specialChars = (pathname.match(/[^a-zA-Z0-9/]/g) || []).length;
  const pathSpecialCharRatio = pathname.length > 0 ? specialChars / pathname.length : 0;

  // Check: does any path segment contain a known TLD? (e.g., /something.com/login)
  const hasTldInPath = segments.some(seg => {
    const segLower = seg.toLowerCase();
    if (COMMON_TLDS.has(segLower)) return true;
    const dotIdx = segLower.lastIndexOf('.');
    if (dotIdx > 0) {
      const ext = segLower.slice(dotIdx + 1);
      if (COMMON_TLDS.has(ext)) return true;
    }
    return false;
  }) ? 1 : 0;

  // Phishing keywords specifically in path
  const kwInPath = PHISHING_PATH_KW.filter(kw =>
    pathname.toLowerCase().includes(kw)
  ).length;

  // Last segment analysis
  const lastSeg = segments[segments.length - 1] || '';
  const lastSegGibberish = lastSeg ? (isGibberish(lastSeg) || looksLikeBase64(lastSeg) ? 1 : 0) : 0;

  // Query parameter count
  const queryParams = query.length > 1 ? query.slice(1).split('&').length : 0;

  // Domain-to-path ratio
  const domainPathRatio = hostname.length > 0
    ? Math.min(pathname.length / hostname.length, 1)
    : 0;

  return {
    // Domain (16)
    urlLength:         Math.min(url.length / 200, 1),
    domainLength:      Math.min(hostname.length / 60, 1),
    isHttps:           u.protocol === 'https:' ? 1 : 0,
    atSymbol:          url.includes('@') ? 1 : 0,
    isIp:              /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? 1 : 0,
    suspiciousTld:     SUSPICIOUS_TLDS.has(tld) ? 1 : 0,
    isShortener:       SHORTENERS.has(regDomain) ? 1 : 0,
    hasPort:           u.port ? 1 : 0,
    subdomainDepth:    Math.min(Math.max(hostParts.length - 2, 0) / 4, 1),
    dotCount:          Math.min((hostname.match(/\./g) || []).length / 6, 1),
    dashCount:         Math.min((hostname.match(/-/g) || []).length / 5, 1),
    numericRatio:      (hostname.match(/\d/g) || []).length / Math.max(hostname.length, 1),
    encodedChars:      /%[0-9a-fA-F]{2}/.test(hostname) ? 1 : 0,
    cyrillicChars:     /[а-яА-Я]/.test(hostname) ? 1 : 0,
    brandSpoof:        hasSpoof ? 1 : 0,
    isTrusted:         TRUSTED_DOMAINS.has(hostname) ? 1 : 0,

    // Path (13)
    pathLength:              Math.min(path.length / 300, 1),
    pathSegmentCount:        Math.min(segments.length / 8, 1),
    maxPathSegmentEntropy:   Math.min(maxEntropy, 1),
    meanPathSegmentEntropy:  Math.min(meanEntropy, 1),
    pathNumericRatio:        pathNumericRatio,
    pathSpecialCharRatio:    Math.min(pathSpecialCharRatio / 0.5, 1),
    pathSuspiciousKwCount:   Math.min(kwInPath / 4, 1),
    lastSegmentGibberish:    lastSegGibberish,
    tldInPath:               hasTldInPath,
    queryParamCount:         Math.min(queryParams / 8, 1),
    doubleSlashInPath:       pathname.includes('//') ? 1 : 0,
    repeatedCharsInPath:     segments.some(s => hasRepeatedRun(s)) ? 1 : 0,
    domainPathRatio:         domainPathRatio,
  };
}

// ─── Heuristic scoring for preCheck / postCheck use ────────────────────────────

export interface HeuristicScore {
  total: number;          // 0–1
  reasons: string[];      // human-readable flags
  isMalicious: boolean;   // strong signal — bypass ML
  isSuspicious: boolean;  // weak signal — escalate
}

/**
 * Run deterministic rule checks that catch path-level phishing patterns.
 * Returns a score and actionable flags. Call this *after* the whitelist check,
 * or replace the whitelist short-circuit with a softer version.
 */
export function pathHeuristics(u: URL): HeuristicScore {
  const hostname = u.hostname.toLowerCase();
  const pathname = u.pathname;
  const query = u.search;
  const segments = pathname.split('/').filter(Boolean);
  const lastSeg = segments[segments.length - 1] || '';

  let score = 0;
  const reasons: string[] = [];
  const weight = (fraction: number, reason: string) => {
    score += fraction;
    reasons.push(reason);
  };

  // 1. High-entropy path segment (gibberish/random)
  for (const seg of segments) {
    if (isGibberish(seg)) {
      weight(0.30, `Random/gibberish path segment "${seg}"`);
      break;
    }
    if (looksLikeBase64(seg)) {
      weight(0.25, `Base64-like path segment "${seg.slice(0, 12)}..."`);
      break;
    }
  }

  // 2. Long repeated character runs in path
  for (const seg of segments) {
    if (hasRepeatedRun(seg)) {
      weight(0.20, `Suspicious repeated characters in path "${seg}"`);
      break;
    }
  }

  // 3. Suspicious file extension
  const extMatch = pathname.match(/\.([a-zA-Z0-9]+)$/);
  const ext = extMatch?.[1]?.toLowerCase();
  if (ext && SUSPICIOUS_EXTENSIONS.has(ext)) {
    weight(0.35, `Suspicious file extension ".${ext}"`);
  }

  // 4. Too many path segments (deep nesting with no meaningful names)
  if (segments.length >= 5) {
    weight(0.15, `Unusually deep path (${segments.length} segments)`);
  }

  // 5. Phishing keywords in path (2+ is a strong signal)
  const kwMatchCount = PHISHING_PATH_KW.filter(kw =>
    pathname.toLowerCase().includes(kw)
  ).length;
  if (kwMatchCount >= 3) {
    weight(0.30, `Multiple phishing keywords in path (${kwMatchCount})`);
  } else if (kwMatchCount >= 1) {
    weight(0.10, `Phishing keyword in path`);
  }

  // 6. TLD in path (e.g., /something.com/login) — match segment extensions only
  const hasTld = segments.some(seg => {
    if (COMMON_TLDS.has(seg.toLowerCase())) return true;
    const dotIdx = seg.lastIndexOf('.');
    if (dotIdx > 0) {
      return COMMON_TLDS.has(seg.slice(dotIdx + 1).toLowerCase());
    }
    return false;
  });
  if (hasTld) {
    weight(0.25, `TLD pattern found in URL path (may be impersonating a domain)`);
  }

  // 7. Very long path relative to domain
  if (hostname.length > 0 && pathname.length / hostname.length > 3) {
    weight(0.15, `Path is disproportionately long relative to domain`);
  }

  // 8. Double slash in path (often used in open redirects / SSRF)
  if (pathname.includes('//') && !pathname.startsWith('//')) {
    weight(0.20, `Double slash in path — possible open redirect or SSRF`);
  }

  // 9. Many query parameters with no meaningful path
  const paramCount = query.length > 1 ? query.slice(1).split('&').length : 0;
  if (paramCount >= 5 && segments.length <= 1) {
    weight(0.15, `Many query parameters (${paramCount}) on a shallow path`);
  }

  // 10. Last segment is numeric-only (e.g., /category/12345 — common in CMS attacks)
  if (lastSeg.length >= 8 && /^\d+$/.test(lastSeg)) {
    weight(0.15, `Last path segment is a long numeric string`);
  }

  // 11. Path contains brand names (suggesting fake login pages)
  const brandNames = ['login','signin','account','verify','paypal','banking','secure'];
  const brandHit = brandNames.filter(b => pathname.toLowerCase().includes(b));
  if (brandHit.length >= 2) {
    weight(0.15, `Path references brand/login keywords: ${brandHit.join(', ')}`);
  }

  const total = Math.min(score, 1);

  return {
    total,
    reasons,
    isMalicious: total >= 0.50,
    isSuspicious: total >= 0.15 && total < 0.50,
  };
}
