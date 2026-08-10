/**
 * Enhanced phishing URL feature extraction.
 *
 * Focus: detect URLs that use legitimate or trusted-looking domains
 * but have suspicious, random, or phishing-structured paths/queries.
 *
 * 33 features: 17 domain-level + 16 path/query-level.
 * Shared helpers/sets live in heuristics.ts (single source of truth).
 */

import {
  normalizeUrl, shannonEntropy, isGibberish, looksLikeBase64, hasRepeatedRun,
  detectBrandSubstring, isBrandImpersonation,
  SUSPICIOUS_TLDS, SHORTENERS, PHISHING_PATH_KW,
  COMMON_TLDS, TRUSTED_DOMAINS,
} from './heuristics.ts';

export { normalizeUrl, pathHeuristics } from './heuristics.ts';
export type { HeuristicScore } from './heuristics.ts';

// ─── Feature interface ─────────────────────────────────────────────────────────

export interface UrlFeatures {
  // Domain-level (17)
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
  punycode: number;

  // Path/query-level (16)
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
  queryEntropy: number;
  brandSubstring: number;
  suspiciousScheme: number;
}

export const FEATURE_COUNT = 33;
export const FEATURE_NAMES: (keyof UrlFeatures)[] = [
  'urlLength','domainLength','isHttps','atSymbol','isIp','suspiciousTld',
  'isShortener','hasPort','subdomainDepth','dotCount','dashCount','numericRatio',
  'encodedChars','cyrillicChars','brandSpoof','isTrusted','punycode',
  'pathLength','pathSegmentCount','maxPathSegmentEntropy','meanPathSegmentEntropy',
  'pathNumericRatio','pathSpecialCharRatio','pathSuspiciousKwCount',
  'lastSegmentGibberish','tldInPath','queryParamCount','doubleSlashInPath',
  'repeatedCharsInPath','domainPathRatio','queryEntropy','brandSubstring',
  'suspiciousScheme',
];

// ─── Main extraction ───────────────────────────────────────────────────────────

export function extractFeatures(url: string): UrlFeatures {
  const raw = url.trim();

  // Detect dangerous schemes from the raw string before URL parsing
  const schemeMatch = raw.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  const scheme = schemeMatch?.[1]?.toLowerCase();
  const suspiciousScheme = scheme && scheme !== 'http' && scheme !== 'https' ? 1 : 0;

  let u: URL;
  try {
    u = new URL(normalizeUrl(raw));
  } catch {
    return {
      urlLength: 1, domainLength: 1, isHttps: 0, atSymbol: 1, isIp: 0,
      suspiciousTld: 1, isShortener: 0, hasPort: 1, subdomainDepth: 0,
      dotCount: 0, dashCount: 0, numericRatio: 0, encodedChars: 1,
      cyrillicChars: 0, brandSpoof: 0, isTrusted: 0, punycode: 0,
      pathLength: 1, pathSegmentCount: 1, maxPathSegmentEntropy: 1,
      meanPathSegmentEntropy: 1, pathNumericRatio: 1, pathSpecialCharRatio: 1,
      pathSuspiciousKwCount: 1, lastSegmentGibberish: 1, tldInPath: 1,
      queryParamCount: 1, doubleSlashInPath: 1, repeatedCharsInPath: 1,
      domainPathRatio: 1, queryEntropy: 1, brandSubstring: 0,
      suspiciousScheme,
    };
  }

  const hostname = u.hostname.toLowerCase();
  const hostParts = hostname.split('.');
  const tld = hostParts[hostParts.length - 1];
  const regDomain = hostParts.length >= 2 ? hostParts.slice(-2).join('.') : hostname;
  const pathname = u.pathname;
  const query = u.search;

  // ── Domain features ───────────────────────────────────────────────────────

  // Brand impersonation: label-aware (google.com.evil.com → yes, google.com.mx → no)
  const hasSpoof = isBrandImpersonation(hostname) ? 1 : 0;

  // Brand keyword embedded in hostname (e.g. "paypal-security.com")
  const brandSubstring = detectBrandSubstring(hostname) ? 1 : 0;

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

  // Query parameter count + entropy
  const queryStr = query.length > 1 ? query.slice(1) : '';
  const queryParams = queryStr ? queryStr.split('&').length : 0;
  const queryEntropy = queryStr.length >= 4 ? Math.min(shannonEntropy(queryStr), 1) : 0;

  // Domain-to-path ratio
  const domainPathRatio = hostname.length > 0
    ? Math.min(pathname.length / hostname.length, 1)
    : 0;

  return {
    // Domain (17)
    urlLength:         Math.min(raw.length / 200, 1),
    domainLength:      Math.min(hostname.length / 60, 1),
    isHttps:           u.protocol === 'https:' ? 1 : 0,
    atSymbol:          raw.includes('@') ? 1 : 0,
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
    punycode:          hostname.includes('xn--') ? 1 : 0,

    // Path (16)
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
    queryEntropy:            queryEntropy,
    brandSubstring:          brandSubstring,
    suspiciousScheme:        suspiciousScheme,
  };
}
