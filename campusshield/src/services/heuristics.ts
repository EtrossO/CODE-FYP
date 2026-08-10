/**
 * Shared rule-based heuristics engine.
 *
 * Pure module (no browser / framework dependencies) so it can be reused by the
 * app (geminiService.ts, mlService.ts), the Node training script, and the
 * batch test suite — keeping a single source of truth for static sets, URL
 * helpers, path heuristics and the preCheck rule engine.
 */

import { SafetyStatusValues, type SafetyStatus } from '../types.ts';

// ─── URL normalisation ─────────────────────────────────────────────────────────

export function normalizeUrl(raw: string): string {
  const s = raw.trim();
  if (/^https?:\/\//i.test(s)) return s;
  if (s.startsWith('//')) return `https:${s}`;
  return `https://${s}`;
}

// ─── Generic string helpers ────────────────────────────────────────────────────

/** Shannon entropy of a string — higher = more random (normalised to ~4 = 1). */
export function shannonEntropy(s: string): number {
  const len = s.length;
  if (len < 2) return 0;
  const freq: Record<string, number> = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const ch in freq) {
    const p = freq[ch] / len;
    h -= p * Math.log2(p);
  }
  return Math.min(h / 4, 1);
}

/** Does a segment look like gibberish? High entropy + consonant-heavy + no vowels. */
export function isGibberish(segment: string): boolean {
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

/** Does the string look like a base64 token? */
export function looksLikeBase64(s: string): boolean {
  if (s.length < 16) return false;
  if (!/\d/.test(s)) return false; // base64 almost always has digits
  return /^[A-Za-z0-9+/=_-]{16,}$/.test(s);
}

/** Check if string contains repeated runs of the same character (e.g., "aaaa", "1111"). */
export function hasRepeatedRun(s: string): boolean {
  return /(.)\1{3,}/.test(s);
}

/** Levenshtein distance — used for typosquat detection. */
export function levenshteinDistance(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

// ─── Static sets ───────────────────────────────────────────────────────────────

export const SUSPICIOUS_TLDS = new Set([
  'tk','ml','ga','cf','gq','xyz','top','work','date','men','loan',
  'download','win','bid','trade','webcam','review','science','party',
  'racing','click','link','info','biz','rest','monster','icu','live','stream',
]);

export const SHORTENERS = new Set([
  'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly',
  'shorturl.at','rb.gy','tiny.cc','cutt.ly','s.id','lc.ch','bl.ink',
  'rebrandly','short.link','t.ly','zip.co','v.gd',
]);

export const PHISHING_PATH_KW = [
  'login','signin','verify','secure','update','confirm','account',
  'password','credential','banking','paypal','refund','reward','prize',
  'winner','free','urgent','suspended','restrict','unlock','authenticate',
  'token','reset','recovery','authorize','auth','session','2fa','mfa',
  'verification','identity','validate','billing','invoice','payment',
  'wallet','webscr','sign-in','log-in','signin',
];

export const SUSPICIOUS_EXTENSIONS = new Set([
  'exe','scr','bat','cmd','msi','vbs','ps1','jar','apk','xapk',
  'dmg','pkg','zip','rar','7z','doc','docm','xlsm','pptm',
]);

export const COMMON_TLDS = new Set([
  'com','org','net','edu','gov','mil','int','io','co','me','tv',
  'my','uk','jp','de','fr','au','ca','in','br','kr','sg','hk','nz',
  'th','ph','id','vn','mx','es','it','pt','nl','be','ch','at','se',
  'no','dk','fi','pl','ru','tr','ar','cl','pe','ve','za','eg','sa',
  'ae','il','tw','cn','cz','gr','hu','ie','is','lt','lv','my',
]);

export const OPEN_REDIRECT_PARAMS = new Set([
  'url','redirect','redirect_uri','redirect_url','next','return',
  'return_to','return_url','dest','destination','target','to',
  'login_url','continue','out','view','link','ref','href',
]);

export const BRAND_DOMAINS_FOR_TYPOSQUAT = [
  'google','youtube','facebook','instagram','linkedin','whatsapp',
  'amazon','apple','microsoft','netflix','paypal','twitter','x',
  'github','stackoverflow','wikipedia','spotify','telegram','discord','zoom',
  'canva','figma','reddit','gmail','microsoft365','outlook','dropbox',
];

export const BRAND_KEYWORDS = [
  'paypal','google','gmail','youtube','facebook','instagram','linkedin',
  'whatsapp','amazon','apple','microsoft','netflix','twitter','github',
  'stackoverflow','wikipedia','spotify','telegram','discord','reddit','zoom',
  'canva','figma','microsoft365','outlook','dropbox','adobe','steam',
  'battle','binance','coinbase','metamask','maya','hsbc','cimb','maybank',
  'webscr',
];

export const TRUSTED_DOMAINS = new Set([
  'youtube.com','www.youtube.com','m.youtube.com',
  'google.com','goo.gl','www.google.com','mail.google.com','drive.google.com',
  'docs.google.com','maps.google.com','photos.google.com','maps.app.goo.gl',
  'forms.gle','sites.google.com','classroom.google.com','meet.google.com',
  'calendar.google.com','sheets.google.com','slides.google.com','forms.google.com',
  'googleusercontent.com','gstatic.com','googleapis.com','googlevideo.com',
  'ggpht.com','googlesyndication.com','googleadservices.com','doubleclick.net',
  'www.openlearning.com','openlearning.com',
  'www.padlet.com','padlet.com',
  'facebook.com','www.facebook.com','m.facebook.com',
  'twitter.com','www.twitter.com','x.com','www.x.com',
  'instagram.com','www.instagram.com',
  'linkedin.com','www.linkedin.com',
  'whatsapp.com','www.whatsapp.com',
  'amazon.com','www.amazon.com',
  'apple.com','www.apple.com',
  'microsoft.com','www.microsoft.com','live.com','www.live.com',
  'office.com','www.office.com','mail.office.com','onedrive.com','www.onedrive.com',
  'microsoftedge.com','www.microsoftedge.com',
  'github.com','www.github.com','raw.githubusercontent.com',
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

// ─── Detection helpers ─────────────────────────────────────────────────────────

function countDots(s: string): number {
  return (s.match(/\./g) || []).length;
}

export function detectIDNHomograph(hostname: string): boolean {
  const scripts: string[] = [];
  for (const ch of hostname) {
    const code = ch.codePointAt(0)!;
    if (code >= 0x0400 && code <= 0x04FF) { scripts.push('cyrillic'); continue; }
    if ((code >= 0x0370 && code <= 0x03FF) || (code >= 0x1F00 && code <= 0x1FFF)) { scripts.push('greek'); continue; }
    if (code >= 0x3040 && code <= 0x309F) { scripts.push('hiragana'); continue; }
    if (code >= 0x30A0 && code <= 0x30FF) { scripts.push('katakana'); continue; }
    if (code >= 0x4E00 && code <= 0x9FFF) { scripts.push('han'); continue; }
  }
  return new Set(scripts).size >= 2;
}

export function detectTyposquatting(hostname: string): string | null {
  if (TRUSTED_DOMAINS.has(hostname)) return null;
  const parts = hostname.toLowerCase().split('.');
  // Compare only the registrable label (e.g. "google" from "google.com")
  // so trusted subdomains like mail.google.com are never misclassified.
  const registered = parts.length >= 2 ? parts.slice(-2) : parts;
  const domain = registered[0].replace(/^www\./, '');
  for (const brand of BRAND_DOMAINS_FOR_TYPOSQUAT) {
    const dist = levenshteinDistance(domain, brand);
    if (dist === 1 || (dist === 2 && domain.length === brand.length)) {
      return brand;
    }
  }
  return null;
}

/**
 * Brand keyword embedded in an otherwise untrusted hostname
 * (e.g. "paypal-security.com" — fused, or "google.com.evil.com" — label trick).
 * Legitimate country domains (google.com.mx) are skipped.
 */
export function detectBrandSubstring(hostname: string): string | null {
  const lower = hostname.toLowerCase();
  if (TRUSTED_DOMAINS.has(lower)) return null;
  const labels = lower.split('.');
  for (const brand of BRAND_KEYWORDS) {
    const brandIdx = labels.indexOf(brand);
    if (brandIdx !== -1) {
      // Brand is a whole label — trusted only if every label after it is a TLD.
      const after = labels.slice(brandIdx + 1);
      if (after.length > 0 && after.every(l => COMMON_TLDS.has(l) || SUSPICIOUS_TLDS.has(l))) {
        continue;
      }
      return brand;
    }
    // Fused brand (e.g. "paypal-security-check.com")
    if (lower.includes(brand)) return brand;
  }
  return null;
}

export function detectOpenRedirect(u: URL): { hit: boolean; param: string; target: string } | null {
  const params = new URLSearchParams(u.search);
  for (const [key, value] of params) {
    if (OPEN_REDIRECT_PARAMS.has(key.toLowerCase())) {
      try {
        const decoded = decodeURIComponent(value);
        if (/^https?:\/\//i.test(decoded)) {
          return { hit: true, param: key, target: decoded };
        }
      } catch { /* ignore malformed encoding */ }
    }
  }
  return null;
}

/** Dangerous non-http(s) schemes used to smuggle payloads (data:, javascript:, ...). */
export function detectSuspiciousScheme(raw: string): { scheme: string } | null {
  const match = raw.trim().match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  if (!match) return null;
  const scheme = match[1].toLowerCase();
  if (scheme === 'http' || scheme === 'https') return null;
  return { scheme };
}

// ─── Path-level heuristics ─────────────────────────────────────────────────────

export interface HeuristicScore {
  total: number;          // 0–1
  reasons: string[];      // human-readable flags
  isMalicious: boolean;   // strong signal — bypass ML
  isSuspicious: boolean;  // weak signal — escalate
}

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

  // 11. Path contains brand/login keywords (suggesting fake login pages)
  const brandNames = ['login','signin','account','verify','paypal','banking','secure','wallet'];
  const brandHit = brandNames.filter(b => pathname.toLowerCase().includes(b));
  if (brandHit.length >= 2) {
    weight(0.15, `Path references brand/login keywords: ${brandHit.join(', ')}`);
  }

  // 12. Encoded / base64-looking payload in the query string
  const queryStr = query.length > 1 ? query.slice(1) : '';
  if (queryStr.length >= 16) {
    if (queryStr.includes('data:') || /%00|\\x00/.test(queryStr)) {
      weight(0.30, `Encoded payload detected in query string`);
    } else {
      const querySegments = queryStr.split(/[&;]/);
      const hasB64 = querySegments.some(seg => looksLikeBase64(seg) || isGibberish(seg));
      if (hasB64) {
        weight(0.20, `Base64/gibberish token in query parameters`);
      }
    }
  }

  // 13. Double-encoded characters in path (e.g. %252e — used to bypass WAFs)
  if (/%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}/.test(pathname)) {
    weight(0.20, `Double-encoded characters in path (WAF evasion)`);
  }

  const total = Math.min(score, 1);

  return {
    total,
    reasons,
    isMalicious: total >= 0.50,
    isSuspicious: total >= 0.15 && total < 0.50,
  };
}

// ─── preCheck rule engine ──────────────────────────────────────────────────────

export interface PreCheckResult {
  status: SafetyStatus | null;
  reason: string;
}

const BRAND_SPOOF_DOMAINS = [
  'paypal.com','facebook.com','instagram.com','twitter.com','x.com',
  'linkedin.com','whatsapp.com','amazon.com','apple.com','microsoft.com',
  'google.com','gmail.com','netflix.com','microsoft365.com','office.com',
];

/**
 * Label-aware brand impersonation check.
 *
 * Returns true when a well-known brand's labels appear inside the hostname but
 * are followed by a non-TLD label (e.g. google.com.evil.com), while correctly
 * allowing legitimate uses:
 *   - subdomains of the brand (login.paypal.com)
 *   - brand + country/regional TLD (www.google.com.mx, google.co.uk)
 */
export function isBrandImpersonation(hostname: string): boolean {
  if (TRUSTED_DOMAINS.has(hostname)) return false;
  const labels = hostname.split('.');
  for (const brand of BRAND_SPOOF_DOMAINS) {
    const brandLabels = brand.split('.');
    for (let i = 0; i + brandLabels.length <= labels.length; i++) {
      let match = true;
      for (let k = 0; k < brandLabels.length; k++) {
        if (labels[i + k] !== brandLabels[k]) { match = false; break; }
      }
      if (!match) continue;
      const after = labels.slice(i + brandLabels.length);
      // Subdomain of the brand (e.g. login.paypal.com) → official
      if (after.length === 0) return false;
      // Brand + country/regional TLD (e.g. google.com.mx) → official
      if (after.every(l => COMMON_TLDS.has(l) || SUSPICIOUS_TLDS.has(l))) return false;
      // Brand followed by non-TLD label → impersonation
      return true;
    }
  }
  return false;
}

export function preCheck(url: string): PreCheckResult {
  // 1. Dangerous URI schemes (data:, javascript:, ...) → UNSAFE
  const scheme = detectSuspiciousScheme(url);
  if (scheme) {
    return {
      status: SafetyStatusValues.UNSAFE,
      reason: `URL uses a dangerous "${scheme.scheme}:" scheme — commonly used to smuggle payloads or execute code.`,
    };
  }

  let u: URL;
  try {
    u = new URL(normalizeUrl(url));
  } catch {
    return { status: SafetyStatusValues.SUSPICIOUS, reason: 'Invalid URL format.' };
  }

  const hostname = u.hostname.toLowerCase();
  const path     = u.pathname + u.search;

  // ── Weighted risk signals ─────────────────────────────────────────────────
  let unsafe = false;

  // IP address → UNSAFE (strong signal)
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    return { status: SafetyStatusValues.UNSAFE,
      reason: 'URL uses a raw IP address instead of a domain name — a common hiding technique for phishing sites.' };
  }

  // @ symbol → UNSAFE (strong signal) — but only when in the authority part,
  // i.e. before the first / ? or #. Email addresses in query params are fine.
  const authorityEnd = url.search(/[/?#]/);
  const authorityPart = authorityEnd === -1 ? url : url.slice(0, authorityEnd);
  if (authorityPart.includes('@') && !url.trim().startsWith('mailto:')) {
    const beforeAt = authorityPart.slice(0, authorityPart.indexOf('@'));
    if (beforeAt.includes('://') || /[a-zA-Z]/.test(beforeAt)) {
      return { status: SafetyStatusValues.UNSAFE,
        reason: 'URL contains an "@" symbol to hide the real destination domain from the user.' };
    }
  }

  // ── Weighted risk signals ─────────────────────────────────────────────────
  // Each signal contributes a weight; the total decides the final status.
  //   total >= 0.70 → UNSAFE (multiple independent malicious indicators)
  //   total >= 0.15 → SUSPICIOUS (needs deeper analysis)
  const signals: { weight: number; reason: string }[] = [];
  const add = (weight: number, reason: string) => signals.push({ weight, reason });

  // Non-HTTPS → weak signal
  if (!u.protocol.startsWith('https')) {
    add(0.10, 'Connection is not encrypted (non-HTTPS).');
  }

  // Uncommon port → risk (phishing often hosts on non-standard ports)
  if (u.port && !['80', '443', '8080', '8443'].includes(u.port)) {
    add(0.20, `URL uses unusual port "${u.port}" — often used to evade blocklists.`);
  }

  // Many subdomains
  if (countDots(hostname) >= 4) {
    add(0.15, `Unusually many subdomains (${countDots(hostname)} dots) — may be attempting to appear as a trusted site.`);
  }

  const parts = hostname.split('.');
  const registeredDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;

  // Suspicious TLD
  if (SUSPICIOUS_TLDS.has(parts[parts.length - 1])) {
    add(0.20, `Suspicious top-level domain ".${parts[parts.length - 1]}" — commonly used for malicious sites.`);
  }

  // URL shortener
  if (SHORTENERS.has(registeredDomain)) {
    add(0.20, 'Shortened URL hides the real destination. Proceed with caution.');
  }

  // Phishing keywords in path / hostname
  const keywordMatches = PHISHING_PATH_KW.filter(kw =>
    path.toLowerCase().includes(kw) || hostname.includes(kw)
  );
  if (keywordMatches.length >= 2) {
    add(0.30, `Contains phishing-related keywords: ${keywordMatches.join(', ')}.`);
  } else if (keywordMatches.length === 1) {
    add(0.15, `Contains phishing-related keyword "${keywordMatches[0]}".`);
  }

  // Long URL
  if (path.length > 400) {
    add(0.10, 'Unusually long URL — may be hiding malicious parameters.');
  }

  // Encoded characters in hostname
  if (/%[0-9a-fA-F]{2}/.test(hostname)) {
    add(0.20, 'Domain name contains encoded characters used to disguise the real website address.');
  }

  // IDN homograph (mixed scripts) → strong
  if (detectIDNHomograph(hostname)) {
    unsafe = true;
    signals.push({ weight: 1, reason: 'Domain mixes multiple character scripts (homograph attack) to visually impersonate trusted domains.' });
  }

  // Punycode-encoded domain (xn-- prefix)
  if (hostname.startsWith('xn--')) {
    add(0.25, 'Domain uses Punycode encoding (xn-- prefix) to hide non-ASCII characters — possible homograph attack.');
  }

  // Typosquatting
  const typosquat = detectTyposquatting(hostname);
  if (typosquat) {
    add(0.25, `Domain name "${hostname}" is a close misspelling of "${typosquat}" — possible typosquatting attack.`);
  }

  // Brand substring (e.g. "paypal-verify.com") — moderate signal
  const brandSub = detectBrandSubstring(hostname);
  if (brandSub) {
    add(0.30, `Hostname embeds brand "${brandSub}" but is not an official domain — possible impersonation.`);
  }

  // Open redirect → moderate signal
  const redirect = detectOpenRedirect(u);
  if (redirect) {
    add(0.30, `Open redirect via parameter "${redirect.param}" pointing to external URL "${redirect.target}".`);
  }

  // Brand impersonation (label-aware) → UNSAFE
  if (isBrandImpersonation(hostname)) {
    return { status: SafetyStatusValues.UNSAFE,
      reason: 'Domain appears to be impersonating a well-known brand using a subdomain trick.' };
  }

  // If any UNSAFE-level signal was found, return immediately
  if (unsafe) {
    return { status: SafetyStatusValues.UNSAFE, reason: signals[0]?.reason ?? '' };
  }

  // Path-level heuristics
  const heuristic = pathHeuristics(u);

  if (heuristic.isMalicious) {
    return { status: SafetyStatusValues.UNSAFE, reason: heuristic.reasons[0] };
  }

  // Whitelisted domain with a benign path → SAFE.
  // (Trusted domains legitimately use /login, /signin, etc., so weak keyword
  // signals must not downgrade them. Strong signals above still override.)
  if (TRUSTED_DOMAINS.has(hostname)) {
    return { status: SafetyStatusValues.SAFE, reason: '' };
  }

  // Multiple strong signals → UNSAFE
  const riskTotal = signals.reduce((acc, s) => acc + s.weight, 0);
  if (riskTotal >= 0.70) {
    return { status: SafetyStatusValues.UNSAFE, reason: signals[0]?.reason ?? '' };
  }

  // Single risk signal or path is suspicious → SUSPICIOUS
  if (riskTotal >= 0.15 || heuristic.isSuspicious) {
    const reason = heuristic.isSuspicious
      ? heuristic.reasons[0]
      : signals[0]?.reason ?? '';
    return { status: SafetyStatusValues.SUSPICIOUS, reason };
  }

  return { status: null, reason: '' };
}
