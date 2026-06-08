import { GoogleGenerativeAI } from "@google/generative-ai";
import { SafetyStatusValues, type SafetyStatus } from "../types";
import { checkUrlSafeBrowsing } from "./safeBrowsingService";
import { classifyUrl } from "./mlService";
import { pathHeuristics, normalizeUrl } from "./features";

const apiKey = import.meta.env.VITE_API_KEY;
if (!apiKey) {
  console.warn("VITE_API_KEY environment variable is not set.");
}

const masked = apiKey ? apiKey.slice(0, 6) + '...' + apiKey.slice(-4) : 'none';
console.log('🔑 Gemini API key loaded:', masked);

const ai = new GoogleGenerativeAI(apiKey || "");

// ─── Static lookup sets (unchanged) ──────────────────────────────────────────

const SUSPICIOUS_TLDS = new Set([
  'tk','ml','ga','cf','gq','xyz','top','work','date','men','loan',
  'download','win','bid','trade','webcam','review','science','party',
  'racing','click','link',
]);

const URL_SHORTENERS = new Set([
  'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly',
  'shorturl.at','rb.gy','tiny.cc','lc.ch','bl.ink','cutt.ly',
  'rebrandly','short.link','s.id',
]);

const SUSPICIOUS_KEYWORDS = [
  'login','signin','verify','secure','update','confirm','account',
  'password','credential','banking','paypal','refund','reward','prize',
  'winner','free','urgent','suspended','restrict','unlock','authenticate',
];

const OPEN_REDIRECT_PARAMS = new Set([
  'url','redirect','redirect_uri','redirect_url','next','return',
  'return_to','return_url','dest','destination','target','to',
  'login_url','continue','out','view','link','ref','href',
]);

const BRAND_DOMAINS_FOR_TYPOSQUAT = [
  'google','youtube','facebook','instagram','linkedin','whatsapp',
  'amazon','apple','microsoft','netflix','paypal','twitter','x',
  'github','stackoverflow','wikipedia','spotify','telegram','discord','zoom',
  'canva','figma','reddit',
];

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

const resultCache = new Map<string, {
  status: SafetyStatus; reason: string; title: string; description: string;
}>();

// ─── Stage 1: Rule-based heuristics ──────────────────────────────────────────

interface PreCheckResult {
  status: SafetyStatus | null;
  reason: string;
}

function countDots(s: string): number {
  return (s.match(/\./g) || []).length;
}

function levenshteinDistance(a: string, b: string): number {
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

function detectOpenRedirect(u: URL): { hit: boolean; param: string; target: string } | null {
  const params = new URLSearchParams(u.search);
  for (const [key, value] of params) {
    if (OPEN_REDIRECT_PARAMS.has(key.toLowerCase())) {
      const decoded = decodeURIComponent(value);
      if (/^https?:\/\//i.test(decoded)) {
        return { hit: true, param: key, target: decoded };
      }
    }
  }
  return null;
}

function detectIDNHomograph(hostname: string): boolean {
  const scripts: string[] = [];
  for (const ch of hostname) {
    const code = ch.codePointAt(0)!;
    if (code >= 0x0400 && code <= 0x04FF) { scripts.push('cyrillic'); continue; }
    if ((code >= 0x0370 && code <= 0x03FF) || (code >= 0x1F00 && code <= 0x1FFF)) { scripts.push('greek'); continue; }
    if (code >= 0x3040 && code <= 0x309F) { scripts.push('hiragana'); continue; }
    if (code >= 0x30A0 && code <= 0x30FF) { scripts.push('katakana'); continue; }
    if (code >= 0x4E00 && code <= 0x9FFF) { scripts.push('han'); continue; }
  }
  const unique = new Set(scripts);
  return unique.size >= 2;
}

function detectTyposquatting(hostname: string): string | null {
  const domain = hostname.replace(/^www\./, '').split('.')[0];
  for (const brand of BRAND_DOMAINS_FOR_TYPOSQUAT) {
    const dist = levenshteinDistance(domain, brand);
    if (dist === 1 || (dist === 2 && domain.length === brand.length)) {
      return brand;
    }
  }
  return null;
}

function preCheck(url: string): PreCheckResult {
  let u: URL;
  try {
    u = new URL(normalizeUrl(url));
  } catch {
    return { status: SafetyStatusValues.SUSPICIOUS, reason: 'Invalid URL format.' };
  }

  const hostname = u.hostname.toLowerCase();
  const path     = u.pathname + u.search;

  // ── Collect risk signals instead of early-returning ───────────────────────
  const risks: string[] = [];
  let unsafe = false;

  // IP address → UNSAFE (strong signal)
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    return { status: SafetyStatusValues.UNSAFE,
      reason: 'URL uses a raw IP address instead of a domain name — a common hiding technique for phishing sites.' };
  }

  // @ symbol → UNSAFE (strong signal)
  const atIndex = url.indexOf('@');
  if (atIndex > 0 && !url.startsWith('mailto:')) {
    const beforeAt = url.slice(0, atIndex);
    if (beforeAt.includes('://') || /[a-zA-Z]/.test(beforeAt)) {
      return { status: SafetyStatusValues.UNSAFE,
        reason: 'URL contains an "@" symbol to hide the real destination domain from the user.' };
    }
  }

  // Non-HTTPS → mild risk (no longer immediate SUSPICIOUS)
  if (!u.protocol.startsWith('https')) {
    risks.push('Connection is not encrypted (non-HTTPS).');
  }

  // Many subdomains
  if (countDots(hostname) >= 4) {
    risks.push(`Unusually many subdomains (${countDots(hostname)} dots) — may be attempting to appear as a trusted site.`);
  }

  const parts = hostname.split('.');
  const registeredDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;

  // Suspicious TLD
  if (SUSPICIOUS_TLDS.has(parts[parts.length - 1])) {
    risks.push(`Suspicious top-level domain ".${parts[parts.length - 1]}" — commonly used for malicious sites.`);
  }

  // URL shortener
  if (URL_SHORTENERS.has(registeredDomain)) {
    risks.push('Shortened URL hides the real destination. Proceed with caution.');
  }

  // Phishing keywords in path
  const keywordMatches = SUSPICIOUS_KEYWORDS.filter(kw =>
    path.toLowerCase().includes(kw) || hostname.includes(kw)
  );
  if (keywordMatches.length >= 2) {
    risks.push(`Contains phishing-related keywords: ${keywordMatches.join(', ')}.`);
  }

  // Long URL
  if (path.length > 400) {
    risks.push('Unusually long URL — may be hiding malicious parameters.');
  }

  // Encoded characters in hostname
  if (/%[0-9a-fA-F]{2}/.test(hostname)) {
    risks.push('Domain name contains encoded characters used to disguise the real website address.');
  }

  // ── New: IDN homograph (mixed scripts) ────────────────────────────────────
  if (detectIDNHomograph(hostname)) {
    unsafe = true;
    risks.push('Domain mixes multiple character scripts (homograph attack) to visually impersonate trusted domains.');
  }

  // Punycode-encoded domain (xn-- prefix) — may hide homograph characters
  if (hostname.startsWith('xn--')) {
    risks.push('Domain uses Punycode encoding (xn-- prefix) to hide non-ASCII characters — possible homograph attack.');
  }

  // ── New: Typosquatting ────────────────────────────────────────────────────
  const typosquat = detectTyposquatting(hostname);
  if (typosquat) {
    risks.push(`Domain name "${hostname}" is a close misspelling of "${typosquat}" — possible typosquatting attack.`);
  }

  // ── New: Open redirect ───────────────────────────────────────────────────
  const redirect = detectOpenRedirect(u);
  if (redirect) {
    risks.push(`Open redirect via parameter "${redirect.param}" pointing to external URL "${redirect.target}".`);
  }

  // ── Brand spoof check ─────────────────────────────────────────────────────
  const brandDomains = ['paypal.com','facebook.com','instagram.com','twitter.com','x.com',
    'linkedin.com','whatsapp.com','amazon.com','apple.com','microsoft.com',
    'google.com','gmail.com','netflix.com'];
  const hasSpoof = brandDomains.some(d => {
    if (hostname === d) return false;
    const isSubdomain = hostname.endsWith('.' + d);
    const isEmbedded = hostname.startsWith(d + '.') || hostname.includes('.' + d + '.');
    if (!isSubdomain && !isEmbedded) return false;
    const rd = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
    return !TRUSTED_DOMAINS.has(hostname) && !TRUSTED_DOMAINS.has(rd);
  });
  if (hasSpoof) {
    return { status: SafetyStatusValues.UNSAFE,
      reason: 'Domain appears to be impersonating a well-known brand using a subdomain trick.' };
  }

  // If any UNSAFE-level signal was found, return immediately
  if (unsafe) {
    return { status: SafetyStatusValues.UNSAFE, reason: risks[0] };
  }

  // ── Path-level heuristics ─────────────────────────────────────────────────
  const heuristic = pathHeuristics(u);

  if (heuristic.isMalicious) {
    return { status: SafetyStatusValues.UNSAFE, reason: heuristic.reasons[0] };
  }

  // 2+ risk signals → UNSAFE (combined signals strongly suggest malicious intent)
  if (risks.length >= 2) {
    return { status: SafetyStatusValues.UNSAFE, reason: risks[0] };
  }

  // Single risk signal or path is suspicious → SUSPICIOUS
  if (risks.length > 0 || heuristic.isSuspicious) {
    const reason = heuristic.isSuspicious
      ? heuristic.reasons[0]
      : risks[0];
    return { status: SafetyStatusValues.SUSPICIOUS, reason };
  }

  // Whitelisted domain with clean path → SAFE
  if (TRUSTED_DOMAINS.has(hostname)) {
    return { status: SafetyStatusValues.SAFE, reason: '' };
  }

  return { status: null, reason: '' };
}

// ─── Main analyser ────────────────────────────────────────────────────────────

export const analyzeLinkSafety = async (url: string): Promise<{
  status: SafetyStatus; reason: string; title: string; description: string;
}> => {
  // Cache check
  const cached = resultCache.get(url);
  if (cached) {
    console.log('📦 Using cached result for:', url);
    return cached;
  }

  // ── Stage 1: Heuristics ──────────────────────────────────────────────────
  const pre = preCheck(url);

  if (pre.status === SafetyStatusValues.SAFE) {
    const result = {
      status: SafetyStatusValues.SAFE,
      reason: 'Known trusted domain.',
      title: 'Verified Safe',
      description: 'This URL belongs to a recognised reputable website.',
    };
    resultCache.set(url, result);
    return result;
  }

  if (pre.status === SafetyStatusValues.UNSAFE) {
    const result = {
      status: pre.status,
      reason: pre.reason,
      title: 'Blocked — Threat Detected',
      description: 'This URL was flagged by local safety heuristics as unsafe.',
    };
    resultCache.set(url, result);
    return result;
  }

  // ── Stage 2: TF.js ML classifier ──────────────────────────────────────────
  try {
    const ml = await classifyUrl(url);
    console.log(`🤖 ML result: ${ml.label} (confidence: ${(ml.confidence * 100).toFixed(1)}%)`);

    if (ml.isHighConfidence) {
      // If heuristics found path issues, don't let ML override to SAFE
      if (ml.label === 'SAFE' && pre.status === SafetyStatusValues.SUSPICIOUS) {
        // Heuristic flagged something — keep it at SUSPICIOUS, don't downgrade
        console.log('⚠️ Heuristic flagged path issues; overriding ML SAFE → SUSPICIOUS');
      } else if (ml.label === 'SAFE') {
        const result = {
          status: SafetyStatusValues.SAFE,
          reason: `AI classifier assessed this URL as safe (${(ml.confidence * 100).toFixed(0)}% confidence). No threat indicators found.`,
          title: 'Likely Safe',
          description: 'On-device ML analysis found no signs of phishing or malware.',
        };
        resultCache.set(url, result);
        return result;
      }

      if (ml.label === 'UNSAFE') {
        const result = {
          status: SafetyStatusValues.UNSAFE,
          reason: `AI classifier flagged this URL as unsafe (${(ml.confidence * 100).toFixed(0)}% confidence). Multiple threat signals detected.`,
          title: 'Blocked — ML Threat Detected',
          description: 'On-device ML analysis identified threat patterns in this URL.',
        };
        resultCache.set(url, result);
        return result;
      }
    }
  } catch (mlErr) {
    console.warn('⚠️ ML classifier error (non-fatal):', mlErr);
  }

  // ── Stage 3: Google Safe Browsing ────────────────────────────────────────
  const sbResult = await checkUrlSafeBrowsing(url);
  if (sbResult?.matched) {
    const result = {
      status: SafetyStatusValues.UNSAFE,
      reason: sbResult.threatMessage!,
      title: 'Blocked — Safe Browsing Match',
      description: `Google Safe Browsing identified this URL as a known threat (${sbResult.threatType}). It has been blocked.`,
    };
    resultCache.set(url, result);
    return result;
  }

  // ── Stage 4: Gemini AI ────────────────────────────────────────────────────
  if (!apiKey) {
    return {
      status: pre.status ?? SafetyStatusValues.SUSPICIOUS,
      reason: pre.reason || 'API key not configured. Please set VITE_API_KEY in your .env file.',
      title: 'Configuration Required',
      description: 'Gemini AI analysis is not available without an API key.',
    };
  }

  try {
    const modelName = 'gemini-2.0-flash';
    console.log('🤖 Calling Gemini model:', modelName, 'for URL:', url);
    const model = ai.getGenerativeModel({ model: modelName });

    const prompt = `You are a cybersecurity expert. Analyze this URL for safety threats such as phishing, malware, scams, or suspicious behavior: ${url}

Respond ONLY with a raw JSON object (no markdown, no code fences). Use this exact shape:
{
  "status": "SAFE" | "SUSPICIOUS" | "UNSAFE",
  "reason": "one or two sentence explanation",
  "title": "estimated or known page title",
  "description": "brief description of the site or threat"
}`;

    const geminiResult = await model.generateContent(prompt);
    const response    = await geminiResult.response;
    const raw         = response.text();
    const cleaned     = raw.replace(/```json\s*/gi, '').replace(/```\s*/g, '').trim();
    const data        = JSON.parse(cleaned);

    const validStatuses = [
      SafetyStatusValues.SAFE,
      SafetyStatusValues.SUSPICIOUS,
      SafetyStatusValues.UNSAFE,
    ] as string[];
    const status = validStatuses.includes(data.status)
      ? (data.status as SafetyStatus)
      : SafetyStatusValues.SUSPICIOUS;

    if (pre.status === SafetyStatusValues.SUSPICIOUS && status === SafetyStatusValues.SAFE) {
      const knownSafePlatforms = ['google.com','googleapis.com','goo.gl','microsoft.com','apple.com'];
      const isKnownPlatform = knownSafePlatforms.some(p => {
        try { return new URL(url).hostname.endsWith(p); } catch { return false; }
      });
      if (!isKnownPlatform) {
        return {
          status: SafetyStatusValues.SUSPICIOUS,
          reason: pre.reason,
          title: data.title || 'Proceed with Caution',
          description: data.description || 'Local heuristics flagged this URL.',
        };
      }
    }

    const finalResult = {
      status,
      reason:      data.reason      || pre.reason || 'No reason provided.',
      title:       data.title       || 'Unknown Page',
      description: data.description || 'No description available.',
    };
    resultCache.set(url, finalResult);
    return finalResult;

  } catch (error) {
    const msg     = error instanceof Error ? error.message : '';
    const isQuota = msg.includes('429') || msg.includes('quota') || msg.includes('Quota');
    console.error('❌ Gemini Analysis Error:', isQuota ? 'QUOTA_EXCEEDED' : msg);

    const errorResult = {
      status: pre.status ?? SafetyStatusValues.SUSPICIOUS,
      reason: pre.reason || (isQuota
        ? 'AI analysis unavailable (API quota reached). Result based on local heuristics + ML model.'
        : 'Analysis failed. Please proceed with caution.'),
      title: isQuota ? 'AI Unavailable' : 'Error in analysis',
      description: isQuota
        ? 'Gemini quota exhausted. On-device ML model was used instead. Quota resets daily.'
        : "We couldn't verify this link safely via AI.",
    };
    resultCache.set(url, errorResult);
    return errorResult;
  }
};