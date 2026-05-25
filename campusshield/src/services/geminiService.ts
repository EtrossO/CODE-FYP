import { GoogleGenerativeAI } from "@google/generative-ai";
import { SafetyStatusValues, type SafetyStatus } from "../types";
import { checkUrlSafeBrowsing } from "./safeBrowsingService";

const apiKey = import.meta.env.VITE_API_KEY;
if (!apiKey) {
  console.warn("VITE_API_KEY environment variable is not set.");
}

const masked = apiKey ? apiKey.slice(0, 6) + '...' + apiKey.slice(-4) : 'none';
console.log('🔑 Gemini API key loaded:', masked);

const ai = new GoogleGenerativeAI(apiKey || "");

const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'date',
  'men', 'loan', 'download', 'win', 'bid', 'trade', 'webcam',
  'review', 'science', 'party', 'racing', 'click', 'link',
]);

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
  'buff.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 'lc.ch', 'bl.ink',
  'cutt.ly', 'rebrandly', 'short.link', 's.id',
]);

const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'secure', 'update', 'confirm',
  'account', 'password', 'credential', 'banking', 'paypal',
  'refund', 'reward', 'prize', 'winner', 'free', 'urgent',
  'suspended', 'restrict', 'unlock', 'authenticate',
];

const TRUSTED_DOMAINS = new Set([
  'youtube.com', 'www.youtube.com', 'm.youtube.com',
  'google.com', 'www.google.com', 'mail.google.com', 'drive.google.com',
  'docs.google.com', 'maps.google.com', 'photos.google.com',
  'facebook.com', 'www.facebook.com', 'm.facebook.com',
  'twitter.com', 'www.twitter.com', 'x.com', 'www.x.com',
  'instagram.com', 'www.instagram.com',
  'linkedin.com', 'www.linkedin.com',
  'whatsapp.com', 'www.whatsapp.com',
  'amazon.com', 'www.amazon.com',
  'apple.com', 'www.apple.com',
  'microsoft.com', 'www.microsoft.com',
  'github.com', 'www.github.com',
  'stackoverflow.com', 'www.stackoverflow.com',
  'wikipedia.org', 'www.wikipedia.org', 'en.wikipedia.org',
  'netflix.com', 'www.netflix.com',
  'spotify.com', 'www.spotify.com',
  'telegram.org', 'www.telegram.org',
  'discord.com', 'www.discord.com',
  'reddit.com', 'www.reddit.com',
  'zoom.us', 'www.zoom.us',
  'canva.com', 'www.canva.com',
  'figma.com', 'www.figma.com',
  'npmjs.com', 'www.npmjs.com',
  'react.dev', 'www.react.dev',
  'uptm.edu.my', 'www.uptm.edu.my',
  'kptm.edu.my', 'www.kptm.edu.my',
  'lms.uptm.edu.my',
  'mycms.kptm.edu.my',
  'epay.kptm.edu.my',
  'edupage.org', 'uptm.edupage.org',
]);

const resultCache = new Map<string, { status: SafetyStatus; reason: string; title: string; description: string }>();

function countDots(s: string): number {
  return (s.match(/\./g) || []).length;
}

interface PreCheckResult {
  status: SafetyStatus | null;
  reason: string;
}

function preCheck(url: string): PreCheckResult {
  let u: URL;
  try {
    u = new URL(url.startsWith('//') ? `https:${url}` : url);
  } catch {
    return { status: SafetyStatusValues.SUSPICIOUS, reason: 'Invalid URL format.' };
  }

  const hostname = u.hostname.toLowerCase();
  const path = u.pathname + u.search;

  if (TRUSTED_DOMAINS.has(hostname)) {
    return { status: SafetyStatusValues.SAFE, reason: '' };
  }

  if (!u.protocol.startsWith('https')) {
    return { status: SafetyStatusValues.SUSPICIOUS, reason: 'Connection is not encrypted (non-HTTPS). Sensitive data could be intercepted.' };
  }

  const isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
  if (isIp) {
    return { status: SafetyStatusValues.UNSAFE, reason: 'URL uses a raw IP address instead of a domain name — a common hiding technique for phishing sites.' };
  }

  const atIndex = url.indexOf('@');
  if (atIndex > 0 && !url.startsWith('mailto:')) {
    const beforeAt = url.slice(0, atIndex);
    if (beforeAt.includes('://') || /[a-zA-Z]/.test(beforeAt)) {
      return { status: SafetyStatusValues.UNSAFE, reason: 'URL contains an "@" symbol to hide the real destination domain from the user.' };
    }
  }

  const dotCount = countDots(hostname);
  if (dotCount >= 4) {
    return { status: SafetyStatusValues.SUSPICIOUS, reason: `Unusually many subdomains (${dotCount} dots) — may be attempting to appear as a trusted site.` };
  }

  const parts = hostname.split('.');
  const registeredDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;

  if (SUSPICIOUS_TLDS.has(parts[parts.length - 1])) {
    return { status: SafetyStatusValues.SUSPICIOUS, reason: `Suspicious top-level domain ".${parts[parts.length - 1]}" — commonly used for malicious sites.` };
  }

  if (URL_SHORTENERS.has(registeredDomain)) {
    return { status: SafetyStatusValues.SUSPICIOUS, reason: 'Shortened URL hides the real destination. Proceed with caution.' };
  }

  const keywordMatches = SUSPICIOUS_KEYWORDS.filter(kw =>
    path.toLowerCase().includes(kw) || hostname.includes(kw)
  );
  if (keywordMatches.length >= 2) {
    return { status: SafetyStatusValues.SUSPICIOUS, reason: `Contains phishing-related keywords: ${keywordMatches.join(', ')}.` };
  }

  if (path.length > 200) {
    return { status: SafetyStatusValues.SUSPICIOUS, reason: 'Unusually long URL — may be hiding malicious parameters.' };
  }

  if (/[а-яА-Я]/.test(hostname)) {
    return { status: SafetyStatusValues.UNSAFE, reason: 'Domain contains Cyrillic characters that may visually impersonate a trusted Latin-character domain (homograph attack).' };
  }

  if (/%[0-9a-fA-F]{2}/.test(hostname)) {
    return { status: SafetyStatusValues.SUSPICIOUS, reason: 'Domain name contains encoded characters used to disguise the real website address.' };
  }

  const brandDomains = ['paypal.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'linkedin.com', 'whatsapp.com', 'amazon.com', 'apple.com', 'microsoft.com',
    'google.com', 'gmail.com', 'netflix.com', 'bank', 'secure'];
  const hasSpoof = brandDomains.some(d => {
    if (d === 'bank') return hostname.includes('bank') && !hostname.endsWith('.bank');
    return hostname !== d && hostname.endsWith('.' + d);
  });
  if (hasSpoof) {
    return { status: SafetyStatusValues.UNSAFE, reason: 'Domain appears to be impersonating a well-known brand using a subdomain trick.' };
  }

  return { status: null, reason: '' };
}

export const analyzeLinkSafety = async (url: string): Promise<{
  status: SafetyStatus;
  reason: string;
  title: string;
  description: string;
}> => {
  const cached = resultCache.get(url);
  if (cached) {
    console.log('📦 Using cached result for:', url);
    return cached;
  }

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
    const response = await geminiResult.response;
    const raw = response.text();

    const cleaned = raw
      .replace(/```json\s*/gi, "")
      .replace(/```\s*/g, "")
      .trim();

    const data = JSON.parse(cleaned);

    const validStatuses = [
      SafetyStatusValues.SAFE,
      SafetyStatusValues.SUSPICIOUS,
      SafetyStatusValues.UNSAFE,
    ] as string[];
    const status = validStatuses.includes(data.status)
      ? (data.status as SafetyStatus)
      : SafetyStatusValues.SUSPICIOUS;

    if (pre.status === SafetyStatusValues.SUSPICIOUS && status === SafetyStatusValues.SAFE) {
      const overrideResult = {
        status: SafetyStatusValues.SUSPICIOUS,
        reason: pre.reason,
        title: data.title || 'Proceed with Caution',
        description: data.description || 'Local heuristics flagged this URL. AI analysis was inconclusive.',
      };
      resultCache.set(url, overrideResult);
      return overrideResult;
    }

    const finalResult = {
      status,
      reason: data.reason || pre.reason || 'No reason provided.',
      title: data.title || 'Unknown Page',
      description: data.description || 'No description available.',
    };
    resultCache.set(url, finalResult);
    return finalResult;
  } catch (error) {
    const msg = error instanceof Error ? error.message : '';
    const isQuota = msg.includes('429') || msg.includes('quota') || msg.includes('Quota');
    console.error("❌ Gemini Analysis Error:", isQuota ? 'QUOTA_EXCEEDED' : msg);

    const errorResult = {
      status: pre.status ?? SafetyStatusValues.SUSPICIOUS,
      reason: pre.reason || (isQuota
        ? 'AI analysis is currently unavailable due to API quota limits. Try again later.'
        : 'Analysis failed. Please proceed with caution.'),
      title: isQuota ? 'AI Unavailable' : 'Error in analysis',
      description: isQuota
        ? 'The Gemini API daily free quota has been reached. Results are based on local heuristics only. The quota resets daily.'
        : 'We couldn\'t verify this link safely via AI.',
    };
    resultCache.set(url, errorResult);
    return errorResult;
  }
};
