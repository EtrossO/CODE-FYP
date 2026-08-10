import { GoogleGenerativeAI } from "@google/generative-ai";
import { SafetyStatusValues, type SafetyStatus } from "../types";
import { checkUrlSafeBrowsing } from "./safeBrowsingService";
import { classifyUrl } from "./mlService";
import { preCheck } from "./heuristics";

const apiKey = import.meta.env.VITE_API_KEY;
if (!apiKey) {
  console.warn("VITE_API_KEY environment variable is not set.");
}

const masked = apiKey ? apiKey.slice(0, 6) + '...' + apiKey.slice(-4) : 'none';
console.log('🔑 Gemini API key loaded:', masked);

const ai = new GoogleGenerativeAI(apiKey || "");

const resultCache = new Map<string, {
  status: SafetyStatus; reason: string; title: string; description: string;
}>();

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
