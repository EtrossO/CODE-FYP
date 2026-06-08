/**
 * Batch heuristic test — run from Node.js:
 *   node scripts/batchTest.mjs
 *
 * Tests preCheck + pathHeuristics (no ML, no browser needed).
 * For full pipeline (including ML), paste the browser snippet below into F12 console.
 */

// ── Test cases ─────────────────────────────────────────────────────────────────
const TEST_CASES = [
  // [URL, expected_label, description]
  ['https://docs.google.com/forms/u/0/create?usp=chrome_actions',    'SAFE',        'Google Forms — trusted domain, clean path'],
  ['https://www.uptm.edu.my/index.php/students/student-portal',       'SAFE',        'UPTM student portal — trusted domain'],
  ['https://www.google.com/search?q=phishing',                        'SAFE',        'Google search — trusted domain'],
  ['https://mail.google.com/mail/u/0/',                                'SAFE',        'Gmail — trusted subdomain'],
  ['https://github.com/opencode-ai/opencode',                          'SAFE',        'GitHub — trusted domain'],
  ['https://microsoft.com/en-us/software-download/windows11',         'SAFE',        'Microsoft — trusted domain'],
  ['http://bit.ly/3xAmple',                                            'SUSPICIOUS',  'URL shortener — hides destination'],
  ['https://login.unknown-site.com/verify?email=test@test.com',       'SUSPICIOUS',  'Contains phishing keyword "verify"'],
  ['https://google.com.evil.com/login',                                 'UNSAFE',     'Brand spoof — google.com on evil.com'],
  ['https://paypal.com.security-alerts.com/update-account',            'UNSAFE',     'Brand spoof — paypal subdomain on fake domain'],
  ['https://192.168.1.1/admin/login',                                  'UNSAFE',     'Raw IP address — hiding domain'],
  ['https://www.secure-update.com/confirm/account/verify',             'SUSPICIOUS',  'Multiple phishing keywords'],
  ['https://tinyurl.com/y8md9sx',                                      'SUSPICIOUS', 'Shortened URL'],
  ['https://example.com/reset-password/verify-account',                'SUSPICIOUS', 'Phishing keywords in path'],
  ['https://example.com/aHR0cHM6Ly9leGFtcGxlLmNvbS9sb2dpbg==',        'SUSPICIOUS', 'Base64-like path segment'],
  ['https://forms.gle/abc123xyz',                                      'SAFE',        'Google Forms shortener — trusted'],
  ['https://lms.uptm.edu.my/login',                                    'SAFE',        'UPTM LMS — trusted subdomain with /login (clean path check)'],
  ['https://google.com',                                                'SAFE',        'Google root — trusted domain'],
  ['https://www.google.com.malicious-site.com/login',                  'UNSAFE',     'Brand spoof — google.com subdomain on malicious domain'],
  ['https://xn--mgba3a4f16a.com/',                                     'SUSPICIOUS',  'Punycode homograph — xn-- prefix detected'],
  // New test cases for improved detection
  ['https://example.com/login?url=https://evil.com/phish',             'SUSPICIOUS',  'Open redirect parameter to external URL'],
  ['http://example.com/reset-password',                                'SUSPICIOUS',  'Non-HTTPS + phishing keyword "reset"'],
  ['https://gooogle.com/login',                                        'SUSPICIOUS',  'Typosquatting — gooogle vs google (1 char diff)'],
  ['https://example.com/redirect?next=http://phish.com',               'SUSPICIOUS',  'Open redirect with "next" param'],
  ['https://secure.example.com/login?return=https://evil.com',         'SUSPICIOUS',  'Open redirect via "return" param'],
];

import { normalizeUrl, extractFeatures, pathHeuristics } from '../src/services/features.ts';

// ── Helper functions (mirroring geminiService.ts) ────────────────────────────────

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

function levenshteinDistance(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
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

function detectOpenRedirect(u) {
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

function detectTyposquatting(hostname) {
  const domain = hostname.replace(/^www\./, '').split('.')[0];
  for (const brand of BRAND_DOMAINS_FOR_TYPOSQUAT) {
    const dist = levenshteinDistance(domain, brand);
    if (dist === 1 || (dist === 2 && domain.length === brand.length)) {
      return brand;
    }
  }
  return null;
}

const PHISHING_KEYWORDS = ['login','signin','verify','secure','update','confirm',
  'account','password','credential','banking','paypal','refund','reward','prize',
  'winner','free','urgent','suspended','restrict','unlock','authenticate',
  'token','reset','recovery','authorize','auth','session','2fa','mfa',
  'verification','identity','validate','billing','invoice','payment'];

// ── Simulated preCheck (mirrors updated geminiService.ts logic) ──────────────────

function simulatePreCheck(url, features, heuristic) {
  let u;
  try { u = new URL(normalizeUrl(url)); } catch { return { status: 0 }; }
  const hostname = u.hostname.toLowerCase();
  const path = u.pathname + u.search;

  // Strong signals → immediate return
  if (features.brandSpoof) return { status: -1 };
  if (features.isIp) return { status: -1 };

  // Collect risk signals
  const risks = [];

  if (!u.protocol.startsWith('https')) {
    risks.push('non-https');
  }

  if (features.suspiciousTld) {
    risks.push('suspicious-tld');
  }

  if (features.isShortener) {
    risks.push('url-shortener');
  }

  const kwHits = PHISHING_KEYWORDS.filter(kw =>
    path.toLowerCase().includes(kw) || hostname.includes(kw)
  );
  if (kwHits.length >= 2) {
    risks.push('keywords: ' + kwHits.join(', '));
  }

  if (path.length > 400) {
    risks.push('long-url');
  }

  // IDN/Punycode
  if (hostname.startsWith('xn--')) {
    risks.push('punycode-domain');
  }

  // Open redirect
  const redirect = detectOpenRedirect(u);
  if (redirect) {
    risks.push('open-redirect: ' + redirect.param + ' → ' + redirect.target);
  }

  // Typosquatting
  const typosquat = detectTyposquatting(hostname);
  if (typosquat) {
    risks.push('typosquatting: ' + typosquat);
  }

  // Path heuristics
  if (heuristic.isMalicious) return { status: -1 };

  // If any risks or path is suspicious → SUSPICIOUS
  if (risks.length > 0 || heuristic.isSuspicious) {
    return { status: 0, reason: risks[0] || heuristic.reasons[0] };
  }

  // Trusted domain with clean path → SAFE
  if (features.isTrusted) {
    return { status: 1 };
  }

  return null; // no decision — falls through
}

console.log('\n=== BATCH HEURISTIC TEST ===\n');
let pass = 0, fail = 0;
for (const [url, expected, desc] of TEST_CASES) {
  const features = extractFeatures(url);
  const u = new URL(normalizeUrl(url));
  const heuristic = pathHeuristics(u);

  const preCheck = simulatePreCheck(url, features, heuristic);
  let actual;
  if (preCheck !== null) {
    if (preCheck.status === 1) actual = 'SAFE';
    else if (preCheck.status === -1) actual = 'UNSAFE';
    else actual = 'SUSPICIOUS';
  } else if (heuristic.isMalicious) {
    actual = 'UNSAFE';
  } else if (heuristic.isSuspicious) {
    actual = 'SUSPICIOUS';
  } else {
    actual = 'SAFE / INCONCLUSIVE';
  }
  const ok = actual === expected;
  if (ok) pass++; else fail++;
  const icon = ok ? '✅' : '❌';
  console.log(`${icon} ${actual.padEnd(20)} ${expected.padEnd(15)} ${desc}`);
  if (!ok) {
    console.log(`   URL: ${url}`);
    console.log(`   spoof=${features.brandSpoof} isIp=${features.isIp} trusted=${features.isTrusted} shortener=${features.isShortener}`);
    console.log(`   heuristic: total=${heuristic.total.toFixed(2)} isMalicious=${heuristic.isMalicious} isSuspicious=${heuristic.isSuspicious}`);
    if (heuristic.reasons.length) console.log(`   reasons: ${heuristic.reasons.join('; ')}`);
  }
}

console.log(`\n=== Results: ${pass}/${pass+fail} passed ===\n`);


// ═══════════════════════════════════════════════════════════════════════════════
// BROWSER CONSOLE SNIPPET — paste into F12 console on the running site
// ═══════════════════════════════════════════════════════════════════════════════
/*
// Paste this block into DevTools console while the app is running:

(async () => {
  const urls = [
    ['https://docs.google.com/forms/u/0/create?usp=chrome_actions',  'SAFE'],
    ['https://www.uptm.edu.my/index.php/students/student-portal',     'SAFE'],
    ['https://mail.google.com/mail/u/0/',                              'SAFE'],
    ['https://www.google.com/search?q=hello',                          'SAFE'],
    ['http://bit.ly/3xAmple',                                          'SUSPICIOUS'],
    ['https://google.com.evil.com/login',                               'UNSAFE'],
    ['https://192.168.1.1/admin/login',                                'UNSAFE'],
    ['https://tinyurl.com/y8md9sx',                                     'SUSPICIOUS'],
    ['https://example.com/aHR0cHM6Ly9leGFtcGxlLmNvbS9sb2dpbg==',      'SUSPICIOUS'],
    ['https://forms.gle/abc123xyz',                                    'SAFE'],
    ['https://google.com',                                              'SAFE'],
  ];
  const mod = await import('./src/services/geminiService.ts');
  let pass = 0, fail = 0;
  console.log('\\n=== FULL PIPELINE BATCH TEST ===\\n');
  for (const [url, expected] of urls) {
    const r = await mod.analyzeLinkSafety(url);
    const status = r.status === 1 ? 'SAFE' : r.status === 0 ? 'SUSPICIOUS' : r.status === -1 ? 'UNSAFE' : '???';
    const ok = status === expected;
    if (ok) pass++; else fail++;
    console.log(`${ok ? '✅' : '❌'} ${status.padEnd(12)} ${expected.padEnd(10)} ${url}`);
  }
  console.log(`\\n=== Results: ${pass}/${pass+fail} passed ===\\n`);
})();
*/
