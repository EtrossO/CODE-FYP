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
  ['https://lms.uptm.edu.my/login',                                    'SAFE',        'UPTM LMS — trusted subdomain with /login (might be SUSPICIOUS)'],
  ['https://google.com',                                                'SAFE',        'Google root — trusted domain'],
  ['https://www.google.com.malicious-site.com/login',                  'UNSAFE',     'Brand spoof — google.com subdomain on malicious domain'],
  ['https://xn--mgba3a4f16a.com/',                                     'SUSPICIOUS',  'IDN homograph attack domain'],
];

import { normalizeUrl, extractFeatures, pathHeuristics } from '../src/services/features.ts';

// ── Simulated preCheck (mirrors geminiService.ts logic) ──────────────────────────
const PHISHING_KEYWORDS = ['login','signin','verify','secure','update','confirm',
  'account','password','credential','banking','paypal','refund','reward','prize',
  'winner','free','urgent','suspended','restrict','unlock','authenticate',
  'token','reset','recovery','authorize','auth','session','2fa','mfa',
  'verification','identity','validate','billing','invoice','payment'];

function simulatePreCheck(url, features, heuristic) {
  // Whitelisted domain + clean path → SAFE
  if (features.isTrusted && !heuristic.isSuspicious) return { status: 1 };

  // Brand spoof → UNSAFE
  if (features.brandSpoof) return { status: -1 };

  // Raw IP → UNSAFE
  if (features.isIp) return { status: -1 };

  // Suspicious TLD → SUSPICIOUS
  if (features.suspiciousTld) return { status: 0 };

  // URL shortener → SUSPICIOUS
  if (features.isShortener) return { status: 0 };

  // 2+ phishing keywords in path → SUSPICIOUS
  const hostname = new URL(normalizeUrl(url)).hostname.toLowerCase();
  const path = new URL(normalizeUrl(url)).pathname + new URL(normalizeUrl(url)).search;
  const kwHits = PHISHING_KEYWORDS.filter(kw =>
    path.toLowerCase().includes(kw) || hostname.includes(kw)
  );
  if (kwHits.length >= 2) return { status: 0, reason: `Keywords: ${kwHits.join(', ')}` };

  // Punycode/IDN domain → SUSPICIOUS
  if (hostname.startsWith('xn--')) return { status: 0 };

  return null; // no decision — falls through to heuristic
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
