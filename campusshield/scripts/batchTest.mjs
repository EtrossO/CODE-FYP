/**
 * Batch heuristic test — run from Node.js:
 *   node scripts/batchTest.mjs
 *
 * Tests the REAL preCheck + pathHeuristics from src/services/heuristics.ts
 * (no ML, no browser, no API keys needed).
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
  ['data:text/html,<script>alert(1)</script>',                         'UNSAFE',     'Dangerous data: URI scheme'],
  ['javascript:alert(document.cookie)',                                'UNSAFE',     'Dangerous javascript: scheme'],
  ['https://paypal-security-check.com/update/account',                 'SUSPICIOUS',  'Brand substring in hostname (paypal)'],
  ['https://login.verify.paypal-account.com',                          'SUSPICIOUS',  'Brand substring + phishing keywords'],
  ['https://login.verify.paypal-account.ml/account/verify',            'UNSAFE',     'Brand substring + keywords + suspicious TLD'],
  ['https://example.com/login?token=aHR0cHM6Ly9ldmlsLmNvbS9waXNo',     'SUSPICIOUS',  'Base64 token in query string'],
  ['https://example.com/%252e%252e//etc/passwd',                       'SUSPICIOUS',  'Double-encoded path characters'],
  ['https://www.google.com.mx',                                        'SAFE / INCONCLUSIVE', 'Brand as whole label + country TLD — falls to ML'],
  ['https://mail.office.com/owa/',                                     'SAFE',        'Office 365 — trusted subdomain'],
  ['https://example.com:8081/admin',                                   'SUSPICIOUS',  'Unusual port'],
];

import { normalizeUrl, preCheck, pathHeuristics } from '../src/services/heuristics.ts';
import { extractFeatures } from '../src/services/features.ts';
import { SafetyStatusValues } from '../src/types.ts';

console.log('\n=== BATCH HEURISTIC TEST (real heuristics.ts code) ===\n');
let pass = 0, fail = 0;
for (const [url, expected, desc] of TEST_CASES) {
  let u;
  try { u = new URL(normalizeUrl(url)); } catch { /* parse failure handled below */ }

  const heuristic = u ? pathHeuristics(u) : null;
  const preCheckResult = preCheck(url);

  let actual;
  if (preCheckResult.status === SafetyStatusValues.SAFE) actual = 'SAFE';
  else if (preCheckResult.status === SafetyStatusValues.UNSAFE) actual = 'UNSAFE';
  else if (preCheckResult.status === SafetyStatusValues.SUSPICIOUS) actual = 'SUSPICIOUS';
  else if (heuristic?.isMalicious) actual = 'UNSAFE';
  else if (heuristic?.isSuspicious) actual = 'SUSPICIOUS';
  else actual = 'SAFE / INCONCLUSIVE';

  const ok = actual === expected;
  if (ok) pass++; else fail++;
  const icon = ok ? '✅' : '❌';
  console.log(`${icon} ${actual.padEnd(20)} ${expected.padEnd(15)} ${desc}`);
  if (!ok) {
    const features = u ? extractFeatures(url) : null;
    console.log(`   URL: ${url}`);
    console.log(`   preCheck: status=${preCheckResult.status} reason=${preCheckResult.reason}`);
    if (heuristic) console.log(`   heuristic: total=${heuristic.total.toFixed(2)} reasons=${heuristic.reasons.join('; ') || 'none'}`);
    if (features) console.log(`   spoof=${features.brandSpoof} isIp=${features.isIp} trusted=${features.isTrusted} shortener=${features.isShortener} brandSub=${features.brandSubstring} punycode=${features.punycode} scheme=${features.suspiciousScheme}`);
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
    ['data:text/html,<script>alert(1)</script>',                        'UNSAFE'],
  ];
  const mod = await import('./src/services/geminiService.ts');
  const { SafetyStatusValues } = await import('./src/types.ts');
  let pass = 0, fail = 0;
  console.log('\\n=== FULL PIPELINE BATCH TEST ===\\n');
  for (const [url, expected] of urls) {
    const r = await mod.analyzeLinkSafety(url);
    const status = r.status;
    const ok = status === expected;
    if (ok) pass++; else fail++;
    console.log(`${ok ? '✅' : '❌'} ${status.padEnd(12)} ${expected.padEnd(10)} ${url}`);
  }
  console.log(`\\n=== Results: ${pass}/${pass+fail} passed ===\\n`);
})();
*/
