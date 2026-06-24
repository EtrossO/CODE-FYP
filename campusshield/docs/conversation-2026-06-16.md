# Campus Shield — Conversation Saved on 2026-06-16

---

## 1. Non-Functional Testing (Academic Explanations)

### 5.3.1 Performance Testing

Performance testing measures system responsiveness, throughput, and resource utilisation under varying workload conditions.

**For Campus Shield:** This involves testing QR code decoding speed (jsQR processing latency), API response times from Google Gemini and Safe Browsing services under concurrent requests, client-side TensorFlow.js model inference time for URL classification, and camera initialisation duration. Tools like Lighthouse or custom `performance.now()` instrumentation can benchmark frame rates during live camera scanning and measure end-to-end scan-to-result latency. Key metrics include throughput (scans per minute), response time (ms from scan to result), and resource consumption (CPU/memory during TensorFlow.js execution in the browser).

### 5.3.2 Security Testing

Security testing identifies vulnerabilities in the system's data handling, access controls, and resilience against malicious inputs.

**For Campus Shield:** Since the app processes URLs that could be malicious, security testing must verify that scanned URLs are never executed or rendered unsafely (e.g., no injection via result display), that camera permissions follow the W3C Media Capture specification securely, that API keys stored in environment variables (`VITE_API_KEY`, `VITE_SAFE_BROWSING_API_KEY`) are not hardcoded or logged, that IndexedDB scan history is not accessible cross-origin, and that the application sanitises all output to prevent XSS. Penetration testing should attempt malformed QR codes and specially crafted URLs to verify robust error handling.

### 5.3.3 Usability Testing

Usability testing evaluates the effectiveness, efficiency, and satisfaction with which users can accomplish tasks using the system.

**For Campus Shield:** This assesses whether users can intuitively navigate the camera scan, image upload, and manual URL input modes; whether the loading indicators ("Initializing camera...") provide adequate feedback; whether colour-coded safety results (safe/suspicious/malicious) are immediately comprehensible; and whether the history tab and threat heatmap are accessible. Think-aloud protocols and task-completion-rate metrics would be appropriate. The dark mode toggle and responsive mobile layout would also be evaluated for accessibility compliance (WCAG 2.1).

### 5.3.4 Reliability Testing

Reliability testing verifies that the system operates consistently and correctly over time, maintaining data integrity and availability.

**For Campus Shield:** This tests whether the camera stream recovers gracefully from temporary disconnection, whether the IndexedDB (Dexie) persists scan history across page refreshes without data loss, whether API failures (rate limiting, network timeout) degrade gracefully with meaningful error messages rather than application crashes, and whether the TensorFlow.js model loads correctly on repeated page visits. Long-duration testing would involve repeated scanning cycles to check for memory leaks in canvas and WebRTC stream allocations.

### 5.4 Functional Testing

Functional testing validates that the system behaves according to specified requirements — that each feature produces the correct output for a given input.

**For Campus Shield:**

| Test Case | Input | Expected Result |
|-----------|-------|-----------------|
| QR Camera Scan | Valid QR code containing `https://google.com` | Camera activates → QR decoded → URL sent to Gemini/Safe Browsing → "Safe" result displayed |
| QR Image Upload | Image file containing QR code | jsQR decodes QR → same analysis pipeline → result shown |
| Manual URL Input | `https://example.com` | URL bypasses QR path → directly analysed → classification returned |
| Malicious URL Detection | Known phishing URL | Safe Browsing API or ML model flags as "Malicious" with red indicator |
| Suspicious URL | URL with obfuscated domain | Gemini analysis returns "Suspicious" with amber warning |
| Invalid QR Image | Random non-QR image | Graceful "No QR code found" message |
| Empty URL Input | Empty string | Validation rejects with prompt to enter a URL |
| History Recording | After any scan | Scan result stored in Dexie IndexedDB with timestamp, URL, and status |
| Threat Heatmap | Multiple historical scans | Heatmap renders correctly, reflecting geographic or frequency data |
| Camera Permission Denied | User blocks camera | "Camera permission denied" error message with guidance |
| Network Offline | Scan without internet | Clear error indicating connectivity failure, not a crash |

---

## 2. Security Code Snippets (with Academic Explanations)

### 2.1 Multi-Layered URL Analysis Pipeline (Defence in Depth)

**File:** `src/services/geminiService.ts:310–465`

```typescript
// Stage 1: Heuristics
const pre = preCheck(url);
if (pre.status === SafetyStatusValues.UNSAFE) {
  return { status: pre.status, reason: pre.reason, ... };
}

// Stage 2: TensorFlow.js ML classifier
const ml = await classifyUrl(url);
if (ml.isHighConfidence && ml.label === 'UNSAFE') {
  return { status: SafetyStatusValues.UNSAFE, ... };
}

// Stage 3: Google Safe Browsing
const sbResult = await checkUrlSafeBrowsing(url);
if (sbResult?.matched) {
  return { status: SafetyStatusValues.UNSAFE, ... };
}

// Stage 4: Gemini AI
const model = ai.getGenerativeModel({ model: 'gemini-2.0-flash' });
const geminiResult = await model.generateContent(prompt);
```

**Explanation:** This layered architecture implements the principle of *defence in depth* (Anderson, 2008), where multiple independent detection mechanisms compensate for each other's weaknesses. The rule-based layer provides deterministic, explainable decisions for known attack patterns. The ML classifier generalises to unseen threats through learned feature representations. Safe Browsing offers crowd-sourced threat intelligence from Google's indexed database of known malicious URLs. The Gemini LLM provides semantic understanding of the URL's context and intent. This redundancy ensures that failure or evasion of any single layer does not compromise the overall security posture.

---

### 2.2 IDN Homograph Attack Detection

**File:** `src/services/geminiService.ts:128–140`

```typescript
function detectIDNHomograph(hostname: string): boolean {
  const scripts: string[] = [];
  for (const ch of hostname) {
    const code = ch.codePointAt(0)!;
    if (code >= 0x0400 && code <= 0x04FF) scripts.push('cyrillic');
    if ((code >= 0x0370 && code <= 0x03FF) ||
        (code >= 0x1F00 && code <= 0x1FFF)) scripts.push('greek');
    if (code >= 0x3040 && code <= 0x309F) scripts.push('hiragana');
    if (code >= 0x4E00 && code <= 0x9FFF) scripts.push('han');
  }
  const unique = new Set(scripts);
  return unique.size >= 2;
}
```

**Explanation:** IDN homograph attacks exploit the visual similarity of Unicode code points across different writing systems (Gabrilovich & Gontmakher, 2002). The algorithm iterates through each character in the hostname, classifying it into Unicode script ranges (Cyrillic, Greek, Hiragana, Han). A domain containing characters from two or more distinct scripts is flagged as a potential homograph. This detection is critical because modern browsers render Punycode-encoded internationalised domains identically to their Latin equivalents, making visual inspection by users unreliable.

---

### 2.3 Typosquatting Detection via Levenshtein Distance

**File:** `src/services/geminiService.ts:100–151`

```typescript
function levenshteinDistance(a: string, b: string): number {
  const dp: number[][] = Array.from(
    { length: m + 1 }, () => new Array(n + 1).fill(0)
  );
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
  return dp[m][n];
}

function detectTyposquatting(hostname: string): string | null {
  const domain = hostname.replace(/^www\./, '').split('.')[0];
  for (const brand of BRAND_DOMAINS_FOR_TYPOSQUAT) {
    const dist = levenshteinDistance(domain, brand);
    if (dist === 1 || (dist === 2 && domain.length === brand.length))
      return brand;
  }
  return null;
}
```

**Explanation:** Typosquatting, a form of URL hijacking identified by Moore and Edelman (2010), registers domain names that are common misspellings of popular brands. The Levenshtein edit distance algorithm (Levenshtein, 1966) quantifies string dissimilarity as the minimum number of single-character insertions, deletions, or substitutions required to transform one string into another. A distance of 1 (e.g., "googel" → "google") or distance 2 with equal length (e.g., "go0gle" → substitution of '0' for 'o') produces a strong typosquatting signal, as these are the most common typographical error patterns.

---

### 2.4 Open Redirect Detection

**File:** `src/services/geminiService.ts:115–126`

```typescript
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
```

**Explanation:** Open redirects are parameters such as `?url=`, `?redirect=`, or `?next=` that cause the server to issue an HTTP redirect to a user-supplied URL (Li et al., 2015). Attackers exploit legitimate websites with open redirect vulnerabilities to construct convincing phishing URLs (e.g., `legitimate-bank.com/login?redirect=https://evil.com`). The detection checks for 22 known open redirect parameter names and verifies that the decoded value is an absolute HTTP(S) URL, indicating an external redirect.

---

### 2.5 Shannon Entropy-Based Gibberish Detection

**File:** `src/services/features.ts:18–55`

```typescript
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
  return Math.min(h / 4, 1);
}

function isGibberish(segment: string): boolean {
  if (segment.length < 4) return false;
  const entropy = shannonEntropy(segment);
  if (entropy < 0.6) return false;
  const vowels = (segment.match(/[aeiou]/gi) || []).length;
  const letters = (segment.match(/[a-zA-Z]/g) || []).length;
  if (segment.length < 12) {
    if (vowels > 0) return false;
    return entropy > 0.7 && letters >= 4;
  }
  if (letters > 0 && (letters - vowels) / letters > 0.8) return true;
  if (segment.length >= 6 && vowels === 0 && letters >= 4) return true;
  return false;
}
```

**Explanation:** Shannon entropy (Shannon, 1948) measures the information density of a string. Natural language text typically has entropy ≤ 4 bits per character, while randomly generated strings approach the maximum. Phishing kits frequently use randomised path segments to evade signature-based detection. The algorithm combines entropy with vowel-consonant ratio analysis: segments with high entropy (>0.6), low vowel density (<20% vowels), and no readable characters are classified as gibberish. This two-factor approach reduces false positives from legitimate but lengthy alphanumeric identifiers.

---

### 2.6 Content Security — Safe Link Rendering

**File:** `src/components/ScannerTab.tsx:147–160`

```tsx
{result.status !== SafetyStatusValues.UNSAFE && (
  <a
    href={result.url}
    target="_blank"
    rel="noopener noreferrer"
    className="text-xs font-medium text-blue-600 ..."
  >
    Visit site
  </a>
)}
```

**Explanation:** The conditional rendering ensures that the "Visit site" hyperlink is only displayed when the URL is classified as SAFE or SUSPICIOUS, and is entirely suppressed for UNSAFE results. The `rel="noopener noreferrer"` attribute follows the OWASP (2021) secure coding guideline that prevents the opened page from accessing `window.opener` and from sending HTTP `Referer` headers, mitigating tab-napping attacks (Raskin et al., 2016) and information leakage.

---

### 2.7 Secure Camera Access — WebRTC Permission Enforcement

**File:** `src/components/ScannerTab.tsx:289–298`

```typescript
if (!window.isSecureContext) {
  setCameraError({ type: 'insecure' });
  return;
}
if (!navigator.mediaDevices?.getUserMedia) {
  setCameraError({ type: 'unavailable' });
  return;
}
```

**Explanation:** The W3C Media Capture and Streams specification (W3C, 2023) mandates that `getUserMedia()` is only available in secure contexts (HTTPS or localhost) to prevent man-in-the-middle attacks from intercepting camera streams. The `isSecureContext` check enforces this requirement before any camera initialisation. Additionally, feature detection for `getUserMedia` availability handles environments where the API may be absent (e.g., non-browser runtimes or restricted iframes). Each failure mode is mapped to a distinct user-facing error with actionable remediation steps, implementing a fail-secure rather than fail-obscure philosophy.

---

### 2.8 API Key Management — Credential Exposure Mitigation

**File:** `src/services/geminiService.ts:7–13` and `src/services/safeBrowsingService.ts:1–5`

```typescript
const apiKey = import.meta.env.VITE_API_KEY;
if (!apiKey) {
  console.warn("VITE_API_KEY environment variable is not set.");
}
const masked = apiKey
  ? apiKey.slice(0, 6) + '...' + apiKey.slice(-4)
  : 'none';
```

**Explanation:** Client-side API keys are inherently exposed to end users (OWASP, 2021). The system mitigates this by (a) loading keys exclusively through Vite environment variables (`import.meta.env`), which prevents accidental hardcoding in version control; (b) logging only the first six and last four characters of the key to facilitate debugging without full credential disclosure; and (c) providing a graceful degradation path when keys are absent, allowing the application to function with reduced capabilities (rule-based heuristics and ML inference) rather than failing entirely.

---

## 3. Database Schema and ERD

### Schema Code

**File:** `src/db/database.ts:1–15`

```typescript
import Dexie, { type Table } from 'dexie';
import type { ScanResult } from '../types';

export class CampusShieldDB extends Dexie {
  scanHistory!: Table<ScanResult, string>;

  constructor() {
    super('CampusShieldDB');
    this.version(1).stores({
      scanHistory: 'id, status, timestamp',
    });
  }
}

export const db = new CampusShieldDB();
```

**File:** `src/types.ts:10–19`

```typescript
export interface ScanResult {
    id: string;
    url: string;
    status: SafetyStatus;
    timestamp: number;
    reason?: string;
    title?: string;
    description?: string;
    imageUrl?: string;
}
```

### Entity-Relationship Diagram

```
┌───────────────────────────────────────┐
│           ScanHistory                 │
│───────────────────────────────────────│
│ PK  id            : string (UUID)     │
│     url           : string            │
│     status        : SafetyStatus      │
│     timestamp     : number (Unix ms)  │
│     reason        : string (optional) │
│     title         : string (optional) │
│     description   : string (optional) │
│     imageUrl      : string (optional) │
└───────────────────────────────────────┘
         │
         │ (derived / computed view)
         ▼
┌───────────────────────────────────────┐
│         DomainStats                   │
│───────────────────────────────────────│
│     domain       : string             │
│     total        : number             │
│     safe         : number             │
│     suspicious   : number             │
│     unsafe       : number             │
└───────────────────────────────────────┘
```

### Indexes

Schema string: `scanHistory: 'id, status, timestamp'`

- `id` — Primary key (unique, string)
- `status` — Non-unique index for filtering by safety classification
- `timestamp` — Non-unique index for chronological sorting

### CRUD Operations

**Create** — `App.tsx:58`:
```typescript
await db.scanHistory.add(result);
```

**Read (all, reverse chronological)** — `App.tsx:27`:
```typescript
db.scanHistory.orderBy('timestamp').reverse().toArray().then(setHistory);
```

**Read (filtered by domain)** — `ThreatHeatmap.tsx:24`:
```typescript
const all = await db.scanHistory.toArray();
setDomainResults(
  all.filter((r) => extractDomain(r.url) === domain)
    .sort((a, b) => b.timestamp - a.timestamp)
);
```

**Delete (clear all)** — `App.tsx:79`:
```typescript
await db.scanHistory.clear();
```

### Computed View: Domain Statistics

**File:** `src/services/statsService.ts:20–38`

```typescript
export async function getDomainStats(): Promise<DomainStats[]> {
  const all = await db.scanHistory.toArray();
  const map = new Map<string, DomainStats>();
  for (const item of all) {
    const domain = extractDomain(item.url);
    let entry = map.get(domain);
    if (!entry) {
      entry = { domain, total: 0, safe: 0, suspicious: 0, unsafe: 0 };
      map.set(domain, entry);
    }
    entry.total++;
    if (item.status === SafetyStatusValues.SAFE) entry.safe++;
    else if (item.status === SafetyStatusValues.SUSPICIOUS) entry.suspicious++;
    else if (item.status === SafetyStatusValues.UNSAFE) entry.unsafe++;
  }
  return Array.from(map.values()).sort((a, b) => b.total - a.total);
}
```

---

## Summary

| Aspect | Detail |
|---|---|
| DBMS | IndexedDB (client-side, NoSQL document store) |
| Wrapper | Dexie.js v4 |
| Database name | `CampusShieldDB` |
| Version | 1 |
| Tables | 1 (`scanHistory`) |
| Primary key | `id` (string, Date.now-based) |
| Indexes | `id`, `status`, `timestamp` |
| Relationships | None (single-entity, no foreign keys) |
| Derived views | `DomainStats` (in-memory aggregation) |
