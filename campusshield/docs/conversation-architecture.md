# Campus Shield — Architecture Conversation

## Date: 12 June 2026

---

## 1. Database (IndexedDB via Dexie.js)

**File:** `src/db/database.ts`
- Database name: `CampusShieldDB`
- Table: `scanHistory`
- Indexed columns: `id` (PK), `status`, `timestamp`

**Record structure** (`src/types.ts`):
```typescript
interface ScanResult {
    id: string;
    url: string;
    status: 'SAFE' | 'SUSPICIOUS' | 'UNSAFE' | 'LOADING';
    timestamp: number;
    reason?: string;
    title?: string;
    description?: string;
}
```

**Key operations:**
- Write: `db.scanHistory.add(result)` — after analysis completes
- Read all: `db.scanHistory.orderBy('timestamp').reverse().toArray()`
- Aggregate: `db.scanHistory.toArray()` then group by domain
- Clear: `db.scanHistory.clear()`

---

## 2. Data Flow (End-to-End)

1. **User enters URL** in ScannerTab (or scans QR code via jsQR)
2. **ScannerTab** calls `App.handleCheck(url)`
3. **App.tsx** calls `analyzeLinkSafety(url)` (4-stage pipeline)
4. **Pipeline** (geminiService.ts):
   - Stage 1: Heuristics (rule-based, 0 external calls) — IP check, brand spoof, typosquatting, IDN homograph, URL shorteners, phishing keywords, open redirects
   - Stage 2: TF.js ML Classifier — 29 URL features → Neural Network (128→64→32→3 layers) → SAFE/SUSPICIOUS/UNSAFE + confidence
   - Stage 3: Google Safe Browsing API — checks known threat databases
   - Stage 4: Gemini 2.0 Flash (LLM) — analyzes URL context, returns JSON
5. **Result saved** to IndexedDB via `db.scanHistory.add(result)`
6. **React state updated** — UI components re-render

---

## 3. System Architecture Diagram

See `architecture.svg` in the project root for the full visual diagram.

---

## 4. Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 19 + TypeScript 5.9 |
| Build | Vite 7.2 |
| Styling | Tailwind CSS 3.4 |
| Client DB | Dexie.js 4.4 (IndexedDB) |
| ML | TensorFlow.js 4.22 |
| AI API | Google Generative AI (Gemini 2.0 Flash) |
| Security API | Google Safe Browsing v4 |
| QR Scanner | jsQR 1.4 |
| Deployment | Cloudflare Pages (Wrangler 4) |

---

## 5. Key Points for Lecturer

- **Zero server-side code** — fully client-side SPA
- **IndexedDB** chosen because no backend is needed; data persists in browser
- **4-layer defense** — each stage catches what previous might miss; short-circuit logic for performance
- **On-device ML** — TF.js runs in browser, no data leaves user's device for ML
- **No authentication** — public tool, history is per-device
- **API keys** bundled in client (VITE_ prefix); README acknowledges this limitation
