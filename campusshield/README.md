# Campus Shield

**An AI-Powered URL & QR Code Phishing Scanner**

> **Final Year Project** — Mohamad Syaher Izham Bin Isshamwil (AM2412017976)
> Information Technology (Cyber Security), Universiti Poly-Tech Malaysia (UPTM)

---

## Overview

Campus Shield is a fully client-side single-page application that analyses URLs and QR codes for phishing, malware, and other security threats using a **4-layer defence pipeline**. Users can scan URLs manually, scan QR codes via their device camera, or upload QR code images — all within the browser with no server-side backend.

---

## Features

- **URL Scanning** — Enter any URL for a comprehensive 4-stage safety analysis
- **QR Code Scanner** — Scan QR codes in real time using your device camera
- **QR Code Upload** — Upload QR code images for decoding and analysis
- **Scan History** — View and search past scan results (stored locally in IndexedDB)
- **Threat Heatmap** — Visualise aggregated domain statistics across all scans
- **4-Layer Detection Pipeline** — Rule-based heuristics, on-device ML, Google Safe Browsing, and Gemini AI

---

## Architecture: 4-Layer Detection Pipeline

| Stage | Layer | Technology | Description |
|-------|-------|------------|-------------|
| 1 | **Heuristics** | Rule-based ruleset | IP check, brand spoofing, typosquatting, IDN homograph attacks, URL shorteners, phishing keywords, open redirect detection |
| 2 | **On-Device ML** | TensorFlow.js | Neural network classifier (128->64->32->3 layers) using 33 URL features — runs entirely in-browser |
| 3 | **Safe Browsing** | Google Safe Browsing API v4 | Checks URL against Google's known threat database |
| 4 | **Gemini AI** | Gemini 2.0 Flash (LLM) | Semantic URL analysis using Google's large language model |

Each stage can short-circuit on strong signals for performance. Stages are cumulative — if a URL passes earlier stages, later stages provide deeper analysis.

---

## Tech Stack

| Category | Technology |
|----------|-----------|
| Frontend | React 19, TypeScript 5.9, Tailwind CSS 3.4 |
| Build | Vite 7.2 |
| Client Database | Dexie.js 4.4 (IndexedDB) |
| Machine Learning | TensorFlow.js 4.22 |
| AI | Google Generative AI (Gemini 2.0 Flash) |
| Security API | Google Safe Browsing v4 |
| QR Decoding | jsQR 1.4 |
| Deployment | Cloudflare Pages / Vercel |

---

## Project Structure

```
campusshield/
├── src/
│   ├── main.tsx                  # React entry point
│   ├── App.tsx                   # Root component with routing
│   ├── types.ts                  # TypeScript type definitions
│   ├── components/
│   │   ├── ScannerTab.tsx        # URL input + QR camera/upload scanner
│   │   ├── HistoryTab.tsx        # Scan history with search/filter
│   │   ├── ResultModal.tsx       # Detailed scan result modal
│   │   ├── Sidebar.tsx           # UPTM student portal sidebar
│   │   └── ThreatHeatmap.tsx     # Domain statistics heatmap
│   ├── services/
│   │   ├── geminiService.ts      # Main analysis pipeline (4 stages)
│   │   ├── heuristics.ts         # Shared rule engine (preCheck, path heuristics, static sets)
│   │   ├── mlService.ts          # TensorFlow.js model inference
│   │   ├── safeBrowsingService.ts# Google Safe Browsing API client
│   │   ├── features.ts           # 33-feature URL extraction
│   │   └── statsService.ts       # Domain statistics aggregation
│   └── db/
│       └── database.ts           # Dexie IndexedDB setup
├── docs/                         # Architecture & testing documentation
├── public/tfjs_model/            # Trained ML model + metrics.json
├── scripts/                      # ML training & testing scripts
├── datasets/                     # Training datasets (CSV)
└── architecture.svg              # System architecture diagram
```

---

## Getting Started

### Prerequisites

- **Node.js 22.x** (see `.nvmrc`)
- A **Google Gemini API key** (get one at https://aistudio.google.com/apikey)
- A **Google Safe Browsing API key** (enable the Safe Browsing API in Google Cloud Console)

### Local Development

```bash
# 1. Install dependencies
npm install

# 2. Create environment file
cp .env.example .env

# 3. Add your API keys to .env
#    VITE_API_KEY=your_gemini_key
#    VITE_SAFE_BROWSING_API_KEY=your_safe_browsing_key

# 4. Start the dev server
npm run dev
```

The app will be available at `http://localhost:5173`.

### Build for Production

```bash
npm run build
npm run preview   # preview the production build locally
```

---

## Deployment

### Cloudflare Pages (Recommended)

1. Push this repository to GitHub
2. Go to **Cloudflare Dashboard -> Workers & Pages -> Create -> Pages -> Connect to Git**
3. Select your repository
4. Build settings:
   - **Framework preset:** `Vite`
   - **Build command:** `npm run build`
   - **Build output directory:** `dist`
5. Add environment variables:
   - `VITE_API_KEY` — your Gemini API key
   - `VITE_SAFE_BROWSING_API_KEY` — your Safe Browsing API key
6. Deploy

### Manual Deployment

```bash
npm run pages:deploy   # builds and deploys via Wrangler
```

---

## API Key Security Note

> Because this app calls the Gemini and Safe Browsing APIs directly from the browser (no backend proxy), the API keys are bundled into the client-side JavaScript and are technically visible to end users. This is an accepted architectural trade-off for a fully client-side SPA. For production use behind a login, consider adding a Cloudflare Worker proxy.

---

## Documentation

- [`docs/conversation-architecture.md`](docs/conversation-architecture.md) — Architecture overview, data flow, tech stack, and design rationale
- [`docs/conversation-2026-06-16.md`](docs/conversation-2026-06-16.md) — Testing methodology, security analysis, and database schema
- [`CAMPUSHIELD_DFD.md`](CAMPUSHIELD_DFD.md) — Data Flow Diagrams (Level 0, 1, 2)
- [`architecture.svg`](architecture.svg) — System architecture diagram (visual)

---

## ML Model Training

The on-device ML model can be retrained using the provided scripts:

```bash
npm run train-model            # trains TF.js model on dataset_balanced_9k.csv
node scripts/trainModel.js --data ./dataset.csv --epochs 60
node scripts/trainModel.js --data ./malicious_phish.csv --maxSamples 30000
```

Training:
- Extracts the **same 33 features** the app uses at inference (imported from `src/services/features.ts` — no drift)
- Applies class weighting, early stopping, a holdout test split, and reports a **confusion matrix + per-class precision/recall/F1**
- Saves the model to `public/tfjs_model/` along with a `metrics.json` evaluation report

Heuristic rule tests (no ML, no API keys):

```bash
node scripts/batchTest.mjs     # runs the real preCheck + pathHeuristics from src/services/heuristics.ts
```

See `scripts/trainModel.js` for details.

---

## License

This project is developed for academic purposes as part of the Final Year Project at Universiti Poly-Tech Malaysia (UPTM).
