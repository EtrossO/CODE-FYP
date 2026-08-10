# Campus Shield — Conversation Saved on 2026-08-10

> Session: ML model & heuristics overhaul + deployment prep.
> Committed as `6db9640` ("Improve ML model (33 features) and heuristics engine") and pushed to GitHub (`main`).

---

## 1. Critical Bug Found

### 1.1 Quoted CSV URLs corrupted ML training features

The training datasets (`dataset_5k.csv`, `dataset_balanced_9k.csv`, `dataset.csv`) store every URL wrapped in
double quotes, e.g. `"br-icloud.com.br",unsafe`. The old `loadCSV()` in `scripts/trainModel.js` split on the last
comma **without stripping the quotes**, so every URL was parsed as `"br-icloud.com.br"` (quotes included).

Because `new URL()` does **not** throw on quote characters, the hostname became `"br-icloud.com.br"` — so
`isTrusted`, `brandSpoof`, TLD and path features were all computed against a corrupted hostname. In effect the
old model was trained on garbage features.

**Fix:** added `unquote()` to the CSV loader (strips a wrapping `"..."` pair from URL and label fields).

### 1.2 Heuristic test suite tested stale logic

`scripts/batchTest.mjs` had its own hand-written copy of `preCheck` (`simulatePreCheck`) that no longer matched the
real `preCheck` in `geminiService.ts` — so tests could pass while real behaviour was different.

**Fix:** the rule engine was extracted into a shared module and the test now imports the real code (see §2).

---

## 2. New Shared Module: `src/services/heuristics.ts`

Pure module (no browser/framework dependencies). Single source of truth used by the app, the training script and the
test suite, eliminating drift.

**Exports:**
- Static sets: `SUSPICIOUS_TLDS`, `SHORTENERS`, `PHISHING_PATH_KW`, `SUSPICIOUS_EXTENSIONS`, `COMMON_TLDS`,
  `OPEN_REDIRECT_PARAMS`, `BRAND_DOMAINS_FOR_TYPOSQUAT`, `BRAND_KEYWORDS`, `TRUSTED_DOMAINS`
- Helpers: `normalizeUrl`, `shannonEntropy`, `isGibberish`, `looksLikeBase64`, `hasRepeatedRun`,
  `levenshteinDistance`, `detectIDNHomograph`, `detectTyposquatting`, `detectBrandSubstring`,
  `detectOpenRedirect`, `detectSuspiciousScheme`, `isBrandImpersonation`
- Logic: `pathHeuristics(u): HeuristicScore`, `preCheck(url): PreCheckResult`

Import graph (no cycles):
```
heuristics.ts  ← features.ts ← mlService.ts
             ← geminiService.ts
             ← scripts/batchTest.mjs
             ← scripts/trainModel.js (via features.ts)
```

Note: `heuristics.ts` and `features.ts` use explicit `.ts` extensions on relative imports so Node.js 24 can run
them directly with type stripping (`tsconfig.app.json` already has `allowImportingTsExtensions`).

---

## 3. Heuristics Improvements

### 3.1 `@` symbol — false positive fixed
Only flagged when `@` appears in the **authority** part (before the first `/`, `?` or `#`). Email addresses inside
query params (`?email=test@test.com`) no longer trigger UNSAFE.

### 3.2 Brand impersonation — label-aware (`isBrandImpersonation`)
Replaced the naive `hostname.includes('.google.com.')` string check (which wrongly matched legitimate country
domains like `www.google.com.mx`) with a label-sequence matcher that allows:
- subdomains of the brand (`login.paypal.com`)
- brand + country/regional TLD (`www.google.com.mx`, `google.co.uk`)

and flags anything else (e.g. `google.com.evil.com`).

### 3.3 Typosquatting — registered domain only
`detectTyposquatting` now compares only the registrable label (e.g. `google` from `google.com`), so trusted
subdomains like `mail.google.com` are no longer misclassified as a misspelling of `gmail`.

### 3.4 Brand substring (`detectBrandSubstring`)
Flags fused brands in untrusted hostnames (`paypal-security-check.com`) while skipping whole-label country domains.

### 3.5 Weighted risk scoring
Replaced the crude "2+ risk signals → UNSAFE" rule with weighted signals summed to a total:
- `total >= 0.70` → UNSAFE (multiple independent malicious indicators)
- `total >= 0.15` → SUSPICIOUS

New signals added: dangerous schemes (`data:`, `javascript:`, ... → immediate UNSAFE), unusual ports, base64/
double-encoded payloads in the query string (`%252e%252e` WAF-evasion pattern), encoded payload in query.

### 3.6 Trusted-domain ordering
Trusted domains are now checked for SAFE **after** strong-signal checks but **before** weak keyword signals, so
`lms.uptm.edu.my/login` and `docs.google.com/forms/...` are SAFE while strong signals still override.

### 3.7 Keyword list cleanup
Removed `action` (too noisy — matched `chrome_actions`, `interaction`, etc.). Added `wallet`, `webscr`,
`sign-in`, `log-in`.

---

## 4. ML Model Upgrade: 29 → 33 Features

`src/services/features.ts` — `FEATURE_COUNT` is now **33** (17 domain + 16 path/query).

| # | New feature | Meaning |
|---|-------------|---------|
| 17 | `punycode` | hostname contains `xn--` (homograph hiding) |
| 31 | `queryEntropy` | Shannon entropy of the query string |
| 32 | `brandSubstring` | brand keyword embedded in untrusted hostname |
| 33 | `suspiciousScheme` | protocol is not http/https |

`FEATURE_NAMES` and the synthetic fallback in `mlService.ts` / `trainModel.js` were updated to match.

---

## 5. Training Script Rewrite (`scripts/trainModel.js`)

- **Imports feature extraction directly from `src/services/features.ts`** — the same code the app uses at
  inference, so training and inference can never drift.
- **CSV fixes:** strips quotes, handles both `url,label` and `url,type` (e.g. `malicious_phish.csv`) columns,
  skips control-character/corrupted rows.
- **Class weighting** (inverse frequency) — handles imbalanced sets like `dataset_50k.csv` (~73% SAFE).
- **Holdout evaluation:** deterministic seeded shuffle, 80/20 train/test split, confusion matrix, per-class
  precision/recall/F1, macro-F1 — written to `public/tfjs_model/metrics.json`.
- **Early stopping** on `val_acc` (patience 8). (TF.js core in this project only exposes
  `tf.callbacks.earlyStopping` — no `customCallback`/`reduceLROnPlateau`/`restoreBestWeights`.)

### Usage
```bash
npm run train-model                                  # dataset_balanced_9k.csv
node scripts/trainModel.js --data ./dataset.csv --epochs 60 --batchSize 64
node scripts/trainModel.js --data ./malicious_phish.csv --maxSamples 30000
```

### Retrained model results (dataset_balanced_9k.csv, 7200 train / 1800 test)
| Metric | Value |
|--------|-------|
| Test accuracy | ~89.7–89.8% |
| Macro F1 | ~89.8% |
| UNSAFE precision / recall / F1 | 84.3% / 92.2% / 88.1% |
| SUSPICIOUS precision / recall / F1 | 89.4% / 94.5% / 91.9% |
| SAFE precision / recall / F1 | 97.8% / 82.5% / 89.5% |

Known limitation: the dataset labels noisy/placeholder domains (e.g. `example.com` examples) as unsafe, so the ML
stage may flag `example.com/...` as UNSAFE even though the heuristic stage says SUSPICIOUS.

---

## 6. Verification

| Check | Command | Result |
|-------|---------|--------|
| Heuristic batch tests | `node scripts/batchTest.mjs` | **35/35 passed** |
| Lint | `npm run lint` | clean |
| Build (tsc + vite) | `npm run build` | passes (pre-existing chunk-size warning) |
| Model inference shape | load `model.json` via `tf.io.fromMemory`, predict on 33-vec | input `[null,33]` → 3-class softmax |

Sample inference:
- `https://www.google.com/search?q=phishing` → SAFE (99.3%)
- `https://google.com.evil.com/login` → UNSAFE (93.5%)
- `https://paypal-security-check.com/update/account` → UNSAFE (98.2%)

---

## 7. Deployment Status (Vercel)

- `vercel.json` already present: framework Vite, build `npm run build`, output `dist`.
- Retrained model lives in `public/tfjs_model/` → served at `/tfjs_model/model.json` automatically.
- Repo: `https://github.com/EtrossO/CODE-FYP.git`, branch `main` (pushed).
- `.env` is gitignored (secrets safe). API keys are set in Vercel, not committed.

### To deploy live
1. Vercel → New Project → import `EtrossO/CODE-FYP`
2. Framework **Vite** (auto-detected), build command and output dir already in `vercel.json`
3. Add env vars: `VITE_API_KEY` (Gemini), `VITE_SAFE_BROWSING_API_KEY` (Safe Browsing)
4. Deploy

The app works without keys too — heuristics + ML run fully client-side; Safe Browsing and Gemini stages show a
"configuration required" notice.

---

## 8. Key Files Changed (commit `6db9640`)

| File | Change |
|------|--------|
| `src/services/heuristics.ts` | **new** — shared rule engine (preCheck, pathHeuristics, sets/helpers) |
| `src/services/features.ts` | 33 features; imports from heuristics.ts; label-aware brand spoof |
| `src/services/mlService.ts` | 33-feature synthetic fallback + risk formula |
| `src/services/geminiService.ts` | uses shared `preCheck`; removed duplicated rule code |
| `scripts/trainModel.js` | rewrite: quote fix, class weights, holdout eval, metrics.json |
| `scripts/batchTest.mjs` | tests the real `preCheck`/`pathHeuristics`; 35 cases |
| `public/tfjs_model/*` | retrained model + `metrics.json` (new) |
| `README.md`, `docs/conversation-architecture.md` | feature count + structure updates |
