# Campus Shield — Data Flow Diagram

## Level 0: Context Diagram

```mermaid
flowchart LR
    User([End User])
    subgraph CS[Campus Shield System]
        CORE[Scan URLs & QR Codes]
    end
    GS([Google Safe Browsing API])
    GM([Google Gemini AI API])

    User -- "1. URL / QR image" --> CORE
    CORE -- "2. Scan result (SAFE/SUSPICIOUS/UNSAFE)" --> User
    CORE -- "3. Threat match check" --> GS
    GS -- "4. Threat matches / no match" --> CORE
    CORE -- "5. AI safety analysis" --> GM
    GM -- "6. Structured verdict" --> CORE
```

---

## Level 1: Main Processes & Data Stores

```mermaid
flowchart LR
    User([End User])
    subgraph Browser[Browser Environment]
        direction LR
        UI[("1.0<br/>User Interface<br/>(ScannerTab / HistoryTab)")]
        SCAN[("2.0<br/>Scan Pipeline<br/>(analyzeLinkSafety)")]
        DB[("D1<br/>IndexedDB<br/>Scan History")]
        CACHE[("D2<br/>In-Memory<br/>Result Cache")]
        ML[("D3<br/>TF.js Model<br/>/tfjs_model/")]
        THEME[("D4<br/>localStorage<br/>Theme")]
    end
    GS([Google Safe Browsing API])
    GM([Google Gemini AI API])

    User -- "URL / QR" --> UI
    UI -- "url string" --> SCAN
    SCAN -- "write result" --> DB
    SCAN -- "read/write cache" --> CACHE
    SCAN -- "load model" --> ML
    SCAN -- "API call" --> GS
    SCAN -- "API call" --> GM
    UI -- "read history" --> DB
    UI -- "read aggregate stats" --> DB
    UI -- "read/write theme" --> THEME
    SCAN -- "result" --> UI
```

---

## Level 2: Detailed Scan Pipeline (Process 2.0)

```mermaid
flowchart TD
    START(["URL String"]) --> PRE

    subgraph Stage1[Stage 1: Rule-Based Heuristics]
        PRE[("2.1<br/>preCheck()")] 
        PRE_RULES{Match rule?}
        PRE --> PRE_RULES
        PRE_RULES -- "Yes (UNSAFE/SAFE)" --> RET
        PRE_RULES -- "Inconclusive / SUSPICIOUS" --> ST2
    end

    subgraph Stage2[Stage 2: On-Device ML]
        FEAT[("2.2.1<br/>extractFeatures()")]
        TENSOR[("2.2.2<br/>featuresToTensor()")]
        INFER[("2.2.3<br/>model.predict()")]
        ML_OVERRIDE{Post-ML heuristic}
        MODEL[(D3: TF.js Model)]

        ST2 --> FEAT
        FEAT --> TENSOR
        TENSOR --> INFER
        INFER --> ML_OVERRIDE
        MODEL --> INFER
        ML_OVERRIDE -- "High confidence" --> RET
        ML_OVERRIDE -- "Low confidence" --> ST3
    end

    subgraph Stage3[Stage 3: Google Safe Browsing]
        SB[("2.3<br/>checkUrlSafeBrowsing()")]
        SB_RES{Threat matched?}
        GS([Google Safe Browsing API])

        ST3 --> SB
        SB --> GS
        GS --> SB
        SB --> SB_RES
        SB_RES -- "Yes (UNSAFE)" --> RET
        SB_RES -- "No match" --> ST4
    end

    subgraph Stage4[Stage 4: Gemini AI Analysis]
        GM_CALL[("2.4<br/>Gemini generateContent()")]
        PARSE[Parse JSON response]
        OVERRIDE{Override for SUSPICIOUS?}
        GM([Google Gemini AI API])

        ST4 --> GM_CALL
        GM_CALL --> GM
        GM --> GM_CALL
        GM_CALL --> PARSE
        PARSE --> OVERRIDE
    end

    subgraph Final[Result Assembly]
        RET[("2.5<br/>Return ScanResult")]
        CACHE_DB[("Write to Cache & IndexedDB")]
    end

    OVERRIDE -- "Yes" --> RET
    OVERRIDE -- "No" --> RET
    RET --> CACHE_DB
```

---

## Level 2: User Interface Data Flows (Process 1.0)

```mermaid
flowchart LR
    User([End User])
    subgraph UI[User Interface]
        SCANNER[ScannerTab<br/>1.1]
        HISTORY_UI[HistoryTab<br/>1.2]
        HEATMAP[ThreatHeatmap<br/>1.3]
        RESULT[ResultCard / Modal<br/>1.4]
        SIDEBAR[Sidebar<br/>1.5]
    end
    APP[App.tsx - State Manager]
    DB[(D1: IndexedDB)]
    CACHE[(D2: In-Memory Cache)]
    THEME[(D4: localStorage)]

    User -- "types URL" --> SCANNER
    User -- "scans QR" --> SCANNER
    User -- "uploads image" --> SCANNER
    User -- "views history" --> HISTORY_UI
    User -- "views heatmap" --> HEATMAP

    SCANNER -- "url" --> APP
    APP -- "result" --> SCANNER
    SCANNER -- "display" --> RESULT

    APP -- "save result" --> DB
    APP -- "cache result" --> CACHE
    APP -- "read history" --> DB
    HISTORY_UI -- "query" --> APP
    HEATMAP -- "read stats" --> DB
    APP -- "aggregated stats" --> HEATMAP

    APP -- "read/write theme" --> THEME
    SIDEBAR -- "external links" --> User

    HISTORY_UI -- "selected result" --> RESULT
```

---

## Data Store Definitions

| ID | Store | Technology | Description |
|----|-------|-----------|-------------|
| D1 | Scan History | IndexedDB (Dexie) | Persistent log of all URL scan results |
| D2 | Result Cache | Map<string, ScanResult> | In-memory session cache to avoid re-scanning the same URL |
| D3 | TF.js Model | Static files (`/tfjs_model/`) | Pre-trained neural network for URL classification |
| D4 | Theme | localStorage | User's dark/light mode preference |

## External Entity Definitions

| Entity | Description | Data Flow Direction |
|--------|-------------|---------------------|
| End User | Person submitting URLs or QR codes for scanning | Bidirectional |
| Google Safe Browsing | Google API for checking URLs against known threat databases | App → API (request), API → App (response) |
| Google Gemini AI | Google Gemini 2.0 Flash LLM for deep semantic URL analysis | App → API (request), API → App (response) |

## Data Flow Descriptions

| # | Flow | From | To | Data |
|---|------|------|----|------|
| 1 | URL / QR Image | User | ScannerTab | URL string or ImageData from QR decode |
| 2 | Scan Result | App | User | ScanResult {id, url, status, reason, title, description} |
| 3 | Threat Match Check | Scan Pipeline | Safe Browsing API | POST: {client, threatInfo {url, threatTypes}} |
| 4 | Match Response | Safe Browsing API | Scan Pipeline | JSON: {matches: [{threatType, threat, ...}]} |
| 5 | AI Safety Analysis | Scan Pipeline | Gemini API | POST: {contents: [{parts: [{text: prompt + url}]}]} |
| 6 | AI Verdict | Gemini API | Scan Pipeline | JSON: {status, reason, title, description} |
