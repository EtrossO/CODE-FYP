# Campus Shield — Final Year Project

**Student:** Mohamad Syaher Izham Bin Isshamwil (AM2412017976)
**Course:** Information Technology (Cyber Security)
**Institution:** Universiti Poly-Tech Malaysia (UPTM)

---

An AI-powered URL & QR Code phishing scanner with a 4-layer defence pipeline.

## Repository Structure

```
├── campusshield/          # Main application (React + TypeScript + Vite)
│   ├── src/               # Source code
│   ├── docs/              # Architecture & design documentation
│   ├── scripts/           # ML training & testing scripts
│   ├── public/            # Static assets & ML model
│   └── README.md          # App setup & deployment guide
├── docs/                  # Additional documentation
│   └── QR_SCANNER_SETUP_GUIDE.md
├── testing/               # Testing evidence & scripts
│   ├── campusshield_testing_table.docx
│   └── create_testing_table.py
├── archive/               # Legacy/old prototype files
│   ├── index.html
│   └── prepare_dataset.js
└── .gitignore
```

## Quick Start

```bash
cd campusshield
npm install
cp .env.example .env
# Add your API keys to .env
npm run dev
```

See [`campusshield/README.md`](campusshield/README.md) for full setup and deployment instructions.
