# Campus Shield

An AI-powered URL / QR-code phishing scanner (React + TypeScript + Vite).

## Deploying to Cloudflare Pages

This project is a static single-page app and is configured to deploy on
**Cloudflare Pages**. The following files make it work:

- `public/_redirects` – SPA catch-all so deep links / refreshes return `index.html`.
- `public/_headers` – basic security + cache headers.
- `.node-version` – pins the Cloudflare build image to Node 22.
- `wrangler.toml` – Wrangler/Pages project settings (`pages_build_output_dir = "dist"`).

### Option A — Connect your Git repo (recommended)

1. Go to the [Cloudflare dashboard](https://dash.cloudflare.com/) → **Workers & Pages → Create → Pages → Connect to Git**.
2. Select the `EtrossO/CODE-FYP` repository.
3. Set the build settings:
   - **Framework preset:** `Vite`
   - **Build command:** `npm run build`
   - **Build output directory:** `dist`
4. Under **Settings → Environment variables**, add your keys (these are still
   bundled into the client because the app calls the APIs from the browser):
   - `VITE_API_KEY` = your Google Gemini API key
   - `VITE_SAFE_BROWSING_API_KEY` = your Google Safe Browsing API key
5. Click **Save and Deploy**. Every push to `main` then auto-deploys.

> Note: Because this app calls Gemini / Safe Browsing directly from the browser,
> the API keys are visible in the shipped bundle. To hide them you would need a
> Cloudflare Worker / Pages Function proxy (not included in this deployment-only setup).

### Option B — Deploy manually with Wrangler CLI

```bash
npm install            # installs deps incl. wrangler
npm run pages:deploy   # builds then runs: wrangler pages deploy dist
```

The first run will prompt you to log in to Cloudflare and create the
`campus-shield` Pages project.

### Local preview of the production build

```bash
npm run build
npm run pages:dev      # serves dist/ via wrangler with Pages behaviour
```

---

## React + TypeScript + Vite (template notes)

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Babel](https://babeljs.io/) (or [oxc](https://oxc.rs) when used in [rolldown-vite](https://vite.dev/guide/rolldown)) for Fast Refresh
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/) for Fast Refresh

## React Compiler

The React Compiler is not enabled on this template because of its impact on dev & build performances. To add it, see [this documentation](https://react.dev/learn/react-compiler/installation).

## Expanding the ESLint configuration

If you are developing a production application, we recommend updating the configuration to enable type-aware lint rules:

```js
export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      // Other configs...

      // Remove tseslint.configs.recommended and replace with this
      tseslint.configs.recommendedTypeChecked,
      // Alternatively, use this for stricter rules
      tseslint.configs.strictTypeChecked,
      // Optionally, add this for stylistic rules
      tseslint.configs.stylisticTypeChecked,

      // Other configs...
    ],
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.node.json', './tsconfig.app.json'],
        tsconfigRootDir: import.meta.dirname,
      },
      // other options...
    },
  },
])
```

You can also install [eslint-plugin-react-x](https://github.com/Rel1cx/eslint-react/tree/main/packages/plugins/eslint-plugin-react-x) and [eslint-plugin-react-dom](https://github.com/Rel1cx/eslint-react/tree/main/packages/plugins/eslint-plugin-react-dom) for React-specific lint rules:

```js
// eslint.config.js
import reactX from 'eslint-plugin-react-x'
import reactDom from 'eslint-plugin-react-dom'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      // Other configs...
      // Enable lint rules for React
      reactX.configs['recommended-typescript'],
      // Enable lint rules for React DOM
      reactDom.configs.recommended,
    ],
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.node.json', './tsconfig.app.json'],
        tsconfigRootDir: import.meta.dirname,
      },
      // other options...
    },
  },
])
```
