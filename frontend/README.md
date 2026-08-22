# Bug-Bounty Pipeline — React frontend

Vite + React 18 + TypeScript + Tailwind v3 + React Router + lucide-react.

## Layout

```
frontend/
├── index.html
├── package.json
├── vite.config.ts        # Dev server proxies /api → FastAPI on :8000
├── src/
│   ├── main.tsx          # BrowserRouter mounted at /app
│   ├── App.tsx           # Route definitions
│   ├── index.css         # Tailwind v3 + design tokens (light/dark)
│   ├── lib/api.ts        # Typed JSON client
│   ├── hooks/
│   │   ├── useTheme.ts   # localStorage-persisted light/dark
│   │   └── usePoll.ts    # Stop-on-condition polling
│   ├── components/       # Navbar, Footer, Layout, StageChip
│   └── pages/            # Home, Features, Dashboard, RunDetail, Findings,
│                         # Audit, About, Contact, Artifact, NotFound
```

## Dev

```bash
# Terminal 1 — FastAPI (from project root)
LD_LIBRARY_PATH=/mnt/nixmodules/nix/store/6vzcxjxa2wlh3p9f5nhbk62bl3q313ri-gcc-14.3.0-lib/lib \
  venv/bin/python -m uvicorn src.web.app:app --host 0.0.0.0 --port 8000

# Terminal 2 — Vite dev server
cd frontend
npm install   # first time
npm run dev   # http://localhost:5173/app/
```

Vite proxies `/api/*` to `http://127.0.0.1:8000`. CORS is permissive for any
`http://localhost:*` and `http://127.0.0.1:*` origin.

## Production

```bash
cd frontend
npm run build           # outputs frontend/dist/
```

FastAPI serves the build at `/app/*`:
- `/app/assets/*` — JS/CSS chunks (mounted as StaticFiles)
- `/app`, `/app/`, `/app/<anything>` — fall back to `index.html` so React Router can resolve client-side routes.

So once built, the React app is reachable at `http://<host>:8000/app/`.

## API surface

The React app talks to these JSON endpoints (added in `src/web/app.py`):

| Method | Path | Purpose |
|---|---|---|
| GET  | `/api/health` | liveness |
| GET  | `/api/targets` | authorized allowlist |
| GET  | `/api/quota` | per-model usage today |
| GET  | `/api/runs?limit=20` | recent runs |
| POST | `/api/runs` | start a run (JSON body, attestation required) |
| GET  | `/api/runs/{id}` | live status + log + tokens + artifact list |
| POST | `/api/runs/{id}/gate` | approve/abort a pending HITL gate |
| GET  | `/api/runs/{id}/artifact/{name}` | artifact JSON / rendered MD |
| GET  | `/api/findings?target=…` | findings index |
| GET  | `/api/audit?limit=200` | hash-chained audit log |

## Theming

`html[data-theme="light|dark"]` switches a CSS-variable palette defined in
`index.css`. `useTheme` persists the choice to `localStorage` and a tiny
inline script in `index.html` applies it before paint to avoid a flash.

## Notes on Tailwind v3

Standard v3 setup: `@tailwind base/components/utilities` directives in
`index.css`, `tailwind.config.js` for the design tokens (named colors that
resolve to CSS variables, so theming stays runtime), and `postcss.config.js`
wiring `tailwindcss` + `autoprefixer`. Light/dark switch is via the
`darkMode: ["selector", '[data-theme="dark"]']` config — no `dark:` class
soup, just CSS variables that re-bind under `[data-theme="dark"]`.
