# Deploying (Render backend + Vercel frontend)

This guide deploys the FastAPI backend on **Render** and the React frontend on
**Vercel**, both on free tiers.

## What works and what doesn't on this setup

- **Works:** recon, analysis, patch generation, reports, scoring, roadmap,
  chat, auth, audit log, the full UI.
- **Skipped:** PoC validation and patch verification. Render has no Docker
  daemon, so the sandbox can't run — the pipeline reports these as skipped.
- **Ephemeral data (free tier):** Render's free disk is wiped on restart/redeploy
  and the service sleeps when idle. Findings, artifacts, and the audit log do not
  persist. `SESSION_SECRET` is set as an env var so logins still survive restarts.
  For durable storage, upgrade to a Render instance with a persistent disk mounted
  at `data/`.

---

## 1. Backend on Render

You can use the included `render.yaml` Blueprint, or configure a Web Service by hand.

### Option A — Blueprint (recommended)

1. Push this repo to GitHub.
2. In Render: **New → Blueprint**, pick the repo. It reads `render.yaml`.
3. Set the secret env vars when prompted (see the table below).

### Option B — Manual Web Service

- **Runtime:** Python 3
- **Build command:** `pip install -r requirements-web.txt`
- **Start command:** `uvicorn src.web.app:app --host 0.0.0.0 --port $PORT --workers 1`
  (one worker — run state is in memory)

### Backend environment variables

| Key | Value |
|-----|-------|
| `LOGIN_PASSWORD` | your operator password (e.g. `baymax`) |
| `SESSION_SECRET` | a long random string (Blueprint generates one) |
| `COOKIE_SECURE` | `1` |
| `COOKIE_SAMESITE` | `none` |
| `ALLOWED_ORIGINS` | your Vercel URL, e.g. `https://your-app.vercel.app` |
| `GEMINI_API_KEY` | a Gemini API key (free tier) |
| `PYTHON_VERSION` | `3.12.6` |

Note your backend URL, e.g. `https://bughunter-api.onrender.com`.

> `ALLOWED_ORIGINS` must exactly match the Vercel origin (scheme + host, no
> trailing slash). You can set it after the Vercel deploy and redeploy Render.

---

## 2. Frontend on Vercel

1. In Vercel: **Add New → Project**, import the same repo.
2. Set **Root Directory** to `frontend`. Vercel detects Vite and reads
   `frontend/vercel.json` (SPA rewrites are already configured).
3. Add these environment variables:

| Key | Value |
|-----|-------|
| `VITE_API_BASE` | your Render URL, e.g. `https://bughunter-api.onrender.com` |
| `VITE_BASE` | `/` |
| `VITE_ROUTER_BASE` | `/` |

4. Deploy. Note the Vercel URL and put it into the backend's `ALLOWED_ORIGINS`,
   then redeploy the Render service.

---

## 3. Verify

1. Open the Vercel URL — you should see the login screen.
2. Sign in with `LOGIN_PASSWORD`.
3. Start a run against an allowlisted target. Live logs stream in; PoC/patch
   steps report "Docker not available" (expected on Render).

### If login "succeeds" but you're bounced back to the sign-in screen

That means the session cookie isn't sticking cross-site. Check:

- Backend `COOKIE_SAMESITE=none` and `COOKIE_SECURE=1`.
- Backend `ALLOWED_ORIGINS` exactly equals the Vercel origin.
- Frontend `VITE_API_BASE` points at the Render URL (HTTPS).
- Both sites are HTTPS (Render and Vercel both are by default).

---

## Free-tier caveats to expect

- **Cold starts:** the Render free service sleeps after ~15 min idle; the first
  request wakes it (slow), and any run in progress at sleep time is lost.
- **No persistence:** see the note at the top — data resets on restart.
- **Single instance only:** never scale Render to more than one instance/worker;
  run state lives in memory.
- **Cross-site cookies** can be blocked by strict browser privacy settings.

For a version where the sandbox runs and data persists, host on a small VM with
Docker instead (ask and I can provide that setup).
