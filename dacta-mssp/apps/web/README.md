# DACTA — Mission Control Center

Operational intelligence dashboard for DACTA, built with React + Vite + Supabase.

---

## Tech Stack

- **Frontend:** React 18, TypeScript, Vite 6, TailwindCSS v4
- **Routing:** React Router v6
- **Backend/DB:** Supabase (Postgres + Auth + Realtime)
- **API:** Railway-hosted backend (proxied via `/api`)
- **Deployment:** Vercel (frontend) + Railway (backend)

---

## Monorepo Structure

```
apps/
  web/               ← React frontend (this app)
    src/
    package.json
    vite.config.ts
    tsconfig.json
    index.html
packages/
  shared/            ← Shared types and utilities
package.json         ← Root workspace
pnpm-workspace.yaml
turbo.json
railway.toml
```

---

## Local Development

### 1. Clone the repository

```bash
git clone https://github.com/your-org/your-repo.git
cd your-repo
```

### 2. Copy environment variables

```bash
cp apps/web/.env.example apps/web/.env
```

### 3. Fill in Supabase credentials

Open `apps/web/.env` and set your values:

```env
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your-anon-key
VITE_API_URL=http://localhost:3001   # or your Railway backend URL
```

You can find these values in your [Supabase project settings](https://supabase.com/dashboard) under **Project Settings → API**.

### 4. Install dependencies and start dev server

```bash
pnpm install
pnpm dev
```

The app runs at **http://localhost:5173**.

> **Note:** If running only the web app without Turborepo, `cd apps/web` first and run `pnpm dev` from there.

### 5. Run SQL migrations in Supabase

In the [Supabase SQL Editor](https://supabase.com/dashboard), run the migration files found in `packages/shared/migrations/` (or the project's `supabase/migrations/` folder) in order.

---

## Deployment

### Deploy to Vercel

1. Push your code to GitHub.
2. Import the repository at [vercel.com/new](https://vercel.com/new).
3. Set the **Root Directory** to `apps/web`.
4. Add the following **Environment Variables** in Vercel project settings:
   - `VITE_SUPABASE_URL`
   - `VITE_SUPABASE_ANON_KEY`
   - `VITE_API_URL` (your Railway backend URL, e.g. `https://your-app.railway.app`)
5. Click **Deploy**. Vercel auto-detects Vite and uses the settings in `vercel.json`.

> All client-side routes are rewritten to `/index.html` for SPA navigation — this is already configured in `vercel.json`.

### Deploy Backend to Railway

The backend is configured via `railway.toml` in the repo root. Connect your Railway project to the same GitHub repo and Railway will detect the configuration automatically.

---

## Type Checking

```bash
pnpm type-check
```

---

## Build

```bash
pnpm build
```

Output goes to `dist/`. Preview the production build with:

```bash
pnpm preview
```

---

## Environment Variables Reference

| Variable | Required | Description |
|---|---|---|
| `VITE_SUPABASE_URL` | Yes | Supabase project URL |
| `VITE_SUPABASE_ANON_KEY` | Yes | Supabase anonymous (public) API key |
| `VITE_API_URL` | No | Railway backend base URL (defaults to `http://localhost:3001`) |

> All `VITE_` prefixed variables are exposed to the browser bundle. Never put secret keys here.
