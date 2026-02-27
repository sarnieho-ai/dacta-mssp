# DACTA MSSP Platform

Managed Security Operations Center platform for multi-tenant SOC services.

## Architecture

```
dacta-mssp/
├── apps/
│   ├── api/          # Hono backend (port 3001)
│   └── web/          # Vite + React frontend (port 5173)
├── packages/
│   └── shared/       # Types & constants shared across apps
├── turbo.json        # Turborepo build orchestration
└── pnpm-workspace.yaml
```

## Prerequisites

- Node.js >= 22
- pnpm >= 9 (`npm install -g pnpm`)
- Supabase project (free tier works)

## Setup (Step by Step)

### 1. Install dependencies

```bash
pnpm install
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your Supabase credentials
```

Also create `apps/web/.env`:
```bash
VITE_SUPABASE_URL=https://xxxxx.supabase.co
VITE_SUPABASE_ANON_KEY=eyJhbGciOi...
VITE_API_URL=http://localhost:3001
```

### 3. Run the database schema

In Supabase SQL Editor, run the contents of `dacta-platform-schema.sql`.

### 4. Seed test data

```bash
cd apps/api
pnpm db:seed
```

### 5. Create your admin user

In Supabase Dashboard > Authentication > Users > Add User:
- Email: `admin@dacta.sg`
- Password: your choice

Then in SQL Editor:
```sql
INSERT INTO users (auth_id, email, name, role)
VALUES (
  'paste-auth-uuid-here',
  'admin@dacta.sg',
  'Admin',
  'platform_admin'
);
```

### 6. Start development

```bash
# From root - starts both API and Web
pnpm dev
```

Or individually:
```bash
# Terminal 1: API
cd apps/api && pnpm dev

# Terminal 2: Web
cd apps/web && pnpm dev
```

### 7. Open the app

Navigate to http://localhost:5173 and log in with your admin credentials.

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /auth/login | No | Email/password login |
| POST | /auth/refresh | No | Refresh JWT |
| GET | /auth/me | Yes | Current user profile |
| GET | /tickets | Yes | List tickets (filterable) |
| GET | /tickets/:id | Yes | Ticket details |
| PATCH | /tickets/:id | SOC | Update ticket |
| GET | /tickets/:id/timeline | Yes | Ticket timeline |
| GET | /tickets/:id/comments | Yes | Ticket comments |
| POST | /tickets/:id/comments | SOC | Add comment |
| GET | /organizations | Yes | List organizations |
| GET | /organizations/:id | Yes | Org details + stats |
| GET | /assets | Yes | List assets |
| GET | /assets/:id | Yes | Asset details |
| GET | /users | SOC | List users |
| GET | /users/analysts | SOC | Analyst workload data |
| GET | /dashboard/kpis | SOC | Dashboard aggregates |
| GET | /health | No | Health check |

## Roles

| Role | Access |
|------|--------|
| platform_admin | Full access |
| soc_manager | Full SOC access |
| soc_analyst_l1 | Triage + investigate |
| soc_analyst_l2 | Triage + investigate |
| soc_engineer | Triage + detection engineering |
| threat_hunter | Triage + hunting |
| management | Read-only dashboards |
| client_viewer | Own org data only |
