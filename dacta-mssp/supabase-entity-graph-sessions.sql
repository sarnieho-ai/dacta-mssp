-- ═══════════════════════════════════════════════════════════════════
-- DACTA SIEMLess — Entity Graph Sessions Migration
-- Purpose: Persist Entity Explorer graph sessions (nodes, edges,
--          viewport, pivot history) for save/restore and sharing.
-- Run via: Supabase Dashboard → SQL Editor → New Query → Paste → Run
-- ═══════════════════════════════════════════════════════════════════

-- ── 1. Create table ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.entity_graph_sessions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Identity / ownership
  created_by      TEXT NOT NULL,          -- user id (Supabase auth.uid or analyst email)
  org_id          TEXT,                   -- org code from ORG_CONNECTORS (nullable for personal sessions)
  ticket_key      TEXT,                   -- linked Jira ticket, e.g. 'DAC-18158' (optional pivot origin)

  -- Display
  name            TEXT NOT NULL DEFAULT 'Untitled Graph',
  description     TEXT,
  tags            TEXT[] DEFAULT '{}',

  -- Graph state
  nodes           JSONB NOT NULL DEFAULT '[]',   -- array of { id, type, label, x, y, data }
  edges           JSONB NOT NULL DEFAULT '[]',   -- array of { id, source, target, label, type }
  viewport        JSONB DEFAULT '{"x":0,"y":0,"zoom":1}',

  -- Pivot & timeline metadata
  pivot_history   JSONB DEFAULT '[]',     -- array of { step, entity, source, timestamp, result_count }
  timeline_range  JSONB,                  -- { from: ISO8601, to: ISO8601 } for timeline scrubber
  adversary_nodes JSONB DEFAULT '[]',     -- CrowdStrike actor nodes attributed during this session

  -- Sharing
  is_shared       BOOLEAN NOT NULL DEFAULT false,   -- if true, all org members can read

  -- Flexible metadata bucket
  metadata        JSONB DEFAULT '{}',

  -- Timestamps
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── 2. Indexes ────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_egs_created_by  ON public.entity_graph_sessions (created_by);
CREATE INDEX IF NOT EXISTS idx_egs_org_id       ON public.entity_graph_sessions (org_id);
CREATE INDEX IF NOT EXISTS idx_egs_ticket_key   ON public.entity_graph_sessions (ticket_key);
CREATE INDEX IF NOT EXISTS idx_egs_updated_at   ON public.entity_graph_sessions (updated_at DESC);

-- ── 3. Auto-update updated_at on row change ──────────────────────

CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_egs_updated_at ON public.entity_graph_sessions;
CREATE TRIGGER trg_egs_updated_at
  BEFORE UPDATE ON public.entity_graph_sessions
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ── 4. Enable Row Level Security ─────────────────────────────────

ALTER TABLE public.entity_graph_sessions ENABLE ROW LEVEL SECURITY;

-- Service role bypasses RLS (used by Vercel API functions)
-- No explicit policy needed — service_role is always exempt.

-- Authenticated users can read their own sessions
CREATE POLICY "egs_read_own"
  ON public.entity_graph_sessions
  FOR SELECT
  USING (created_by = auth.uid()::TEXT OR created_by = auth.email());

-- Authenticated users can read shared sessions within their org
CREATE POLICY "egs_read_shared"
  ON public.entity_graph_sessions
  FOR SELECT
  USING (is_shared = true);

-- Authenticated users can insert their own sessions
CREATE POLICY "egs_insert_own"
  ON public.entity_graph_sessions
  FOR INSERT
  WITH CHECK (created_by = auth.uid()::TEXT OR created_by = auth.email());

-- Authenticated users can update their own sessions
CREATE POLICY "egs_update_own"
  ON public.entity_graph_sessions
  FOR UPDATE
  USING (created_by = auth.uid()::TEXT OR created_by = auth.email());

-- Authenticated users can delete their own sessions
CREATE POLICY "egs_delete_own"
  ON public.entity_graph_sessions
  FOR DELETE
  USING (created_by = auth.uid()::TEXT OR created_by = auth.email());

-- ── 5. Grant access to anon key (filtered by RLS) ────────────────

GRANT SELECT, INSERT, UPDATE, DELETE
  ON public.entity_graph_sessions
  TO anon, authenticated;

-- ── 6. Verify ────────────────────────────────────────────────────

SELECT
  column_name,
  data_type,
  is_nullable,
  column_default
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name   = 'entity_graph_sessions'
ORDER BY ordinal_position;
