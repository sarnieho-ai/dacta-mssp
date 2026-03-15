-- =============================================================
-- DACTA Novelty Catcher — Database Migration
-- Run in Supabase Dashboard → SQL Editor
-- Project: qiqrizggitcqwkwshmfy
-- =============================================================

CREATE TABLE IF NOT EXISTS public.novelty_catchers (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  org_id UUID REFERENCES public.organizations(id),
  hostname TEXT NOT NULL DEFAULT 'unnamed',
  version TEXT DEFAULT '2.0.0',
  mode TEXT DEFAULT 'learn',
  status TEXT DEFAULT 'pending',
  platform TEXT DEFAULT 'linux',
  events_processed BIGINT DEFAULT 0,
  alerts_24h INTEGER DEFAULT 0,
  last_heartbeat TIMESTAMPTZ,
  stats JSONB DEFAULT '{}'::jsonb,
  config JSONB DEFAULT '{}'::jsonb,
  indices TEXT[] DEFAULT ARRAY[]::TEXT[],
  learn_progress INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.novelty_alerts (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  catcher_id UUID,
  org_id UUID REFERENCES public.organizations(id),
  alert_type TEXT NOT NULL DEFAULT 'unknown',
  severity TEXT DEFAULT 'medium',
  source_key TEXT DEFAULT '',
  detail TEXT DEFAULT '',
  alert_data JSONB DEFAULT '{}'::jsonb,
  acknowledged BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Add FK after both tables exist
DO $$ BEGIN
  ALTER TABLE public.novelty_alerts 
    ADD CONSTRAINT novelty_alerts_catcher_fk 
    FOREIGN KEY (catcher_id) REFERENCES public.novelty_catchers(id) ON DELETE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- RLS
ALTER TABLE public.novelty_catchers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.novelty_alerts ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN DROP POLICY IF EXISTS novelty_catchers_anon_all ON public.novelty_catchers; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN DROP POLICY IF EXISTS novelty_alerts_anon_all ON public.novelty_alerts; EXCEPTION WHEN OTHERS THEN NULL; END $$;

CREATE POLICY novelty_catchers_anon_all ON public.novelty_catchers FOR ALL TO anon USING (true) WITH CHECK (true);
CREATE POLICY novelty_alerts_anon_all ON public.novelty_alerts FOR ALL TO anon USING (true) WITH CHECK (true);
