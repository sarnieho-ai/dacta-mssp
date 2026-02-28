import { useState, useEffect, useCallback } from 'react'
import { supabase } from '../lib/supabase'
import type { Session, User as SupabaseUser } from '@supabase/supabase-js'
import type { User } from '../types/database'

interface AuthState {
  session: Session | null
  supabaseUser: SupabaseUser | null
  profile: User | null
  loading: boolean
}

export function useAuth() {
  const [state, setState] = useState<AuthState>({
    session: null,
    supabaseUser: null,
    profile: null,
    loading: true,
  })

  const fetchProfile = useCallback(async (userId: string) => {
    const { data } = await supabase
      .from('users')
      .select('*')
      .eq('auth_id', userId)
      .single()
    return data ?? null
  }, [])

  useEffect(() => {
    supabase.auth.getSession().then(async ({ data: { session } }) => {
      let profile: User | null = null
      if (session?.user) {
        profile = await fetchProfile(session.user.id)
      }
      setState({ session, supabaseUser: session?.user ?? null, profile, loading: false })
    })

    const { data: { subscription } } = supabase.auth.onAuthStateChange(async (_event, session) => {
      let profile: User | null = null
      if (session?.user) {
        profile = await fetchProfile(session.user.id)
      }
      setState(prev => ({ ...prev, session, supabaseUser: session?.user ?? null, profile }))
    })

    return () => subscription.unsubscribe()
  }, [fetchProfile])

  return state
}
