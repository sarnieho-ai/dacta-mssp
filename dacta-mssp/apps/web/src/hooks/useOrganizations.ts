import { useState, useEffect, useCallback } from 'react'
import { supabase } from '../lib/supabase'
import type { Organization } from '../types/database'

interface UseOrganizationsResult {
  organizations: Organization[]
  loading: boolean
  error: string | null
  refetch: () => Promise<void>
}

export function useOrganizations(): UseOrganizationsResult {
  const [organizations, setOrganizations] = useState<Organization[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchOrganizations = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const { data, error: fetchError } = await supabase
        .from('organizations')
        .select('*')
        .order('name', { ascending: true })

      if (fetchError) throw fetchError
      setOrganizations(data ?? [])
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load organizations')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchOrganizations()
  }, [fetchOrganizations])

  return { organizations, loading, error, refetch: fetchOrganizations }
}
