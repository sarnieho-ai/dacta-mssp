import { useEffect, useRef } from 'react'
import { supabase } from '../lib/supabase'
import type { RealtimeChannel } from '@supabase/supabase-js'

type EventType = 'INSERT' | 'UPDATE' | 'DELETE' | '*'

interface UseRealtimeOptions {
  table: string
  schema?: string
  event?: EventType
  filter?: string
  onChange?: (payload: unknown) => void
  onInsert?: (payload: unknown) => void
  onUpdate?: (payload: unknown) => void
  onDelete?: (payload: unknown) => void
}

export function useRealtime({
  table,
  schema = 'public',
  event = '*',
  filter,
  onChange,
  onInsert,
  onUpdate,
  onDelete,
}: UseRealtimeOptions) {
  const channelRef = useRef<RealtimeChannel | null>(null)

  useEffect(() => {
    const channelName = `realtime:${schema}:${table}:${event}:${filter ?? 'all'}:${Date.now()}`

    const channel = supabase.channel(channelName)

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const changesConfig: any = { event, schema, table }
    if (filter) changesConfig.filter = filter

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    channel.on('postgres_changes' as any, changesConfig, (payload: any) => {
      onChange?.(payload)
      if (payload.eventType === 'INSERT') onInsert?.(payload)
      if (payload.eventType === 'UPDATE') onUpdate?.(payload)
      if (payload.eventType === 'DELETE') onDelete?.(payload)
    })

    channel.subscribe()
    channelRef.current = channel

    return () => {
      channel.unsubscribe()
      supabase.removeChannel(channel)
    }
  }, [table, schema, event, filter]) // eslint-disable-line react-hooks/exhaustive-deps

  return channelRef
}
