import React, { useState, useMemo } from 'react'
import { ChevronUp, ChevronDown, ChevronsUpDown } from 'lucide-react'
import { EmptyState } from './EmptyState'
import { Loader } from './Loader'

export interface Column<T> {
  key: keyof T | string
  header: string
  width?: string
  sortable?: boolean
  render?: (row: T) => React.ReactNode
  className?: string
}

interface DataTableProps<T extends Record<string, unknown>> {
  columns: Column<T>[]
  data: T[]
  loading?: boolean
  emptyTitle?: string
  emptyDescription?: string
  onRowClick?: (row: T) => void
  rowKey?: (row: T) => string
  maxHeight?: string
  stickyHeader?: boolean
}

type SortDir = 'asc' | 'desc' | null

export function DataTable<T extends Record<string, unknown>>({
  columns,
  data,
  loading = false,
  emptyTitle = 'No data found',
  emptyDescription = 'No records match your current filters.',
  onRowClick,
  rowKey,
  maxHeight,
  stickyHeader = true,
}: DataTableProps<T>) {
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDir>(null)

  const handleSort = (key: string) => {
    if (sortKey === key) {
      if (sortDir === 'asc') setSortDir('desc')
      else if (sortDir === 'desc') { setSortDir(null); setSortKey(null) }
      else setSortDir('asc')
    } else {
      setSortKey(key)
      setSortDir('asc')
    }
  }

  const sorted = useMemo(() => {
    if (!sortKey || !sortDir) return data
    return [...data].sort((a, b) => {
      const av = a[sortKey as keyof T]
      const bv = b[sortKey as keyof T]
      if (av === null || av === undefined) return 1
      if (bv === null || bv === undefined) return -1
      const aStr = String(av)
      const bStr = String(bv)
      const cmp = aStr.localeCompare(bStr, undefined, { numeric: true })
      return sortDir === 'asc' ? cmp : -cmp
    })
  }, [data, sortKey, sortDir])

  if (loading) {
    return (
      <div className="p-4">
        <Loader variant="table" rows={6} />
      </div>
    )
  }

  if (!data.length) {
    return <EmptyState title={emptyTitle} description={emptyDescription} />
  }

  const SortIcon = ({ col }: { col: Column<T> }) => {
    if (!col.sortable) return null
    const key = col.key as string
    if (sortKey === key) {
      return sortDir === 'asc'
        ? <ChevronUp size={12} className="text-[#38bdf8]" />
        : <ChevronDown size={12} className="text-[#38bdf8]" />
    }
    return <ChevronsUpDown size={12} className="text-[#64748b] opacity-50" />
  }

  return (
    <div className={`overflow-auto ${maxHeight ? `max-h-[${maxHeight}]` : ''}`}>
      <table className="mcc-table">
        <thead className={stickyHeader ? 'sticky top-0 z-10' : ''}>
          <tr>
            {columns.map(col => (
              <th
                key={col.key as string}
                style={{ width: col.width }}
                className={col.sortable ? 'cursor-pointer select-none hover:text-[#94a3b8] transition-colors' : ''}
                onClick={() => col.sortable && handleSort(col.key as string)}
              >
                <span className="inline-flex items-center gap-1">
                  {col.header}
                  <SortIcon col={col} />
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row, i) => (
            <tr
              key={rowKey ? rowKey(row) : i}
              className={onRowClick ? 'cursor-pointer' : ''}
              onClick={() => onRowClick?.(row)}
            >
              {columns.map(col => (
                <td key={col.key as string} className={col.className}>
                  {col.render
                    ? col.render(row)
                    : (row[col.key as keyof T] as React.ReactNode) ?? <span className="text-[#64748b]">—</span>
                  }
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
