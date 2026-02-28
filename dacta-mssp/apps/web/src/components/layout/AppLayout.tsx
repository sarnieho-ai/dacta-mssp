import { useState } from 'react'
import { Outlet } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'

export function AppLayout() {
  const [collapsed, setCollapsed] = useState(false)

  return (
    <div className="mcc-root">
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed(v => !v)} />
      <div className="mcc-main">
        <TopBar />
        <main className="mcc-content">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
