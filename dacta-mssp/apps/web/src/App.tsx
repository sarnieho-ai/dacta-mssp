import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from './contexts/AuthContext'
import { AppLayout } from './components/layout/AppLayout'
import { LoginPage } from './pages/LoginPage'
import { DashboardPage } from './pages/DashboardPage'
import { AlertTriagePage } from './pages/AlertTriagePage'
import { ThreatIntelPage } from './pages/ThreatIntelPage'
import { MitrePage } from './pages/MitrePage'
import { PlaceholderPage } from './pages/PlaceholderPage'
import { ProtectedRoute } from './components/layout/ProtectedRoute'

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <AppLayout />
              </ProtectedRoute>
            }
          >
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard" element={<DashboardPage />} />
            <Route path="triage" element={<AlertTriagePage />} />
            <Route path="threat-intel" element={<ThreatIntelPage />} />
            <Route path="mitre" element={<MitrePage />} />
            <Route path="detection-rules" element={<PlaceholderPage title="Detection Rules" icon="FileCode" description="Manage Sigma, YARA, and custom detection rules across your environment." />} />
            <Route path="log-parser" element={<PlaceholderPage title="Log Parser" icon="Terminal" description="Configure log ingestion, parsing patterns, and novelty detection." />} />
            <Route path="assets" element={<PlaceholderPage title="Asset Inventory" icon="Monitor" description="Track and manage assets across all monitored organizations." />} />
            <Route path="geo-map" element={<PlaceholderPage title="Geo Map" icon="Map" description="Visualize attack origins and alert hotspots on the world map." />} />
            <Route path="reports" element={<PlaceholderPage title="Reports" icon="FileText" description="Generate and distribute scheduled and on-demand security reports." />} />
            <Route path="integration-hub" element={<PlaceholderPage title="Integration Hub" icon="Puzzle" description="Connect and manage SIEM, SOAR, ticketing, and enrichment integrations." />} />
            <Route path="settings" element={<PlaceholderPage title="Settings" icon="Settings" description="Platform configuration, user management, and SLA policies." />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}
