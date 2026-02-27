import { AuthProvider, useAuth } from "./stores/auth";
import LoginPage from "./pages/Login";

function AppRouter() {
  const { user, loading, logout } = useAuth();

  // Loading spinner
  if (loading) {
    return (
      <div
        style={{
          height: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#060a12",
          color: "#5a6478",
          fontFamily: "'Inter', sans-serif",
          fontSize: 14,
        }}
      >
        Loading...
      </div>
    );
  }

  // Not logged in
  if (!user) {
    return <LoginPage />;
  }

  // Logged in - show shell placeholder
  // This will be replaced with the full dashboard shell in Steps 9-10
  return (
    <div
      style={{
        height: "100vh",
        background: "#060a12",
        color: "#e2e8f0",
        fontFamily: "'Inter', -apple-system, sans-serif",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: 20,
      }}
    >
      <div
        style={{
          width: 56,
          height: 56,
          borderRadius: 14,
          background: "linear-gradient(135deg, #3b82f6, #a78bfa)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontWeight: 800,
          fontSize: 24,
          color: "#fff",
        }}
      >
        D
      </div>
      <div style={{ fontSize: 20, fontWeight: 700 }}>DACTA MSSP Platform</div>
      <div style={{ color: "#8892a8", fontSize: 14 }}>
        Welcome, <strong>{user.name}</strong> ({user.role})
      </div>
      <div style={{ color: "#5a6478", fontSize: 12 }}>
        Auth is working! The full dashboard shell comes in Step 10.
      </div>
      <button
        onClick={logout}
        style={{
          marginTop: 16,
          padding: "8px 24px",
          background: "transparent",
          border: "1px solid #1a2540",
          borderRadius: 8,
          color: "#8892a8",
          fontSize: 13,
          cursor: "pointer",
        }}
      >
        Sign Out
      </button>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppRouter />
    </AuthProvider>
  );
}
