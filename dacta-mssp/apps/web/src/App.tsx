import { AuthProvider, useAuth } from "./stores/auth";
import LoginPage from "./pages/Login";
import Dashboard from "./pages/Dashboard";

function AppRouter() {
  var auth = useAuth();

  if (auth.loading) {
    return (
      <div style={{
        height: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "#060a12",
        color: "#5a6478",
        fontFamily: "'Inter', sans-serif",
        fontSize: 14,
      }}>
        Loading...
      </div>
    );
  }

  if (!auth.user) {
    return <LoginPage />;
  }

  return <Dashboard />;
}

export default function App() {
  return (
    <AuthProvider>
      <AppRouter />
    </AuthProvider>
  );
}
