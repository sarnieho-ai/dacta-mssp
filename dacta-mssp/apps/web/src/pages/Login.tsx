import React, { useState } from "react";
import { useAuth } from "../stores/auth";

const T = {
  bg: "#060a12",
  bgCard: "#0c1220",
  border: "#1a2540",
  text: "#e2e8f0",
  textMuted: "#5a6478",
  accent: "#3b82f6",
  red: "#ef4444",
  purple: "#a78bfa",
};

export default function LoginPage() {
  const { login, loading, error } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await login(email, password);
  };

  return (
    <div
      style={{
        height: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: T.bg,
        fontFamily: "'Inter', -apple-system, sans-serif",
      }}
    >
      <div
        style={{
          width: 400,
          background: T.bgCard,
          border: "1px solid " + T.border,
          borderRadius: 16,
          padding: 40,
        }}
      >
        {/* Logo */}
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div
            style={{
              width: 56,
              height: 56,
              borderRadius: 14,
              background: `linear-gradient(135deg, ${T.accent}, ${T.purple})`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontWeight: 800,
              fontSize: 24,
              color: "#fff",
              margin: "0 auto 16px",
            }}
          >
            D
          </div>
          <div style={{ fontWeight: 700, fontSize: 20, color: T.text }}>
            DACTA MSSP
          </div>
          <div style={{ fontSize: 13, color: T.textMuted, marginTop: 4 }}>
            Sign in to the SOC Platform
          </div>
        </div>

        {/* Error */}
        {error && (
          <div
            style={{
              background: "rgba(239,68,68,0.1)",
              border: "1px solid rgba(239,68,68,0.3)",
              borderRadius: 8,
              padding: "10px 14px",
              marginBottom: 20,
              fontSize: 13,
              color: T.red,
            }}
          >
            {error}
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 16 }}>
            <label
              style={{
                display: "block",
                fontSize: 12,
                fontWeight: 500,
                color: T.textMuted,
                marginBottom: 6,
              }}
            >
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@dacta.sg"
              required
              style={{
                width: "100%",
                padding: "10px 14px",
                background: T.bg,
                border: "1px solid " + T.border,
                borderRadius: 8,
                color: T.text,
                fontSize: 14,
                outline: "none",
              }}
            />
          </div>

          <div style={{ marginBottom: 24 }}>
            <label
              style={{
                display: "block",
                fontSize: 12,
                fontWeight: 500,
                color: T.textMuted,
                marginBottom: 6,
              }}
            >
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your password"
              required
              style={{
                width: "100%",
                padding: "10px 14px",
                background: T.bg,
                border: "1px solid " + T.border,
                borderRadius: 8,
                color: T.text,
                fontSize: 14,
                outline: "none",
              }}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            style={{
              width: "100%",
              padding: "12px 0",
              background: loading ? T.textMuted : T.accent,
              color: "#fff",
              border: "none",
              borderRadius: 8,
              fontSize: 14,
              fontWeight: 600,
              cursor: loading ? "not-allowed" : "pointer",
            }}
          >
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>

        <div
          style={{
            textAlign: "center",
            fontSize: 11,
            color: T.textMuted,
            marginTop: 24,
          }}
        >
          DACTA SG Managed Security Operations
        </div>
      </div>
    </div>
  );
}
