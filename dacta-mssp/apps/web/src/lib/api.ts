import { supabase } from "./supabase";
import type { ApiResponse, ApiError } from "@dacta/shared";

const API_BASE = import.meta.env.VITE_API_URL || "";

/**
 * Typed API client. Automatically attaches the current user's
 * Supabase JWT to every request.
 *
 * Usage:
 *   const { data } = await api.get<Ticket[]>("/tickets");
 *   const { data } = await api.patch<Ticket>("/tickets/123", { status: "resolved" });
 */
async function getToken(): Promise<string | null> {
  const { data } = await supabase.auth.getSession();
  return data.session?.access_token || null;
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown
): Promise<ApiResponse<T>> {
  const token = await getToken();
  if (!token) {
    throw new ApiClientError("Not authenticated", "NO_TOKEN");
  }

  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };

  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  const json = await res.json();

  if (!res.ok) {
    const err = json as ApiError;
    throw new ApiClientError(
      err.error || "Request failed",
      err.code || "UNKNOWN",
      res.status
    );
  }

  return json as ApiResponse<T>;
}

export class ApiClientError extends Error {
  code: string;
  status: number;

  constructor(message: string, code: string, status: number = 0) {
    super(message);
    this.code = code;
    this.status = status;
    this.name = "ApiClientError";
  }
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body: unknown) => request<T>("POST", path, body),
  patch: <T>(path: string, body: unknown) => request<T>("PATCH", path, body),
  delete: <T>(path: string) => request<T>("DELETE", path),
};
