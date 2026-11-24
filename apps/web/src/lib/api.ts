/**
 * Same-origin client for the Skyline API (`/api/v1`, proxied by Next.js).
 *
 * * Unsafe methods send the CSRF token from the `__Host-skyline_csrf` cookie in
 *   `X-CSRF-Token`; the browser adds `Origin` and `Sec-Fetch-Site` itself.
 * * 401 sends the user to `/login?next=<current path>`, 403 `password_change_required`
 *   to `/change-password`. Both targets are re-checked with `safeNext` on arrival.
 * * Error messages shown to users come from the API's generic error body, never from
 *   exception text.
 */

export const CSRF_COOKIE = "__Host-skyline_csrf";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly correlationId: string | null,
  ) {
    super(message);
  }
}

export function readCookie(name: string, cookies: string = document.cookie): string | undefined {
  for (const part of cookies.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return undefined;
}

function currentPath(): string {
  return `${window.location.pathname}${window.location.search}`;
}

type Json = Record<string, unknown> | unknown[];

export async function api<T>(
  path: string,
  init: { method?: "GET" | "POST" | "PATCH" | "DELETE"; body?: Json } = {},
): Promise<T> {
  const method = init.method ?? "GET";
  const headers = new Headers({ Accept: "application/json" });
  if (init.body !== undefined) headers.set("Content-Type", "application/json");
  if (method !== "GET") {
    const token = readCookie(CSRF_COOKIE);
    if (token) headers.set("X-CSRF-Token", token);
  }
  const response = await fetch(`/api/v1${path}`, {
    method,
    headers,
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
    credentials: "same-origin",
    cache: "no-store",
  });
  if (response.status === 204) return undefined as T;
  const body = (await response.json().catch(() => null)) as {
    error?: { code?: string; message?: string; correlation_id?: string };
  } | null;
  if (!response.ok) {
    const code = body?.error?.code ?? "error";
    // Full page loads on purpose: this runs outside the React tree, and losing the session
    // should drop every piece of client state (cached queries included).
    if (response.status === 401 && !path.startsWith("/auth/login")) {
      // eslint-disable-next-line @next/next/no-location-assign-relative-destination
      window.location.assign(`/login?next=${encodeURIComponent(currentPath())}`);
    } else if (code === "password_change_required") {
      // eslint-disable-next-line @next/next/no-location-assign-relative-destination
      window.location.assign(`/change-password?next=${encodeURIComponent(currentPath())}`);
    }
    throw new ApiError(
      response.status,
      code,
      body?.error?.message ?? "The request failed",
      body?.error?.correlation_id ?? null,
    );
  }
  return body as T;
}
