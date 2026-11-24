import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api, ApiError, readCookie } from "./api";

describe("readCookie", () => {
  it("finds a cookie among others", () => {
    expect(readCookie("__Host-skyline_csrf", "a=1; __Host-skyline_csrf=tok%3D; b=2")).toBe("tok=");
    expect(readCookie("missing", "a=1")).toBeUndefined();
  });
});

describe("api", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    // jsdom won't set a __Host- cookie over http, so stub the getter.
    vi.spyOn(document, "cookie", "get").mockReturnValue("__Host-skyline_csrf=csrf-token");
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    fetchMock.mockReset();
  });

  it("sends the CSRF token on unsafe methods only", async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    await api("/integrations", { method: "POST", body: { name: "x" } });
    await api("/integrations");
    const [, post] = fetchMock.mock.calls[0] as [string, RequestInit];
    const [, get] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(new Headers(post.headers).get("X-CSRF-Token")).toBe("csrf-token");
    expect(new Headers(get.headers).get("X-CSRF-Token")).toBeNull();
    expect(post.credentials).toBe("same-origin");
  });

  it("raises the API's generic error, with the correlation ID", async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          error: { code: "not_found", message: "The finding was not found", correlation_id: "c1" },
        }),
        { status: 404 },
      ),
    );
    await expect(api("/findings/x")).rejects.toMatchObject({
      status: 404,
      code: "not_found",
      correlationId: "c1",
    } satisfies Partial<ApiError>);
  });
});
