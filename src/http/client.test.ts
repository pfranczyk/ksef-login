import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { KSeFNetworkError } from "../errors.js";
import { httpRequest, TIMEOUTS } from "./client.js";

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

function mockResponse(
  status: number,
  body: unknown = {},
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

describe("TIMEOUTS", () => {
  it("DEFAULT is 30s", () => expect(TIMEOUTS.DEFAULT).toBe(30_000));
  it("AUTH is 60s", () => expect(TIMEOUTS.AUTH).toBe(60_000));
});

describe("httpRequest — default headers", () => {
  it("sends Content-Type and Accept application/json by default", async () => {
    vi.mocked(fetch).mockResolvedValue(mockResponse(200, {}));
    await httpRequest("https://example.com/test");
    const [, init] = vi.mocked(fetch).mock.calls[0];
    const headers = init?.headers as Record<string, string>;
    expect(headers["Content-Type"]).toBe("application/json");
    expect(headers.Accept).toBe("application/json");
  });

  it("merges custom headers with defaults", async () => {
    vi.mocked(fetch).mockResolvedValue(mockResponse(200, {}));
    await httpRequest("https://example.com/test", { headers: { Authorization: "Bearer tok" } });
    const [, init] = vi.mocked(fetch).mock.calls[0];
    const headers = init?.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer tok");
    expect(headers["Content-Type"]).toBe("application/json");
  });

  it("custom Accept header overrides default", async () => {
    vi.mocked(fetch).mockResolvedValue(mockResponse(200, {}));
    await httpRequest("https://example.com/test", { headers: { Accept: "application/xml" } });
    const [, init] = vi.mocked(fetch).mock.calls[0];
    const headers = init?.headers as Record<string, string>;
    expect(headers.Accept).toBe("application/xml");
  });
});

describe("httpRequest — success", () => {
  it("returns parsed JSON and status", async () => {
    vi.mocked(fetch).mockResolvedValue(mockResponse(200, { challenge: "abc" }));
    const result = await httpRequest("https://example.com/test");
    expect(result.status).toBe(200);
    expect(result.data).toEqual({ challenge: "abc" });
  });
});

describe("httpRequest — timeout", () => {
  it("throws KSeFNetworkError when AbortError is raised", async () => {
    const abortError = Object.assign(new Error("aborted"), { name: "AbortError" });
    vi.mocked(fetch).mockRejectedValue(abortError);
    await expect(httpRequest("https://example.com/test", { timeoutMs: 5_000 })).rejects.toThrow(
      /timed out after 5000ms/,
    );
  });

  it("throws KSeFNetworkError on network error", async () => {
    vi.mocked(fetch).mockRejectedValue(new Error("connection reset"));
    await expect(httpRequest("https://example.com/test")).rejects.toThrow(KSeFNetworkError);
  });
});

describe("httpRequest — non-JSON error body", () => {
  it("throws KSeFNetworkError with HTTP status info when body is not JSON", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response("<html>error</html>", { status: 503 }));
    await expect(httpRequest("https://example.com/test")).rejects.toThrow(/HTTP 503 error/);
  });
});

describe("httpRequest — HTTP 429 rate limiting", () => {
  it("retries after Retry-After seconds and succeeds on second attempt", async () => {
    vi.useFakeTimers();
    vi.mocked(fetch)
      .mockResolvedValueOnce(new Response(null, { status: 429, headers: { "Retry-After": "2" } }))
      .mockResolvedValueOnce(mockResponse(200, { ok: true }));

    const promise = httpRequest("https://example.com/test", { maxRetries: 3 });
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(result.status).toBe(200);
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2);
    vi.useRealTimers();
  });

  it("uses 60s default wait when Retry-After header is absent", async () => {
    vi.useFakeTimers();
    vi.mocked(fetch)
      .mockResolvedValueOnce(new Response(null, { status: 429 }))
      .mockResolvedValueOnce(mockResponse(200, {}));

    const promise = httpRequest("https://example.com/test", { maxRetries: 3 });
    await vi.advanceTimersByTimeAsync(60_000);
    await promise;

    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2);
    vi.useRealTimers();
  });

  it("throws KSeFNetworkError after exhausting all retries", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(null, { status: 429, headers: { "Retry-After": "1" } }),
    );

    await expect(
      httpRequest("https://example.com/test", { maxRetries: 2, timeoutMs: 100 }),
    ).rejects.toThrow(/Rate limit exceeded after 2 attempts/);
  });
});
