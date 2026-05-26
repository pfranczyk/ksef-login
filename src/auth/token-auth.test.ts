import { beforeEach, describe, expect, it, vi } from "vitest";
import { KSeFNetworkError, KSeFTokenError } from "../errors.js";
import { pollAuthStatus, redeemToken, refreshTokens, submitAuth } from "./token-auth.js";

// Mock httpRequest to control HTTP responses without network calls
vi.mock("../http/client.js", () => ({
  httpRequest: vi.fn(),
  TIMEOUTS: { DEFAULT: 30_000, AUTH: 60_000 },
}));

import { httpRequest } from "../http/client.js";

const mockHttp = vi.mocked(httpRequest);

beforeEach(() => {
  vi.clearAllMocks();
});

describe("submitAuth", () => {
  const validResponse = {
    authenticationToken: { token: "AUTH_TOKEN", type: "KSeF" },
    referenceNumber: "REF123",
  };

  it.each([200, 201, 202])("accepts HTTP %i", async (status) => {
    mockHttp.mockResolvedValue({ status, data: validResponse });
    await expect(submitAuth("http://api", "1234567890", "CHALLENGE", "ENCRYPTED")).resolves.toEqual(
      validResponse,
    );
  });

  it.each([400, 401, 500])("throws KSeFTokenError for HTTP %i", async (status) => {
    mockHttp.mockResolvedValue({ status, data: {} });
    await expect(submitAuth("http://api", "1234567890", "CHALLENGE", "ENCRYPTED")).rejects.toThrow(
      KSeFTokenError,
    );
  });

  it("throws KSeFTokenError when response is missing required fields", async () => {
    mockHttp.mockResolvedValue({ status: 202, data: {} });
    await expect(submitAuth("http://api", "1234567890", "CHALLENGE", "ENCRYPTED")).rejects.toThrow(
      KSeFTokenError,
    );
  });
});

describe("redeemToken", () => {
  const validResponse = {
    accessToken: { token: "ACCESS", type: "Bearer" },
    refreshToken: { token: "REFRESH", type: "Bearer" },
  };

  it.each([200, 201, 202])("accepts HTTP %i", async (status) => {
    mockHttp.mockResolvedValue({ status, data: validResponse });
    await expect(redeemToken("http://api", "AUTH_TOKEN")).resolves.toEqual({
      accessToken: "ACCESS",
      refreshToken: "REFRESH",
    });
  });

  it.each([400, 401, 500])("throws KSeFTokenError for HTTP %i", async (status) => {
    mockHttp.mockResolvedValue({ status, data: {} });
    await expect(redeemToken("http://api", "AUTH_TOKEN")).rejects.toThrow(KSeFTokenError);
  });
});

describe("pollAuthStatus", () => {
  it("resolves when body status.code is 200", async () => {
    mockHttp.mockResolvedValue({ status: 200, data: { status: { code: 200 } } });
    await expect(pollAuthStatus("http://api", "REF123", "AUTH_TOKEN")).resolves.toBeUndefined();
  });

  it("retries while body status.code is pending (100/101)", async () => {
    mockHttp
      .mockResolvedValueOnce({ status: 200, data: { status: { code: 100 } } })
      .mockResolvedValueOnce({ status: 200, data: { status: { code: 200 } } });
    await expect(pollAuthStatus("http://api", "REF123", "AUTH_TOKEN")).resolves.toBeUndefined();
    expect(mockHttp).toHaveBeenCalledTimes(2);
  });

  it("throws KSeFTokenError immediately when body status.code >= 400", async () => {
    mockHttp.mockResolvedValue({
      status: 200,
      data: { status: { code: 401 }, processingDescription: "Unauthorized" },
    });
    await expect(pollAuthStatus("http://api", "REF123", "AUTH_TOKEN")).rejects.toThrow(
      /Authentication rejected by KSeF.*401.*Unauthorized/,
    );
  });

  it("throws KSeFTokenError for non-200 HTTP status", async () => {
    mockHttp.mockResolvedValue({ status: 500, data: {} });
    await expect(pollAuthStatus("http://api", "REF123", "AUTH_TOKEN")).rejects.toThrow(
      KSeFTokenError,
    );
  });
});

describe("refreshTokens", () => {
  it.each([200, 201, 202])("accepts HTTP %i", async (status) => {
    mockHttp.mockResolvedValue({
      status,
      data: { accessToken: "NEW_ACCESS", refreshToken: "NEW_REFRESH" },
    });
    const result = await refreshTokens("http://api", "OLD_REFRESH");
    expect(result).toEqual({ accessToken: "NEW_ACCESS", refreshToken: "NEW_REFRESH" });
  });

  it("falls back to the original refreshToken when API does not return a new one", async () => {
    mockHttp.mockResolvedValue({
      status: 200,
      data: { accessToken: "NEW_ACCESS" },
    });
    const result = await refreshTokens("http://api", "OLD_REFRESH");
    expect(result).toEqual({ accessToken: "NEW_ACCESS", refreshToken: "OLD_REFRESH" });
  });

  it("falls back to the original refreshToken when API returns TokenValue without refreshToken", async () => {
    mockHttp.mockResolvedValue({
      status: 202,
      data: { accessToken: { token: "NEW_ACCESS", type: "Bearer" } },
    });
    const result = await refreshTokens("http://api", "OLD_REFRESH");
    expect(result).toEqual({ accessToken: "NEW_ACCESS", refreshToken: "OLD_REFRESH" });
  });

  it.each([400, 401, 500])("throws KSeFTokenError for HTTP %i", async (status) => {
    mockHttp.mockResolvedValue({ status, data: {} });
    await expect(refreshTokens("http://api", "OLD_REFRESH")).rejects.toThrow(KSeFTokenError);
  });

  it("throws KSeFNetworkError when accessToken is missing", async () => {
    mockHttp.mockResolvedValue({ status: 200, data: {} });
    await expect(refreshTokens("http://api", "OLD_REFRESH")).rejects.toThrow(KSeFNetworkError);
  });
});
