import { beforeEach, describe, expect, it, vi } from "vitest";
import { KSeFPublicKeyError } from "./errors.js";

vi.mock("./auth/challenge.js", () => ({ getChallenge: vi.fn() }));
vi.mock("./auth/crypto.js", () => ({ encryptKsefToken: vi.fn() }));
vi.mock("./auth/public-key.js", () => ({
  fetchPublicKey: vi.fn(),
  normalizePem: vi.fn(),
  validatePublicKey: vi.fn(),
}));
vi.mock("./auth/token-auth.js", () => ({
  submitAuth: vi.fn(),
  pollAuthStatus: vi.fn(),
  redeemToken: vi.fn(),
  refreshTokens: vi.fn(),
}));
vi.mock("./token/jwt.js", () => ({ isTokenValid: vi.fn() }));

import { getChallenge } from "./auth/challenge.js";
import { encryptKsefToken } from "./auth/crypto.js";
import { fetchPublicKey, normalizePem, validatePublicKey } from "./auth/public-key.js";
import { pollAuthStatus, redeemToken, refreshTokens, submitAuth } from "./auth/token-auth.js";
import { KSeFAuth } from "./KSeFAuth.js";
import { isTokenValid } from "./token/jwt.js";

const BASE_OPTIONS = {
  baseUrl: "https://ksef-demo.mf.gov.pl/api",
  nip: "1234567890",
  ksefToken: "MY_KSEF_TOKEN",
  publicKey: "MOCK_PUBLIC_KEY",
};

beforeEach(() => {
  vi.clearAllMocks();

  // Default: all tokens are invalid → triggers the full 7-step flow.
  // Individual tests override this as needed.
  vi.mocked(isTokenValid).mockReturnValue(false);

  // Default happy-path stubs — every step succeeds and returns predictable values.
  vi.mocked(validatePublicKey).mockReturnValue(undefined);
  vi.mocked(normalizePem).mockReturnValue("NORMALIZED_PEM");
  vi.mocked(getChallenge).mockResolvedValue({
    challenge: "CHALLENGE_XYZ",
    timestampMs: 1700000000000,
  });
  vi.mocked(encryptKsefToken).mockReturnValue("ENCRYPTED_BASE64");
  vi.mocked(submitAuth).mockResolvedValue({
    authenticationToken: { token: "AUTH_TOKEN", validUntil: "2099-01-01" },
    referenceNumber: "REF-001",
  });
  vi.mocked(pollAuthStatus).mockResolvedValue(undefined);
  vi.mocked(redeemToken).mockResolvedValue({
    accessToken: "ACCESS_TOKEN",
    refreshToken: "REFRESH_TOKEN",
  });
  vi.mocked(refreshTokens).mockResolvedValue({
    accessToken: "NEW_ACCESS",
    refreshToken: "NEW_REFRESH",
  });
  vi.mocked(fetchPublicKey).mockResolvedValue("FETCHED_PEM");
});

// --- Path 1: valid accessToken ---

describe("login() — valid accessToken", () => {
  // login() must short-circuit immediately when a valid accessToken is available.
  // No API call should be made — this is the hot path in multi-tenant environments.
  it("returns the existing tokens without making any API calls", async () => {
    vi.mocked(isTokenValid).mockReturnValue(true);

    const auth = new KSeFAuth(BASE_OPTIONS);
    const result = await auth.login({
      tokens: { accessToken: "VALID_ACCESS", refreshToken: "SOME_REFRESH" },
    });

    expect(result.accessToken).toBe("VALID_ACCESS");
    expect(result.refreshToken).toBe("SOME_REFRESH");
    expect(getChallenge).not.toHaveBeenCalled();
    expect(refreshTokens).not.toHaveBeenCalled();
  });

  it("returns an empty string for refreshToken when it was not provided", async () => {
    vi.mocked(isTokenValid).mockReturnValue(true);

    const auth = new KSeFAuth(BASE_OPTIONS);
    const result = await auth.login({ tokens: { accessToken: "VALID_ACCESS" } });

    expect(result.accessToken).toBe("VALID_ACCESS");
    expect(result.refreshToken).toBe("");
  });
});

// --- Path 2: token refresh ---

describe("login() — refresh via refreshToken", () => {
  it("refreshes tokens when accessToken is expired but refreshToken is valid", async () => {
    vi.mocked(isTokenValid)
      .mockReturnValueOnce(false) // accessToken expired
      .mockReturnValueOnce(true); // refreshToken valid

    const auth = new KSeFAuth(BASE_OPTIONS);
    const result = await auth.login({
      tokens: { accessToken: "EXPIRED", refreshToken: "VALID_REFRESH" },
    });

    expect(refreshTokens).toHaveBeenCalledWith(
      BASE_OPTIONS.baseUrl,
      "VALID_REFRESH",
      expect.anything(),
    );
    expect(result.accessToken).toBe("NEW_ACCESS");
    expect(result.refreshToken).toBe("NEW_REFRESH");
    expect(getChallenge).not.toHaveBeenCalled();
  });

  // autoRefresh: false lets consumers force a full re-authentication
  // even when a refresh token is still valid (e.g. after a permission change).
  it("runs the full flow when autoRefresh is false even if refreshToken is valid", async () => {
    vi.mocked(isTokenValid)
      .mockReturnValueOnce(false) // accessToken expired
      .mockReturnValueOnce(true); // refreshToken would be valid — but autoRefresh is off

    const auth = new KSeFAuth(BASE_OPTIONS);
    await auth.login({
      tokens: { accessToken: "EXPIRED", refreshToken: "VALID_REFRESH" },
      autoRefresh: false,
    });

    expect(refreshTokens).not.toHaveBeenCalled();
    expect(getChallenge).toHaveBeenCalled();
  });
});

// --- Path 3: full 7-step authentication flow ---

describe("login() — full flow", () => {
  // Smoke test for the entire happy path: confirms all steps are called in order
  // and that the correct arguments flow from one step to the next.
  it("executes all 7 steps in the correct order", async () => {
    const auth = new KSeFAuth(BASE_OPTIONS);
    const result = await auth.login();

    // Step 1 — public key validation
    expect(validatePublicKey).toHaveBeenCalledWith("MOCK_PUBLIC_KEY");
    expect(normalizePem).toHaveBeenCalledWith("MOCK_PUBLIC_KEY");

    // Step 2 — challenge
    expect(getChallenge).toHaveBeenCalledWith(BASE_OPTIONS.baseUrl, expect.anything());

    // Step 3 — encryption (normalized PEM must reach encryptKsefToken)
    expect(encryptKsefToken).toHaveBeenCalledWith("MY_KSEF_TOKEN", 1700000000000, "NORMALIZED_PEM");

    // Step 4 — submit
    expect(submitAuth).toHaveBeenCalledWith(
      BASE_OPTIONS.baseUrl,
      "1234567890",
      "CHALLENGE_XYZ",
      "ENCRYPTED_BASE64",
      expect.anything(),
    );

    // Step 5 — polling
    expect(pollAuthStatus).toHaveBeenCalledWith(
      BASE_OPTIONS.baseUrl,
      "REF-001",
      "AUTH_TOKEN",
      expect.anything(),
    );

    // Step 6 — redeem
    expect(redeemToken).toHaveBeenCalledWith(BASE_OPTIONS.baseUrl, "AUTH_TOKEN", expect.anything());

    // Step 7 — result
    expect(result.accessToken).toBe("ACCESS_TOKEN");
    expect(result.refreshToken).toBe("REFRESH_TOKEN");
    expect(result.publicKey).toBeUndefined(); // key was provided and valid → not returned
  });

  it("throws KSeFPublicKeyError when no publicKey is set and autoFetchPublicKey is false", async () => {
    const auth = new KSeFAuth({ ...BASE_OPTIONS, publicKey: undefined, autoFetchPublicKey: false });
    await expect(auth.login()).rejects.toThrow(KSeFPublicKeyError);
    expect(getChallenge).not.toHaveBeenCalled();
  });

  // When autoFetchPublicKey is true, the library fetches the key automatically
  // and returns it in the result so the developer can cache it for subsequent calls.
  it("fetches publicKey from API when none is provided and autoFetchPublicKey is true", async () => {
    const auth = new KSeFAuth({ ...BASE_OPTIONS, publicKey: undefined, autoFetchPublicKey: true });
    const result = await auth.login();

    expect(fetchPublicKey).toHaveBeenCalledWith(BASE_OPTIONS.baseUrl, expect.anything());
    expect(normalizePem).not.toHaveBeenCalled(); // fetched PEM goes directly to encryptKsefToken
    expect(encryptKsefToken).toHaveBeenCalledWith(
      "MY_KSEF_TOKEN",
      expect.any(Number),
      "FETCHED_PEM",
    );
    expect(result.publicKey).toBe("FETCHED_PEM"); // new key is returned for the developer to store
  });

  // Handles the key-rotation scenario: a previously cached key becomes invalid
  // (expired or replaced). With autoFetchPublicKey the library recovers automatically.
  it("fetches publicKey from API when the provided key is invalid and autoFetchPublicKey is true", async () => {
    vi.mocked(validatePublicKey).mockImplementation(() => {
      throw new KSeFPublicKeyError("invalid key");
    });

    const auth = new KSeFAuth({ ...BASE_OPTIONS, autoFetchPublicKey: true });
    const result = await auth.login();

    expect(fetchPublicKey).toHaveBeenCalled();
    expect(result.publicKey).toBe("FETCHED_PEM");
  });

  // Without autoFetchPublicKey, an invalid key is a hard error — the developer
  // must explicitly call fetchPublicKey() and update their stored key.
  it("rethrows KSeFPublicKeyError when the provided key is invalid and autoFetchPublicKey is false", async () => {
    vi.mocked(validatePublicKey).mockImplementation(() => {
      throw new KSeFPublicKeyError("invalid key");
    });

    const auth = new KSeFAuth({ ...BASE_OPTIONS, autoFetchPublicKey: false });
    await expect(auth.login()).rejects.toThrow(KSeFPublicKeyError);
    expect(fetchPublicKey).not.toHaveBeenCalled();
  });

  // publicKey is only returned when the library had to fetch it.
  // If the developer's key was already valid, returning it would be redundant.
  it("does not include publicKey in the result when the provided key was valid", async () => {
    const auth = new KSeFAuth(BASE_OPTIONS);
    const result = await auth.login();
    expect(result.publicKey).toBeUndefined();
  });
});

// --- refresh() ---

describe("refresh()", () => {
  it("delegates to refreshTokens with the given refresh token", async () => {
    const auth = new KSeFAuth(BASE_OPTIONS);
    const result = await auth.refresh("MY_REFRESH_TOKEN");

    expect(refreshTokens).toHaveBeenCalledWith(
      BASE_OPTIONS.baseUrl,
      "MY_REFRESH_TOKEN",
      expect.anything(),
    );
    expect(result.accessToken).toBe("NEW_ACCESS");
    expect(result.refreshToken).toBe("NEW_REFRESH");
  });
});

// --- fetchPublicKey() ---

describe("fetchPublicKey()", () => {
  it("delegates to the fetchPublicKey module function with baseUrl", async () => {
    const auth = new KSeFAuth(BASE_OPTIONS);
    const result = await auth.fetchPublicKey();

    expect(fetchPublicKey).toHaveBeenCalledWith(BASE_OPTIONS.baseUrl, expect.anything());
    expect(result).toBe("FETCHED_PEM");
  });
});

// --- isTokenValid() ---

describe("isTokenValid()", () => {
  it("delegates to the isTokenValid module function with token and buffer", () => {
    vi.mocked(isTokenValid).mockReturnValue(true);
    const auth = new KSeFAuth(BASE_OPTIONS);
    const result = auth.isTokenValid("SOME_TOKEN", 10);

    expect(isTokenValid).toHaveBeenCalledWith("SOME_TOKEN", 10);
    expect(result).toBe(true);
  });

  it("returns false when the token is invalid", () => {
    vi.mocked(isTokenValid).mockReturnValue(false);
    const auth = new KSeFAuth(BASE_OPTIONS);
    expect(auth.isTokenValid("EXPIRED_TOKEN")).toBe(false);
  });
});

// --- Multi-tenant instance isolation ---

describe("instance isolation (multi-tenant)", () => {
  // KSeFAuth is designed for environments where hundreds of taxpayers are handled
  // concurrently. Each instance must be completely independent — no shared state.
  it("two instances with different NIPs submit auth with their own NIP", async () => {
    const authA = new KSeFAuth({ ...BASE_OPTIONS, nip: "1111111111" });
    const authB = new KSeFAuth({ ...BASE_OPTIONS, nip: "2222222222" });

    await Promise.all([authA.login(), authB.login()]);

    const nipCalls = vi.mocked(submitAuth).mock.calls.map((call) => call[1]);
    expect(nipCalls).toContain("1111111111");
    expect(nipCalls).toContain("2222222222");
  });

  it("two instances with different ksefTokens encrypt their own tokens independently", async () => {
    const authA = new KSeFAuth({ ...BASE_OPTIONS, ksefToken: "TOKEN_A" });
    const authB = new KSeFAuth({ ...BASE_OPTIONS, ksefToken: "TOKEN_B" });

    await Promise.all([authA.login(), authB.login()]);

    const encryptCalls = vi.mocked(encryptKsefToken).mock.calls.map((call) => call[0]);
    expect(encryptCalls).toContain("TOKEN_A");
    expect(encryptCalls).toContain("TOKEN_B");
  });
});
