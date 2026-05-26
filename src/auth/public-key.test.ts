import { X509Certificate } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { KSeFPublicKeyError } from "../errors.js";

// X509Certificate is mocked so tests don't need a real certificate.
// Each test controls the mock's behavior (valid/expired/throws) via mockImplementation.
vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>();
  return {
    ...actual,
    X509Certificate: vi.fn(),
  };
});

// httpRequest is mocked to keep fetchPublicKey tests fully offline.
vi.mock("../http/client.js", () => ({
  httpRequest: vi.fn(),
}));

import { httpRequest } from "../http/client.js";
import { fetchPublicKey, normalizePem, validatePublicKey } from "./public-key.js";

const MockX509 = vi.mocked(X509Certificate);

const NOW = new Date();
const YESTERDAY = new Date(NOW.getTime() - 24 * 60 * 60 * 1000).toISOString();
const NEAR_FUTURE = new Date(NOW.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
const FAR_FUTURE = new Date(NOW.getTime() + 365 * 24 * 60 * 60 * 1000).toISOString();
const PAST_YEAR = new Date(NOW.getTime() - 365 * 24 * 60 * 60 * 1000).toISOString();

beforeEach(() => {
  vi.clearAllMocks();
});

// --- normalizePem ---

describe("normalizePem", () => {
  it("adds a trailing newline when PEM header is present but newline is missing", () => {
    const pem = "-----BEGIN CERTIFICATE-----\nDATA\n-----END CERTIFICATE-----";
    expect(normalizePem(pem)).toBe(`${pem}\n`);
  });

  it("does not add an extra newline when PEM already ends with one", () => {
    const pem = "-----BEGIN CERTIFICATE-----\nDATA\n-----END CERTIFICATE-----\n";
    expect(normalizePem(pem)).toBe(pem);
  });

  // Developers may store the public key as a raw base64 DER string
  // (without PEM headers). normalizePem must wrap it into a valid PEM certificate.
  it("wraps raw base64 input as a PEM certificate", () => {
    const base64 = "AAABBBCCC".repeat(10);
    const result = normalizePem(base64);
    expect(result).toContain("-----BEGIN CERTIFICATE-----");
    expect(result).toContain("-----END CERTIFICATE-----");
  });

  // PEM format requires lines of exactly 64 characters.
  it("splits raw base64 into lines of at most 64 characters", () => {
    const base64 = "A".repeat(100);
    const result = normalizePem(base64);
    const lines = result
      .replace("-----BEGIN CERTIFICATE-----\n", "")
      .replace("\n-----END CERTIFICATE-----\n", "")
      .split("\n");
    for (const line of lines.slice(0, -1)) {
      expect(line.length).toBe(64);
    }
  });
});

// --- validatePublicKey ---

describe("validatePublicKey", () => {
  it("does not throw for a valid non-expired certificate", () => {
    // Vitest 4: mock implementations used with `new` must be constructable.
    // A class expression avoids Biome's useArrowFunction rewrite (an arrow
    // function would be reverted and then throw when invoked as a constructor).
    MockX509.mockImplementation(
      class {
        validTo = FAR_FUTURE;
      } as never,
    );
    expect(() =>
      validatePublicKey("-----BEGIN CERTIFICATE-----\nDATA\n-----END CERTIFICATE-----"),
    ).not.toThrow();
  });

  // If the developer provides a key from a different environment (e.g. prod key on demo),
  // X509Certificate will throw a parse error — we wrap it in a descriptive KSeFPublicKeyError.
  it("throws KSeFPublicKeyError when X509Certificate cannot parse the input", () => {
    MockX509.mockImplementation(
      class {
        constructor() {
          throw new Error("Failed to parse X.509 cert");
        }
      } as never,
    );
    expect(() => validatePublicKey("garbage-input")).toThrow(KSeFPublicKeyError);
    expect(() => validatePublicKey("garbage-input")).toThrow(/cannot parse/i);
  });

  it("throws KSeFPublicKeyError for an expired certificate", () => {
    MockX509.mockImplementation(
      class {
        validTo = "2020-01-01T00:00:00Z";
      } as never,
    );
    expect(() =>
      validatePublicKey("-----BEGIN CERTIFICATE-----\nDATA\n-----END CERTIFICATE-----"),
    ).toThrow(KSeFPublicKeyError);
    expect(() =>
      validatePublicKey("-----BEGIN CERTIFICATE-----\nDATA\n-----END CERTIFICATE-----"),
    ).toThrow(/expired/i);
  });

  // The expiry date in the message helps the developer diagnose stale cached keys.
  it("includes the expiry date in the error message", () => {
    const expiredDate = "2019-06-15T12:00:00Z";
    MockX509.mockImplementation(
      class {
        validTo = expiredDate;
      } as never,
    );
    expect(() =>
      validatePublicKey("-----BEGIN CERTIFICATE-----\nDATA\n-----END CERTIFICATE-----"),
    ).toThrow(expiredDate);
  });
});

// --- fetchPublicKey ---

describe("fetchPublicKey", () => {
  it("throws KSeFPublicKeyError on a non-200 HTTP response", async () => {
    vi.mocked(httpRequest).mockResolvedValue({ status: 500, data: {} });
    await expect(fetchPublicKey("https://example.com/api")).rejects.toThrow(KSeFPublicKeyError);
  });

  it("throws KSeFPublicKeyError when the API returns an empty certificate array", async () => {
    vi.mocked(httpRequest).mockResolvedValue({ status: 200, data: [] });
    await expect(fetchPublicKey("https://example.com/api")).rejects.toThrow(KSeFPublicKeyError);
  });

  // KSeF API may return certificates for multiple purposes (e.g. SignatureVerification).
  // Only certificates with KsefTokenEncryption usage are valid for our encryption step.
  it("throws KSeFPublicKeyError when no certificate has KsefTokenEncryption usage", async () => {
    vi.mocked(httpRequest).mockResolvedValue({
      status: 200,
      data: [
        {
          certificate: "CERTDATA",
          usage: ["SomethingElse"],
          validFrom: YESTERDAY,
          validTo: FAR_FUTURE,
        },
      ],
    });
    await expect(fetchPublicKey("https://example.com/api")).rejects.toThrow(KSeFPublicKeyError);
  });

  it("throws KSeFPublicKeyError when all KsefTokenEncryption certificates are expired", async () => {
    vi.mocked(httpRequest).mockResolvedValue({
      status: 200,
      data: [
        {
          certificate: "EXPIRED_CERT",
          usage: ["KsefTokenEncryption"],
          validFrom: PAST_YEAR,
          validTo: YESTERDAY,
        },
      ],
    });
    await expect(fetchPublicKey("https://example.com/api")).rejects.toThrow(KSeFPublicKeyError);
  });

  it("returns a PEM string for a single valid KsefTokenEncryption certificate", async () => {
    vi.mocked(httpRequest).mockResolvedValue({
      status: 200,
      data: [
        {
          certificate: "VALIDCERTDATA",
          usage: ["KsefTokenEncryption"],
          validFrom: YESTERDAY,
          validTo: FAR_FUTURE,
        },
      ],
    });
    const result = await fetchPublicKey("https://example.com/api");
    expect(result).toContain("-----BEGIN CERTIFICATE-----");
    expect(result).toContain("VALIDCERTDATA");
    expect(result).toContain("-----END CERTIFICATE-----");
  });

  // When KSeF rotates keys, the old and new certificates may both be valid.
  // We always prefer the one with the longest remaining validity.
  it("selects the certificate with the latest validTo when multiple valid ones exist", async () => {
    vi.mocked(httpRequest).mockResolvedValue({
      status: 200,
      data: [
        {
          certificate: "CERT_NEAR",
          usage: ["KsefTokenEncryption"],
          validFrom: YESTERDAY,
          validTo: NEAR_FUTURE,
        },
        {
          certificate: "CERT_FAR",
          usage: ["KsefTokenEncryption"],
          validFrom: YESTERDAY,
          validTo: FAR_FUTURE,
        },
      ],
    });
    const result = await fetchPublicKey("https://example.com/api");
    expect(result).toContain("CERT_FAR");
    expect(result).not.toContain("CERT_NEAR");
  });

  it("ignores certificates without KsefTokenEncryption usage", async () => {
    vi.mocked(httpRequest).mockResolvedValue({
      status: 200,
      data: [
        {
          certificate: "WRONG_USAGE_CERT",
          usage: ["SignatureVerification"],
          validFrom: YESTERDAY,
          validTo: FAR_FUTURE,
        },
        {
          certificate: "CORRECT_CERT",
          usage: ["KsefTokenEncryption"],
          validFrom: YESTERDAY,
          validTo: NEAR_FUTURE,
        },
      ],
    });
    const result = await fetchPublicKey("https://example.com/api");
    expect(result).toContain("CORRECT_CERT");
    expect(result).not.toContain("WRONG_USAGE_CERT");
  });

  it("calls httpRequest with the correct endpoint URL", async () => {
    vi.mocked(httpRequest).mockResolvedValue({
      status: 200,
      data: [
        {
          certificate: "CERT",
          usage: ["KsefTokenEncryption"],
          validFrom: YESTERDAY,
          validTo: FAR_FUTURE,
        },
      ],
    });
    await fetchPublicKey("https://ksef-demo.mf.gov.pl/api");
    expect(httpRequest).toHaveBeenCalledWith(
      "https://ksef-demo.mf.gov.pl/api/v2/security/public-key-certificates",
      expect.objectContaining({}),
    );
  });
});
