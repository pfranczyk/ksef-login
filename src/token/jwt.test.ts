import { describe, expect, it } from "vitest";
import { decodeJwt, isTokenValid } from "./jwt.js";

// Creates a syntactically valid JWT with the given payload.
// The signature part is intentionally fake — this library never verifies signatures,
// only reads the payload (exp, sub, etc.) from KSeF-issued tokens.
function makeJwt(payload: Record<string, unknown>): string {
  const encodeBase64url = (obj: object) =>
    Buffer.from(JSON.stringify(obj))
      .toString("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

  const header = encodeBase64url({ alg: "RS256", typ: "JWT" });
  const body = encodeBase64url(payload);
  return `${header}.${body}.fakesignature`;
}

function futureExp(minutesFromNow: number): number {
  return Math.floor((Date.now() + minutesFromNow * 60 * 1000) / 1000);
}

function pastExp(minutesAgo: number): number {
  return Math.floor((Date.now() - minutesAgo * 60 * 1000) / 1000);
}

describe("decodeJwt", () => {
  it("decodes a valid JWT payload", () => {
    const token = makeJwt({ sub: "12345", exp: 9999999999, custom: "value" });
    const payload = decodeJwt(token);
    expect(payload.sub).toBe("12345");
    expect(payload.exp).toBe(9999999999);
    expect(payload.custom).toBe("value");
  });

  it("throws for a token with fewer than 3 parts", () => {
    expect(() => decodeJwt("header.payload")).toThrow("Invalid JWT format");
    expect(() => decodeJwt("onlyonepart")).toThrow("Invalid JWT format");
  });

  it("throws for a token with more than 3 parts", () => {
    expect(() => decodeJwt("a.b.c.d")).toThrow("Invalid JWT format");
  });

  // Ensures the JSON.parse failure is caught and re-thrown with a descriptive message
  // rather than surfacing a raw SyntaxError to the consumer.
  it("throws when the payload is not valid JSON", () => {
    const badPayload = Buffer.from("not-valid-json").toString("base64url");
    expect(() => decodeJwt(`header.${badPayload}.sig`)).toThrow(
      "Failed to parse JWT payload as JSON",
    );
  });
});

describe("isTokenValid", () => {
  it("returns true when exp is well in the future (beyond buffer)", () => {
    const token = makeJwt({ exp: futureExp(60) }); // 60 minutes from now
    expect(isTokenValid(token)).toBe(true);
  });

  it("returns false for an expired token", () => {
    const token = makeJwt({ exp: pastExp(10) }); // expired 10 minutes ago
    expect(isTokenValid(token)).toBe(false);
  });

  // The buffer (default 5 min) prevents using a token that would expire mid-request.
  // A token expiring in 3 minutes is considered invalid despite not being expired yet.
  it("returns false when exp falls within the default buffer window (5 minutes)", () => {
    const token = makeJwt({ exp: futureExp(3) }); // expires in 3 min, buffer = 5 min
    expect(isTokenValid(token)).toBe(false);
  });

  it("returns true when exp is just beyond a custom buffer", () => {
    const token = makeJwt({ exp: futureExp(10) }); // expires in 10 minutes
    expect(isTokenValid(token, 8)).toBe(true); // buffer = 8 min → still valid
  });

  it("returns false when exp falls within a custom buffer window", () => {
    const token = makeJwt({ exp: futureExp(5) }); // expires in 5 minutes
    expect(isTokenValid(token, 10)).toBe(false); // buffer = 10 min → invalid
  });

  // KSeF tokens always have exp. If it's missing, we treat the token as invalid
  // rather than assuming it never expires.
  it("returns false when exp field is missing", () => {
    const token = makeJwt({ sub: "no-exp-here" });
    expect(isTokenValid(token)).toBe(false);
  });

  // isTokenValid must never throw — it's used as a guard in login() and should
  // safely return false for any malformed input.
  it("returns false for an invalid token string", () => {
    expect(isTokenValid("not-a-jwt")).toBe(false);
    expect(isTokenValid("")).toBe(false);
    expect(isTokenValid("a.b.c.d")).toBe(false);
  });
});
