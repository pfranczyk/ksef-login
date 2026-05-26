import type { IJwtPayload } from "../types.js";

/**
 * Decodes the payload section of a JWT without verifying the signature.
 * Use only for reading non-sensitive claims such as `exp` — never for trust decisions.
 *
 * @param {string} token - JWT in compact serialization form (`header.payload.signature`).
 * @returns {IJwtPayload} Decoded payload claims.
 * @throws {Error} When the token does not have three parts or the payload is not valid JSON.
 */
export function decodeJwt(token: string): IJwtPayload {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format — expected 3 parts");
  }

  const payload = parts[1];
  // Base64url → Base64
  const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
  const json = Buffer.from(base64, "base64").toString("utf8");

  try {
    return JSON.parse(json) as IJwtPayload;
  } catch {
    throw new Error("Failed to parse JWT payload as JSON");
  }
}

/**
 * Checks whether a JWT is still valid based on its `exp` claim, optionally
 * treating it as expired earlier by `bufferMinutes`. A malformed token or one
 * without an `exp` claim is treated as invalid.
 *
 * @param {string} token - JWT to inspect.
 * @param {number} [bufferMinutes=5] - Early-expiry buffer in minutes.
 * @returns {boolean} `true` if the token is still valid, `false` otherwise.
 */
export function isTokenValid(token: string, bufferMinutes = 5): boolean {
  try {
    const payload = decodeJwt(token);
    if (payload.exp === undefined) return false;

    const expiresAt = payload.exp * 1000;
    const bufferMs = bufferMinutes * 60 * 1000;
    return Date.now() < expiresAt - bufferMs;
  } catch {
    return false;
  }
}
