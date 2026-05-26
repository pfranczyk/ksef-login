import { constants, generateKeyPairSync, privateDecrypt } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { KSeFPublicKeyError } from "../errors.js";
import { encryptKsefToken } from "./crypto.js";

let publicKeyPem: string;
let privateKeyPem: string;

// RSA key generation is expensive — done once for the entire suite.
// 2048-bit key matches the minimum recommended size for production RSA-OAEP.
beforeAll(() => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  publicKeyPem = publicKey as string;
  privateKeyPem = privateKey as string;
});

describe("encryptKsefToken", () => {
  it("returns a non-empty base64 string", () => {
    const result = encryptKsefToken("MY_TOKEN", 1700000000000, publicKeyPem);
    expect(typeof result).toBe("string");
    expect(result.length).toBeGreaterThan(0);
    expect(() => Buffer.from(result, "base64")).not.toThrow();
  });

  // This is the core correctness test: we encrypt with the public key and decrypt
  // with the private key to confirm that the plaintext payload is exactly
  // "ksefToken|timestampMs" — the format KSeF requires.
  it("encrypts the payload as 'ksefToken|timestampMs' — verified by decryption", () => {
    const ksefToken = "ABC-DEF-TOKEN-123";
    const timestampMs = 1700000000000;

    const encrypted = encryptKsefToken(ksefToken, timestampMs, publicKeyPem);

    const decrypted = privateDecrypt(
      {
        key: privateKeyPem,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(encrypted, "base64"),
    );

    expect(decrypted.toString("utf8")).toBe(`${ksefToken}|${timestampMs}`);
  });

  // Separate assertion that the '|' separator is present and positioned correctly,
  // guarding against accidental changes to the payload format (e.g. space or comma).
  it("payload contains token and timestamp separated by '|'", () => {
    const ksefToken = "TOKEN_WITH_SPECIAL_CHARS";
    const timestampMs = 9876543210123;

    const encrypted = encryptKsefToken(ksefToken, timestampMs, publicKeyPem);

    const decrypted = privateDecrypt(
      {
        key: privateKeyPem,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(encrypted, "base64"),
    );

    const parts = decrypted.toString("utf8").split("|");
    expect(parts[0]).toBe(ksefToken);
    expect(parts[1]).toBe(String(timestampMs));
  });

  it("throws KSeFPublicKeyError when PEM is invalid", () => {
    expect(() => encryptKsefToken("token", 123, "not-valid-pem")).toThrow(KSeFPublicKeyError);
  });

  it("throws KSeFPublicKeyError when PEM is an empty string", () => {
    expect(() => encryptKsefToken("token", 123, "")).toThrow(KSeFPublicKeyError);
  });

  // RSA-OAEP generates a fresh random seed on every call, so the same plaintext
  // produces a different ciphertext each time. This test guards against accidentally
  // switching to a deterministic padding scheme (e.g. PKCS1 v1.5).
  it("produces different ciphertext on each call due to RSA-OAEP random padding", () => {
    const r1 = encryptKsefToken("TOKEN", 12345, publicKeyPem);
    const r2 = encryptKsefToken("TOKEN", 12345, publicKeyPem);
    expect(r1).not.toBe(r2);
  });
});
