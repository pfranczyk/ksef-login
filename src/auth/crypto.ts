import { constants, createPublicKey, publicEncrypt } from "node:crypto";
import { KSeFPublicKeyError } from "../errors.js";

/**
 * Encrypts the KSeF token together with the challenge timestamp using RSA-OAEP (SHA-256).
 * Implements step 3 of the auth flow: the payload `"{ksefToken}|{timestampMs}"` is
 * encrypted with the KSeF public key and the result is base64-encoded.
 *
 * @param {string} ksefToken - KSeF token value (not a file path).
 * @param {number} timestampMs - Timestamp returned by the challenge endpoint.
 * @param {string} pemCertificate - KSeF public key in PEM format.
 * @returns {string} Base64-encoded ciphertext ready for the `/v2/auth/ksef-token` endpoint.
 * @throws {KSeFPublicKeyError} When the certificate cannot be parsed or encryption fails.
 */
export function encryptKsefToken(
  ksefToken: string,
  timestampMs: number,
  pemCertificate: string,
): string {
  const payload = `${ksefToken}|${timestampMs}`;

  let publicKey: ReturnType<typeof createPublicKey>;
  try {
    publicKey = createPublicKey({ key: pemCertificate, format: "pem" });
  } catch (err: unknown) {
    throw new KSeFPublicKeyError("Failed to load public key from certificate for encryption", err);
  }

  let encrypted: Buffer;
  try {
    encrypted = publicEncrypt(
      {
        key: publicKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(payload, "utf8"),
    );
  } catch (err: unknown) {
    throw new KSeFPublicKeyError("RSA-OAEP encryption failed", err);
  }

  return encrypted.toString("base64");
}
