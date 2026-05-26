import { X509Certificate } from "node:crypto";
import { KSeFPublicKeyError } from "../errors.js";
import { httpRequest } from "../http/client.js";
import type { ILogger } from "../logger.js";

const PUBLIC_KEY_ENDPOINT = "/v2/security/public-key-certificates";
const USAGE_KSEF_TOKEN_ENCRYPTION = "KsefTokenEncryption";

interface IApiCertificate {
  readonly certificate: string;
  readonly usage: readonly string[];
  readonly validFrom: string;
  readonly validTo: string;
}

/**
 * Wraps a raw base64 DER certificate body into a PEM-formatted X.509 certificate
 * by inserting line breaks every 64 characters and adding BEGIN/END markers.
 *
 * @param {string} base64Der - Raw base64-encoded DER certificate body (no PEM markers).
 * @returns {string} PEM-formatted certificate.
 */
function derBase64ToPem(base64Der: string): string {
  const lines = base64Der.match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
}

/**
 * Normalizes a public key input (PEM or raw base64 DER) into canonical PEM form
 * with a trailing newline. Inputs already starting with `-----BEGIN` are passed
 * through; raw base64 is wrapped as a certificate.
 *
 * @param {string} input - Public key as PEM or raw base64 DER.
 * @returns {string} PEM-formatted certificate with trailing newline.
 */
function normalizeToPem(input: string): string {
  const trimmed = input.trim();
  if (trimmed.startsWith("-----BEGIN")) {
    return trimmed.endsWith("\n") ? trimmed : `${trimmed}\n`;
  }
  // Raw base64 — wrap as PEM certificate
  return derBase64ToPem(trimmed);
}

/**
 * Validates that a public key can be parsed as an X.509 certificate and has not expired.
 *
 * @param {string} publicKey - Public key as PEM or raw base64 DER.
 * @returns {void}
 * @throws {KSeFPublicKeyError} When the certificate cannot be parsed or has expired.
 */
export function validatePublicKey(publicKey: string): void {
  const pem = normalizeToPem(publicKey);
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(pem);
  } catch (err: unknown) {
    throw new KSeFPublicKeyError("Invalid public key — cannot parse X.509 certificate", err);
  }

  const validTo = new Date(cert.validTo);
  if (validTo < new Date()) {
    throw new KSeFPublicKeyError(`Public key certificate has expired (validTo: ${cert.validTo})`);
  }
}

/**
 * Normalizes a public key input (PEM or raw base64 DER) into canonical PEM form.
 * Public wrapper around the internal `normalizeToPem` helper.
 *
 * @param {string} publicKey - Public key as PEM or raw base64 DER.
 * @returns {string} PEM-formatted certificate with trailing newline.
 */
export function normalizePem(publicKey: string): string {
  return normalizeToPem(publicKey);
}

/**
 * Fetches the current `KsefTokenEncryption` public key certificate from the KSeF API.
 * Filters the response for certificates that are currently valid (validFrom ≤ now < validTo)
 * and marked for KSeF token encryption usage, then returns the one with the latest expiry.
 *
 * @param {string} baseUrl - Base URL of the KSeF API.
 * @param {ILogger} [logger] - Optional logger for diagnostics.
 * @returns {Promise<string>} PEM-formatted certificate of the selected public key.
 * @throws {KSeFPublicKeyError} When the API returns no usable certificate or a non-success status.
 * @throws {KSeFNetworkError} When a network or HTTP error occurs.
 */
export async function fetchPublicKey(baseUrl: string, logger?: ILogger): Promise<string> {
  const url = `${baseUrl}${PUBLIC_KEY_ENDPOINT}`;
  logger?.debug(`Fetching public key certificate from ${url}`);

  const response = await httpRequest<IApiCertificate[]>(url, { logger });

  if (![200, 201, 202].includes(response.status)) {
    throw new KSeFPublicKeyError(
      `Failed to fetch public key certificates: HTTP ${response.status}`,
    );
  }

  const certificates = response.data;
  if (!Array.isArray(certificates) || certificates.length === 0) {
    throw new KSeFPublicKeyError("No certificates returned from API");
  }

  const now = new Date();
  const valid = certificates.filter(
    (c) =>
      c.usage.includes(USAGE_KSEF_TOKEN_ENCRYPTION) &&
      new Date(c.validFrom) <= now &&
      new Date(c.validTo) > now,
  );

  if (valid.length === 0) {
    const usages = certificates.map((c) => c.usage.join(",")).join(" | ");
    throw new KSeFPublicKeyError(
      `No valid KsefTokenEncryption certificate found. Available usages: ${usages}`,
    );
  }

  // Select certificate with the latest validTo
  const best = valid.reduce((a, b) => (new Date(a.validTo) >= new Date(b.validTo) ? a : b));

  logger?.debug(`Using certificate valid until ${best.validTo}`);
  return derBase64ToPem(best.certificate);
}
