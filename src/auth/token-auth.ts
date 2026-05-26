import { KSeFNetworkError, KSeFTokenError } from "../errors.js";
import { httpRequest, TIMEOUTS } from "../http/client.js";
import type { ILogger } from "../logger.js";
import type {
  IPollAuthResponse,
  IRedeemTokenResponse,
  ISubmitAuthResponse,
  ITokenValue,
  TRefreshReturn,
} from "../types.js";

const POLL_INTERVAL_MS = 2_000;
const POLL_TIMEOUT_MS = 120_000;

type TRedeemTokenReturn = {
  readonly accessToken: string;
  readonly refreshToken: string;
};

/**
 * Normalizes a KSeF token field that may be either a plain string or a `{ token, validUntil }` object.
 *
 * @param {string | ITokenValue} value - Token value as returned by the API.
 * @returns {string} The underlying token string.
 */
function extractTokenString(value: string | ITokenValue): string {
  if (typeof value === "string") return value;
  return value.token;
}

/**
 * Submits the encrypted KSeF token to the auth endpoint (step 4 of the auth flow).
 * Returns the authentication token and reference number used to poll for completion.
 *
 * @param {string} baseUrl - Base URL of the KSeF API.
 * @param {string} nip - Polish tax identifier of the entity being authenticated.
 * @param {string} challenge - Challenge string returned by `getChallenge`.
 * @param {string} encryptedToken - Base64-encoded RSA-OAEP ciphertext from `encryptKsefToken`.
 * @param {ILogger} [logger] - Optional logger for diagnostics.
 * @returns {Promise<ISubmitAuthResponse>} Authentication token and reference number.
 * @throws {KSeFTokenError} When the API responds with a non-success status or the response is malformed.
 * @throws {KSeFNetworkError} When a network or HTTP error occurs.
 */
export async function submitAuth(
  baseUrl: string,
  nip: string,
  challenge: string,
  encryptedToken: string,
  logger?: ILogger,
): Promise<ISubmitAuthResponse> {
  const url = `${baseUrl}/v2/auth/ksef-token`;
  logger?.debug("Submitting encrypted KSeF token");

  const body = JSON.stringify({
    challenge,
    contextIdentifier: { type: "Nip", value: nip },
    encryptedToken,
  });

  const response = await httpRequest<ISubmitAuthResponse>(url, {
    method: "POST",
    body,
    timeoutMs: TIMEOUTS.AUTH,
    logger,
  });

  if (![200, 201, 202].includes(response.status)) {
    throw new KSeFTokenError(`Failed to submit auth token: HTTP ${response.status}`);
  }

  const { authenticationToken, referenceNumber } = response.data;
  if (!authenticationToken?.token || !referenceNumber) {
    throw new KSeFTokenError("Invalid submit auth response — missing required fields");
  }

  logger?.debug(`Auth submitted, referenceNumber: ${referenceNumber}`);
  return response.data;
}

/**
 * Polls the KSeF auth status endpoint until the authentication completes (step 5 of the auth flow).
 * Returns successfully when status code 200 is reported; throws on rejection or timeout.
 *
 * @param {string} baseUrl - Base URL of the KSeF API.
 * @param {string} referenceNumber - Reference number returned by `submitAuth`.
 * @param {string} authToken - Authentication token used as Bearer credential.
 * @param {ILogger} [logger] - Optional logger for diagnostics.
 * @returns {Promise<void>} Resolves when authentication succeeds.
 * @throws {KSeFTokenError} When KSeF rejects the authentication, the HTTP status is non-200, or polling times out.
 * @throws {KSeFNetworkError} When a network or HTTP error occurs.
 */
export async function pollAuthStatus(
  baseUrl: string,
  referenceNumber: string,
  authToken: string,
  logger?: ILogger,
): Promise<void> {
  const url = `${baseUrl}/v2/auth/${referenceNumber}`;
  const deadline = Date.now() + POLL_TIMEOUT_MS;

  logger?.debug(`Polling auth status for referenceNumber: ${referenceNumber}`);

  while (Date.now() < deadline) {
    const response = await httpRequest<IPollAuthResponse>(url, {
      headers: { Authorization: `Bearer ${authToken}` },
      logger,
    });

    if (response.status === 200 && response.data.status?.code === 200) {
      logger?.debug("Auth status: success");
      return;
    }

    if (response.status !== 200) {
      throw new KSeFTokenError(`Auth polling failed: HTTP ${response.status}`);
    }

    const bodyCode = response.data.status?.code;
    if (bodyCode !== undefined && bodyCode >= 400) {
      throw new KSeFTokenError(
        `Authentication rejected by KSeF (code: ${bodyCode}${response.data.processingDescription ? ` — ${response.data.processingDescription}` : ""})`,
      );
    }

    logger?.debug(`Auth status code: ${bodyCode} — retrying in ${POLL_INTERVAL_MS}ms`);
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }

  throw new KSeFTokenError(`Auth polling timed out after ${POLL_TIMEOUT_MS / 1000}s`);
}

/**
 * Redeems an authentication token for access and refresh JWTs (step 6 of the auth flow).
 *
 * @param {string} baseUrl - Base URL of the KSeF API.
 * @param {string} authToken - Authentication token used as Bearer credential.
 * @param {ILogger} [logger] - Optional logger for diagnostics.
 * @returns {Promise<TRedeemTokenReturn>} Access and refresh JWTs.
 * @throws {KSeFTokenError} When the API responds with a non-success status or required tokens are missing.
 * @throws {KSeFNetworkError} When a network or HTTP error occurs.
 */
export async function redeemToken(
  baseUrl: string,
  authToken: string,
  logger?: ILogger,
): Promise<TRedeemTokenReturn> {
  const url = `${baseUrl}/v2/auth/token/redeem`;
  logger?.debug("Redeeming authentication token");

  const response = await httpRequest<IRedeemTokenResponse>(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${authToken}` },
    body: "{}",
    timeoutMs: TIMEOUTS.AUTH,
    logger,
  });

  if (![200, 201, 202].includes(response.status)) {
    throw new KSeFTokenError(`Failed to redeem token: HTTP ${response.status}`);
  }

  const { accessToken, refreshToken } = response.data;
  if (!accessToken || !refreshToken) {
    throw new KSeFTokenError("Invalid redeem response — missing tokens");
  }

  logger?.debug("Tokens redeemed successfully");
  return {
    accessToken: extractTokenString(accessToken),
    refreshToken: extractTokenString(refreshToken),
  };
}

/**
 * Refreshes an expired access token using a still-valid refresh token.
 * The KSeF PRD endpoint may omit the refreshToken in the response — in that case
 * the original refreshToken is preserved.
 *
 * @param {string} baseUrl - Base URL of the KSeF API.
 * @param {string} refreshToken - Existing JWT refresh token.
 * @param {ILogger} [logger] - Optional logger for diagnostics.
 * @returns {Promise<TRefreshReturn>} New access token plus refresh token (new one if returned, otherwise the original).
 * @throws {KSeFTokenError} When the API responds with a non-success status.
 * @throws {KSeFNetworkError} When the response is missing the accessToken or a network error occurs.
 */
export async function refreshTokens(
  baseUrl: string,
  refreshToken: string,
  logger?: ILogger,
): Promise<TRefreshReturn> {
  const url = `${baseUrl}/v2/auth/token/refresh`;
  logger?.debug("Refreshing access token");

  const response = await httpRequest<IRedeemTokenResponse>(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${refreshToken}` },
    body: "{}",
    timeoutMs: TIMEOUTS.AUTH,
    logger,
  });

  if (![200, 201, 202].includes(response.status)) {
    throw new KSeFTokenError(`Failed to refresh token: HTTP ${response.status}`);
  }

  const { accessToken, refreshToken: newRefreshToken } = response.data;
  if (!accessToken) {
    throw new KSeFNetworkError("Invalid refresh response — missing accessToken");
  }

  logger?.debug("Tokens refreshed successfully");
  return {
    accessToken: extractTokenString(accessToken),
    refreshToken: newRefreshToken ? extractTokenString(newRefreshToken) : refreshToken,
  };
}
