import { KSeFChallengeError } from "../errors.js";
import { httpRequest, TIMEOUTS } from "../http/client.js";
import type { ILogger } from "../logger.js";
import type { IChallengeResponse } from "../types.js";

/**
 * Fetches an authentication challenge from the KSeF API (step 2 of the auth flow).
 * The challenge string is later concatenated with the KSeF token timestamp and
 * encrypted with the public key in step 3.
 *
 * @param {string} baseUrl - Base URL of the KSeF API.
 * @param {ILogger} [logger] - Optional logger for diagnostics.
 * @returns {Promise<IChallengeResponse>} Challenge value and server timestamp.
 * @throws {KSeFChallengeError} When the API responds with a non-success status or the response is malformed.
 * @throws {KSeFNetworkError} When a network or HTTP error occurs.
 */
export async function getChallenge(baseUrl: string, logger?: ILogger): Promise<IChallengeResponse> {
  const url = `${baseUrl}/v2/auth/challenge`;
  logger?.debug("Fetching auth challenge");

  const response = await httpRequest<IChallengeResponse>(url, {
    method: "POST",
    body: "{}",
    timeoutMs: TIMEOUTS.AUTH,
    logger,
  });

  if (![200, 201, 202].includes(response.status)) {
    throw new KSeFChallengeError(`Failed to get challenge: HTTP ${response.status}`);
  }

  const { challenge, timestampMs } = response.data;
  if (!challenge || timestampMs === undefined) {
    throw new KSeFChallengeError("Invalid challenge response — missing required fields");
  }

  logger?.debug(`Challenge received (timestamp: ${timestampMs})`);
  return { challenge, timestampMs };
}
