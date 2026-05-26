import { getChallenge } from "./auth/challenge.js";
import { encryptKsefToken } from "./auth/crypto.js";
import { fetchPublicKey, normalizePem, validatePublicKey } from "./auth/public-key.js";
import { pollAuthStatus, redeemToken, refreshTokens, submitAuth } from "./auth/token-auth.js";
import { KSeFPublicKeyError } from "./errors.js";
import type { ILogger } from "./logger.js";
import { resolveLogger } from "./logger.js";
import { isTokenValid } from "./token/jwt.js";
import type { TKSeFAuthOptions, TLoginOptions, TLoginReturn, TRefreshReturn } from "./types.js";

type TResolvePublicKeyReturn = {
  readonly pem: string;
  readonly fetched: boolean;
};

/**
 * Authentication client for KSeF (Krajowy System e-Faktur — Polish National e-Invoice System).
 *
 * Each instance is fully isolated, making it safe for multi-tenant environments
 * where many entities (NIPs) authenticate concurrently in a single application.
 *
 * @example
 * ```typescript
 * const auth = new KSeFAuth({
 *   baseUrl: 'https://ksef-demo.mf.gov.pl/api',
 *   nip: '1234567890',
 *   ksefToken: '...KSeF token contents...',
 *   autoFetchPublicKey: true,
 * });
 *
 * const { accessToken, refreshToken, publicKey } = await auth.login();
 * // If publicKey is present, persist it for future use
 * ```
 */
export class KSeFAuth {
  private readonly baseUrl: string;
  private readonly nip: string;
  private readonly ksefToken: string;
  private readonly providedPublicKey: string | undefined;
  private readonly autoFetchPublicKey: boolean;
  private readonly logger: ILogger;

  constructor(options: TKSeFAuthOptions) {
    this.baseUrl = options.baseUrl;
    this.nip = options.nip;
    this.ksefToken = options.ksefToken;
    this.providedPublicKey = options.publicKey;
    this.autoFetchPublicKey = options.autoFetchPublicKey ?? false;
    this.logger = resolveLogger(options.logger);
  }

  /**
   * Returns valid JWT tokens using the minimum number of API calls:
   *
   * 1. If `tokens.accessToken` is still valid → returned immediately, no API call made.
   * 2. If `accessToken` expired but `refreshToken` is valid and `autoRefresh !== false` → refreshed.
   * 3. Otherwise → runs the full 7-step KSeF authentication flow.
   *
   * @param {TLoginOptions} options - Optional existing tokens and `autoRefresh` flag.
   * @returns {Promise<TLoginReturn>} JWT tokens and optionally a new public key (when auto-fetched from the API).
   * @throws {KSeFPublicKeyError} When the public key is missing or invalid.
   * @throws {KSeFChallengeError} When fetching the challenge from the API fails.
   * @throws {KSeFTokenError} When authentication is rejected by KSeF.
   * @throws {KSeFNetworkError} When a network or HTTP error occurs.
   */
  async login(options: TLoginOptions = {}): Promise<TLoginReturn> {
    const { tokens, autoRefresh = true } = options;

    // 1. accessToken is still valid — return without any API call
    if (tokens?.accessToken && isTokenValid(tokens.accessToken)) {
      this.logger.debug("Access token is valid — reusing");
      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken ?? "",
      };
    }

    // 2. refreshToken still valid and autoRefresh enabled — refresh
    if (autoRefresh && tokens?.refreshToken && isTokenValid(tokens.refreshToken)) {
      this.logger.info("Access token expired — refreshing via refresh token");
      const result = await refreshTokens(this.baseUrl, tokens.refreshToken, this.logger);
      return result;
    }

    // 3. Full 7-step flow
    this.logger.info("Starting full KSeF authentication flow");
    return this.runFullFlow();
  }

  /**
   * Forces a token refresh using the provided refresh token.
   * Does not check token validity beforehand — always makes an API call.
   *
   * @param {string} refreshToken - JWT refresh token.
   * @returns {Promise<TRefreshReturn>} New access and refresh tokens.
   * @throws {KSeFNetworkError} When a network or HTTP error occurs.
   */
  async refresh(refreshToken: string): Promise<TRefreshReturn> {
    this.logger.info("Forcing token refresh");
    return refreshTokens(this.baseUrl, refreshToken, this.logger);
  }

  /**
   * Fetches the current public key certificate from the KSeF API.
   * Use this to obtain a key to pass as `publicKey` in future instances.
   *
   * @returns {Promise<string>} Public key in PEM format.
   * @throws {KSeFPublicKeyError} When the API response does not contain a valid certificate.
   * @throws {KSeFNetworkError} When a network or HTTP error occurs.
   */
  async fetchPublicKey(): Promise<string> {
    return fetchPublicKey(this.baseUrl, this.logger);
  }

  /**
   * Synchronously checks whether a JWT token is still valid.
   *
   * @param {string} accessToken - JWT token to check.
   * @param {number} [bufferMinutes] - Early-expiry buffer in minutes — the token is considered
   *   expired `bufferMinutes` minutes before its actual expiry. Defaults to `0`.
   * @returns {boolean} `true` if the token is valid, `false` if expired or malformed.
   */
  isTokenValid(accessToken: string, bufferMinutes?: number): boolean {
    return isTokenValid(accessToken, bufferMinutes);
  }

  private async resolvePublicKey(): Promise<TResolvePublicKeyReturn> {
    if (this.providedPublicKey) {
      try {
        validatePublicKey(this.providedPublicKey);
        return { pem: normalizePem(this.providedPublicKey), fetched: false };
      } catch (err: unknown) {
        if (!this.autoFetchPublicKey) {
          throw err;
        }
        this.logger.warn(
          `Provided public key is invalid (${err instanceof Error ? err.message : String(err)}) — fetching from API`,
        );
      }
    } else if (!this.autoFetchPublicKey) {
      throw new KSeFPublicKeyError(
        "No public key provided. Set autoFetchPublicKey: true or provide publicKey.",
      );
    }

    const pem = await fetchPublicKey(this.baseUrl, this.logger);
    return { pem, fetched: true };
  }

  private async runFullFlow(): Promise<TLoginReturn> {
    // Step 1 — public key
    const { pem, fetched } = await this.resolvePublicKey();

    // Step 2 — challenge
    const { challenge, timestampMs } = await getChallenge(this.baseUrl, this.logger);

    // Step 3 — encryption
    this.logger.debug("Encrypting KSeF token (RSA-OAEP SHA-256)");
    const encryptedToken = encryptKsefToken(this.ksefToken, timestampMs, pem);

    // Step 4 — submit
    const { authenticationToken, referenceNumber } = await submitAuth(
      this.baseUrl,
      this.nip,
      challenge,
      encryptedToken,
      this.logger,
    );

    // Step 5 — polling
    await pollAuthStatus(this.baseUrl, referenceNumber, authenticationToken.token, this.logger);

    // Step 6 — redeem
    const { accessToken, refreshToken } = await redeemToken(
      this.baseUrl,
      authenticationToken.token,
      this.logger,
    );

    this.logger.info("KSeF authentication successful");

    // Step 7 — return tokens (+ publicKey if auto-fetched)
    return {
      accessToken,
      refreshToken,
      ...(fetched ? { publicKey: pem } : {}),
    };
  }
}
