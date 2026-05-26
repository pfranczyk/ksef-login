import type { ILogger } from "./logger.js";

// --- Constructor options ---

/**
 * Configuration options for a `KSeFAuth` instance.
 */
export type TKSeFAuthOptions = {
  /**
   * Base URL of the KSeF API, e.g. `'https://ksef-demo.mf.gov.pl/api'`.
   * The package contains no hardcoded URLs — you choose the environment.
   */
  readonly baseUrl: string;
  /** Polish tax identifier (NIP) of the entity, without dashes. */
  readonly nip: string;
  /**
   * Contents of the KSeF token as a string.
   * Do not pass a file path — this package does not touch the filesystem.
   */
  readonly ksefToken: string;
  /**
   * Optional KSeF public key (X.509 PEM certificate or raw base64).
   * If the key is invalid or expired, behavior depends on `autoFetchPublicKey`.
   */
  readonly publicKey?: string;
  /**
   * When `true`, an invalid or missing `publicKey` will be automatically fetched
   * from the KSeF API and returned in the `login()` result as `publicKey`.
   * @default false
   */
  readonly autoFetchPublicKey?: boolean;
  /**
   * Logger used by this instance.
   * - `false` or omitted → silent
   * - `true` → default implementation using `console`
   * - `ILogger` → your own logger implementation
   */
  readonly logger?: ILogger | boolean;
};

// --- Public method parameters and return types ---

/**
 * Options for the `login()` method.
 */
export type TLoginOptions = {
  /**
   * Existing tokens to validate before running the full authentication flow.
   * If `accessToken` is still valid, it is returned immediately without any API call.
   */
  readonly tokens?: {
    /** JWT access token. */
    readonly accessToken?: string;
    /** JWT refresh token. */
    readonly refreshToken?: string;
  };
  /**
   * When `true` and `accessToken` has expired but `refreshToken` is still valid,
   * tokens are refreshed automatically instead of running the full flow.
   * @default true
   */
  readonly autoRefresh?: boolean;
};

/**
 * Result returned by `login()`.
 */
export type TLoginReturn = {
  /** JWT access token. */
  readonly accessToken: string;
  /** JWT refresh token. */
  readonly refreshToken: string;
  /**
   * KSeF public key (PEM) — present **only** when `autoFetchPublicKey: true`
   * and the key had to be fetched from the API (missing or invalid).
   * Persist this value to avoid fetching it again on subsequent calls.
   */
  readonly publicKey?: string;
};

/**
 * Result returned by `refresh()`.
 */
export type TRefreshReturn = {
  /** New JWT access token. */
  readonly accessToken: string;
  /** New JWT refresh token. */
  readonly refreshToken: string;
};

// --- Internal API responses ---

export interface IChallengeResponse {
  readonly challenge: string;
  readonly timestampMs: number;
}

export interface ISubmitAuthResponse {
  readonly authenticationToken: {
    readonly token: string;
    readonly validUntil: string;
  };
  readonly referenceNumber: string;
}

export interface IPollAuthResponse {
  readonly status: {
    readonly code: number;
  };
  readonly processingCode?: number;
  readonly processingDescription?: string;
}

export interface ITokenValue {
  readonly token: string;
  readonly validUntil: string;
}

export interface IRedeemTokenResponse {
  readonly accessToken: string | ITokenValue;
  readonly refreshToken: string | ITokenValue;
}

// --- JWT payload ---

export interface IJwtPayload {
  readonly exp?: number;
  readonly iat?: number;
  readonly sub?: string;
  readonly [key: string]: unknown;
}
