/**
 * Base error class for all KSeF authentication errors raised by this package.
 * All specialized auth errors inherit from this class so callers can catch a single type.
 */
export class KSeFAuthError extends Error {
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "KSeFAuthError";
    if (cause !== undefined) {
      this.cause = cause;
    }
  }
}

/**
 * Thrown when the KSeF public key is missing, malformed, expired, or cannot be used for encryption.
 */
export class KSeFPublicKeyError extends KSeFAuthError {
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "KSeFPublicKeyError";
  }
}

/**
 * Thrown when retrieving or validating the authentication challenge fails.
 */
export class KSeFChallengeError extends KSeFAuthError {
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "KSeFChallengeError";
  }
}

/**
 * Thrown when submitting, polling, redeeming, or refreshing tokens fails on the KSeF side.
 */
export class KSeFTokenError extends KSeFAuthError {
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "KSeFTokenError";
  }
}

/**
 * Thrown when a network failure, request timeout, or unexpected HTTP-level error occurs.
 */
export class KSeFNetworkError extends KSeFAuthError {
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "KSeFNetworkError";
  }
}
