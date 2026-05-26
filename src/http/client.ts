import { KSeFNetworkError } from "../errors.js";
import type { ILogger } from "../logger.js";

type TTimeouts = {
  readonly DEFAULT: number;
  readonly AUTH: number;
};

export const TIMEOUTS = Object.freeze<TTimeouts>({
  DEFAULT: 30_000,
  AUTH: 60_000,
});

const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RETRY_AFTER_MS = 60_000;

type TRequestOptions = {
  readonly method?: "GET" | "POST";
  readonly headers?: Record<string, string>;
  readonly body?: string;
  readonly timeoutMs?: number;
  readonly maxRetries?: number;
  readonly logger?: ILogger;
};

export interface IHttpResponse<T = unknown> {
  readonly status: number;
  readonly data: T;
}

/**
 * Performs an HTTP request with timeout, automatic JSON parsing, and 429 retry logic.
 * Wraps native `fetch` with KSeF-specific defaults (JSON content type, abort timeout)
 * and translates network/timeout failures into `KSeFNetworkError`.
 *
 * @param {string} url - Absolute URL to call.
 * @param {TRequestOptions} options - Request options (method, headers, body, timeoutMs, maxRetries, logger).
 * @returns {Promise<IHttpResponse<T>>} HTTP status code and parsed JSON body.
 * @throws {KSeFNetworkError} On network failures, timeouts, exhausted rate-limit retries, or non-JSON bodies on error responses.
 */
export async function httpRequest<T = unknown>(
  url: string,
  options: TRequestOptions = {},
): Promise<IHttpResponse<T>> {
  const {
    method = "GET",
    headers = {},
    body,
    timeoutMs = TIMEOUTS.DEFAULT,
    maxRetries = DEFAULT_MAX_RETRIES,
    logger,
  } = options;

  const mergedHeaders: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
    ...headers,
  };

  let attempt = 0;

  while (attempt <= maxRetries) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    logger?.debug(`${method} ${url}`);

    let response: Response;
    try {
      response = await fetch(url, {
        method,
        headers: mergedHeaders,
        body,
        signal: controller.signal,
      });
    } catch (err: unknown) {
      clearTimeout(timer);
      const isTimeout = err instanceof Error && err.name === "AbortError";
      const message = isTimeout
        ? `Request timed out after ${timeoutMs}ms: ${method} ${url}`
        : `Network error: ${method} ${url} — ${err instanceof Error ? err.message : String(err)}`;
      throw new KSeFNetworkError(message, err);
    }
    clearTimeout(timer);

    // Rate limiting — retry after waiting
    if (response.status === 429) {
      if (attempt >= maxRetries) {
        throw new KSeFNetworkError(
          `Rate limit exceeded after ${maxRetries} attempts: ${method} ${url}`,
        );
      }
      const retryAfterHeader = response.headers.get("Retry-After");
      const retryAfterMs = retryAfterHeader
        ? Number.parseInt(retryAfterHeader, 10) * 1000
        : DEFAULT_RETRY_AFTER_MS;
      logger?.warn(
        `HTTP 429 — retrying in ${retryAfterMs / 1000}s (attempt ${attempt + 1}/${maxRetries})`,
      );
      await new Promise((resolve) => setTimeout(resolve, retryAfterMs));
      attempt++;
      continue;
    }

    let data: T;
    try {
      data = (await response.json()) as T;
    } catch {
      // For error HTTP responses, body may not be JSON — still propagate the status code
      if (!response.ok) {
        throw new KSeFNetworkError(
          `HTTP ${response.status} error from ${method} ${url} (non-JSON response body)`,
        );
      }
      throw new KSeFNetworkError(
        `Failed to parse JSON response from ${method} ${url} (HTTP ${response.status})`,
      );
    }

    logger?.debug(`${method} ${url} → HTTP ${response.status}`);

    return { status: response.status, data };
  }

  // Unreachable — loop always returns or throws, but TypeScript needs this
  throw new KSeFNetworkError(`Unexpected error in httpRequest: ${method} ${url}`);
}
