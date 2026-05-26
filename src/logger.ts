export interface ILogger {
  debug: (message: string) => void;
  info: (message: string) => void;
  warn: (message: string) => void;
  error: (message: string) => void;
}

const consoleLogger: ILogger = {
  debug: (message) => console.log(`[ksef-login] DEBUG ${message}`),
  info: (message) => console.log(`[ksef-login] INFO  ${message}`),
  warn: (message) => console.warn(`[ksef-login] WARN  ${message}`),
  error: (message) => console.error(`[ksef-login] ERROR ${message}`),
};

const nullLogger: ILogger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

/**
 * Resolves a logger configuration value into a concrete `ILogger` instance.
 *
 * - `true` → returns the built-in console-based logger.
 * - `ILogger` object → returned as-is.
 * - `false` / `undefined` → returns a silent no-op logger.
 *
 * @param {ILogger | boolean} [logger] - Logger configuration.
 * @returns {ILogger} The resolved logger instance.
 */
export function resolveLogger(logger?: ILogger | boolean): ILogger {
  if (logger === true) return consoleLogger;
  if (logger && typeof logger === "object") return logger;
  return nullLogger;
}
