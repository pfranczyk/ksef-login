import { describe, expect, it, vi } from "vitest";
import { resolveLogger } from "./logger.js";

describe("resolveLogger", () => {
  it("returns a no-op logger for undefined — all methods are callable without throwing", () => {
    const logger = resolveLogger(undefined);
    expect(() => logger.debug("test")).not.toThrow();
    expect(() => logger.info("test")).not.toThrow();
    expect(() => logger.warn("test")).not.toThrow();
    expect(() => logger.error("test")).not.toThrow();
  });

  it("returns a no-op logger for false", () => {
    const logger = resolveLogger(false);
    expect(() => logger.debug("silent")).not.toThrow();
  });

  // Ensures the no-op logger is truly silent — not just non-throwing.
  // Libraries must never produce unexpected console output in user applications.
  it("no-op logger does not call any console methods", () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const logger = resolveLogger(false);
    logger.debug("silent");
    expect(logSpy).not.toHaveBeenCalled();
    logSpy.mockRestore();
  });

  // Each console method is tested individually to catch any copy-paste mistake
  // in the consoleLogger implementation (e.g. warn accidentally calling console.log).
  it("returns console logger for true — debug calls console.log", () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    const logger = resolveLogger(true);
    logger.debug("hello");
    expect(spy).toHaveBeenCalledWith("[ksef-login] DEBUG hello");
    spy.mockRestore();
  });

  it("returns console logger for true — info calls console.log", () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    const logger = resolveLogger(true);
    logger.info("information");
    expect(spy).toHaveBeenCalledWith("[ksef-login] INFO  information");
    spy.mockRestore();
  });

  it("returns console logger for true — warn calls console.warn", () => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const logger = resolveLogger(true);
    logger.warn("warning");
    expect(spy).toHaveBeenCalledWith("[ksef-login] WARN  warning");
    spy.mockRestore();
  });

  it("returns console logger for true — error calls console.error", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const logger = resolveLogger(true);
    logger.error("failure");
    expect(spy).toHaveBeenCalledWith("[ksef-login] ERROR failure");
    spy.mockRestore();
  });

  // The custom logger must be used as-is — resolveLogger must not wrap or proxy it.
  it("returns the provided custom ILogger as-is", () => {
    const custom = {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    };
    const logger = resolveLogger(custom);
    logger.info("hello");
    expect(custom.info).toHaveBeenCalledWith("hello");
    expect(custom.debug).not.toHaveBeenCalled();
  });
});
