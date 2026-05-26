import { describe, expect, it } from "vitest";
import {
  KSeFAuthError,
  KSeFChallengeError,
  KSeFNetworkError,
  KSeFPublicKeyError,
  KSeFTokenError,
} from "./errors.js";

describe("KSeFAuthError", () => {
  it("sets name, message and is instanceof Error", () => {
    const err = new KSeFAuthError("test message");
    expect(err.name).toBe("KSeFAuthError");
    expect(err.message).toBe("test message");
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(KSeFAuthError);
  });

  it("sets cause when provided", () => {
    const cause = new Error("root cause");
    const err = new KSeFAuthError("test", cause);
    expect(err.cause).toBe(cause);
  });

  // The constructor only assigns `this.cause` when cause !== undefined,
  // so the property should remain unset — not just falsy.
  it("does not set cause when not provided", () => {
    const err = new KSeFAuthError("test");
    expect(err.cause).toBeUndefined();
  });
});

describe("KSeFPublicKeyError", () => {
  // Verifies the full inheritance chain: KSeFPublicKeyError → KSeFAuthError → Error.
  // Consumers can catch at any level of the hierarchy.
  it("sets correct name and extends KSeFAuthError", () => {
    const err = new KSeFPublicKeyError("bad key");
    expect(err.name).toBe("KSeFPublicKeyError");
    expect(err).toBeInstanceOf(KSeFAuthError);
    expect(err).toBeInstanceOf(KSeFPublicKeyError);
  });

  it("propagates cause", () => {
    const cause = new Error("x509 parse failed");
    const err = new KSeFPublicKeyError("bad key", cause);
    expect(err.cause).toBe(cause);
  });
});

describe("KSeFChallengeError", () => {
  it("sets correct name and extends KSeFAuthError", () => {
    const err = new KSeFChallengeError("challenge failed");
    expect(err.name).toBe("KSeFChallengeError");
    expect(err).toBeInstanceOf(KSeFAuthError);
    expect(err).toBeInstanceOf(KSeFChallengeError);
  });

  it("propagates cause", () => {
    const cause = new Error("network issue");
    const err = new KSeFChallengeError("challenge failed", cause);
    expect(err.cause).toBe(cause);
  });
});

describe("KSeFTokenError", () => {
  it("sets correct name and extends KSeFAuthError", () => {
    const err = new KSeFTokenError("token error");
    expect(err.name).toBe("KSeFTokenError");
    expect(err).toBeInstanceOf(KSeFAuthError);
    expect(err).toBeInstanceOf(KSeFTokenError);
  });
});

describe("KSeFNetworkError", () => {
  it("sets correct name and extends KSeFAuthError", () => {
    const err = new KSeFNetworkError("network error");
    expect(err.name).toBe("KSeFNetworkError");
    expect(err).toBeInstanceOf(KSeFAuthError);
    expect(err).toBeInstanceOf(KSeFNetworkError);
  });
});
