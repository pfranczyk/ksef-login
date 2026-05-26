# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-26

Initial public release of `@pfranczyk/ksef-login` — a zero-dependency
Node.js library for obtaining and refreshing JWT tokens against the Polish
KSeF API.

### Features
- `KSeFAuth` class — single public entry point; every instance is fully
  isolated (multi-tenant safe — many NIPs authenticating concurrently).
- `login()` — full 7-step KSeF authentication flow with smart token
  reuse (`autoRefresh` configurable).
- `refresh()` — forced token refresh from a refresh token.
- `fetchPublicKey()` — retrieves the current KSeF public-key certificate.
- `isTokenValid()` — synchronous JWT validity check with early-expiry buffer.
- Public-key handling: accepts provided PEM/base64, or fetches from API
  when `autoFetchPublicKey` is enabled.
- Typed error hierarchy: `KSeFAuthError` + 4 specialized subclasses.
- Pluggable logging via `ILogger` (`false` | `true` | custom).
- HTTP layer with per-request timeouts and HTTP 429 retry (honors
  `Retry-After`).
- Zero runtime dependencies (native `node:crypto`); Node.js ≥ 20.
- Dual build: ESM + CJS + bundled TypeScript declarations.
