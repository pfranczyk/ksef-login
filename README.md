# @logrox/ksef-login

A lightweight, zero-dependency Node.js library for authenticating with the Polish **KSeF** (Krajowy System e-Faktur) API. Obtain and refresh JWT tokens using the official 7-step KSeF authentication flow.

[![npm version](https://img.shields.io/npm/v/@logrox/ksef-login)](https://www.npmjs.com/package/@logrox/ksef-login)
[![Node.js ≥ 20](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](https://nodejs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Features

- Full 7-step KSeF authentication flow
- Automatic token validation — skips API calls when your existing tokens are still valid
- Automatic token refresh via refresh token
- RSA-OAEP (SHA-256) encryption using **native `node:crypto`** — zero runtime dependencies
- Multi-tenant safe — every instance is fully isolated, no shared state
- TypeScript-first with complete type definitions
- Flexible logging — silent, console, or bring your own logger

---

## Requirements

- **Node.js ≥ 20**
- A valid KSeF token issued for your NIP
- The KSeF public key certificate (or enable `autoFetchPublicKey`)

---

## Installation

```bash
npm install @logrox/ksef-login
```

---

## Quick Start

```typescript
import { KSeFAuth } from "@logrox/ksef-login";

const auth = new KSeFAuth({
  baseUrl: "https://ksef-demo.mf.gov.pl/api",
  nip: "1234567890",
  ksefToken: "<your KSeF token string>",
  autoFetchPublicKey: true,
  logger: true,
});

const { accessToken, refreshToken, publicKey } = await auth.login();

// If publicKey is returned, it was freshly fetched — save it for future use
if (publicKey) {
  await savePublicKey(publicKey); // your storage logic
}

// Use accessToken to call other KSeF API endpoints
console.log(accessToken);
```

---

## Constructor

```typescript
new KSeFAuth(options: KSeFAuthOptions)
```

| Option | Type | Required | Default | Description |
|---|---|---|---|---|
| `baseUrl` | `string` | ✓ | — | Full KSeF API base URL (see [Environments](#environments)) |
| `nip` | `string` | ✓ | — | NIP of the entity being authenticated |
| `ksefToken` | `string` | ✓ | — | KSeF token contents (not a file path) |
| `publicKey` | `string` | — | `undefined` | PEM certificate or raw base64 DER |
| `autoFetchPublicKey` | `boolean` | — | `false` | Auto-fetch the public key from API when missing or invalid |
| `logger` | `boolean \| ILogger` | — | `false` | `false` = silent, `true` = console, or a custom logger |

### Environments

The `baseUrl` is always provided by you — this library contains no hardcoded URLs.

| Environment | URL |
|---|---|
| Demo | `https://ksef-demo.mf.gov.pl/api` |
| Test | `https://ksef-test.mf.gov.pl/api` |
| Production | `https://ksef.mf.gov.pl/api` |

---

## Methods

### `login(options?)`

The main method. Handles token validation, refresh, and full authentication flow automatically.

```typescript
const result = await auth.login(options?: LoginOptions);
// → Promise<LoginResult>
```

**Options:**

| Option | Type | Default | Description |
|---|---|---|---|
| `tokens` | `{ accessToken?: string; refreshToken?: string }` | `undefined` | Existing tokens to validate before making any API call |
| `autoRefresh` | `boolean` | `true` | Refresh via `refreshToken` when `accessToken` is expired |

**Decision logic:**

```
1. tokens.accessToken is valid?
   → return it immediately (no API calls)

2. tokens.accessToken expired + tokens.refreshToken valid + autoRefresh: true?
   → POST /v2/auth/token/refresh → return new tokens

3. No tokens, or both expired?
   → Run full 7-step authentication flow → return new tokens
```

**Returns:** `LoginResult`

| Field | Type | Description |
|---|---|---|
| `accessToken` | `string` | JWT access token |
| `refreshToken` | `string` | JWT refresh token |
| `publicKey` | `string \| undefined` | Newly fetched PEM certificate — **only present when `autoFetchPublicKey: true` and a fresh key was fetched**. Save it for future use. |

**Examples:**

```typescript
// First login — no existing tokens
const { accessToken, refreshToken, publicKey } = await auth.login();

// Subsequent calls — reuse tokens, library decides what to do
const result = await auth.login({
  tokens: { accessToken, refreshToken },
});

// Opt out of auto-refresh
const result = await auth.login({
  tokens: { accessToken, refreshToken },
  autoRefresh: false,
});
```

---

### `refresh(refreshToken)`

Force-refreshes tokens using the refresh token, without any validity check.

```typescript
const result = await auth.refresh(refreshToken: string);
// → Promise<RefreshResult>
```

**Returns:** `{ accessToken: string; refreshToken: string }`

```typescript
const { accessToken, refreshToken: newRefreshToken } = await auth.refresh(refreshToken);
```

---

### `fetchPublicKey()`

Fetches the current KSeF public key certificate from the API. Returns a PEM-formatted X.509 certificate.

```typescript
const pem = await auth.fetchPublicKey();
// → Promise<string>
```

Use this to obtain and persist the public key before constructing future `KSeFAuth` instances with the `publicKey` option.

```typescript
const publicKey = await auth.fetchPublicKey();
await db.save("ksef_public_key", publicKey);
```

---

### `isTokenValid(accessToken, bufferMinutes?)`

Synchronous utility. Returns `true` if the JWT token's expiry is still in the future (minus an optional buffer).

```typescript
auth.isTokenValid(accessToken: string, bufferMinutes?: number): boolean
```

| Parameter | Default | Description |
|---|---|---|
| `bufferMinutes` | `5` | Consider the token expired this many minutes before actual expiry |

```typescript
if (!auth.isTokenValid(accessToken)) {
  // token expired or expiring within 5 minutes
}

if (!auth.isTokenValid(accessToken, 0)) {
  // token strictly expired
}
```

---

## Public Key Management

The public key (X.509 certificate) is required for the RSA-OAEP encryption step. KSeF certificates rotate periodically.

**Recommended workflow:**

```typescript
// 1. On first run — let the library fetch the key for you
const auth = new KSeFAuth({ ..., autoFetchPublicKey: true });
const { accessToken, refreshToken, publicKey } = await auth.login();

if (publicKey) {
  // A fresh key was fetched — persist it
  await db.save("ksef_public_key", publicKey);
}

// 2. On subsequent runs — provide the saved key
const savedKey = await db.load("ksef_public_key");
const auth = new KSeFAuth({ ..., publicKey: savedKey });

try {
  const { accessToken, refreshToken } = await auth.login();
} catch (err) {
  if (err instanceof KSeFPublicKeyError) {
    // Certificate expired or invalid — re-fetch
    const newKey = await auth.fetchPublicKey();
    await db.save("ksef_public_key", newKey);
    // retry...
  }
}
```

**Behaviour summary:**

| Scenario | `autoFetchPublicKey` | Result |
|---|---|---|
| `publicKey` provided and valid | any | Used directly, `publicKey` not returned in result |
| `publicKey` provided but invalid/expired | `false` | Throws `KSeFPublicKeyError` |
| `publicKey` provided but invalid/expired | `true` | Auto-fetches, returns new `publicKey` in result |
| No `publicKey` provided | `false` | Throws `KSeFPublicKeyError` |
| No `publicKey` provided | `true` | Auto-fetches, returns new `publicKey` in result |

---

## Error Handling

All errors extend `KSeFAuthError` and include a descriptive `message`. The `cause` property contains the original error when applicable.

```typescript
import {
  KSeFAuthError,
  KSeFPublicKeyError,
  KSeFChallengeError,
  KSeFTokenError,
  KSeFNetworkError,
} from "@logrox/ksef-login";
```

| Class | Thrown when |
|---|---|
| `KSeFAuthError` | Base class — catch this to handle all KSeF errors |
| `KSeFPublicKeyError` | Certificate is missing, invalid, expired, or from wrong environment |
| `KSeFChallengeError` | Failed to obtain auth challenge from API |
| `KSeFTokenError` | Submit, polling, or redeem step failed |
| `KSeFNetworkError` | HTTP error, timeout, or JSON parse failure |

```typescript
import { KSeFAuthError, KSeFPublicKeyError, KSeFNetworkError } from "@logrox/ksef-login";

try {
  const result = await auth.login({ tokens });
} catch (err) {
  if (err instanceof KSeFPublicKeyError) {
    console.error("Public key problem — re-fetch and save a new one");
  } else if (err instanceof KSeFNetworkError) {
    console.error("Network issue — retry later:", err.message);
  } else if (err instanceof KSeFAuthError) {
    console.error("KSeF auth error:", err.message);
  } else {
    throw err; // unexpected
  }
}
```

---

## Logging

```typescript
interface ILogger {
  debug: (message: string) => void;
  info:  (message: string) => void;
  warn:  (message: string) => void;
  error: (message: string) => void;
}
```

```typescript
// Silent (default)
new KSeFAuth({ ..., logger: false });

// Built-in console logger
new KSeFAuth({ ..., logger: true });

// Custom logger (e.g. pino, winston)
new KSeFAuth({ ..., logger: pinoInstance });
```

---

## Multi-Tenant Usage

This library is safe for concurrent multi-tenant environments. Each `KSeFAuth` instance is fully isolated — no module-level state, no static caches. Calls for entity A cannot affect entity B.

```typescript
const authA = new KSeFAuth({ baseUrl, nip: nipA, ksefToken: tokenA, publicKey: keyA });
const authB = new KSeFAuth({ baseUrl, nip: nipB, ksefToken: tokenB, publicKey: keyB });

// Safe to run concurrently
const [resultA, resultB] = await Promise.all([
  authA.login({ tokens: tokensA }),
  authB.login({ tokens: tokensB }),
]);
```

---

## TypeScript

Full TypeScript support is included. All public types are exported from the package root.

```typescript
import type {
  KSeFAuthOptions,
  LoginOptions,
  LoginResult,
  RefreshResult,
  ILogger,
} from "@logrox/ksef-login";
```

---

## Authentication Flow

For reference, `login()` without valid existing tokens executes the following 7-step flow:

```
1. Validate / fetch public key certificate
2. POST /v2/auth/challenge → { challenge, timestampMs }
3. Encrypt: RSA-OAEP(SHA-256) on payload "ksefToken|timestampMs"
4. POST /v2/auth/ksef-token → { authenticationToken, referenceNumber }
5. Poll GET /v2/auth/{referenceNumber} until status.code === 200 (2s interval, 120s timeout)
6. POST /v2/auth/token/redeem → { accessToken, refreshToken }
7. Return tokens to caller
```

---

## License

MIT © [Paweł Franczyk](https://github.com/pfranczyk)
