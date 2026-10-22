import { readCookie } from './cookies.ts';
import type { RuntimeConfig } from './types.ts';
import { base64UrlDecode, base64UrlEncode } from './utils.ts';

export const SESSION_COOKIE_NAME = 'zeroauth_session';
export const BROWSER_COOKIE_NAME = 'zeroauth_browser';
export const BROWSER_COOKIE_TTL_SECONDS = 3600;

const SESSION_VERSION = 'v1';
const BROWSER_ID_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

/**
 * The session is a signed stateless cookie: `v1.<expiresAt>.<hmac>`.
 * Signing key material is derived from values the Worker already holds, so no extra
 * secret is required. Rotating the client secret or kid invalidates existing sessions.
 */
function keyMaterial(config: RuntimeConfig): string {
  return `zeroauth-session|${config.kid}|${config.clientSecret}`;
}

async function hmacKey(config: RuntimeConfig): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(keyMaterial(config)),
    { hash: 'SHA-256', name: 'HMAC' },
    false,
    ['sign', 'verify'],
  );
}

export async function createSessionValue(
  config: RuntimeConfig,
  nowMs = Date.now(),
): Promise<string> {
  const expiresAt = Math.floor(nowMs / 1000) + config.sessionTtlSeconds;
  const payload = `${SESSION_VERSION}.${expiresAt}`;
  const signature = await crypto.subtle.sign(
    'HMAC',
    await hmacKey(config),
    new TextEncoder().encode(payload),
  );

  return `${payload}.${base64UrlEncode(new Uint8Array(signature))}`;
}

export async function hasValidSession(
  request: Request,
  config: RuntimeConfig,
  nowMs = Date.now(),
): Promise<boolean> {
  if (config.sessionTtlSeconds <= 0) {
    return false;
  }

  const value = readCookie(request, SESSION_COOKIE_NAME);

  if (!value) {
    return false;
  }

  const parts = value.split('.');

  if (parts.length !== 3) {
    return false;
  }

  const [version, expiresRaw, signature] = parts;

  if (version !== SESSION_VERSION) {
    return false;
  }

  const expiresAt = Number.parseInt(expiresRaw ?? '', 10);
  const nowSeconds = Math.floor(nowMs / 1000);

  if (!Number.isInteger(expiresAt) || expiresAt <= nowSeconds) {
    return false;
  }

  // Reject absurd lifetimes even if the signature happens to be valid (clock skew guard).
  if (expiresAt > nowSeconds + config.sessionTtlSeconds + 60) {
    return false;
  }

  let signatureBytes: Uint8Array<ArrayBuffer>;

  try {
    signatureBytes = base64UrlDecode(signature ?? '');
  } catch {
    return false;
  }

  return crypto.subtle.verify(
    'HMAC',
    await hmacKey(config),
    signatureBytes,
    new TextEncoder().encode(`${version}.${expiresRaw}`),
  );
}

export function isValidBrowserId(value: string | null): value is string {
  return value !== null && BROWSER_ID_PATTERN.test(value);
}
