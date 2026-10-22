import { LOGIN_ATTEMPT_WINDOW_SECONDS } from './attempts.ts';
import type { ZeroAuthStore } from './store-types.ts';

export {
  DEFAULT_MAX_LOGIN_ATTEMPTS,
  LOGIN_ATTEMPT_WINDOW_SECONDS,
  nextLoginAttemptState,
} from './attempts.ts';

/**
 * Keying is best effort. Cloudflare always sets CF-Connecting-IP for public traffic; the
 * forwarded-header fallbacks exist for `wrangler dev` and tunnel setups and can be spoofed.
 */
export function clientKeyForRequest(request: Request): string {
  const candidates = [
    request.headers.get('cf-connecting-ip'),
    request.headers.get('x-forwarded-for')?.split(',')[0],
    request.headers.get('x-real-ip'),
  ];

  for (const candidate of candidates) {
    const trimmed = candidate?.trim();
    if (trimmed) {
      return trimmed;
    }
  }

  return 'unknown-client';
}

export async function isLoginLockedOut(
  store: ZeroAuthStore,
  clientKey: string,
  maxAttempts: number,
): Promise<boolean> {
  if (maxAttempts <= 0) {
    return false;
  }

  const state = await store.getFailedLogins(clientKey);
  return state !== null && state.count >= maxAttempts;
}

export async function recordFailedLogin(
  store: ZeroAuthStore,
  clientKey: string,
  windowSeconds = LOGIN_ATTEMPT_WINDOW_SECONDS,
): Promise<void> {
  await store.recordFailedLogin(clientKey, windowSeconds);
}

export async function clearFailedLogins(
  store: ZeroAuthStore,
  clientKey: string,
): Promise<void> {
  await store.clearFailedLogins(clientKey);
}
