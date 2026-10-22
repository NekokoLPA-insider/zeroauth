export const DEFAULT_MAX_LOGIN_ATTEMPTS = 10;
export const LOGIN_ATTEMPT_WINDOW_SECONDS = 600;

export const DEFAULT_MAX_AUTHORIZE_REQUESTS = 60;
export const AUTHORIZE_RATE_WINDOW_SECONDS = 300;

export const PENDING_LOGIN_TTL_SECONDS = 600;

export interface LoginAttemptState {
  count: number;
  expiresAt: number;
}

export interface RateLimitState {
  count: number;
  expiresAt: number;
}

/**
 * The lockout window starts at the first failure and is never extended, so repeated
 * failures cannot keep an address locked out forever.
 */
export function nextLoginAttemptState(
  previous: LoginAttemptState | null,
  nowMs: number,
  windowSeconds = LOGIN_ATTEMPT_WINDOW_SECONDS,
): LoginAttemptState {
  if (previous && previous.expiresAt > nowMs) {
    return { count: previous.count + 1, expiresAt: previous.expiresAt };
  }

  return { count: 1, expiresAt: nowMs + windowSeconds * 1000 };
}
