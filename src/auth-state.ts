import { nextLoginAttemptState, type LoginAttemptState, type RateLimitState } from './attempts.ts';
import type { RateLimitResult, ZeroAuthStore } from './store-types.ts';
import type { AuthorizationCodeRecord, PendingLoginRecord } from './types.ts';
import { randomToken } from './utils.ts';

const CODE_PREFIX = 'code:';
const PENDING_LOGIN_PREFIX = 'pending:';
const FAILED_LOGIN_PREFIX = 'failed:';
const RATE_LIMIT_PREFIX = 'rate:';

interface Entry<T> {
  expiresAt: number;
  value: T;
}

/**
 * The subset of Durable Object storage this module needs. Keeping it structural lets the
 * same logic run against `ctx.storage` in Workers and an in-memory map in Node tests.
 */
export interface StorageLike {
  get<T = unknown>(key: string): Promise<T | undefined>;
  put<T = unknown>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
  list<T = unknown>(options?: { prefix?: string }): Promise<Map<string, T>>;
}

function isExpired(entry: unknown, nowMs: number): boolean {
  if (typeof entry !== 'object' || entry === null) {
    return true;
  }

  const expiresAt = (entry as { expiresAt?: unknown }).expiresAt;
  return typeof expiresAt !== 'number' || expiresAt <= nowMs;
}

function entryOf<T>(value: T, expiresAt: number): Entry<T> {
  return { expiresAt, value };
}

/**
 * All reads and writes for authorization codes, pending logins and rate limits.
 *
 * A single Durable Object serializes these operations, which is what makes
 * `consumeCode` and `claimPendingLogin` atomic (KV was read-then-delete and racy).
 */
export class AuthState implements ZeroAuthStore {
  readonly #storage: StorageLike;

  constructor(storage: StorageLike) {
    this.#storage = storage;
  }

  async putCode(
    code: string,
    record: AuthorizationCodeRecord,
    ttlSeconds: number,
  ): Promise<void> {
    await this.#storage.put(
      `${CODE_PREFIX}${code}`,
      entryOf(record, Date.now() + ttlSeconds * 1000),
    );
  }

  async consumeCode(code: string): Promise<AuthorizationCodeRecord | null> {
    const key = `${CODE_PREFIX}${code}`;
    const entry = await this.#storage.get<Entry<AuthorizationCodeRecord>>(key);

    if (!entry) {
      return null;
    }

    await this.#storage.delete(key);

    return isExpired(entry, Date.now()) ? null : entry.value;
  }

  async putPendingLogin(record: PendingLoginRecord, ttlSeconds: number): Promise<string> {
    const id = randomToken();

    await this.#storage.put(`${PENDING_LOGIN_PREFIX}${id}`, entryOf(record, Date.now() + ttlSeconds * 1000));

    return id;
  }

  async getPendingLogin(id: string): Promise<PendingLoginRecord | null> {
    const key = `${PENDING_LOGIN_PREFIX}${id}`;
    const entry = await this.#storage.get<Entry<PendingLoginRecord>>(key);

    if (!entry) {
      return null;
    }

    if (isExpired(entry, Date.now())) {
      await this.#storage.delete(key);
      return null;
    }

    return entry.value;
  }

  /**
   * Atomically removes and returns a pending login. Only one caller can win, so two
   * concurrent submissions cannot both mint an authorization code.
   */
  async claimPendingLogin(id: string): Promise<PendingLoginRecord | null> {
    const key = `${PENDING_LOGIN_PREFIX}${id}`;
    const entry = await this.#storage.get<Entry<PendingLoginRecord>>(key);

    if (!entry) {
      return null;
    }

    await this.#storage.delete(key);

    return isExpired(entry, Date.now()) ? null : entry.value;
  }

  async getFailedLogins(clientKey: string): Promise<LoginAttemptState | null> {
    const key = `${FAILED_LOGIN_PREFIX}${clientKey}`;
    const entry = await this.#storage.get<Entry<LoginAttemptState>>(key);

    if (!entry) {
      return null;
    }

    if (isExpired(entry, Date.now())) {
      await this.#storage.delete(key);
      return null;
    }

    return entry.value;
  }

  async recordFailedLogin(clientKey: string, windowSeconds: number): Promise<void> {
    const nowMs = Date.now();
    const previous = await this.getFailedLogins(clientKey);
    const state = nextLoginAttemptState(previous, nowMs, windowSeconds);

    await this.#storage.put(
      `${FAILED_LOGIN_PREFIX}${clientKey}`,
      entryOf(state, state.expiresAt),
    );
  }

  async clearFailedLogins(clientKey: string): Promise<void> {
    await this.#storage.delete(`${FAILED_LOGIN_PREFIX}${clientKey}`);
  }

  async hitRateLimit(
    clientKey: string,
    limit: number,
    windowSeconds: number,
  ): Promise<RateLimitResult> {
    if (limit <= 0) {
      return { allowed: true, retryAfterSeconds: 0 };
    }

    const nowMs = Date.now();
    const key = `${RATE_LIMIT_PREFIX}${clientKey}`;
    const entry = await this.#storage.get<Entry<RateLimitState>>(key);
    const state: RateLimitState =
      entry && entry.expiresAt > nowMs
        ? entry.value
        : { count: 0, expiresAt: nowMs + windowSeconds * 1000 };

    if (state.count >= limit) {
      return {
        allowed: false,
        retryAfterSeconds: Math.max(1, Math.ceil((state.expiresAt - nowMs) / 1000)),
      };
    }

    const next: RateLimitState = { count: state.count + 1, expiresAt: state.expiresAt };
    await this.#storage.put(key, entryOf(next, next.expiresAt));

    return { allowed: true, retryAfterSeconds: 0 };
  }

  /**
   * Removes expired entries. Durable Object storage has no native TTL, so the alarm
   * handler calls this periodically.
   */
  async sweepExpired(nowMs = Date.now()): Promise<number> {
    const entries = await this.#storage.list();
    let removed = 0;

    for (const [key, entry] of entries) {
      if (isExpired(entry, nowMs)) {
        await this.#storage.delete(key);
        removed += 1;
      }
    }

    return removed;
  }
}
