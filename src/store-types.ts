import type { LoginAttemptState } from './attempts.ts';
import type { AuthorizationCodeRecord, PendingLoginRecord } from './types.ts';

export interface RateLimitResult {
  allowed: boolean;
  retryAfterSeconds: number;
}

/**
 * Storage contract shared by the Durable Object and the in-memory implementation used in tests.
 */
export interface ZeroAuthStore {
  putCode(code: string, record: AuthorizationCodeRecord, ttlSeconds: number): Promise<void>;
  consumeCode(code: string): Promise<AuthorizationCodeRecord | null>;
  putPendingLogin(record: PendingLoginRecord, ttlSeconds: number): Promise<string>;
  getPendingLogin(id: string): Promise<PendingLoginRecord | null>;
  claimPendingLogin(id: string): Promise<PendingLoginRecord | null>;
  getFailedLogins(clientKey: string): Promise<LoginAttemptState | null>;
  recordFailedLogin(clientKey: string, windowSeconds: number): Promise<void>;
  clearFailedLogins(clientKey: string): Promise<void>;
  hitRateLimit(clientKey: string, limit: number, windowSeconds: number): Promise<RateLimitResult>;
}
