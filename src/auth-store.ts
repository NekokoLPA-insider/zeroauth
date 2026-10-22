import { DurableObject } from 'cloudflare:workers';

import { AuthState, type StorageLike } from './auth-state.ts';
import type { LoginAttemptState } from './attempts.ts';
import type { RateLimitResult } from './store-types.ts';
import type { AuthorizationCodeRecord, Env, PendingLoginRecord } from './types.ts';

const SWEEP_INTERVAL_MS = 15 * 60 * 1000;

/**
 * Durable Object wrapper. The runtime serializes calls per instance, so the read-modify-write
 * sequences inside AuthState (code consumption, pending login claim, counters) are atomic.
 *
 * Extends DurableObject so the runtime exposes the public methods over RPC.
 * Exported by name from src/index.ts and registered in wrangler.toml migrations.
 */
export class AuthStore extends DurableObject<Env> {
  readonly #state: AuthState;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.#state = new AuthState(ctx.storage as unknown as StorageLike);

    ctx.blockConcurrencyWhile(async () => {
      if ((await ctx.storage.getAlarm()) === null) {
        await ctx.storage.setAlarm(Date.now() + SWEEP_INTERVAL_MS);
      }
    });
  }

  async alarm(): Promise<void> {
    await this.#state.sweepExpired();
    await this.ctx.storage.setAlarm(Date.now() + SWEEP_INTERVAL_MS);
  }

  putCode(code: string, record: AuthorizationCodeRecord, ttlSeconds: number): Promise<void> {
    return this.#state.putCode(code, record, ttlSeconds);
  }

  consumeCode(code: string): Promise<AuthorizationCodeRecord | null> {
    return this.#state.consumeCode(code);
  }

  putPendingLogin(record: PendingLoginRecord, ttlSeconds: number): Promise<string> {
    return this.#state.putPendingLogin(record, ttlSeconds);
  }

  getPendingLogin(id: string): Promise<PendingLoginRecord | null> {
    return this.#state.getPendingLogin(id);
  }

  claimPendingLogin(id: string): Promise<PendingLoginRecord | null> {
    return this.#state.claimPendingLogin(id);
  }

  getFailedLogins(clientKey: string): Promise<LoginAttemptState | null> {
    return this.#state.getFailedLogins(clientKey);
  }

  recordFailedLogin(clientKey: string, windowSeconds: number): Promise<void> {
    return this.#state.recordFailedLogin(clientKey, windowSeconds);
  }

  clearFailedLogins(clientKey: string): Promise<void> {
    return this.#state.clearFailedLogins(clientKey);
  }

  hitRateLimit(
    clientKey: string,
    limit: number,
    windowSeconds: number,
  ): Promise<RateLimitResult> {
    return this.#state.hitRateLimit(clientKey, limit, windowSeconds);
  }

}
