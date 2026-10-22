import type { ZeroAuthStore } from './store-types.ts';
import type { Env } from './types.ts';

const STORE_INSTANCE_NAME = 'zeroauth-store';

/**
 * Returns the single Durable Object instance used for codes, pending logins and limits.
 * One instance keeps all state transitions serialized; a test IdP has nowhere near the
 * throughput where sharding would matter.
 */
export function getStore(env: Env): ZeroAuthStore {
  const id = env.ZEROAUTH_STORE.idFromName(STORE_INSTANCE_NAME);
  return env.ZEROAUTH_STORE.get(id) as unknown as ZeroAuthStore;
}
