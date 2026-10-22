import { PENDING_LOGIN_TTL_SECONDS } from './attempts.ts';
import type { ZeroAuthStore } from './store-types.ts';
import type { PendingLoginRecord } from './types.ts';

export async function savePendingLogin(
  store: ZeroAuthStore,
  record: PendingLoginRecord,
  ttlSeconds = PENDING_LOGIN_TTL_SECONDS,
): Promise<string> {
  return store.putPendingLogin(record, ttlSeconds);
}

export async function getPendingLogin(
  store: ZeroAuthStore,
  id: string,
): Promise<PendingLoginRecord | null> {
  return store.getPendingLogin(id);
}

export async function claimPendingLogin(
  store: ZeroAuthStore,
  id: string,
): Promise<PendingLoginRecord | null> {
  return store.claimPendingLogin(id);
}
