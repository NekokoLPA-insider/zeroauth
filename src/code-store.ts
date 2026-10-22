import type { ZeroAuthStore } from './store-types.ts';
import type { AuthorizationCodeRecord } from './types.ts';
import { randomToken } from './utils.ts';

export async function createAuthorizationCode(
  store: ZeroAuthStore,
  record: AuthorizationCodeRecord,
  ttlSeconds: number,
): Promise<string> {
  const code = randomToken();

  await store.putCode(code, record, ttlSeconds);

  return code;
}

export async function consumeAuthorizationCode(
  store: ZeroAuthStore,
  code: string,
): Promise<AuthorizationCodeRecord | null> {
  return store.consumeCode(code);
}
