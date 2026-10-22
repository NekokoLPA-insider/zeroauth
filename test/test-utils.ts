import { exportJWK, generateKeyPair } from 'jose';

import { AuthState, type StorageLike } from '../src/auth-state.ts';
import type { Env } from '../src/types.ts';

export class MemoryStorage implements StorageLike {
  readonly #entries = new Map<string, unknown>();

  async get<T = unknown>(key: string): Promise<T | undefined> {
    return this.#entries.get(key) as T | undefined;
  }

  async put<T = unknown>(key: string, value: T): Promise<void> {
    this.#entries.set(key, value);
  }

  async delete(key: string): Promise<boolean> {
    return this.#entries.delete(key);
  }

  async list<T = unknown>(): Promise<Map<string, T>> {
    return new Map(this.#entries) as Map<string, T>;
  }
}

export function createTestStore(): AuthState {
  return new AuthState(new MemoryStorage());
}

export async function createTestEnv(overrides: Partial<Env> = {}): Promise<Env> {
  const { privateKey } = await generateKeyPair('RS256', { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  privateJwk.alg = 'RS256';
  privateJwk.use = 'sig';

  const store = createTestStore();

  return {
    ZEROAUTH_STORE: {
      get: () => store,
      idFromName: (name: string) => name,
    } as unknown as DurableObjectNamespace,
    ZEROAUTH_ALLOW_ANY_LOGIN_HINT: 'true',
    ZEROAUTH_ALLOWED_REDIRECT_URIS: 'https://client.example/callback',
    ZEROAUTH_AUTH_CODE_TTL_SECONDS: '60',
    ZEROAUTH_CLIENT_ID: 'test-client-id',
    ZEROAUTH_CLIENT_SECRET: 'test-client-secret',
    ZEROAUTH_ISSUER: 'https://zeroauth.example',
    ZEROAUTH_KID: 'test-kid',
    ZEROAUTH_PRIVATE_JWK: JSON.stringify(privateJwk),
    ZEROAUTH_TOKEN_TTL_SECONDS: '3600',
    ...overrides,
  };
}

export function basicAuthHeader(clientId: string, clientSecret: string): string {
  return `Basic ${btoa(`${clientId}:${clientSecret}`)}`;
}

export function parseLocation(url: string): URL {
  return new URL(url);
}

export function setCookieHeaders(response: Response): string[] {
  const headers = response.headers as Headers & { getSetCookie?: () => string[] };
  return headers.getSetCookie?.() ?? [];
}

export function findCookie(response: Response, name: string): string | null {
  for (const header of setCookieHeaders(response)) {
    const pair = header.split(';')[0];

    if (pair?.startsWith(`${name}=`)) {
      return pair;
    }
  }

  return null;
}
