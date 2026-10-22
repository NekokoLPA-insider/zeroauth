import assert from 'node:assert/strict';
import test from 'node:test';

import { decodeJwt, exportJWK, generateKeyPair } from 'jose';

import {
  DEFAULT_MAX_LOGIN_ATTEMPTS,
  LOGIN_ATTEMPT_WINDOW_SECONDS,
  nextLoginAttemptState,
} from '../src/attempts.ts';
import { AuthState } from '../src/auth-state.ts';
import { handleRequest } from '../src/app.ts';
import type { Env } from '../src/types.ts';
import { sha256Hex } from '../src/utils.ts';
import {
  MemoryStorage,
  basicAuthHeader,
  createTestEnv,
  findCookie,
  parseLocation,
} from './test-utils.ts';

const TEST_PASSWORD = 'correct horse battery staple';

async function createPasswordEnv(overrides: Partial<Env> = {}): Promise<Env> {
  return createTestEnv({
    ZEROAUTH_ALLOW_ANY_LOGIN_HINT: undefined,
    ZEROAUTH_PASSWORD: TEST_PASSWORD,
    ...overrides,
  });
}

function loginQuery(env: Env, overrides: Record<string, string> = {}): string {
  return new URLSearchParams({
    client_id: env.ZEROAUTH_CLIENT_ID,
    login_hint: 'user@example.com',
    redirect_uri: 'https://client.example/callback',
    response_type: 'code',
    scope: 'openid email profile',
    state: 'state-1',
    ...overrides,
  }).toString();
}

function extractRequestId(html: string): string {
  const match = html.match(/name="request_id" value="([^"]+)"/);
  assert.ok(match?.[1], 'login page must include a request_id field');
  return match[1];
}

interface StartedLogin {
  requestId: string;
  browserCookie: string;
  response: Response;
  html: string;
}

async function startLogin(
  env: Env,
  options: { clientIp?: string; overrides?: Record<string, string> } = {},
): Promise<StartedLogin> {
  const response = await authorize(env, loginQuery(env, options.overrides), {
    'CF-Connecting-IP': options.clientIp ?? '203.0.113.7',
  });
  const html = await response.text();
  const browserCookie = findCookie(response, 'zeroauth_browser');

  return {
    browserCookie: browserCookie ?? '',
    html,
    requestId: extractRequestId(html),
    response,
  };
}

async function submitPassword(
  env: Env,
  requestId: string,
  password: string,
  options: { browserCookie?: string; clientIp?: string; email?: string } = {},
): Promise<Response> {
  const headers: Record<string, string> = {
    'CF-Connecting-IP': options.clientIp ?? '203.0.113.7',
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  if (options.browserCookie) {
    headers.Cookie = options.browserCookie;
  }

  const body = new URLSearchParams({ password, request_id: requestId });

  if (options.email !== undefined) {
    body.set('email', options.email);
  }

  return handleRequest(
    new Request('https://zeroauth.example/authorize', {
      body: body.toString(),
      headers,
      method: 'POST',
    }),
    env,
  );
}

async function authorize(
  env: Awaited<ReturnType<typeof createTestEnv>>,
  query: string,
  extraHeaders?: HeadersInit,
): Promise<Response> {
  return handleRequest(
    new Request(`https://zeroauth.example/authorize?${query}`, {
      headers: extraHeaders,
    }),
    env,
  );
}

async function tokenRequest(
  env: Awaited<ReturnType<typeof createTestEnv>>,
  body: URLSearchParams,
  extraHeaders?: HeadersInit,
): Promise<Response> {
  return handleRequest(
    new Request('https://zeroauth.example/token', {
      body: body.toString(),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...extraHeaders,
      },
      method: 'POST',
    }),
    env,
  );
}

test('serves an OpenID discovery document', async () => {
  const env = await createTestEnv();
  const response = await handleRequest(
    new Request('https://zeroauth.example/.well-known/openid-configuration'),
    env,
  );

  assert.equal(response.status, 200);
  const payload = (await response.json()) as Record<string, unknown>;
  assert.equal(payload.issuer, 'https://zeroauth.example');
  assert.equal(payload.authorization_endpoint, 'https://zeroauth.example/authorize');
  assert.deepEqual(payload.response_types_supported, ['code']);
  assert.deepEqual(payload.token_endpoint_auth_methods_supported, [
    'client_secret_basic',
    'client_secret_post',
  ]);
});

test('preserves an explicitly configured issuer string exactly', async () => {
  const env = await createTestEnv({
    ZEROAUTH_ISSUER: 'https://zeroauth.example.workers.dev/',
  });
  const response = await handleRequest(
    new Request('https://zeroauth.example.workers.dev/.well-known/openid-configuration'),
    env,
  );

  assert.equal(response.status, 200);
  const payload = (await response.json()) as Record<string, unknown>;
  assert.equal(payload.issuer, 'https://zeroauth.example.workers.dev/');
});

test('serves a JWKS document with the configured kid', async () => {
  const env = await createTestEnv();
  const response = await handleRequest(new Request('https://zeroauth.example/jwks.json'), env);

  assert.equal(response.status, 200);
  const payload = (await response.json()) as { keys: Array<Record<string, unknown>> };
  assert.equal(payload.keys.length, 1);
  assert.equal(payload.keys[0]?.kid, 'test-kid');
});

test('authorize requires login_hint in the legacy allow-any mode', async () => {
  const env = await createTestEnv();
  const response = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email profile',
      state: 'state-1',
    }).toString(),
  );

  assert.equal(response.status, 302);
  const location = parseLocation(response.headers.get('location')!);
  assert.equal(location.searchParams.get('error'), 'invalid_request');
  assert.equal(location.searchParams.get('state'), 'state-1');
});

test('authorize rejects an invalid login_hint email', async () => {
  const env = await createTestEnv();
  const response = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'not-an-email',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email',
    }).toString(),
  );

  assert.equal(response.status, 302);
  const location = parseLocation(response.headers.get('location')!);
  assert.equal(location.searchParams.get('error'), 'invalid_request');
});

test('authorize rejects a redirect_uri outside the allowlist', async () => {
  const env = await createTestEnv();
  const response = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'user@example.com',
      redirect_uri: 'https://evil.example/callback',
      response_type: 'code',
      scope: 'openid email',
    }).toString(),
  );

  assert.equal(response.status, 400);
  const payload = (await response.json()) as Record<string, unknown>;
  assert.equal(payload.error, 'invalid_request');
});

test('authorize rejects unsupported response_type', async () => {
  const env = await createTestEnv();
  const response = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'user@example.com',
      redirect_uri: 'https://client.example/callback',
      response_type: 'token',
      scope: 'openid email',
      state: 's-1',
    }).toString(),
  );

  assert.equal(response.status, 302);
  const location = parseLocation(response.headers.get('location')!);
  assert.equal(location.searchParams.get('error'), 'unsupported_response_type');
  assert.equal(location.searchParams.get('state'), 's-1');
});

test('authorize creates a code and preserves state', async () => {
  const env = await createTestEnv();
  const response = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'User@Example.com',
      nonce: 'nonce-1',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email profile',
      state: 'state-xyz',
    }).toString(),
  );

  assert.equal(response.status, 302);
  const location = parseLocation(response.headers.get('location')!);
  assert.ok(location.searchParams.get('code'));
  assert.equal(location.searchParams.get('state'), 'state-xyz');
});

test('token endpoint exchanges an authorization code for tokens', async () => {
  const env = await createTestEnv();
  const authorizeResponse = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'User@Example.com',
      nonce: 'nonce-123',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email profile',
    }).toString(),
  );

  const code = parseLocation(authorizeResponse.headers.get('location')!).searchParams.get('code');
  assert.ok(code);

  const response = await tokenRequest(
    env,
    new URLSearchParams({
      code,
      grant_type: 'authorization_code',
      redirect_uri: 'https://client.example/callback',
    }),
    {
      Authorization: basicAuthHeader(env.ZEROAUTH_CLIENT_ID, env.ZEROAUTH_CLIENT_SECRET),
    },
  );

  assert.equal(response.status, 200);
  const payload = (await response.json()) as Record<string, string | number>;
  assert.equal(payload.token_type, 'Bearer');
  assert.equal(payload.expires_in, 3600);

  const idToken = decodeJwt(payload.id_token as string);
  assert.equal(idToken.email, 'user@example.com');
  assert.equal(idToken.email_verified, true);
  assert.equal(idToken.nonce, 'nonce-123');
  assert.equal(idToken.aud, env.ZEROAUTH_CLIENT_ID);

  const accessToken = decodeJwt(payload.access_token as string);
  assert.equal(accessToken.email, 'user@example.com');
  assert.equal(accessToken.scope, 'openid email profile');
});

test('token endpoint supports client_secret_post', async () => {
  const env = await createTestEnv();
  const authorizeResponse = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'user@example.com',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email',
    }).toString(),
  );

  const code = parseLocation(authorizeResponse.headers.get('location')!).searchParams.get('code');
  assert.ok(code);

  const response = await tokenRequest(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      client_secret: env.ZEROAUTH_CLIENT_SECRET,
      code,
      grant_type: 'authorization_code',
      redirect_uri: 'https://client.example/callback',
    }),
  );

  assert.equal(response.status, 200);
});

test('token endpoint rejects an invalid client secret', async () => {
  const env = await createTestEnv();
  const authorizeResponse = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'user@example.com',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email',
    }).toString(),
  );

  const code = parseLocation(authorizeResponse.headers.get('location')!).searchParams.get('code');
  assert.ok(code);

  const response = await tokenRequest(
    env,
    new URLSearchParams({
      code,
      grant_type: 'authorization_code',
      redirect_uri: 'https://client.example/callback',
    }),
    {
      Authorization: basicAuthHeader(env.ZEROAUTH_CLIENT_ID, 'wrong-secret'),
    },
  );

  assert.equal(response.status, 401);
  const payload = (await response.json()) as Record<string, unknown>;
  assert.equal(payload.error, 'invalid_client');
});

test('token endpoint rejects a reused authorization code', async () => {
  const env = await createTestEnv();
  const authorizeResponse = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'user@example.com',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email',
    }).toString(),
  );

  const code = parseLocation(authorizeResponse.headers.get('location')!).searchParams.get('code');
  assert.ok(code);

  const body = new URLSearchParams({
    code,
    grant_type: 'authorization_code',
    redirect_uri: 'https://client.example/callback',
  });

  const headers = {
    Authorization: basicAuthHeader(env.ZEROAUTH_CLIENT_ID, env.ZEROAUTH_CLIENT_SECRET),
  };

  const first = await tokenRequest(env, body, headers);
  assert.equal(first.status, 200);

  const second = await tokenRequest(
    env,
    new URLSearchParams({
      code,
      grant_type: 'authorization_code',
      redirect_uri: 'https://client.example/callback',
    }),
    headers,
  );

  assert.equal(second.status, 400);
  const payload = (await second.json()) as Record<string, unknown>;
  assert.equal(payload.error, 'invalid_grant');
});

test('token endpoint rejects an expired authorization code', async () => {
  const env = await createTestEnv({
    ZEROAUTH_AUTH_CODE_TTL_SECONDS: '0',
  });
  const authorizeResponse = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'user@example.com',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email',
    }).toString(),
  );

  const code = parseLocation(authorizeResponse.headers.get('location')!).searchParams.get('code');
  assert.ok(code);

  const response = await tokenRequest(
    env,
    new URLSearchParams({
      code,
      grant_type: 'authorization_code',
      redirect_uri: 'https://client.example/callback',
    }),
    {
      Authorization: basicAuthHeader(env.ZEROAUTH_CLIENT_ID, env.ZEROAUTH_CLIENT_SECRET),
    },
  );

  assert.equal(response.status, 400);
  const payload = (await response.json()) as Record<string, unknown>;
  assert.equal(payload.error, 'invalid_grant');
});

test('token endpoint validates PKCE S256 verifiers', async () => {
  const env = await createTestEnv();
  const verifier = 'pkce-verifier-123';
  const hashedBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  const challenge = btoa(String.fromCharCode(...new Uint8Array(hashedBuffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');

  const authorizeResponse = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      login_hint: 'user@example.com',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email',
    }).toString(),
  );

  const code = parseLocation(authorizeResponse.headers.get('location')!).searchParams.get('code');
  assert.ok(code);

  const failure = await tokenRequest(
    env,
    new URLSearchParams({
      code,
      code_verifier: 'wrong-verifier',
      grant_type: 'authorization_code',
      redirect_uri: 'https://client.example/callback',
    }),
    {
      Authorization: basicAuthHeader(env.ZEROAUTH_CLIENT_ID, env.ZEROAUTH_CLIENT_SECRET),
    },
  );

  assert.equal(failure.status, 400);
  assert.equal(((await failure.json()) as Record<string, unknown>).error, 'invalid_grant');

  const authorizeAgain = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      login_hint: 'user@example.com',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email',
    }).toString(),
  );

  const code2 = parseLocation(authorizeAgain.headers.get('location')!).searchParams.get('code');
  assert.ok(code2);

  const success = await tokenRequest(
    env,
    new URLSearchParams({
      code: code2,
      code_verifier: verifier,
      grant_type: 'authorization_code',
      redirect_uri: 'https://client.example/callback',
    }),
    {
      Authorization: basicAuthHeader(env.ZEROAUTH_CLIENT_ID, env.ZEROAUTH_CLIENT_SECRET),
    },
  );

  assert.equal(success.status, 200);
});

test('userinfo validates and returns claims from the access token', async () => {
  const env = await createTestEnv();
  const authorizeResponse = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'user@example.com',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email profile',
    }).toString(),
  );

  const code = parseLocation(authorizeResponse.headers.get('location')!).searchParams.get('code');
  assert.ok(code);

  const tokenResponse = await tokenRequest(
    env,
    new URLSearchParams({
      code,
      grant_type: 'authorization_code',
      redirect_uri: 'https://client.example/callback',
    }),
    {
      Authorization: basicAuthHeader(env.ZEROAUTH_CLIENT_ID, env.ZEROAUTH_CLIENT_SECRET),
    },
  );

  const tokenPayload = (await tokenResponse.json()) as Record<string, string>;
  const response = await handleRequest(
    new Request('https://zeroauth.example/userinfo', {
      headers: {
        Authorization: `Bearer ${tokenPayload.access_token}`,
      },
    }),
    env,
  );

  assert.equal(response.status, 200);
  const payload = (await response.json()) as Record<string, unknown>;
  assert.equal(payload.email, 'user@example.com');
  assert.equal(payload.email_verified, true);
  assert.ok(typeof payload.sub === 'string');
});

test('authorize is blocked until unsafe mode is explicitly enabled', async () => {
  const env = await createTestEnv({
    ZEROAUTH_ALLOW_ANY_LOGIN_HINT: 'false',
  });

  const response = await authorize(
    env,
    new URLSearchParams({
      client_id: env.ZEROAUTH_CLIENT_ID,
      login_hint: 'user@example.com',
      redirect_uri: 'https://client.example/callback',
      response_type: 'code',
      scope: 'openid email',
    }).toString(),
  );

  assert.equal(response.status, 400);
  const payload = (await response.json()) as Record<string, unknown>;
  assert.equal(payload.error, 'invalid_request');
});

test('template placeholder configuration returns a clear error', async () => {
  const env = await createTestEnv({
    ZEROAUTH_PRIVATE_JWK:
      '{"kty":"EC","crv":"P-256","x":"replace-me","y":"replace-me","d":"replace-me","alg":"ES256","use":"sig"}',
  });

  const response = await handleRequest(
    new Request('https://zeroauth.example/.well-known/openid-configuration'),
    env,
  );

  assert.equal(response.status, 500);
  const payload = (await response.json()) as Record<string, unknown>;
  assert.equal(payload.error, 'server_error');
  assert.match(
    String(payload.error_description),
    /ZEROAUTH_PRIVATE_JWK is still using the template placeholder/,
  );
});

test('password mode renders a sign-in page instead of issuing a code', async () => {
  const env = await createPasswordEnv();

  const { response, html } = await startLogin(env);

  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type') ?? '', /text\/html/);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.get('location'), null);
  assert.ok(findCookie(response, 'zeroauth_browser'), 'the form must be bound to this browser');

  assert.match(html, /user@example\.com/);
  assert.ok(extractRequestId(html));
  assert.doesNotMatch(html, /name="code"/);
});

test('password mode rejects a wrong password without issuing a code', async () => {
  const env = await createPasswordEnv();
  const { requestId, browserCookie } = await startLogin(env);

  const response = await submitPassword(env, requestId, 'wrong password', { browserCookie });

  assert.equal(response.status, 401);
  assert.equal(response.headers.get('location'), null);
  const html = await response.text();
  assert.match(html, /Incorrect password/);
  assert.equal(extractRequestId(html), requestId);
});

test('password mode issues an authorization code after the correct password', async () => {
  const env = await createPasswordEnv();
  const { requestId, browserCookie } = await startLogin(env);

  const response = await submitPassword(env, requestId, TEST_PASSWORD, { browserCookie });

  assert.equal(response.status, 302);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const location = parseLocation(response.headers.get('location')!);
  assert.equal(location.origin + location.pathname, 'https://client.example/callback');
  assert.equal(location.searchParams.get('state'), 'state-1');
  const code = location.searchParams.get('code');
  assert.ok(code);

  const tokenResponse = await tokenRequest(
    env,
    new URLSearchParams({
      code,
      grant_type: 'authorization_code',
      redirect_uri: 'https://client.example/callback',
    }),
    {
      Authorization: basicAuthHeader(env.ZEROAUTH_CLIENT_ID, env.ZEROAUTH_CLIENT_SECRET),
    },
  );

  assert.equal(tokenResponse.status, 200);
  const payload = (await tokenResponse.json()) as Record<string, string>;
  const idToken = decodeJwt(payload.id_token!);
  assert.equal(idToken.email, 'user@example.com');
  assert.equal(idToken.email_verified, true);
});

test('password sign-in is bound to the browser that loaded the form', async () => {
  const env = await createPasswordEnv();
  const { requestId, browserCookie } = await startLogin(env);
  assert.ok(browserCookie);

  const withoutCookie = await submitPassword(env, requestId, TEST_PASSWORD);
  assert.equal(withoutCookie.status, 400);
  assert.match(await withoutCookie.text(), /not started in this browser/);

  const foreignCookie = await submitPassword(env, requestId, TEST_PASSWORD, {
    browserCookie: 'zeroauth_browser=someone-elses-browser',
  });
  assert.equal(foreignCookie.status, 400);

  const legit = await submitPassword(env, requestId, TEST_PASSWORD, { browserCookie });
  assert.equal(legit.status, 302);
});

test('password sign-in request identifiers are single use', async () => {
  const env = await createPasswordEnv();
  const { requestId, browserCookie } = await startLogin(env);

  const first = await submitPassword(env, requestId, TEST_PASSWORD, { browserCookie });
  assert.equal(first.status, 302);

  const second = await submitPassword(env, requestId, TEST_PASSWORD, { browserCookie });
  assert.equal(second.status, 400);
  assert.equal(second.headers.get('location'), null);
  assert.match(await second.text(), /expired or was already completed/);
});

test('password sign-in rejects an unknown request identifier', async () => {
  const env = await createPasswordEnv();

  const response = await submitPassword(env, 'not-a-real-request-id', TEST_PASSWORD);

  assert.equal(response.status, 400);
  assert.match(await response.text(), /expired or was already completed/);
});

test('password mode locks out repeated failures, including the correct password', async () => {
  const env = await createPasswordEnv();
  const { requestId, browserCookie } = await startLogin(env);

  for (let attempt = 0; attempt < DEFAULT_MAX_LOGIN_ATTEMPTS; attempt += 1) {
    const failed = await submitPassword(env, requestId, `wrong-${attempt}`, { browserCookie });
    assert.equal(failed.status, 401);
  }

  const locked = await submitPassword(env, requestId, TEST_PASSWORD, { browserCookie });
  assert.equal(locked.status, 429);
  assert.equal(locked.headers.get('retry-after'), '600');
  assert.match(await locked.text(), /Too many attempts/);
});

test('password mode accepts a sha256: digest in ZEROAUTH_PASSWORD', async () => {
  const digest = await sha256Hex(TEST_PASSWORD);
  const env = await createPasswordEnv({ ZEROAUTH_PASSWORD: `sha256:${digest}` });
  const { requestId, browserCookie } = await startLogin(env);

  const response = await submitPassword(env, requestId, TEST_PASSWORD, { browserCookie });

  assert.equal(response.status, 302);
  assert.ok(parseLocation(response.headers.get('location')!).searchParams.get('code'));
});

test('password mode takes precedence over ZEROAUTH_ALLOW_ANY_LOGIN_HINT', async () => {
  const env = await createPasswordEnv({ ZEROAUTH_ALLOW_ANY_LOGIN_HINT: 'true' });

  const response = await authorize(env, loginQuery(env));

  assert.equal(response.status, 200);
  assert.equal(response.headers.get('location'), null);
  assert.ok(extractRequestId(await response.text()));
});

test('password mode is disabled when ZEROAUTH_PASSWORD is unset', async () => {
  const env = await createTestEnv({ ZEROAUTH_ALLOW_ANY_LOGIN_HINT: undefined });

  const response = await authorize(env, loginQuery(env));

  assert.equal(response.status, 400);
  const payload = (await response.json()) as Record<string, unknown>;
  assert.equal(payload.error, 'invalid_request');
  assert.match(String(payload.error_description), /ZEROAUTH_PASSWORD/);
});

test('authorize rejects unauthenticated POST attempts when no password is configured', async () => {
  const env = await createTestEnv();
  const response = await submitPassword(env, 'anything', 'anything');

  assert.equal(response.status, 400);
  const payload = (await response.json()) as Record<string, unknown>;
  assert.equal(payload.error, 'invalid_request');
});

test('session cookie skips the password page when sessions are enabled', async () => {
  const env = await createPasswordEnv({ ZEROAUTH_SESSION_TTL_SECONDS: '3600' });
  const { requestId, browserCookie } = await startLogin(env);

  const success = await submitPassword(env, requestId, TEST_PASSWORD, { browserCookie });
  assert.equal(success.status, 302);

  const sessionCookie = findCookie(success, 'zeroauth_session');
  assert.ok(sessionCookie, 'a session cookie should be issued');

  const next = await authorize(env, loginQuery(env), { Cookie: sessionCookie });
  assert.equal(next.status, 302);
  assert.ok(parseLocation(next.headers.get('location')!).searchParams.get('code'));
});

test('no session cookie is issued when sessions are disabled', async () => {
  const env = await createPasswordEnv();
  const { requestId, browserCookie } = await startLogin(env);

  const success = await submitPassword(env, requestId, TEST_PASSWORD, { browserCookie });
  assert.equal(success.status, 302);
  assert.equal(findCookie(success, 'zeroauth_session'), null);

  const next = await authorize(env, loginQuery(env));
  assert.equal(next.status, 200, 'the password page should be shown again');
});

test('a forged session cookie is rejected', async () => {
  const env = await createPasswordEnv({ ZEROAUTH_SESSION_TTL_SECONDS: '3600' });
  const forged = 'zeroauth_session=v1.9999999999.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

  const response = await authorize(env, loginQuery(env), { Cookie: forged });

  assert.equal(response.status, 200);
  assert.equal(response.headers.get('location'), null);
});

test('authorize requests are rate limited per client IP', async () => {  const env = await createPasswordEnv({ ZEROAUTH_MAX_AUTHORIZE_REQUESTS: '2' });
  const headers = { 'CF-Connecting-IP': '198.51.100.5' };

  const first = await authorize(env, loginQuery(env), headers);
  const second = await authorize(env, loginQuery(env), headers);
  const third = await authorize(env, loginQuery(env), headers);

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(third.status, 429);
  assert.ok(third.headers.get('retry-after'));
  assert.match(await third.text(), /Too many authorization requests/);

  const otherClient = await authorize(env, loginQuery(env), {
    'CF-Connecting-IP': '198.51.100.6',
  });
  assert.equal(otherClient.status, 200);
});

test('an invalid issuer surfaces a JSON configuration error instead of throwing', async () => {
  const env = await createTestEnv({ ZEROAUTH_ISSUER: 'http://insecure.example' });

  const response = await handleRequest(new Request('https://zeroauth.example/healthz'), env);

  assert.equal(response.status, 500);
  const payload = (await response.json()) as Record<string, unknown>;
  assert.equal(payload.error, 'server_error');
  assert.match(String(payload.error_description), /must use https/);
});

test('failed-login tracking keeps the original lockout window', () => {
  const start = 1_700_000_000_000;
  const first = nextLoginAttemptState(null, start);
  assert.equal(first.count, 1);
  assert.equal(first.expiresAt, start + LOGIN_ATTEMPT_WINDOW_SECONDS * 1000);

  const second = nextLoginAttemptState(first, start + 60_000);
  assert.equal(second.count, 2);
  assert.equal(second.expiresAt, first.expiresAt, 'repeated failures must not extend the window');

  const afterExpiry = nextLoginAttemptState(second, first.expiresAt + 1);
  assert.equal(afterExpiry.count, 1);
  assert.equal(afterExpiry.expiresAt, first.expiresAt + 1 + LOGIN_ATTEMPT_WINDOW_SECONDS * 1000);
});

test('ZEROAUTH_MAX_LOGIN_ATTEMPTS=0 disables the lockout', async () => {
  const env = await createPasswordEnv({ ZEROAUTH_MAX_LOGIN_ATTEMPTS: '0' });
  const { requestId, browserCookie } = await startLogin(env);

  for (let attempt = 0; attempt < DEFAULT_MAX_LOGIN_ATTEMPTS + 2; attempt += 1) {
    const failed = await submitPassword(env, requestId, `wrong-${attempt}`, { browserCookie });
    assert.equal(failed.status, 401);
  }

  const success = await submitPassword(env, requestId, TEST_PASSWORD, { browserCookie });
  assert.equal(success.status, 302);
});

test('password values with surrounding whitespace must match exactly', async () => {
  const env = await createPasswordEnv({ ZEROAUTH_PASSWORD: '  spaced password  ' });
  const { requestId, browserCookie } = await startLogin(env);

  const trimmed = await submitPassword(env, requestId, 'spaced password', { browserCookie });
  assert.equal(trimmed.status, 401);

  const exact = await submitPassword(env, requestId, '  spaced password  ', { browserCookie });
  assert.equal(exact.status, 302);
});

test('an oversized password is rejected without hashing it', async () => {
  const env = await createPasswordEnv();
  const { requestId, browserCookie } = await startLogin(env);

  const response = await submitPassword(env, requestId, 'a'.repeat(10_000), { browserCookie });

  assert.equal(response.status, 401);
  assert.match(await response.text(), /Incorrect password/);
});

test('password mode asks for an email when login_hint is absent', async () => {
  const env = await createPasswordEnv();
  const response = await authorize(env, loginQuery(env, { login_hint: '' }));
  const html = await response.text();

  assert.equal(response.status, 200);
  assert.match(html, /name="email"/);
  assert.doesNotMatch(html, /name="email"[^>]*value="/);

  const requestId = extractRequestId(html);
  const browserCookie = findCookie(response, 'zeroauth_browser');
  assert.ok(browserCookie);

  const done = await submitPassword(env, requestId, TEST_PASSWORD, {
    browserCookie,
    email: 'Typed.User@Example.com',
  });
  assert.equal(done.status, 302);

  const code = parseLocation(done.headers.get('location')!).searchParams.get('code');
  assert.ok(code);

  const tokenResponse = await tokenRequest(
    env,
    new URLSearchParams({
      code,
      grant_type: 'authorization_code',
      redirect_uri: 'https://client.example/callback',
    }),
    {
      Authorization: basicAuthHeader(env.ZEROAUTH_CLIENT_ID, env.ZEROAUTH_CLIENT_SECRET),
    },
  );

  assert.equal(tokenResponse.status, 200);
  const payload = (await tokenResponse.json()) as Record<string, string>;
  assert.equal(decodeJwt(payload.id_token!).email, 'typed.user@example.com');
});

test('an invalid submitted email is rejected without consuming the request', async () => {
  const env = await createPasswordEnv();
  const response = await authorize(env, loginQuery(env, { login_hint: '' }));
  const requestId = extractRequestId(await response.text());
  const browserCookie = findCookie(response, 'zeroauth_browser')!;

  const invalid = await submitPassword(env, requestId, TEST_PASSWORD, {
    browserCookie,
    email: 'not-an-email',
  });
  assert.equal(invalid.status, 400);
  assert.match(await invalid.text(), /valid email address/);

  const missing = await submitPassword(env, requestId, TEST_PASSWORD, { browserCookie });
  assert.equal(missing.status, 400);

  const valid = await submitPassword(env, requestId, TEST_PASSWORD, {
    browserCookie,
    email: 'user@example.com',
  });
  assert.equal(valid.status, 302);
});

test('an unsupported signing algorithm is rejected with a configuration error', async () => {
  const env = await createTestEnv({
    ZEROAUTH_PRIVATE_JWK: JSON.stringify({ alg: 'HS256', e: 'AQAB', kty: 'RSA', n: 'abc' }),
  });

  const response = await handleRequest(new Request('https://zeroauth.example/jwks.json'), env);

  assert.equal(response.status, 500);
  const payload = (await response.json()) as Record<string, unknown>;
  assert.equal(payload.error, 'server_error');
  assert.match(String(payload.error_description), /Unsupported signing algorithm/);
});

test('an EC signing key is accepted and advertised', async () => {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  privateJwk.alg = 'ES256';
  privateJwk.use = 'sig';

  const env = await createTestEnv({ ZEROAUTH_PRIVATE_JWK: JSON.stringify(privateJwk) });

  const response = await handleRequest(new Request('https://zeroauth.example/jwks.json'), env);

  assert.equal(response.status, 200);
  const payload = (await response.json()) as { keys: Array<Record<string, unknown>> };
  assert.equal(payload.keys[0]?.alg, 'ES256');
  assert.equal(payload.keys[0]?.kty, 'EC');
  assert.equal(payload.keys[0]?.kid, env.ZEROAUTH_KID);
});

const sampleRecord = {
  authTime: 0,
  browserId: 'browser-browser-browser',
  clientId: 'test-client-id',
  email: 'user@example.com',
  redirectUri: 'https://client.example/callback',
  scope: 'openid',
};

test('an authorization code can be consumed only once', async () => {
  const store = new AuthState(new MemoryStorage());
  await store.putCode('single-use-code', sampleRecord, 60);

  assert.ok(await store.consumeCode('single-use-code'));
  assert.equal(await store.consumeCode('single-use-code'), null);
});

test('a pending login can be claimed only once', async () => {
  const store = new AuthState(new MemoryStorage());
  const id = await store.putPendingLogin(sampleRecord, 600);

  assert.ok(await store.claimPendingLogin(id));
  assert.equal(await store.claimPendingLogin(id), null);
});

test('expired entries are removed by the sweep', async () => {
  const store = new AuthState(new MemoryStorage());
  await store.putCode('expired-code', sampleRecord, 0);
  await store.putCode('live-code', sampleRecord, 60);

  assert.equal(await store.sweepExpired(), 1);
  assert.equal(await store.consumeCode('expired-code'), null);
  assert.ok(await store.consumeCode('live-code'));
});
