import { consumeAuthorizationCode } from '../code-store.ts';
import { OAuthError } from '../errors.ts';
import { hashSubject, issueAccessToken, issueIdToken } from '../jwt.ts';
import type { RuntimeConfig, SigningContext } from '../types.ts';
import type { ZeroAuthStore } from '../store-types.ts';
import { decodeBasicAuthHeader, jsonResponse, noStoreHeaders, sha256Base64Url } from '../utils.ts';

function invalidClient(description: string): never {
  throw new OAuthError({
    description,
    error: 'invalid_client',
    status: 401,
  });
}

function invalidGrant(description: string): never {
  throw new OAuthError({
    description,
    error: 'invalid_grant',
    status: 400,
  });
}

function authenticateClient(
  request: Request,
  formData: URLSearchParams,
  config: RuntimeConfig,
): void {
  const basicCredentials = request.headers.get('authorization')
    ? decodeBasicAuthHeader(request.headers.get('authorization')!)
    : null;

  if (request.headers.get('authorization') && !basicCredentials) {
    invalidClient('Malformed Authorization header');
  }

  const clientId = basicCredentials?.clientId ?? formData.get('client_id');
  const clientSecret = basicCredentials?.clientSecret ?? formData.get('client_secret');

  if (!clientId || !clientSecret) {
    invalidClient('Client authentication is required');
  }

  if (clientId !== config.clientId || clientSecret !== config.clientSecret) {
    invalidClient('Client authentication failed');
  }
}

async function validatePkce(
  codeVerifier: string | null,
  codeChallenge: string | undefined,
  method: 'plain' | 'S256' | undefined,
): Promise<void> {
  if (!codeChallenge) {
    return;
  }

  if (!codeVerifier) {
    invalidGrant('code_verifier is required for this authorization code');
  }

  if (method === 'plain') {
    if (codeVerifier !== codeChallenge) {
      invalidGrant('code_verifier does not match code_challenge');
    }
    return;
  }

  const hashedVerifier = await sha256Base64Url(codeVerifier);
  if (hashedVerifier !== codeChallenge) {
    invalidGrant('code_verifier does not match code_challenge');
  }
}

export async function handleToken(
  request: Request,
  config: RuntimeConfig,
  signing: SigningContext,
  store: ZeroAuthStore,
): Promise<Response> {
  const rawBody = await request.text();
  const formData = new URLSearchParams(rawBody);

  await authenticateClient(request, formData, config);

  if (formData.get('grant_type') !== 'authorization_code') {
    throw new OAuthError({
      description: 'Only grant_type=authorization_code is supported',
      error: 'unsupported_grant_type',
      status: 400,
    });
  }

  const code = formData.get('code');
  const redirectUri = formData.get('redirect_uri');

  if (!code || !redirectUri) {
    throw new OAuthError({
      description: 'code and redirect_uri are required',
      error: 'invalid_request',
      status: 400,
    });
  }

  const authorizationCode = await consumeAuthorizationCode(store, code);

  if (!authorizationCode) {
    invalidGrant('Authorization code is invalid, expired, or already used');
  }

  if (authorizationCode.clientId !== config.clientId) {
    invalidGrant('Authorization code client mismatch');
  }

  if (authorizationCode.redirectUri !== redirectUri) {
    invalidGrant('redirect_uri does not match the authorization request');
  }

  await validatePkce(
    formData.get('code_verifier'),
    authorizationCode.codeChallenge,
    authorizationCode.codeChallengeMethod,
  );

  const subject = await hashSubject(authorizationCode.email);

  const [accessToken, idToken] = await Promise.all([
    issueAccessToken({
      clientId: config.clientId,
      config,
      email: authorizationCode.email,
      scope: authorizationCode.scope,
      signing,
      subject,
    }),
    issueIdToken({
      authTime: authorizationCode.authTime,
      clientId: config.clientId,
      config,
      email: authorizationCode.email,
      nonce: authorizationCode.nonce,
      signing,
      subject,
    }),
  ]);

  console.log('zeroauth: authorization code exchanged for tokens');

  return jsonResponse(
    {
      access_token: accessToken,
      expires_in: config.tokenTtlSeconds,
      id_token: idToken,
      scope: authorizationCode.scope,
      token_type: 'Bearer',
    },
    {
      headers: noStoreHeaders(),
      status: 200,
    },
  );
}
