import { AUTHORIZE_RATE_WINDOW_SECONDS, PENDING_LOGIN_TTL_SECONDS } from '../attempts.ts';
import { createAuthorizationCode } from '../code-store.ts';
import { clearCookie, isSecureRequest, readCookie, serializeCookie } from '../cookies.ts';
import { OAuthError } from '../errors.ts';
import {
  LOGIN_ATTEMPT_WINDOW_SECONDS,
  clearFailedLogins,
  clientKeyForRequest,
  isLoginLockedOut,
  recordFailedLogin,
} from '../login-attempts.ts';
import { verifyPassword } from '../password.ts';
import { claimPendingLogin, getPendingLogin, savePendingLogin } from '../pending-store.ts';
import {
  BROWSER_COOKIE_NAME,
  BROWSER_COOKIE_TTL_SECONDS,
  SESSION_COOKIE_NAME,
  createSessionValue,
  hasValidSession,
  isValidBrowserId,
} from '../session.ts';
import type { ZeroAuthStore } from '../store-types.ts';
import type {
  AuthorizationCodeRecord,
  AuthorizationRequestRecord,
  Env,
  PendingLoginRecord,
  RuntimeConfig,
} from '../types.ts';
import {
  appendQueryParameters,
  includesOpenIdScope,
  isValidEmail,
  noStoreHeaders,
  normalizeEmail,
  normalizeScope,
  randomToken,
} from '../utils.ts';
import { renderLoginPage, renderNoticePage } from '../views/login.ts';

function redirectError(
  redirectUri: string,
  state: string | undefined,
  error: string,
  description: string,
): never {
  throw new OAuthError({
    description,
    error,
    redirectUri,
    state,
    status: 302,
  });
}

function invalidRequestError(description: string): OAuthError {
  return new OAuthError({
    description,
    error: 'invalid_request',
    status: 400,
  });
}


function parseAuthorizationRequest(
  request: Request,
  config: RuntimeConfig,
): AuthorizationRequestRecord {
  const url = new URL(request.url);
  const clientId = url.searchParams.get('client_id');
  const redirectUri = url.searchParams.get('redirect_uri');
  const responseType = url.searchParams.get('response_type');
  const scope = url.searchParams.get('scope');
  const state = url.searchParams.get('state') ?? undefined;
  const nonce = url.searchParams.get('nonce') ?? undefined;
  const loginHint = url.searchParams.get('login_hint');
  const codeChallenge = url.searchParams.get('code_challenge') ?? undefined;
  const codeChallengeMethod = url.searchParams.get('code_challenge_method') ?? undefined;

  if (clientId !== config.clientId) {
    throw invalidRequestError('Unknown client_id');
  }

  if (!redirectUri || !config.allowedRedirectUris.has(redirectUri)) {
    throw invalidRequestError('redirect_uri is not allowed');
  }

  if (responseType !== 'code') {
    redirectError(redirectUri, state, 'unsupported_response_type', 'Only response_type=code is supported');
  }

  if (!scope || !includesOpenIdScope(scope)) {
    redirectError(redirectUri, state, 'invalid_scope', 'scope must include openid');
  }

  const email = loginHint ? normalizeEmail(loginHint) : undefined;

  if (email !== undefined && !isValidEmail(email)) {
    redirectError(redirectUri, state, 'invalid_request', 'login_hint must be a valid email address');
  }

  let normalizedCodeChallengeMethod: 'plain' | 'S256' | undefined;
  if (codeChallenge) {
    normalizedCodeChallengeMethod =
      codeChallengeMethod === 'S256' || codeChallengeMethod === 'plain'
        ? codeChallengeMethod
        : codeChallengeMethod === undefined
          ? 'plain'
          : undefined;

    if (!normalizedCodeChallengeMethod) {
      redirectError(
        redirectUri,
        state,
        'invalid_request',
        'code_challenge_method must be plain or S256',
      );
    }
  } else if (codeChallengeMethod) {
    redirectError(
      redirectUri,
      state,
      'invalid_request',
      'code_challenge_method requires code_challenge',
    );
  }

  return {
    authTime: Math.floor(Date.now() / 1000),
    clientId: config.clientId,
    codeChallenge,
    codeChallengeMethod: normalizedCodeChallengeMethod,
    email,
    nonce,
    redirectUri,
    scope: normalizeScope(scope),
    state,
  };
}

function browserCookie(request: Request, browserId: string): string {
  return serializeCookie(BROWSER_COOKIE_NAME, browserId, {
    httpOnly: true,
    maxAgeSeconds: BROWSER_COOKIE_TTL_SECONDS,
    sameSite: 'Lax',
    secure: isSecureRequest(request),
  });
}

function ensureBrowserId(request: Request): { browserId: string; needsCookie: boolean } {
  const existing = readCookie(request, BROWSER_COOKIE_NAME);

  if (isValidBrowserId(existing)) {
    return { browserId: existing, needsCookie: false };
  }

  return { browserId: randomToken(16), needsCookie: true };
}

async function issueCodeResponse(
  store: ZeroAuthStore,
  config: RuntimeConfig,
  record: AuthorizationCodeRecord,
  cookies: string[] = [],
): Promise<Response> {
  const code = await createAuthorizationCode(
    store,
    {
      ...record,
      authTime: Math.floor(Date.now() / 1000),
    },
    config.authCodeTtlSeconds,
  );

  const headers = noStoreHeaders({
    Location: appendQueryParameters(record.redirectUri, { code, state: record.state }),
  });

  for (const cookie of cookies) {
    headers.append('Set-Cookie', cookie);
  }


  return new Response(null, { headers, status: 302 });
}

export async function handleAuthorize(
  request: Request,
  env: Env,
  config: RuntimeConfig,
  store: ZeroAuthStore,
): Promise<Response> {
  const clientKey = clientKeyForRequest(request);
  const rateLimit = await store.hitRateLimit(
    clientKey,
    config.maxAuthorizeRequests,
    AUTHORIZE_RATE_WINDOW_SECONDS,
  );

  if (!rateLimit.allowed) {
    return renderNoticePage({
      message: 'Too many authorization requests from this client. Wait a few minutes and try again.',
      retryAfterSeconds: rateLimit.retryAfterSeconds,
      status: 429,
      title: 'Too many requests',
    });
  }

  const record = parseAuthorizationRequest(request, config);

  if (config.passwordDigest) {
    const { browserId, needsCookie } = ensureBrowserId(request);
    const setCookies = needsCookie ? [browserCookie(request, browserId)] : [];

    // A valid session skips the password, but only when the email is already known.
    if (record.email && (await hasValidSession(request, config))) {
      return issueCodeResponse(store, config, { ...record, email: record.email });
    }

    const pending: PendingLoginRecord = { ...record, browserId };
    const requestId = await savePendingLogin(store, pending, PENDING_LOGIN_TTL_SECONDS);

    return renderLoginPage({
      email: record.email,
      requestId,
      setCookies,
    });
  }

  if (config.allowAnyLoginHint) {
    if (!record.email) {
      redirectError(
        record.redirectUri,
        record.state,
        'invalid_request',
        'login_hint is required in the unsafe allow-any mode',
      );
    }

    return issueCodeResponse(store, config, { ...record, email: record.email });
  }

  throw invalidRequestError(
    'ZeroAuth is disabled until ZEROAUTH_PASSWORD or ZEROAUTH_ALLOW_ANY_LOGIN_HINT=true is configured',
  );
}

export async function handleAuthorizeSubmit(
  request: Request,
  env: Env,
  config: RuntimeConfig,
  store: ZeroAuthStore,
): Promise<Response> {
  if (!config.passwordDigest) {
    throw invalidRequestError('ZeroAuth is not configured for password sign-in');
  }

  const formData = new URLSearchParams(await request.text());
  const requestId = formData.get('request_id')?.trim() ?? '';
  const password = formData.get('password') ?? '';

  if (!requestId) {
    return renderNoticePage({
      message: 'This sign-in request is missing its identifier. Start a new sign-in from the application.',
      status: 400,
      title: 'Sign-in failed',
    });
  }

  const pending = await getPendingLogin(store, requestId);

  if (!pending) {
    return renderNoticePage({
      message: 'This sign-in request expired or was already completed. Start a new sign-in from the application.',
      status: 400,
      title: 'Sign-in expired',
    });
  }

  if (!config.allowedRedirectUris.has(pending.redirectUri)) {
    return renderNoticePage({
      message: 'This sign-in request is no longer allowed by the ZeroAuth configuration. Start a new sign-in from the application.',
      status: 400,
      title: 'Sign-in rejected',
    });
  }

  const browserId = readCookie(request, BROWSER_COOKIE_NAME);

  if (!browserId || browserId !== pending.browserId) {
    return renderNoticePage({
      message: 'This sign-in request was not started in this browser. Start again from the application.',
      status: 400,
      title: 'Sign-in rejected',
    });
  }

  const email = pending.email ?? normalizeEmail(formData.get('email') ?? '');

  if (!isValidEmail(email)) {
    return renderLoginPage({
      email: pending.email,
      error: 'Enter a valid email address to continue.',
      requestId,
      status: 400,
    });
  }

  const clientKey = clientKeyForRequest(request);

  if (await isLoginLockedOut(store, clientKey, config.maxLoginAttempts)) {
    return renderNoticePage({
      message: `Too many failed password attempts. Wait ${Math.ceil(
        LOGIN_ATTEMPT_WINDOW_SECONDS / 60,
      )} minutes and start a new sign-in from the application.`,
      retryAfterSeconds: LOGIN_ATTEMPT_WINDOW_SECONDS,
      status: 429,
      title: 'Too many attempts',
    });
  }

  if (!(await verifyPassword(password, config.passwordDigest))) {
    await recordFailedLogin(store, clientKey);
    console.warn(`zeroauth: failed password attempt from ${clientKey}`);

    return renderLoginPage({
      email,
      error: 'Incorrect password. Try again.',
      requestId,
    });
  }

  await clearFailedLogins(store, clientKey);

  // Only one concurrent submission can claim the pending request and mint a code.
  const claimed = await claimPendingLogin(store, requestId);

  if (!claimed) {
    return renderNoticePage({
      message: 'This sign-in request expired or was already completed. Start a new sign-in from the application.',
      status: 400,
      title: 'Sign-in expired',
    });
  }

  const cookies = [
    clearCookie(BROWSER_COOKIE_NAME, { secure: isSecureRequest(request) }),
  ];

  if (config.sessionTtlSeconds > 0) {
    cookies.push(
      serializeCookie(SESSION_COOKIE_NAME, await createSessionValue(config), {
        httpOnly: true,
        maxAgeSeconds: config.sessionTtlSeconds,
        sameSite: 'Lax',
        secure: isSecureRequest(request),
      }),
    );
  }

  return issueCodeResponse(store, config, { ...claimed, email }, cookies);
}
