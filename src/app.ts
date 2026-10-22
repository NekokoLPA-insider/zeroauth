import { buildDiscoveryDocument, buildJwks } from './metadata.ts';
import { handleAuthorize, handleAuthorizeSubmit } from './routes/authorize.ts';
import { handleChangePassword } from './routes/change-password.ts';
import { handleHealth } from './routes/health.ts';
import { handleToken } from './routes/token.ts';
import { handleUserInfo } from './routes/userinfo.ts';
import { buildSigningContext } from './jwt.ts';
import { readConfig } from './config.ts';
import { getStore } from './store.ts';
import { ConfigurationError, OAuthError } from './errors.ts';
import type { Env, RuntimeConfig, SigningContext } from './types.ts';
import { appendQueryParameters, jsonResponse, noStoreHeaders } from './utils.ts';

function oauthErrorResponse(error: OAuthError): Response {
  if (error.redirectUri) {
    return new Response(null, {
      headers: noStoreHeaders({
        Location: appendQueryParameters(error.redirectUri, {
          error: error.error,
          error_description: error.description,
          state: error.state,
        }),
      }),
      status: 302,
    });
  }

  const headers = noStoreHeaders();

  if (error.error === 'invalid_client') {
    headers.set('WWW-Authenticate', 'Basic realm="ZeroAuth", charset="UTF-8"');
  }

  if (error.error === 'invalid_token') {
    headers.set(
      'WWW-Authenticate',
      `Bearer error="invalid_token", error_description="${error.description ?? 'invalid token'}"`,
    );
  }

  return jsonResponse(
    {
      error: error.error,
      error_description: error.description,
    },
    {
      headers,
      status: error.status,
    },
  );
}

function configurationErrorResponse(error: ConfigurationError): Response {
  return jsonResponse(
    {
      error: 'server_error',
      error_description: error.message,
    },
    {
      headers: noStoreHeaders(),
      status: 500,
    },
  );
}

function notFoundResponse(): Response {
  return jsonResponse(
    {
      error: 'not_found',
      error_description: 'No route matches this request',
    },
    {
      headers: noStoreHeaders(),
      status: 404,
    },
  );
}

export async function handleRequest(request: Request, env: Env): Promise<Response> {
  let config: RuntimeConfig;

  try {
    config = await readConfig(env);
  } catch (error) {
    if (error instanceof ConfigurationError) {
      return configurationErrorResponse(error);
    }

    throw error;
  }

  const signingContextPromise = buildSigningContext(config);
  const signingContext = (): Promise<SigningContext> => signingContextPromise;
  const store = getStore(env);

  const url = new URL(request.url);

  try {
    if (request.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
      return jsonResponse(buildDiscoveryDocument(config, await signingContext()), {
        headers: noStoreHeaders(),
        status: 200,
      });
    }

    if (request.method === 'GET' && url.pathname === '/jwks.json') {
      return jsonResponse(buildJwks(await signingContext()), {
        headers: noStoreHeaders(),
        status: 200,
      });
    }

    if (request.method === 'GET' && url.pathname === '/authorize') {
      return await handleAuthorize(request, env, config, store);
    }

    if (request.method === 'POST' && url.pathname === '/authorize') {
      return await handleAuthorizeSubmit(request, env, config, store);
    }

    if (request.method === 'POST' && url.pathname === '/token') {
      return await handleToken(request, config, await signingContext(), store);
    }

    if (request.method === 'GET' && url.pathname === '/userinfo') {
      return await handleUserInfo(request, config, await signingContext());
    }

    if (request.method === 'GET' && url.pathname === '/change-password') {
      return handleChangePassword();
    }

    if (request.method === 'GET' && url.pathname === '/healthz') {
      return handleHealth();
    }

    return notFoundResponse();
  } catch (error) {
    if (error instanceof OAuthError) {
      console.warn(
        `zeroauth: ${request.method} ${url.pathname} failed with ${error.error}: ${
          error.description ?? '(no description)'
        }`,
      );
      return oauthErrorResponse(error);
    }

    if (error instanceof ConfigurationError) {
      return configurationErrorResponse(error);
    }

    console.error('zeroauth: unhandled error', error);

    return jsonResponse(
      {
        error: 'server_error',
        error_description: error instanceof Error ? error.message : 'Unexpected server error',
      },
      {
        headers: noStoreHeaders(),
        status: 500,
      },
    );
  }
}
