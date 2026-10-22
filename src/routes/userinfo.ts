import { OAuthError } from '../errors.ts';
import { verifyAccessToken } from '../jwt.ts';
import type { RuntimeConfig, SigningContext } from '../types.ts';
import { jsonResponse, noStoreHeaders } from '../utils.ts';

export async function handleUserInfo(
  request: Request,
  config: RuntimeConfig,
  signing: SigningContext,
): Promise<Response> {
  const authorizationHeader = request.headers.get('authorization');

  if (!authorizationHeader?.startsWith('Bearer ')) {
    throw new OAuthError({
      description: 'Missing Bearer access token',
      error: 'invalid_token',
      status: 401,
    });
  }

  const token = authorizationHeader.slice('Bearer '.length);

  try {
    const { payload } = await verifyAccessToken(token, config, signing);

    if (typeof payload.sub !== 'string' || typeof payload.email !== 'string') {
      throw new Error('Access token is missing required claims');
    }

    return jsonResponse(
      {
        email: payload.email,
        email_verified: payload.email_verified === true,
        sub: payload.sub,
      },
      {
        headers: noStoreHeaders(),
        status: 200,
      },
    );
  } catch {
    throw new OAuthError({
      description: 'Access token is invalid or expired',
      error: 'invalid_token',
      status: 401,
    });
  }
}
