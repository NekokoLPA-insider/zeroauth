import { importJWK, jwtVerify, SignJWT } from 'jose';

import { ConfigurationError } from './errors.ts';
import type { RuntimeConfig, SigningContext } from './types.ts';
import { normalizeEmail, sha256Hex } from './utils.ts';

const SUPPORTED_ALGORITHMS = new Set([
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
]);

function inferSigningAlgorithm(jwk: Record<string, unknown>): string {
  const explicit = jwk.alg;
  if (typeof explicit === 'string' && explicit) {
    return explicit;
  }

  if (jwk.kty === 'RSA') {
    return 'RS256';
  }

  if (jwk.kty === 'EC') {
    switch (jwk.crv) {
      case 'P-256':
        return 'ES256';
      case 'P-384':
        return 'ES384';
      case 'P-521':
        return 'ES512';
      default:
        throw new ConfigurationError('Unsupported EC curve for ZEROAUTH_PRIVATE_JWK');
    }
  }

  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    return 'EdDSA';
  }

  throw new ConfigurationError('Unable to infer signing algorithm from ZEROAUTH_PRIVATE_JWK');
}

function toPublicJwk(
  jwk: Record<string, unknown>,
  alg: string,
  kid: string,
): Record<string, unknown> {
  if (jwk.kty === 'RSA') {
    if (typeof jwk.n !== 'string' || typeof jwk.e !== 'string') {
      throw new ConfigurationError('RSA ZEROAUTH_PRIVATE_JWK must include n and e');
    }

    return { alg, e: jwk.e, kid, kty: 'RSA', n: jwk.n, use: 'sig' };
  }

  if (jwk.kty === 'EC') {
    if (typeof jwk.crv !== 'string' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
      throw new ConfigurationError('EC ZEROAUTH_PRIVATE_JWK must include crv, x, and y');
    }

    return { alg, crv: jwk.crv, kid, kty: 'EC', use: 'sig', x: jwk.x, y: jwk.y };
  }

  if (jwk.kty === 'OKP') {
    if (typeof jwk.crv !== 'string' || typeof jwk.x !== 'string') {
      throw new ConfigurationError('OKP ZEROAUTH_PRIVATE_JWK must include crv and x');
    }

    return { alg, crv: jwk.crv, kid, kty: 'OKP', use: 'sig', x: jwk.x };
  }

  throw new ConfigurationError('Unsupported JWK key type');
}

export async function buildSigningContext(config: RuntimeConfig): Promise<SigningContext> {
  const alg = inferSigningAlgorithm(config.privateJwk);

  if (!SUPPORTED_ALGORITHMS.has(alg)) {
    throw new ConfigurationError(
      `Unsupported signing algorithm ${alg}. Use one of: ${[...SUPPORTED_ALGORITHMS].join(', ')}`,
    );
  }

  const privateJwk = { ...config.privateJwk, alg, kid: config.kid, use: 'sig' };
  const publicJwk = toPublicJwk(config.privateJwk, alg, config.kid);

  try {
    const [privateKey, publicKey] = await Promise.all([
      importJWK(privateJwk, alg),
      importJWK(publicJwk, alg),
    ]);

    return {
      alg,
      kid: config.kid,
      privateKey: privateKey as CryptoKey,
      publicJwk,
      publicKey: publicKey as CryptoKey,
    };
  } catch (error) {
    throw new ConfigurationError(
      error instanceof Error ? error.message : 'Unable to import signing JWK',
    );
  }
}

export async function hashSubject(email: string): Promise<string> {
  return sha256Hex(normalizeEmail(email));
}

export async function issueAccessToken(options: {
  clientId: string;
  config: RuntimeConfig;
  email: string;
  scope: string;
  signing: SigningContext;
  subject: string;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  return new SignJWT({
    client_id: options.clientId,
    email: options.email,
    email_verified: true,
    scope: options.scope,
  })
    .setProtectedHeader({ alg: options.signing.alg, kid: options.signing.kid, typ: 'at+jwt' })
    .setIssuer(options.config.issuer)
    .setSubject(options.subject)
    .setIssuedAt(now)
    .setExpirationTime(now + options.config.tokenTtlSeconds)
    .sign(options.signing.privateKey);
}

export async function issueIdToken(options: {
  authTime: number;
  clientId: string;
  config: RuntimeConfig;
  email: string;
  nonce?: string;
  signing: SigningContext;
  subject: string;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  const claims: Record<string, unknown> = {
    auth_time: options.authTime,
    email: options.email,
    email_verified: true,
  };

  if (options.nonce) {
    claims.nonce = options.nonce;
  }

  return new SignJWT(claims)
    .setProtectedHeader({ alg: options.signing.alg, kid: options.signing.kid, typ: 'JWT' })
    .setIssuer(options.config.issuer)
    .setAudience(options.clientId)
    .setSubject(options.subject)
    .setIssuedAt(now)
    .setExpirationTime(now + options.config.tokenTtlSeconds)
    .sign(options.signing.privateKey);
}

export async function verifyAccessToken(
  token: string,
  config: RuntimeConfig,
  signing: SigningContext,
) {
  return jwtVerify(token, signing.publicKey, {
    issuer: config.issuer,
    typ: 'at+jwt',
  });
}
