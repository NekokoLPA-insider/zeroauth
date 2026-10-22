import type { RuntimeConfig, SigningContext } from './types.ts';

function endpoint(issuer: string, path: string): string {
  const normalizedBase = issuer.endsWith('/') ? issuer : `${issuer}/`;
  const normalizedPath = path.replace(/^\//, '');
  return new URL(normalizedPath, normalizedBase).toString();
}

export function buildDiscoveryDocument(
  config: RuntimeConfig,
  signing: SigningContext,
): Record<string, unknown> {
  return {
    authorization_endpoint: endpoint(config.issuer, '/authorize'),
    claims_supported: [
      'aud',
      'auth_time',
      'email',
      'email_verified',
      'exp',
      'iat',
      'iss',
      'nonce',
      'sub',
    ],
    code_challenge_methods_supported: ['plain', 'S256'],
    grant_types_supported: ['authorization_code'],
    id_token_signing_alg_values_supported: [signing.alg],
    issuer: config.issuer,
    jwks_uri: endpoint(config.issuer, '/jwks.json'),
    response_types_supported: ['code'],
    scopes_supported: ['openid', 'email', 'profile'],
    subject_types_supported: ['public'],
    token_endpoint: endpoint(config.issuer, '/token'),
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    userinfo_endpoint: endpoint(config.issuer, '/userinfo'),
  };
}

export function buildJwks(signing: SigningContext): Record<string, unknown> {
  return {
    keys: [signing.publicJwk],
  };
}
