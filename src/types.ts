export interface Env {
  ZEROAUTH_STORE: DurableObjectNamespace;
  ZEROAUTH_CLIENT_ID: string;
  ZEROAUTH_CLIENT_SECRET: string;
  ZEROAUTH_ALLOWED_REDIRECT_URIS?: string;
  ZEROAUTH_PRIVATE_JWK: string;
  ZEROAUTH_KID: string;
  ZEROAUTH_ISSUER?: string;
  ZEROAUTH_AUTH_CODE_TTL_SECONDS?: string;
  ZEROAUTH_TOKEN_TTL_SECONDS?: string;
  ZEROAUTH_PASSWORD?: string;
  ZEROAUTH_MAX_LOGIN_ATTEMPTS?: string;
  ZEROAUTH_MAX_AUTHORIZE_REQUESTS?: string;
  ZEROAUTH_SESSION_TTL_SECONDS?: string;
  ZEROAUTH_ALLOW_ANY_LOGIN_HINT?: string;
}

export interface RuntimeConfig {
  clientId: string;
  clientSecret: string;
  issuer: string;
  authCodeTtlSeconds: number;
  tokenTtlSeconds: number;
  allowAnyLoginHint: boolean;
  passwordDigest: string | null;
  maxLoginAttempts: number;
  maxAuthorizeRequests: number;
  sessionTtlSeconds: number;
  allowedRedirectUris: Set<string>;
  privateJwk: Record<string, unknown>;
  kid: string;
}

export interface AuthorizationRequestRecord {
  authTime: number;
  clientId: string;
  codeChallenge?: string;
  codeChallengeMethod?: 'plain' | 'S256';
  email?: string;
  nonce?: string;
  redirectUri: string;
  scope: string;
  state?: string;
}

export interface PendingLoginRecord extends AuthorizationRequestRecord {
  browserId: string;
}

export type AuthorizationCodeRecord = AuthorizationRequestRecord & { email: string };

export interface SigningContext {
  alg: string;
  kid: string;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicJwk: Record<string, unknown>;
}
