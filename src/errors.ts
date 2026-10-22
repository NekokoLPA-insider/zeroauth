export interface OAuthErrorOptions {
  description?: string;
  error: string;
  redirectUri?: string;
  state?: string;
  status: number;
}

export class OAuthError extends Error {
  readonly description?: string;
  readonly error: string;
  readonly redirectUri?: string;
  readonly state?: string;
  readonly status: number;

  constructor(options: OAuthErrorOptions) {
    super(options.description ?? options.error);
    this.name = 'OAuthError';
    this.description = options.description;
    this.error = options.error;
    this.redirectUri = options.redirectUri;
    this.state = options.state;
    this.status = options.status;
  }
}

export class ConfigurationError extends Error {
  readonly status = 500;

  constructor(message: string) {
    super(message);
    this.name = 'ConfigurationError';
  }
}
