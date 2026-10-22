export interface CookieOptions {
  maxAgeSeconds: number;
  httpOnly?: boolean;
  path?: string;
  sameSite?: 'Lax' | 'Strict' | 'None';
  secure?: boolean;
}

export function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get('cookie');

  if (!header) {
    return null;
  }

  for (const part of header.split(';')) {
    const separatorIndex = part.indexOf('=');

    if (separatorIndex < 0) {
      continue;
    }

    if (part.slice(0, separatorIndex).trim() !== name) {
      continue;
    }

    return part.slice(separatorIndex + 1).trim();
  }

  return null;
}

export function serializeCookie(name: string, value: string, options: CookieOptions): string {
  const parts = [
    `${name}=${value}`,
    `Path=${options.path ?? '/'}`,
    `Max-Age=${options.maxAgeSeconds}`,
  ];

  if (options.httpOnly ?? true) {
    parts.push('HttpOnly');
  }

  parts.push(`SameSite=${options.sameSite ?? 'Lax'}`);

  if (options.secure) {
    parts.push('Secure');
  }

  return parts.join('; ');
}

export function clearCookie(name: string, options?: { path?: string; secure?: boolean }): string {
  return serializeCookie(name, '', {
    maxAgeSeconds: 0,
    path: options?.path,
    secure: options?.secure,
  });
}

/**
 * Cookies get the Secure attribute only over https, so `wrangler dev` on localhost still works.
 */
export function isSecureRequest(request: Request): boolean {
  return new URL(request.url).protocol === 'https:';
}
