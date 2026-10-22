import { escapeHtml, htmlResponse, noStoreHeaders } from '../utils.ts';

const PAGE_STYLE = `
      :root {
        color-scheme: light;
        --ink: #1f1b16;
        --accent: #0f766e;
        --card: #fffaf0;
      }
      * {
        box-sizing: border-box;
      }
      body {
        margin: 0;
        font-family: "IBM Plex Sans", ui-sans-serif, system-ui, sans-serif;
        background:
          radial-gradient(circle at top left, rgba(15, 118, 110, 0.12), transparent 35%),
          linear-gradient(135deg, #f8f5ee, #ece6db);
        color: var(--ink);
      }
      main {
        max-width: 520px;
        margin: 10vh auto;
        padding: 1.5rem;
      }
      .card {
        background: var(--card);
        border: 1px solid rgba(31, 27, 22, 0.08);
        border-radius: 24px;
        padding: 2rem;
        box-shadow: 0 16px 50px rgba(31, 27, 22, 0.08);
      }
      h1 {
        margin: 0 0 0.5rem;
        font-size: clamp(1.6rem, 3vw, 2.2rem);
        line-height: 1.1;
      }
      p {
        margin: 0.5rem 0;
        font-size: 1rem;
        line-height: 1.6;
      }
      .email {
        font-weight: 600;
        overflow-wrap: anywhere;
      }
      label {
        display: block;
        margin: 1.25rem 0 0.4rem;
        font-size: 0.9rem;
        font-weight: 600;
      }
      input[type="email"],
      input[type="password"] {
        width: 100%;
        padding: 0.75rem 0.9rem;
        border: 1px solid rgba(31, 27, 22, 0.2);
        border-radius: 12px;
        background: #fff;
        color: inherit;
        font-size: 1rem;
      }
      input[type="email"]:focus,
      input[type="password"]:focus {
        outline: 2px solid var(--accent);
        outline-offset: 1px;
      }
      button {
        width: 100%;
        margin-top: 1.25rem;
        padding: 0.8rem 1rem;
        border: 0;
        border-radius: 12px;
        background: var(--accent);
        color: #fff;
        font-size: 1rem;
        font-weight: 600;
        cursor: pointer;
      }
      .error {
        margin-top: 1rem;
        padding: 0.75rem 0.9rem;
        border-radius: 12px;
        background: rgba(180, 35, 24, 0.1);
        color: #8c1d13;
        font-size: 0.95rem;
      }
      .note {
        margin-top: 1.5rem;
        font-size: 0.85rem;
        opacity: 0.7;
      }
`;

function pageHeaders(): Headers {
  // No `form-action` directive on purpose: browsers apply it to redirects of form
  // submissions too, which would block the 302 back to the relying party's callback.
  return noStoreHeaders({
    'Content-Security-Policy':
      "default-src 'none'; frame-ancestors 'none'; style-src 'unsafe-inline'; base-uri 'none'",
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
  });
}

function layout(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="robots" content="noindex" />
    <title>${escapeHtml(title)}</title>
    <style>${PAGE_STYLE}    </style>
  </head>
  <body>
    <main>
${body}
    </main>
  </body>
</html>`;
}

export interface LoginPageOptions {
  email?: string;
  requestId: string;
  error?: string;
  setCookies?: string[];
  status?: number;
}

export function renderLoginPage(options: LoginPageOptions): Response {
  const errorBlock = options.error
    ? `\n      <p class="error" role="alert">${escapeHtml(options.error)}</p>`
    : '';

  const emailBlock = options.email
    ? `        <p>
          An application is asking ZeroAuth to sign you in as
          <span class="email">${escapeHtml(options.email)}</span>.
        </p>`
    : `        <p>An application is requesting a sign-in. Enter the email address it should receive.</p>`;

  const emailField = options.email
    ? ''
    : `
          <label for="email">Email</label>
          <input
            id="email"
            name="email"
            type="email"
            autocomplete="username"
            required
            autofocus
          />`;

  const passwordAutofocus = options.email ? 'autofocus' : '';

  const body = `      <section class="card">
        <h1>Sign in to continue</h1>
${emailBlock}${errorBlock}
        <form method="post" action="/authorize">
          <input type="hidden" name="request_id" value="${escapeHtml(options.requestId)}" />${emailField}
          <label for="password">Password</label>
          <input
            id="password"
            name="password"
            type="password"
            autocomplete="current-password"
            required
            ${passwordAutofocus}
          />
          <button type="submit">Continue</button>
        </form>
        <p class="note">
          ZeroAuth has no user accounts. Sign-in uses one shared password.
        </p>
      </section>`;

  const headers = pageHeaders();

  for (const cookie of options.setCookies ?? []) {
    headers.append('Set-Cookie', cookie);
  }

  return htmlResponse(layout('Sign in · ZeroAuth', body), {
    headers,
    status: options.status ?? (options.error ? 401 : 200),
  });
}

export interface NoticePageOptions {
  title: string;
  message: string;
  status: number;
  retryAfterSeconds?: number;
}

export function renderNoticePage(options: NoticePageOptions): Response {
  const headers = pageHeaders();

  if (options.retryAfterSeconds !== undefined) {
    headers.set('Retry-After', String(options.retryAfterSeconds));
  }

  const body = `      <section class="card">
        <h1>${escapeHtml(options.title)}</h1>
        <p>${escapeHtml(options.message)}</p>
      </section>`;

  return htmlResponse(layout(`${options.title} · ZeroAuth`, body), {
    headers,
    status: options.status,
  });
}
