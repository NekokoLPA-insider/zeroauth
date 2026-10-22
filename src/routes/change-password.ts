import { htmlResponse } from '../utils.ts';

export function handleChangePassword(): Response {
  return htmlResponse(
    `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>ZeroAuth Change Password</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #f2efe8;
        --ink: #1f1b16;
        --accent: #0f766e;
        --card: #fffaf0;
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
        max-width: 720px;
        margin: 8vh auto;
        padding: 2rem;
      }
      .card {
        background: var(--card);
        border: 1px solid rgba(31, 27, 22, 0.08);
        border-radius: 24px;
        padding: 2rem;
        box-shadow: 0 16px 50px rgba(31, 27, 22, 0.08);
      }
      h1 {
        margin-top: 0;
        font-size: clamp(2rem, 4vw, 3rem);
        line-height: 1;
      }
      p {
        font-size: 1.05rem;
        line-height: 1.6;
      }
      code {
        background: rgba(15, 118, 110, 0.08);
        padding: 0.15rem 0.35rem;
        border-radius: 6px;
      }
    </style>
  </head>
  <body>
    <main>
      <section class="card">
        <h1>ZeroAuth has no user passwords.</h1>
        <p>
          This endpoint exists because some OIDC relying parties expect a change-password URL
          when they create a connection.
        </p>
        <p>
          ZeroAuth uses a single shared sign-in password. There are no per-user accounts to
          reset, and no directory is stored.
        </p>
        <p>
          If you reached this page unexpectedly, review the relying party configuration and the
          Worker environment variables, especially <code>ZEROAUTH_PASSWORD</code>.
        </p>
      </section>
    </main>
  </body>
</html>`,
    { status: 200 },
  );
}
