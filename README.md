# ZeroAuth

ZeroAuth is a minimal, password-gated OpenID Connect identity provider for testing SSO with any OIDC relying party. The relying party sends a standard authorization request; ZeroAuth asks for one shared test password, then issues tokens for the requested email address.

It works with any client that speaks OIDC authorization code flow, including enterprise SSO control planes, internal admin panels, and self-hosted applications.

This is intentionally unsafe for production use. There is no user directory, no MFA, and no per-user account.

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/NekokoLPA-insider/zeroauth)

## What it implements

- Authorization Code Flow only
- `GET /.well-known/openid-configuration`
- `GET /jwks.json`
- `GET /authorize` (returns the password sign-in page)
- `POST /authorize` (validates the password, then redirects with a code)
- `POST /token`
- `GET /userinfo`
- `GET /healthz`
- `GET /change-password`

## Security model

ZeroAuth has two sign-in modes plus an explicit deny mode. Password mode always wins when it is configured.

- Password mode: if `ZEROAUTH_PASSWORD` is set, `/authorize` renders a sign-in page. A single shared password unlocks any syntactically valid email. When the relying party sends `login_hint`, that address is filled in and locked; otherwise the page asks for an email address.
- Unsafe allow mode: if `ZEROAUTH_PASSWORD` is unset and `ZEROAUTH_ALLOW_ANY_LOGIN_HINT=true`, any syntactically valid `login_hint` email is accepted without interaction.
- Deny mode: if neither is configured, `/authorize` refuses every request.

There are no accounts, 2FA, or account picker. The password is the only gate, and it is shared by everyone.

Only use this against a dedicated test application, never against real user accounts.

## Password mode

- The password lives in the `ZEROAUTH_PASSWORD` Worker secret. Set it with `wrangler secret put ZEROAUTH_PASSWORD`, never in `wrangler.toml`.
- The value is hashed with SHA-256 when the Worker reads its configuration and compared in constant time. You may also store a digest directly as `sha256:<64 hex characters>`.
- Plaintext values are hashed verbatim: leading and trailing spaces are significant. Passwords longer than 1024 characters are rejected.
- The sign-in form carries only an opaque, single-use `request_id`; the authorization request parameters are stored server-side in a Durable Object for 10 minutes, so the form cannot be tampered with to change `login_hint` or `redirect_uri`.
- The form is bound to the browser that loaded it through an `HttpOnly` cookie, so a form or link crafted by someone else cannot be completed with your password. Pages also send `frame-ancestors 'none'`.
- A second concurrent submission cannot mint a second code: claiming the pending request is atomic inside the Durable Object.
- After 10 failed attempts from the same client IP, sign-in returns `429` until the 10-minute window that started at the first failure ends. The window is never extended by further failures. Set `ZEROAUTH_MAX_LOGIN_ATTEMPTS=0` to disable the lockout.
- Each client IP may load `/authorize` 60 times per 5 minutes. Set `ZEROAUTH_MAX_AUTHORIZE_REQUESTS=0` to disable the limit.
- The IP-based limits are best effort. Cloudflare always sets `CF-Connecting-IP`, but deployments behind another proxy or tunnel can collapse all clients into one bucket (or let clients spoof the address). Raise the limits or disable them in that case.
- The password is asked for every authorization request unless sessions are enabled. Set `ZEROAUTH_SESSION_TTL_SECONDS` (for example `28800`) to issue a signed session cookie so a browser that already passed the password skips the page until the cookie expires. `0` keeps sessions disabled.

## Architecture

Authorization codes, pending logins and counters live in a single Durable Object (`AuthStore`). A Durable Object serializes its own calls, so `consume` and `claim` are atomic and single-use semantics hold under concurrency. Workers KV is no longer used. Expired entries are swept by an alarm every 15 minutes.

## Prerequisites

- Node.js 22+
- A Cloudflare Workers account (Durable Objects are included; `wrangler deploy` applies the migration)
- An OIDC relying party you can configure (any client that accepts a custom issuer, client ID and secret)

## Install

```bash
npm install
```

## Local quick start

```bash
npm install
cp .dev.vars.example .dev.vars
node scripts/generate-jwk.mjs   # paste kid + privateJwk into .dev.vars
npm run dev -- --local --port 8787
```

The tracked template is [.dev.vars.example](.dev.vars.example). It ships with `replace-me` placeholders for the signing key, so ZeroAuth refuses to start until you generate one. The template also uses the local-only password `zeroauth-local-password`; change it before deploying anywhere real.

`ZEROAUTH_ISSUER` must be the URL the relying party will actually call. `wrangler dev` listens on `http://localhost:8787`, which is not a valid issuer (issuers must be https), so for a full local callback flow use a tunnel and put its URL here.

## Generate a signing key

Generate a private JWK and a random `kid`:

```bash
node scripts/generate-jwk.mjs
```

The script prints JSON like:

```json
{
  "kid": "9c9c1d2a-1f13-4f03-9705-a13a0e2798cf",
  "privateJwk": {
    "kty": "RSA",
    "n": "...",
    "e": "AQAB",
    "d": "...",
    "alg": "RS256",
    "use": "sig"
  }
}
```

Copy `kid` to `ZEROAUTH_KID` and stringify `privateJwk` into `ZEROAUTH_PRIVATE_JWK`. RS256 is the safest default; ES256, ES384, ES512 and EdDSA are also supported, and the discovery document advertises whichever algorithm the key declares.

## Configure Cloudflare

1. Copy [.dev.vars.example](.dev.vars.example) to `.dev.vars` if you have not already.
2. Put the non-secret values in the `[vars]` block of [wrangler.toml](wrangler.toml), or set them in the dashboard:

   - `ZEROAUTH_CLIENT_ID`
   - `ZEROAUTH_KID`
   - `ZEROAUTH_ISSUER`
   - `ZEROAUTH_ALLOWED_REDIRECT_URIS`

3. Store the secret values with Wrangler:

   ```bash
   npx wrangler secret put ZEROAUTH_CLIENT_SECRET
   npx wrangler secret put ZEROAUTH_PRIVATE_JWK
   npx wrangler secret put ZEROAUTH_PASSWORD
   ```

4. Run `npx wrangler deploy`. The first deploy creates the `AuthStore` Durable Object declared in [wrangler.toml](wrangler.toml); no KV namespace is needed.
5. Optionally attach a custom domain with a `routes` entry in `wrangler.toml`, and make sure `ZEROAUTH_ISSUER` uses that same URL.

## Connect a relying party

1. Deploy ZeroAuth once so the issuer URL is reachable.
2. Open your relying party's OIDC / SSO configuration and create a connection with:

   - Client ID: your `ZEROAUTH_CLIENT_ID`
   - Client secret: your `ZEROAUTH_CLIENT_SECRET`
   - Issuer / discovery URL: your `ZEROAUTH_ISSUER`, for example `https://zeroauth.example.com`
   - Change password URL (if required): `https://zeroauth.example.com/change-password`

3. Save it and copy the callback / redirect URI the relying party shows you.
4. Put that exact URI into `ZEROAUTH_ALLOWED_REDIRECT_URIS`.

If there are multiple redirect URIs, set `ZEROAUTH_ALLOWED_REDIRECT_URIS` to a comma-separated list or a JSON array string.

5. Deploy again.
6. Test the sign-in with a dedicated test account or group, never with real users.

Compatibility notes for custom OIDC relying parties:

- ZeroAuth returns an `email` claim with `email_verified: true`.
- Only the authorization code flow is implemented; there is no implicit flow and no refresh token.
- The issuer must be https and must match exactly on both sides.
- If the relying party does not send `login_hint`, the sign-in page asks for an email address.

## Environment variables

| Variable                         | Required | Description                                                     |
| -------------------------------- | -------- | --------------------------------------------------------------- |
| `ZEROAUTH_CLIENT_ID`             | Yes      | Single allowed OAuth client ID                                  |
| `ZEROAUTH_CLIENT_SECRET`         | Yes      | Single allowed OAuth client secret                              |
| `ZEROAUTH_ALLOWED_REDIRECT_URIS` | No       | Comma-separated or JSON array allowlist of redirect URIs        |
| `ZEROAUTH_PRIVATE_JWK`           | Yes      | Private signing JWK as a JSON string                            |
| `ZEROAUTH_KID`                   | Yes      | Key ID used in JWT headers and JWKS                             |
| `ZEROAUTH_ISSUER`                | Yes      | Explicit public issuer URL; must exactly match the relying party configuration |
| `ZEROAUTH_AUTH_CODE_TTL_SECONDS` | No       | Authorization code TTL, default `60`                            |
| `ZEROAUTH_TOKEN_TTL_SECONDS`     | No       | Access token and ID token TTL, default `3600`                   |
| `ZEROAUTH_PASSWORD`              | Yes\*    | Shared test password, or `sha256:<64 hex characters>` digest. Use a Worker secret |
| `ZEROAUTH_MAX_LOGIN_ATTEMPTS`    | No       | Failed password attempts allowed per client IP before lockout, default `10`; `0` disables |
| `ZEROAUTH_MAX_AUTHORIZE_REQUESTS` | No      | `/authorize` requests allowed per client IP per 5 minutes, default `60`; `0` disables |
| `ZEROAUTH_SESSION_TTL_SECONDS`   | No       | Signed session lifetime in seconds, default `0` (password asked every time) |
| `ZEROAUTH_ALLOW_ANY_LOGIN_HINT`  | No       | Legacy unsafe mode; only applies when `ZEROAUTH_PASSWORD` is unset |

\* Required unless you deliberately enable the legacy `ZEROAUTH_ALLOW_ANY_LOGIN_HINT` mode.

## Commands

```bash
npm test
npm run typecheck
npm run deploy
```

## Behavior notes

- `/authorize` requires `client_id`, `redirect_uri`, `response_type=code` and a `scope` containing `openid`. `login_hint` is optional; in password mode the page asks for an email address when it is absent.
- In password mode, `GET /authorize` renders the sign-in page and `POST /authorize` issues the code. A wrong password returns the form with `401`; a completed or expired `request_id` returns `400`; a request that was not started in the same browser returns `400`.
- `login_hint` and the submitted email are normalized to lowercase before token issuance.
- Authorization codes are single-use and stored in a Durable Object, so concurrent exchanges cannot both succeed.
- `sub` is the SHA-256 hex digest of the lowercase email address.
- `refresh_token` is never issued.
- `/userinfo` accepts only the JWT access token minted by ZeroAuth.

## References

- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [Cloudflare Durable Objects](https://developers.cloudflare.com/durable-objects/)
- [Cloudflare Workers Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)

## Credits

ZeroAuth was originally created by [Damon](https://github.com/damonto) as a Google Workspace SSO test IdP. This fork generalizes it into a password-gated OIDC provider for any relying party. Both are released under the MIT license.
