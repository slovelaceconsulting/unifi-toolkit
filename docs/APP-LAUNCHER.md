# Sign in with App Launcher

This fork (`slovelaceconsulting/unifi-toolkit`) adds **Sign in with App
Launcher**: App Launcher acts as the toolkit's identity provider over OpenID
Connect, and App Launcher's app manager installs and updates the toolkit from
`ghcr.io/slovelaceconsulting/unifi-toolkit`.

The contract is App Launcher's `docs/app-sso-integration.md` (provider v1.6.0
or later). The toolkit's side is `app/routers/launcher.py`.

## How it behaves

- **Off unless `LAUNCHER_ISSUER` is set.** With it blank the toolkit works
  exactly as upstream.
- **Setting `LAUNCHER_ISSUER` turns sign-in on, even with
  `DEPLOYMENT_TYPE=local`.** If the rest of the settings are missing, the
  toolkit stays locked and the login page names what's missing, rather than
  falling back to no login.
- **App Launcher decides who gets in.** Only people with access to the
  toolkit's tile can finish sign-in; everyone else sees "Your App Launcher
  account doesn't have access to the UniFi Toolkit." The toolkit has a single
  admin and no roles, so **everyone the launcher lets through gets full
  access.** `launcher_role` is not used.
- **Break-glass:** the local `AUTH_USERNAME` / `AUTH_PASSWORD_HASH` login keeps
  working. With `LAUNCHER_ONLY=true` its form is hidden, and stays at
  `/login?local=1`.
- **Sign-out** clears the toolkit session, then ends the launcher session at
  its `end_session_endpoint` and comes back to `/login`.
- Protocol: authorization code + PKCE (S256), `state` and `nonce`, RS256 ID
  token checked against the launcher's JWKS (signature, `iss`, `aud`, `exp`,
  `nonce`), RFC 9207 `iss` on the callback. The client secret is only sent to
  the token endpoint and never logged. Certificate checks are never turned
  off.
- `GET /.well-known/launcher-app.json` lets App Launcher's *Add app* form fill
  itself in. It holds nothing secret.

## Settings

| Variable | Example | Notes |
|---|---|---|
| `LAUNCHER_ISSUER` | `https://apps.lakelandlakers.net:8443` | Required. Blank = feature off. No path. |
| `LAUNCHER_CLIENT_ID` | `unifi-toolkit` | Default `unifi-toolkit`. Must match App Launcher. |
| `LAUNCHER_CLIENT_SECRET` | (shown once by App Launcher) | Required. `LAUNCHER_CLIENT_SECRET_FILE` works too. |
| `LAUNCHER_REDIRECT_URI` | `https://apps.lakelandlakers.net:9402/auth/launcher/callback` | Recommended. Blank = built from the request (`X-Forwarded-Proto` / `X-Forwarded-Host`). Must exactly match what's registered. |
| `LAUNCHER_POST_LOGOUT_REDIRECT_URI` | | Blank = the redirect address's origin + `/login`. |
| `LAUNCHER_CA_FILE` | `/app/data/launcher-ca.pem` | The launcher's CA (`ca.pem`, not `cert.pem`). Blank = system trust store. A path that doesn't exist is an error, not a fallback. |
| `LAUNCHER_BUTTON_LABEL` | `Sign in with App Launcher` | |
| `LAUNCHER_ONLY` | `false` | `true` hides the password form (break-glass at `/login?local=1`). |

The host in `LAUNCHER_REDIRECT_URI` is added to the anti-DNS-rebinding
allowlist automatically. If people reach the toolkit through another name, set
`DOMAIN` or `ALLOWED_HOSTS`.

## Installing on the App Launcher machine

1. **Make the folder** `/srv/apps/unifi-toolkit/` with a `data/` folder in it
   (`chown 1000:1000 data`: the container runs as uid 1000).
2. Copy `deploy/compose.yaml` → `compose.yaml` and `deploy/.env.example` →
   `.env`.
3. **Copy the launcher's CA certificate** (App Launcher's `data/tls/ca.pem`)
   to `data/launcher-ca.pem`. It's valid for 10 years and doesn't change when
   the launcher renews its own certificate.
4. **Register the client in App Launcher:** *Management → Sign-in → Apps that
   use "Sign in with App Launcher" → Add app.* Pick the toolkit (the form
   pre-fills from its manifest or compose labels), client ID `unifi-toolkit`,
   set *Who can sign in* to the toolkit's tile, and check the redirect and
   post-logout addresses. **Copy the secret: it's shown once.**
5. **Fill in `.env`:** `ENCRYPTION_KEY` (generate once, never change),
   `LAUNCHER_ISSUER`, `LAUNCHER_HOSTNAME`, `LAUNCHER_CLIENT_SECRET`,
   `LAUNCHER_REDIRECT_URI`, and optionally a break-glass
   `AUTH_PASSWORD_HASH` (every `$` written as `$$`).
6. **Start it** from App Launcher (or `docker compose up -d`). The log shows
   `App Launcher sign-in enabled (issuer ..., client unifi-toolkit)`, or names
   the missing settings.
7. **Check:** sign in through the button as someone with access, then as
   someone without (expect the no-access message), then sign out and confirm
   both sessions are gone. Use the *Test* button on the app's registration in
   App Launcher too.
8. Once it works, optionally set `LAUNCHER_ONLY=true`.

### HTTPS

The launcher only registers `https://` return addresses (except localhost),
and the toolkit's session cookie is `Secure`. Reach the toolkit over HTTPS:

- **App Launcher's gateway (recommended):** turn on *Require App Launcher
  sign-in* for the tile. People reach it at the gateway's https port; the
  gateway forwards to the toolkit over plain http with `X-Forwarded-Proto` /
  `X-Forwarded-Host`, which the toolkit uses for its addresses. Publish the
  toolkit on `127.0.0.1` (`HOST_BIND=127.0.0.1`).
- or the upstream Caddy setup (`DEPLOYMENT_TYPE=production`, `--profile
  production` with the repo's own `docker-compose.yml`).

### Reaching the launcher from the container

The toolkit's server calls the launcher's token and JWKS endpoints itself, so
the container must resolve the launcher's name (`extra_hosts` with
`LAUNCHER_HOSTNAME` in `deploy/compose.yaml`, pointing at `host-gateway`) and
trust its CA (`LAUNCHER_CA_FILE`). "Couldn't reach App Launcher" on the login
page means one of these is wrong.

### Moving an existing install

Everything the toolkit keeps is in its `data/` folder (`unifi_toolkit.db`).
Stop the old container, copy its `data/` contents into
`/srv/apps/unifi-toolkit/data/`, and reuse **the same `ENCRYPTION_KEY`**, or
the stored UniFi credentials can't be decrypted.

## Keeping the fork current

```
git fetch origin                      # origin = Crosstalk-Solutions/unifi-toolkit
git merge origin/main                 # or a release tag, e.g. v1.13.7
git push fork main
```

The launcher code is confined to `app/routers/launcher.py`, a few hooks in
`app/routers/auth.py` and `app/main.py`, the login template, and the deploy
files, so upstream merges rarely conflict.

Releases of the fork are tagged `vX.Y.Z-launcher.N` (upstream version + fork
revision). A tag builds `:X.Y.Z-launcher.N`, `:latest` and `:stable`; every
push to `main` builds `:edge`.

## Tests

`tests/test_launcher.py` runs a mock OpenID provider in-process (RSA key,
discovery, JWKS, token endpoint) and covers: feature off, fail-closed when half
configured, happy path with return path, PKCE, forwarded-header redirect
address, every refusal (state, nonce, `aud`, `iss`, expired, bad signature,
unknown `kid`, token error, `access_denied`, `iss` parameter, replay), the
secret never appearing in responses or logs, open-redirect attempts, the
break-glass login, sign-out, and the manifest.
