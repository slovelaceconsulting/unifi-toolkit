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
| `APP_PUBLIC_URL` | `https://apps.lakelandlakers.net:9402` | The toolkit's address as people reach it; App Launcher keeps it current. Its host passes the anti-rebinding check. |
| `LAUNCHER_HOSTNAME` | `apps.lakelandlakers.net` | The launcher's name (filled in by App Launcher). Used by `extra_hosts`, and accepted by the anti-rebinding check (the gateway serves apps on it). |
| `LAUNCHER_REDIRECT_URI` | `https://apps.lakelandlakers.net:9402/auth/launcher/callback` | Blank = `APP_PUBLIC_URL` + `/auth/launcher/callback`, else built from the request (`X-Forwarded-Proto` / `X-Forwarded-Host`). Must exactly match what's registered. |
| `LAUNCHER_POST_LOGOUT_REDIRECT_URI` | | Blank = the redirect address's origin + `/login`. |
| `LAUNCHER_CA_FILE` | `/app/data/launcher-ca.pem` | The launcher's CA (`ca.pem`, not `cert.pem`). Blank = system trust store. A path that doesn't exist is an error, not a fallback. |
| `LAUNCHER_BUTTON_LABEL` | `Sign in with App Launcher` | |
| `LAUNCHER_ONLY` | `false` | `true` hides the password form (break-glass at `/login?local=1`). |

`ENCRYPTION_KEY` may be left blank: the toolkit then keeps its key in
`data/encryption.key` (made on first start, mode 600), beside the database.

The hosts of `LAUNCHER_REDIRECT_URI`, `APP_PUBLIC_URL`, the issuer and
`LAUNCHER_HOSTNAME` are added to the anti-DNS-rebinding allowlist
automatically. If people reach the toolkit through another name, set
`DOMAIN` or `ALLOWED_HOSTS`.

## Installing with App Launcher

App Launcher's *Add app* reads `deploy/compose.yaml` and `deploy/.env.example`
straight from this repository, so there's nothing to copy by hand.

1. **Add the app:** *Management → App manager → Add app*, repository
   `slovelaceconsulting/unifi-toolkit`. The form fills in `LAUNCHER_ISSUER`
   and `LAUNCHER_HOSTNAME` with the launcher's own address. Leave
   `ENCRYPTION_KEY` blank (the toolkit makes one in `data/encryption.key`).
   If port 8000 is taken, the form suggests another `HOST_PORT`. Add it.
   It starts locked: the login page says `LAUNCHER_CLIENT_SECRET` is missing.
2. **Give the tile HTTPS:** turn on *Require App Launcher sign-in* for the
   toolkit's tile, so people reach it through the gateway's https port. Put
   that address in `APP_PUBLIC_URL` (e.g. `https://apps.example.org:9402`).
3. **Register the sign-in client:** *Management → Sign-in → Apps that use
   "Sign in with App Launcher" → Add app.* Pick the toolkit: the form fills
   itself from the toolkit's manifest and compose labels (client ID
   `unifi-toolkit`, `/auth/launcher/callback`, `/login`). Set *Who can sign
   in* to the toolkit's tile. **Copy the secret: it's shown once.**
4. **Finish `.env`** in the app manager's settings for the toolkit:
   `LAUNCHER_CLIENT_SECRET`, and, only if the launcher uses its own CA rather
   than a public certificate, `LAUNCHER_CA_FILE=/app/data/launcher-ca.pem`
   after copying the launcher's `data/tls/ca.pem` to the toolkit's
   `data/launcher-ca.pem`. Optionally a break-glass `AUTH_PASSWORD_HASH`
   (every `$` written as `$$`). Restart it.
5. **Check:** the log shows `App Launcher sign-in enabled`. Use *Test* on the
   sign-in registration, then sign in as someone with access, as someone
   without (expect the no-access message), and sign out (both sessions end).
6. Once it works, optionally set `LAUNCHER_ONLY=true`.

The container runs as uid 1000 and writes to `data/`. On Linux, if the app
manager's user isn't uid 1000, `sudo chown 1000:1000 <apps>/unifi-toolkit/data`.

Without App Launcher's app manager: make `/srv/apps/unifi-toolkit/`, copy
`deploy/compose.yaml` → `compose.yaml` and `deploy/.env.example` → `.env`,
fill it in, and `docker compose up -d`.

### HTTPS

The launcher only registers `https://` return addresses (except localhost),
and the toolkit's session cookie is `Secure`. Reach the toolkit over HTTPS:

- **App Launcher's gateway (recommended):** turn on *Require App Launcher
  sign-in* for the tile. People reach it at the gateway's https port; the
  gateway forwards to the toolkit over plain http with `X-Forwarded-Proto` /
  `X-Forwarded-Host`, which the toolkit uses for its addresses. Publish the
  toolkit only where the gateway can reach it: `HOST_BIND=172.17.0.1`
  (Docker's bridge) on Linux, the default; `HOST_BIND=127.0.0.1` on Docker
  Desktop. On Linux, `127.0.0.1` can't be reached from the launcher's
  container, and the tile says "UniFi Toolkit isn't responding".
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
