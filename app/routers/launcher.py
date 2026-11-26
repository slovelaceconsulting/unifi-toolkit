"""
Sign in with App Launcher (OpenID Connect).

App Launcher is a standard OpenID Connect provider. The contract (endpoint
paths, claims, errors) is fixed by App-Launcher's docs/app-sso-integration.md:
authorization-code flow with PKCE (S256), state and nonce, RS256 ID tokens
signed with a key from the provider's JWKS. This module is the toolkit's side
of it, written for FastAPI (suite-core's launcher.py is the Flask equivalent).

The whole feature is off unless LAUNCHER_ISSUER is set. When it is set, sign-in
is required even in local mode (see auth.is_auth_enabled), so a half-finished
configuration never leaves the toolkit open.

The toolkit has one admin and no user accounts or roles, so there is no user
linking: App Launcher already refuses anyone without access to the toolkit's
tile (error=access_denied), and everyone it lets through gets the toolkit.

Certificate checks are never turned off. The launcher's CA comes from
LAUNCHER_CA_FILE; when unset, the system trust store is used.
"""

import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import ssl
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote, urlencode, urlsplit

import aiohttp
import jwt
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

logger = logging.getLogger(__name__)

router = APIRouter()

START_PATH = "/auth/launcher/start"
CALLBACK_PATH = "/auth/launcher/callback"
LOGOUT_RETURN_PATH = "/login"
MANIFEST_PATH = "/.well-known/launcher-app.json"
STATE_COOKIE = "launcher_state"
STATE_COOKIE_PATH = "/auth/launcher"
STATE_MAX_AGE = 600          # 10 minutes, per the contract
HTTP_TIMEOUT = 10
METADATA_TTL = 3600          # discovery + JWKS cache
CLOCK_LEEWAY = 30
DEFAULT_CLIENT_ID = "unifi-toolkit"
DEFAULT_BUTTON = "Sign in with App Launcher"
APP_NAME = "UniFi Toolkit"

GENERIC_FAILURE = "Sign-in with App Launcher failed. Please try again."
NO_ACCESS = "Your App Launcher account doesn't have access to the UniFi Toolkit. Ask an administrator."
STALE_STATE = ("That sign-in took too long, or was started in another browser tab. "
               "Please sign in again.")
UNREACHABLE = ("Couldn't reach App Launcher. Check LAUNCHER_ISSUER, that this container can resolve "
               "the launcher's name (extra_hosts), and that LAUNCHER_CA_FILE is its CA certificate.")


class LauncherError(Exception):
    """A sign-in that must not go ahead. `code` is for the log; `message` is shown."""

    def __init__(self, code: str, message: str = GENERIC_FAILURE):
        super().__init__(code)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# Configuration (environment only, names shared with every suite app)
# ---------------------------------------------------------------------------

def _env_bool(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class LauncherConfig:
    issuer: str
    client_id: str
    client_secret: str
    redirect_uri: str
    post_logout_uri: str
    ca_file: str
    button_label: str
    launcher_only: bool

    @property
    def configured(self) -> bool:
        """LAUNCHER_ISSUER is set: sign-in is required, whether or not the rest is complete."""
        return bool(self.issuer)

    @property
    def missing(self) -> list:
        required = {"LAUNCHER_ISSUER": self.issuer, "LAUNCHER_CLIENT_ID": self.client_id,
                    "LAUNCHER_CLIENT_SECRET": self.client_secret}
        return [name for name, value in required.items() if not value]

    @property
    def ready(self) -> bool:
        return self.configured and not self.missing


def get_config() -> LauncherConfig:
    """Read on every call, like is_auth_enabled(), so tests and restarts see the same thing."""
    return LauncherConfig(
        issuer=os.getenv("LAUNCHER_ISSUER", "").strip().rstrip("/"),
        client_id=os.getenv("LAUNCHER_CLIENT_ID", "").strip() or DEFAULT_CLIENT_ID,
        client_secret=os.getenv("LAUNCHER_CLIENT_SECRET", "").strip(),
        redirect_uri=os.getenv("LAUNCHER_REDIRECT_URI", "").strip(),
        post_logout_uri=os.getenv("LAUNCHER_POST_LOGOUT_REDIRECT_URI", "").strip(),
        ca_file=os.getenv("LAUNCHER_CA_FILE", "").strip(),
        button_label=os.getenv("LAUNCHER_BUTTON_LABEL", "").strip() or DEFAULT_BUTTON,
        launcher_only=_env_bool("LAUNCHER_ONLY"),
    )


def is_configured() -> bool:
    return get_config().configured


def is_ready() -> bool:
    return get_config().ready


def app_public_url() -> str:
    """APP_PUBLIC_URL: the toolkit's address as people reach it. App Launcher
    writes it (and keeps it current) for apps it manages."""
    return os.getenv("APP_PUBLIC_URL", "").strip().rstrip("/")


def configured_hostnames() -> set:
    """Hostnames the anti-rebinding check must accept: the configured return
    addresses, APP_PUBLIC_URL, and the launcher's own name. App Launcher's
    gateway serves apps on the launcher's hostname (other ports), and passes
    that Host header on."""
    c = get_config()
    hosts = set()
    for url in (c.redirect_uri, c.post_logout_uri, app_public_url(), c.issuer if c.configured else ""):
        host = urlsplit(url).hostname if url else None
        if host:
            hosts.add(host.lower())
    hostname = os.getenv("LAUNCHER_HOSTNAME", "").strip().lower()
    if c.configured and hostname:
        hosts.add(hostname)
    return hosts


# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------

def _is_https(request: Request) -> bool:
    proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return (proto or request.url.scheme) == "https"


def _public_origin(request: Request) -> str:
    """scheme://host[:port] as the browser sees it. Behind App Launcher's gateway
    (or Caddy) that comes from X-Forwarded-Proto / X-Forwarded-Host. A forged
    value only changes the redirect_uri sent to the launcher, which refuses any
    address that isn't registered for this client."""
    proto = "https" if _is_https(request) else request.url.scheme
    host = (request.headers.get("x-forwarded-host", "").split(",")[0].strip()
            or request.headers.get("host", "")
            or request.url.netloc)
    return f"{proto}://{host}"


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def redirect_uri_for(request: Request, c: Optional[LauncherConfig] = None) -> str:
    """LAUNCHER_REDIRECT_URI, else APP_PUBLIC_URL + callback, else the address
    the request came in on."""
    c = c or get_config()
    if c.redirect_uri:
        return c.redirect_uri
    base = _origin(app_public_url()) if app_public_url() else _public_origin(request)
    return base + CALLBACK_PATH


def post_logout_uri_for(request: Request, c: Optional[LauncherConfig] = None) -> str:
    c = c or get_config()
    if c.post_logout_uri:
        return c.post_logout_uri
    if c.redirect_uri:
        return _origin(c.redirect_uri) + LOGOUT_RETURN_PATH
    if app_public_url():
        return _origin(app_public_url()) + LOGOUT_RETURN_PATH
    return _public_origin(request) + LOGOUT_RETURN_PATH


def safe_return_path(value: Optional[str]) -> str:
    """A relative path on this site, or "/". Blocks //host and /\\host open redirects."""
    value = (value or "").strip()
    if (not value.startswith("/") or value.startswith("//") or value.startswith("/\\")
            or any(ch in value for ch in "\r\n\t") or "://" in value.split("?", 1)[0]):
        return "/"
    return value


# ---------------------------------------------------------------------------
# HTTP to the launcher (server side). Tests replace `_http`.
# ---------------------------------------------------------------------------

def _ssl_context(c: LauncherConfig) -> ssl.SSLContext:
    if c.ca_file:
        if not os.path.isfile(c.ca_file):
            raise LauncherError("ca_file_missing", f"LAUNCHER_CA_FILE ({c.ca_file}) doesn't exist in the container.")
        return ssl.create_default_context(cafile=c.ca_file)
    return ssl.create_default_context()


class _Http:
    async def get_json(self, url: str, c: LauncherConfig) -> dict:
        timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.get(url, ssl=_ssl_context(c), headers={"Accept": "application/json"}) as r:
                r.raise_for_status()
                return await r.json(content_type=None)

    async def post_form(self, url: str, data: dict, auth_header: str, c: LauncherConfig) -> tuple:
        timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT)
        headers = {"Authorization": auth_header, "Accept": "application/json"}
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.post(url, data=data, headers=headers, ssl=_ssl_context(c)) as r:
                try:
                    body = await r.json(content_type=None)
                except Exception:  # noqa: BLE001 - a non-JSON error page
                    body = {}
                return r.status, body if isinstance(body, dict) else {}


_http = _Http()
_cache: dict = {}


def reset_cache():
    _cache.clear()


async def _cached(key, loader):
    hit = _cache.get(key)
    if hit and time.monotonic() - hit[0] < METADATA_TTL:
        return hit[1]
    value = await loader()
    _cache[key] = (time.monotonic(), value)
    return value


async def discovery(c: LauncherConfig) -> dict:
    async def load():
        try:
            doc = await _http.get_json(f"{c.issuer}/.well-known/openid-configuration", c)
        except LauncherError:
            raise
        except Exception as e:  # noqa: BLE001
            logger.warning("App Launcher discovery failed: %s", type(e).__name__)
            raise LauncherError("discovery_failed", UNREACHABLE) from None
        if not isinstance(doc, dict) or str(doc.get("issuer", "")).rstrip("/") != c.issuer:
            logger.warning("App Launcher discovery: issuer mismatch (%r)", doc.get("issuer") if isinstance(doc, dict) else None)
            raise LauncherError("issuer_mismatch", UNREACHABLE)
        for k in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not doc.get(k):
                raise LauncherError("discovery_incomplete", UNREACHABLE)
        if "S256" not in (doc.get("code_challenge_methods_supported") or []):
            raise LauncherError("no_pkce", UNREACHABLE)
        return doc
    return await _cached(("disc", c.issuer, c.ca_file), load)


async def _jwks(c: LauncherConfig, uri: str, fresh: bool = False) -> list:
    key = ("jwks", uri, c.ca_file)
    if fresh:
        _cache.pop(key, None)

    async def load():
        try:
            doc = await _http.get_json(uri, c)
        except Exception as e:  # noqa: BLE001
            logger.warning("App Launcher JWKS fetch failed: %s", type(e).__name__)
            raise LauncherError("jwks_failed") from None
        return list(doc.get("keys") or []) if isinstance(doc, dict) else []
    return await _cached(key, load)


# ---------------------------------------------------------------------------
# Protocol pieces
# ---------------------------------------------------------------------------

def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def pkce_challenge(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def _serializer() -> URLSafeTimedSerializer:
    # Derived from ENCRYPTION_KEY (always set) so no new secret has to be managed.
    base = os.getenv("ENCRYPTION_KEY", "")
    if not base:
        raise LauncherError("no_encryption_key")
    secret = hashlib.sha256(b"unifi-toolkit/launcher-state:" + base.encode()).hexdigest()
    return URLSafeTimedSerializer(secret, salt="launcher-state")


def basic_auth(client_id: str, client_secret: str) -> str:
    """client_secret_basic: each part form-encoded first (RFC 6749 2.3.1)."""
    raw = f"{quote(client_id, safe='')}:{quote(client_secret, safe='')}".encode()
    return "Basic " + base64.b64encode(raw).decode("ascii")


async def verify_id_token(id_token: str, nonce: str, c: LauncherConfig, disc: dict) -> dict:
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError:
        raise LauncherError("bad_token") from None
    if header.get("alg") != "RS256":
        raise LauncherError("bad_alg")
    kid = header.get("kid")

    def find(keys):
        return next((k for k in keys if k.get("kid") == kid and k.get("kty") == "RSA"), None)

    jwk = find(await _jwks(c, disc["jwks_uri"]))
    if jwk is None:  # the launcher may have rotated its key: refetch once
        jwk = find(await _jwks(c, disc["jwks_uri"], fresh=True))
    if jwk is None:
        raise LauncherError("unknown_kid")
    try:
        key = jwt.PyJWK(jwk, algorithm="RS256").key
        claims = jwt.decode(
            id_token, key=key, algorithms=["RS256"], audience=c.client_id, issuer=c.issuer,
            leeway=CLOCK_LEEWAY, options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        raise LauncherError("expired_token") from None
    except jwt.InvalidAudienceError:
        raise LauncherError("bad_aud") from None
    except jwt.InvalidIssuerError:
        raise LauncherError("bad_iss") from None
    except jwt.PyJWTError:
        raise LauncherError("bad_token") from None
    token_nonce = claims.get("nonce")
    if not isinstance(token_nonce, str) or not hmac.compare_digest(token_nonce, nonce):
        raise LauncherError("bad_nonce")
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub.strip():
        raise LauncherError("bad_sub")
    return claims


def display_name(claims: dict) -> str:
    raw = (str(claims.get("preferred_username") or "").strip()
           or str(claims.get("email") or "").strip()
           or f"launcher-{str(claims.get('sub'))[-8:]}")
    return "".join(ch for ch in raw if ch.isprintable())[:100]


def _clean_error_code(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "", value or "")[:64] or "unknown"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def _not_found():
    return JSONResponse(status_code=404, content={"detail": "Not Found"})


def _login_error(request: Request, message: str, status_code: int):
    from app.routers.auth import render_login
    response = render_login(request, error=message, status_code=status_code)
    response.delete_cookie(STATE_COOKIE, path=STATE_COOKIE_PATH)
    return response


@router.get(START_PATH)
async def launcher_start(request: Request):
    c = get_config()
    if not c.ready:
        return _not_found()
    try:
        disc = await discovery(c)
        serializer = _serializer()
    except LauncherError as e:
        logger.warning("App Launcher sign-in could not start: %s", e.code)
        return _login_error(request, e.message, 502)

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    redirect_uri = redirect_uri_for(request, c)
    cookie = serializer.dumps({
        "state": state, "nonce": nonce, "verifier": verifier, "redirect_uri": redirect_uri,
        "return": safe_return_path(request.query_params.get("return")),
    })
    query = urlencode({
        "response_type": "code",
        "client_id": c.client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": pkce_challenge(verifier),
        "code_challenge_method": "S256",
    })
    endpoint = disc["authorization_endpoint"]
    response = RedirectResponse(endpoint + ("&" if "?" in endpoint else "?") + query, status_code=303)
    response.set_cookie(STATE_COOKIE, cookie, max_age=STATE_MAX_AGE, path=STATE_COOKIE_PATH,
                        httponly=True, secure=_is_https(request), samesite="lax")
    return response


@router.get(CALLBACK_PATH)
async def launcher_callback(request: Request):
    c = get_config()
    if not c.ready:
        return _not_found()
    params = request.query_params

    raw = request.cookies.get(STATE_COOKIE)
    if not raw:
        logger.warning("App Launcher callback refused: no state cookie")
        return _login_error(request, STALE_STATE, 400)
    try:
        saved = _serializer().loads(raw, max_age=STATE_MAX_AGE)
    except (SignatureExpired, BadSignature, LauncherError):
        logger.warning("App Launcher callback refused: state cookie expired or invalid")
        return _login_error(request, STALE_STATE, 400)

    if not hmac.compare_digest(str(params.get("state", "")), str(saved.get("state", ""))):
        logger.warning("App Launcher callback refused: state mismatch")
        return _login_error(request, STALE_STATE, 400)

    if params.get("error"):
        code = _clean_error_code(params.get("error"))
        logger.warning("App Launcher refused sign-in: error=%s", code)
        if code == "access_denied":
            return _login_error(request, NO_ACCESS, 403)
        return _login_error(request, f"{GENERIC_FAILURE} (error: {code})", 400)

    # RFC 9207: when the launcher names itself, it must be the issuer we used.
    if params.get("iss") and params.get("iss").rstrip("/") != c.issuer:
        logger.warning("App Launcher callback refused: iss parameter mismatch")
        return _login_error(request, GENERIC_FAILURE, 400)

    code = params.get("code")
    if not code:
        return _login_error(request, GENERIC_FAILURE, 400)

    try:
        disc = await discovery(c)
        try:
            status, body = await _http.post_form(
                disc["token_endpoint"],
                {"grant_type": "authorization_code", "code": code,
                 "redirect_uri": saved["redirect_uri"], "code_verifier": saved["verifier"]},
                basic_auth(c.client_id, c.client_secret), c,
            )
        except LauncherError:
            raise
        except Exception as e:  # noqa: BLE001
            logger.warning("App Launcher token request failed: %s", type(e).__name__)
            raise LauncherError("token_unreachable", UNREACHABLE) from None
        if status != 200 or not body.get("id_token"):
            raise LauncherError(f"token_error:{_clean_error_code(str(body.get('error', status)))}")
        claims = await verify_id_token(body["id_token"], saved["nonce"], c, disc)
    except LauncherError as e:
        logger.warning("App Launcher sign-in refused: %s", e.code)
        return _login_error(request, e.message, 400)

    from app.routers.auth import start_session_response
    username = display_name(claims)
    logger.info("App Launcher sign-in: user=%r sub=%s amr=%s", username, claims.get("sub"), claims.get("amr"))
    response = start_session_response(username, method="launcher", redirect_to=saved.get("return") or "/")
    response.delete_cookie(STATE_COOKIE, path=STATE_COOKIE_PATH)
    return response


async def logout_url(request: Request) -> Optional[str]:
    """The launcher's end-session address, or None if the launcher isn't set up.
    No id_token_hint: the ID token is never kept."""
    c = get_config()
    if not c.ready:
        return None
    try:
        endpoint = (await discovery(c)).get("end_session_endpoint")
    except LauncherError:
        endpoint = None
    endpoint = endpoint or f"{c.issuer}/oidc/logout"
    query = urlencode({"client_id": c.client_id, "post_logout_redirect_uri": post_logout_uri_for(request, c)})
    return endpoint + ("&" if "?" in endpoint else "?") + query


@router.get(MANIFEST_PATH)
async def launcher_manifest(request: Request):
    """Lets App Launcher pre-fill its Add app form. Public; nothing in it is secret."""
    c = get_config()
    doc = {
        "clientId": c.client_id,
        "name": APP_NAME,
        "callbackPath": CALLBACK_PATH,
        "logoutReturnPath": LOGOUT_RETURN_PATH,
        "startPath": START_PATH,
    }
    if c.redirect_uri or app_public_url():
        doc["redirectUris"] = [redirect_uri_for(request, c)]
        doc["postLogoutRedirectUris"] = [post_logout_uri_for(request, c)]
    return JSONResponse(doc, headers={"Cache-Control": "no-store"})
