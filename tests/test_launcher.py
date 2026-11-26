"""Tests for Sign in with App Launcher (app/routers/launcher.py).

A mock OpenID provider stands in for App Launcher: an RSA key pair, a
discovery document, JWKS, and a token endpoint that signs RS256 ID tokens with
a `kid`. It replaces the module's HTTP layer, so nothing touches the network.
Cases follow App-Launcher docs/app-sso-integration.md section 5.
"""
import base64
import hashlib
import logging
import os
import time
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import bcrypt
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routers import launcher
from app.routers.auth import AuthMiddleware, _sessions, is_auth_enabled, router as auth_router

ISSUER = "https://apps.example.test:8443"
CLIENT_ID = "unifi-toolkit"
SECRET = "s3cr3t-value-that-must-never-leak"
REDIRECT = "https://toolkit.example.test/auth/launcher/callback"


def _rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(private_key, kid):
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return jwk


class MockProvider:
    """App Launcher's OIDC endpoints, in-process."""

    def __init__(self):
        self.key = _rsa()
        self.kid = "k1"
        self.token_requests = []
        self.claims_override = {}
        self.sign_key = None        # sign with a different key (bad signature)
        self.sign_kid = None        # put a different kid in the header
        self.token_status = 200
        self.token_body = None      # replace the token response body
        self.discovery = {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/oidc/authorize",
            "token_endpoint": f"{ISSUER}/oidc/token",
            "userinfo_endpoint": f"{ISSUER}/oidc/userinfo",
            "jwks_uri": f"{ISSUER}/oidc/jwks",
            "end_session_endpoint": f"{ISSUER}/oidc/logout",
            "code_challenge_methods_supported": ["S256"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        self.codes = {}

    # what the browser sends to /oidc/authorize, the provider remembers per code
    def authorize(self, location):
        q = {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}
        code = f"code-{len(self.codes)}"
        self.codes[code] = q
        return code, q

    def id_token(self, request):
        now = int(time.time())
        claims = {
            "iss": ISSUER, "aud": CLIENT_ID, "sub": "u_7f3a9c2e41b8",
            "preferred_username": "slovelace", "name": "slovelace",
            "email": "slovelace@example.test", "email_verified": True,
            "launcher_role": "user", "amr": ["pwd"],
            "iat": now, "exp": now + 300, "auth_time": now,
            "nonce": request["nonce"],
        }
        claims.update(self.claims_override)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, self.sign_key or self.key, algorithm="RS256",
                          headers={"kid": self.sign_kid or self.kid})

    # --- the HTTP layer launcher.py calls ---
    async def get_json(self, url, c):
        if url == f"{ISSUER}/.well-known/openid-configuration":
            return dict(self.discovery)
        if url == self.discovery["jwks_uri"]:
            return {"keys": [_jwk(self.key, self.kid)]}
        raise AssertionError(f"unexpected GET {url}")

    async def post_form(self, url, data, auth_header, c):
        assert url == self.discovery["token_endpoint"]
        self.token_requests.append({"data": dict(data), "auth": auth_header})
        if self.token_body is not None:
            return self.token_status, self.token_body
        request = self.codes[data["code"]]
        return self.token_status, {"access_token": "opaque", "token_type": "Bearer",
                                   "expires_in": 300, "id_token": self.id_token(request)}


def _app():
    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.include_router(auth_router)
    app.include_router(launcher.router)

    @app.get("/")
    async def home():
        return {"home": True}

    @app.get("/arrest/")
    async def arrest():
        return {"arrest": True}

    return app


BASE_ENV = {
    "DEPLOYMENT_TYPE": "local",
    "LAUNCHER_ISSUER": ISSUER,
    "LAUNCHER_CLIENT_ID": CLIENT_ID,
    "LAUNCHER_CLIENT_SECRET": SECRET,
    "LAUNCHER_REDIRECT_URI": REDIRECT,
    "LAUNCHER_ONLY": "false",
    "AUTH_USERNAME": "admin",
    "AUTH_PASSWORD_HASH": bcrypt.hashpw(b"BreakGlass123!", bcrypt.gensalt()).decode(),
}


@pytest.fixture
def provider():
    p = MockProvider()
    launcher.reset_cache()
    with patch.object(launcher, "_http", p):
        yield p
    launcher.reset_cache()


@pytest.fixture
def env():
    with patch.dict(os.environ, BASE_ENV):
        yield os.environ


@pytest.fixture
def client(env, provider):
    _sessions.clear()
    yield TestClient(_app(), base_url="https://toolkit.example.test")
    _sessions.clear()


def _start(client, provider, path="/auth/launcher/start"):
    r = client.get(path, follow_redirects=False)
    assert r.status_code == 303, r.text
    code, q = provider.authorize(r.headers["location"])
    return code, q


def _callback(client, **params):
    return client.get("/auth/launcher/callback", params=params, follow_redirects=False)


def _sign_in(client, provider, path="/auth/launcher/start"):
    code, q = _start(client, provider, path)
    return _callback(client, code=code, state=q["state"], iss=ISSUER), q


# ---------------------------------------------------------------------------
# 1. Feature off
# ---------------------------------------------------------------------------

class TestFeatureOff:
    def test_routes_404_and_no_button_when_issuer_unset(self, provider):
        env = {k: v for k, v in BASE_ENV.items() if not k.startswith("LAUNCHER_")}
        env["DEPLOYMENT_TYPE"] = "production"
        with patch.dict(os.environ, env):
            os.environ.pop("LAUNCHER_ISSUER", None)
            c = TestClient(_app(), base_url="https://t.example.test")
            assert c.get("/auth/launcher/start", follow_redirects=False).status_code == 404
            assert c.get("/auth/launcher/callback", follow_redirects=False).status_code == 404
            page = c.get("/login")
            assert page.status_code == 200
            assert "App Launcher" not in page.text
            assert 'id="login-form"' in page.text

    def test_local_mode_without_issuer_stays_open(self):
        with patch.dict(os.environ, {"DEPLOYMENT_TYPE": "local"}):
            os.environ.pop("LAUNCHER_ISSUER", None)
            assert is_auth_enabled() is False

    def test_issuer_turns_auth_on_even_in_local_mode(self, env):
        assert is_auth_enabled() is True

    def test_half_configured_fails_closed(self, provider):
        with patch.dict(os.environ, BASE_ENV):
            os.environ.pop("LAUNCHER_CLIENT_SECRET", None)
            c = TestClient(_app(), base_url="https://t.example.test")
            assert c.get("/", follow_redirects=False).status_code == 303   # to /login, not open
            assert c.get("/auth/launcher/start", follow_redirects=False).status_code == 404
            page = c.get("/login")
            assert "LAUNCHER_CLIENT_SECRET" in page.text
            assert 'id="launcher-btn"' not in page.text


# ---------------------------------------------------------------------------
# 2. Happy path, 5. PKCE
# ---------------------------------------------------------------------------

class TestHappyPath:
    def test_sign_in_creates_session(self, client, provider):
        r, _ = _sign_in(client, provider)
        assert r.status_code == 303
        assert r.headers["location"] == "/"
        token = r.cookies.get("session_token") or client.cookies.get("session_token")
        assert token in _sessions
        assert _sessions[token]["method"] == "launcher"
        assert _sessions[token]["username"] == "slovelace"
        assert client.get("/", follow_redirects=False).json() == {"home": True}

    def test_return_path_honoured(self, client, provider):
        r, _ = _sign_in(client, provider, "/auth/launcher/start?return=/arrest/")
        assert r.headers["location"] == "/arrest/"

    def test_authorize_request_parameters(self, client, provider):
        _, q = _start(client, provider)
        assert q["response_type"] == "code"
        assert q["client_id"] == CLIENT_ID
        assert q["redirect_uri"] == REDIRECT
        assert q["scope"] == "openid profile email"
        assert q["code_challenge_method"] == "S256"
        assert q["state"] and q["nonce"]

    def test_pkce_verifier_matches_challenge(self, client, provider):
        r, q = _sign_in(client, provider)
        assert r.status_code == 303
        sent = provider.token_requests[0]
        verifier = sent["data"]["code_verifier"]
        expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        assert expected == q["code_challenge"]
        assert sent["data"]["redirect_uri"] == REDIRECT
        assert sent["data"]["grant_type"] == "authorization_code"
        assert sent["auth"] == "Basic " + base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode()

    def test_redirect_uri_built_from_forwarded_headers_when_unset(self, provider):
        with patch.dict(os.environ, BASE_ENV):
            os.environ.pop("LAUNCHER_REDIRECT_URI", None)
            c = TestClient(_app(), base_url="http://127.0.0.1:8000")
            r = c.get("/auth/launcher/start", follow_redirects=False, headers={
                "X-Forwarded-Proto": "https", "X-Forwarded-Host": "apps.example.test:9402"})
            q = parse_qs(urlsplit(r.headers["location"]).query)
            assert q["redirect_uri"] == ["https://apps.example.test:9402/auth/launcher/callback"]

    def test_state_cookie_cleared_after_sign_in(self, client, provider):
        r, _ = _sign_in(client, provider)
        assert any(h.startswith("launcher_state=") and "Max-Age=0" in h
                   for h in r.headers.get_list("set-cookie"))


# ---------------------------------------------------------------------------
# 4. Refusals
# ---------------------------------------------------------------------------

class TestRefusals:
    def _no_session(self, r):
        assert not any(h.startswith("session_token=") and "Max-Age=0" not in h
                       for h in r.headers.get_list("set-cookie"))
        assert not _sessions

    def test_missing_state_cookie(self, client, provider):
        code, q = _start(client, provider)
        client.cookies.clear()
        r = _callback(client, code=code, state=q["state"])
        assert r.status_code == 400
        assert "sign in again" in r.text
        self._no_session(r)

    def test_state_mismatch(self, client, provider):
        code, _ = _start(client, provider)
        r = _callback(client, code=code, state="not-the-state")
        assert r.status_code == 400
        self._no_session(r)

    def test_tampered_state_cookie(self, client, provider):
        code, q = _start(client, provider)
        client.cookies.set("launcher_state", "garbage", domain="toolkit.example.test", path="/auth/launcher")
        r = _callback(client, code=code, state=q["state"])
        assert r.status_code == 400
        self._no_session(r)

    def test_expired_state_cookie(self, client, provider):
        code, q = _start(client, provider)
        with patch.object(launcher, "STATE_MAX_AGE", -1):
            r = _callback(client, code=code, state=q["state"])
        assert r.status_code == 400
        self._no_session(r)

    @pytest.mark.parametrize("override", [
        {"nonce": "wrong-nonce"},
        {"aud": "some-other-app"},
        {"iss": "https://evil.example.test"},
        {"exp": int(time.time()) - 600, "iat": int(time.time()) - 900},
        {"sub": ""},
    ], ids=["nonce", "aud", "iss", "expired", "empty-sub"])
    def test_bad_claims(self, client, provider, override):
        provider.claims_override = override
        r, _ = _sign_in(client, provider)
        assert r.status_code == 400
        assert launcher.GENERIC_FAILURE in r.text
        self._no_session(r)

    def test_bad_signature(self, client, provider):
        provider.sign_key = _rsa()
        r, _ = _sign_in(client, provider)
        assert r.status_code == 400
        self._no_session(r)

    def test_unknown_kid(self, client, provider):
        provider.sign_kid = "rotated-away"
        r, _ = _sign_in(client, provider)
        assert r.status_code == 400
        self._no_session(r)

    def test_token_endpoint_error(self, client, provider):
        provider.token_status, provider.token_body = 400, {"error": "invalid_grant"}
        r, _ = _sign_in(client, provider)
        assert r.status_code == 400
        self._no_session(r)

    def test_access_denied(self, client, provider):
        _, q = _start(client, provider)
        r = _callback(client, error="access_denied", state=q["state"])
        assert r.status_code == 403
        assert "doesn&#39;t have access" in r.text or "doesn't have access" in r.text
        self._no_session(r)

    def test_other_error_shows_code_escaped(self, client, provider):
        _, q = _start(client, provider)
        r = _callback(client, error="server_error<script>", state=q["state"],
                      error_description="<b>raw</b>")
        assert r.status_code == 400
        assert "server_errorscript" in r.text
        assert "server_error<script>" not in r.text and "<b>raw</b>" not in r.text

    def test_iss_parameter_mismatch(self, client, provider):
        code, q = _start(client, provider)
        r = _callback(client, code=code, state=q["state"], iss="https://evil.example.test")
        assert r.status_code == 400
        self._no_session(r)

    def test_code_is_not_replayable_across_sign_ins(self, client, provider):
        r, q = _sign_in(client, provider)
        assert r.status_code == 303
        # The state cookie was consumed: replaying the same callback is refused.
        r2 = _callback(client, code="code-0", state=q["state"], iss=ISSUER)
        assert r2.status_code == 400

    def test_discovery_issuer_mismatch_refuses_start(self, client, provider):
        provider.discovery["issuer"] = "https://someone-else.example.test"
        r = client.get("/auth/launcher/start", follow_redirects=False)
        assert r.status_code == 502


# ---------------------------------------------------------------------------
# 6. Secrets, 7. open redirect
# ---------------------------------------------------------------------------

class TestSecretsAndRedirects:
    def test_secret_never_in_responses_or_logs(self, client, provider, caplog):
        caplog.set_level(logging.DEBUG)
        texts = []
        r = client.get("/auth/launcher/start", follow_redirects=False)
        texts += [r.text, r.headers.get("location", ""), str(r.headers)]
        code, q = provider.authorize(r.headers["location"])
        r = _callback(client, code=code, state=q["state"])
        texts += [r.text, str(r.headers)]
        texts.append(client.get("/login").text)
        texts.append(client.get("/.well-known/launcher-app.json").text)
        provider.token_status, provider.token_body = 400, {"error": "invalid_client"}
        texts.append(_sign_in(client, provider)[0].text)
        joined = "\n".join(texts + [rec.getMessage() for rec in caplog.records])
        assert SECRET not in joined

    @pytest.mark.parametrize("target", [
        "//evil.example", "https://evil.example", "/\\evil.example", "evil.example", "",
    ])
    def test_open_redirect_ignored(self, client, provider, target):
        r, _ = _sign_in(client, provider, f"/auth/launcher/start?return={target}")
        assert r.headers["location"] == "/"


# ---------------------------------------------------------------------------
# Login page, break-glass, logout, manifest
# ---------------------------------------------------------------------------

class TestLoginPageAndLogout:
    def test_button_and_password_form_both_shown(self, client):
        page = client.get("/login").text
        assert 'id="launcher-btn"' in page
        assert "Sign in with App Launcher" in page
        assert 'id="login-form"' in page

    def test_custom_button_label(self, client, env):
        with patch.dict(os.environ, {"LAUNCHER_BUTTON_LABEL": "Sign in with Lakeland Apps"}):
            assert "Sign in with Lakeland Apps" in client.get("/login").text

    def test_launcher_only_hides_form_but_local_1_shows_it(self, client, env):
        with patch.dict(os.environ, {"LAUNCHER_ONLY": "true"}):
            assert 'id="login-form"' not in client.get("/login").text
            assert 'id="login-form"' in client.get("/login?local=1").text

    def test_break_glass_password_login_still_works(self, client, env):
        with patch.dict(os.environ, {"LAUNCHER_ONLY": "true"}):
            r = client.post("/login?local=1", data={"username": "admin", "password": "BreakGlass123!"},
                            follow_redirects=False)
            assert r.status_code == 303
            token = r.cookies.get("session_token") or client.cookies.get("session_token")
            assert _sessions[token]["method"] == "password"

    def test_launcher_logout_ends_launcher_session(self, client, provider):
        _sign_in(client, provider)
        r = client.get("/logout", follow_redirects=False)
        assert r.status_code == 303
        loc = urlsplit(r.headers["location"])
        assert f"{loc.scheme}://{loc.netloc}{loc.path}" == f"{ISSUER}/oidc/logout"
        q = parse_qs(loc.query)
        assert q["client_id"] == [CLIENT_ID]
        assert q["post_logout_redirect_uri"] == ["https://toolkit.example.test/login"]
        assert not _sessions

    def test_password_logout_stays_local(self, client, env):
        client.post("/login", data={"username": "admin", "password": "BreakGlass123!"})
        r = client.get("/logout", follow_redirects=False)
        assert r.headers["location"] == "/login"

    def test_manifest(self, client):
        r = client.get("/.well-known/launcher-app.json")
        assert r.status_code == 200
        doc = r.json()
        assert doc["clientId"] == CLIENT_ID
        assert doc["redirectUris"] == [REDIRECT]
        assert doc["postLogoutRedirectUris"] == ["https://toolkit.example.test/login"]
        assert doc["startPath"] == "/auth/launcher/start"
        assert doc["callbackPath"] == "/auth/launcher/callback"
        assert SECRET not in r.text

    def test_manifest_public_without_session(self, client):
        client.cookies.clear()
        assert client.get("/.well-known/launcher-app.json").status_code == 200


class TestAppLauncherManagedSettings:
    """Settings App Launcher writes into a managed app's .env."""

    def test_app_public_url_sets_return_addresses(self, provider):
        with patch.dict(os.environ, {**BASE_ENV, "APP_PUBLIC_URL": "https://apps.example.test:9402/"}):
            os.environ.pop("LAUNCHER_REDIRECT_URI", None)
            c = TestClient(_app(), base_url="http://127.0.0.1:8000")
            r = c.get("/auth/launcher/start", follow_redirects=False)
            q = parse_qs(urlsplit(r.headers["location"]).query)
            assert q["redirect_uri"] == ["https://apps.example.test:9402/auth/launcher/callback"]
            doc = c.get("/.well-known/launcher-app.json").json()
            assert doc["redirectUris"] == ["https://apps.example.test:9402/auth/launcher/callback"]
            assert doc["postLogoutRedirectUris"] == ["https://apps.example.test:9402/login"]

    def test_explicit_redirect_uri_beats_app_public_url(self, client, env):
        with patch.dict(os.environ, {"APP_PUBLIC_URL": "https://elsewhere.example.test"}):
            assert client.get("/.well-known/launcher-app.json").json()["redirectUris"] == [REDIRECT]

    def test_gateway_hostname_accepted_by_rebinding_check(self, env):
        with patch.dict(os.environ, {"LAUNCHER_HOSTNAME": "apps.example.test",
                                     "APP_PUBLIC_URL": "https://toolkit-pub.example.test"}):
            hosts = launcher.configured_hostnames()
        assert {"apps.example.test", "toolkit-pub.example.test", "toolkit.example.test"} <= hosts

    def test_launcher_hostname_ignored_when_feature_off(self):
        with patch.dict(os.environ, {"LAUNCHER_HOSTNAME": "apps.example.test"}):
            os.environ.pop("LAUNCHER_ISSUER", None)
            os.environ.pop("LAUNCHER_REDIRECT_URI", None)
            os.environ.pop("APP_PUBLIC_URL", None)
            assert launcher.configured_hostnames() == set()


class TestHelpers:
    def test_basic_auth_form_encodes_parts(self):
        h = launcher.basic_auth("a b", "p:w%")
        assert base64.b64decode(h.split()[1]).decode() == "a+b:p%3Aw%25".replace("+", "%20")

    def test_ca_file_missing_is_an_error_not_a_fallback(self, env):
        with patch.dict(os.environ, {"LAUNCHER_CA_FILE": "/nonexistent/ca.pem"}):
            with pytest.raises(launcher.LauncherError):
                launcher._ssl_context(launcher.get_config())
