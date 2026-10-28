"""
Tests for hosted (multi-user) mode: the SQLite auth store, the login page and the
full OAuth flow from client registration to an authenticated tool call.

The Intervals.icu API is replaced by an httpx MockTransport so the tests can check
which athlete and API key each request used.
"""

import asyncio
import base64
import hashlib
import json
import os
import pathlib
import secrets
import sys
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx  # pylint: disable=import-error
import pytest  # pylint: disable=import-error
from cryptography.fernet import Fernet  # pylint: disable=import-error
from starlette.testclient import TestClient  # pylint: disable=import-error

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
os.environ.setdefault("API_KEY", "test")
os.environ.setdefault("ATHLETE_ID", "i1")

from intervals_mcp_server.api import client as client_module  # pylint: disable=wrong-import-position
from intervals_mcp_server.auth import context as context_module  # pylint: disable=wrong-import-position
from intervals_mcp_server.auth import login as login_module  # pylint: disable=wrong-import-position
from intervals_mcp_server.auth.hosted import build_hosted_mcp  # pylint: disable=wrong-import-position
from intervals_mcp_server.auth.models import GrantAccessToken  # pylint: disable=wrong-import-position
from intervals_mcp_server.auth.store import AuthStore, set_store  # pylint: disable=wrong-import-position
from intervals_mcp_server.config import get_config  # pylint: disable=wrong-import-position
from intervals_mcp_server.server import get_gear_list, get_wellness_data  # pylint: disable=wrong-import-position
from intervals_mcp_server.tools import gear as gear_module  # pylint: disable=wrong-import-position
from intervals_mcp_server.utils import validation as validation_module  # pylint: disable=wrong-import-position

BASE_URL = "http://localhost:8000"
REDIRECT_URI = "http://localhost:9999/callback"
API_KEY = "user-secret-key"


class FakeIntervals:  # pylint: disable=too-few-public-methods
    """Records requests and answers like the Intervals.icu API."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.reject_key = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        """Answer a request the way Intervals.icu would for athlete i42."""
        self.requests.append(request)
        expected = "Basic " + base64.b64encode(f"API_KEY:{API_KEY}".encode()).decode()
        if self.reject_key or request.headers.get("authorization") != expected:
            return httpx.Response(401, text="unauthorized")
        path = request.url.path
        if path.endswith("/athlete/i42"):
            return httpx.Response(200, json={"id": "i42", "name": "Test Athlete"})
        if path.endswith("/athlete/i42/wellness"):
            return httpx.Response(200, json=[{"id": "2024-01-01", "ctl": 50, "restingHR": 48}])
        if path.endswith("/athlete/i42/gear"):
            return httpx.Response(200, json=[{"id": "b1", "name": "Road Bike", "type": "Bike"}])
        return httpx.Response(403, text="forbidden")


@pytest.fixture(name="hosted")
def hosted_fixture(tmp_path, monkeypatch):
    """Switch the shared config to hosted mode and build a hosted server."""
    config = get_config()
    monkeypatch.setattr(config, "auth_mode", "hosted")
    monkeypatch.setattr(config, "api_key", "")
    monkeypatch.setattr(config, "athlete_id", "")
    monkeypatch.setattr(config, "public_base_url", BASE_URL)
    monkeypatch.setattr(config, "token_encryption_key", Fernet.generate_key().decode())
    monkeypatch.setattr(config, "db_path", str(tmp_path / "auth.sqlite3"))

    store = AuthStore(config.db_path, config.token_encryption_key)
    set_store(store)

    fake = FakeIntervals()
    monkeypatch.setattr(
        client_module,
        "httpx_client",
        httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)),
    )
    monkeypatch.setattr(
        login_module,
        "_login_limiter",
        login_module._RateLimiter(1000, 60.0),  # pylint: disable=protected-access
    )
    gear_module._GEAR_RAW_CACHE.clear()  # pylint: disable=protected-access

    server = build_hosted_mcp(config)
    server.add_tool(get_wellness_data)
    server.add_tool(get_gear_list)

    with TestClient(server.streamable_http_app()) as http:
        yield http, fake, store

    set_store(None)


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    return verifier, challenge


def _register(http: TestClient) -> str:
    response = http.post(
        "/register",
        json={
            "redirect_uris": [REDIRECT_URI],
            "client_name": "Test Client",
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["client_id"]


def _start_login(http: TestClient, client_id: str, challenge: str) -> str:
    """Call /authorize and return the pending login id from the redirect."""
    response = http.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "client-state",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    location = urlparse(response.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == f"{BASE_URL}/login"
    return parse_qs(location.query)["req"][0]


def _submit_login(http: TestClient, req: str, **fields: str) -> httpx.Response:
    data = {"req": req, "athlete_id": "i42", "api_key": API_KEY, "action": "login", **fields}
    return http.post("/login", data=data, follow_redirects=False)


def _login(http: TestClient) -> dict[str, Any]:
    """Run the whole flow and return the token response plus the client id."""
    client_id = _register(http)
    verifier, challenge = _pkce()
    req = _start_login(http, client_id, challenge)
    response = _submit_login(http, req)
    assert response.status_code == 302, response.text
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["state"] == ["client-state"]
    token_response = http.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": query["code"][0],
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    assert token_response.status_code == 200, token_response.text
    return {
        **token_response.json(),
        "client_id": client_id,
        "code": query["code"][0],
        "verifier": verifier,
    }


def _call_tool(
    http: TestClient, token: str, name: str, arguments: dict[str, Any] | None = None
) -> httpx.Response:
    return http.post(
        "/mcp",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        },
    )


def _tool_text(response: httpx.Response) -> str:
    assert response.status_code == 200, response.text
    for line in response.text.splitlines():
        if line.startswith("data: "):
            payload = json.loads(line[len("data: ") :])
            return payload["result"]["content"][0]["text"]
    raise AssertionError(f"No tool result in response: {response.text}")


def test_full_flow_uses_signed_in_users_credentials(hosted):
    """A tool call made with the issued token uses that user's key and athlete."""
    http, fake, _store = hosted
    tokens = _login(http)

    text = _tool_text(_call_tool(http, tokens["access_token"], "get_wellness_data"))

    assert "Wellness Data" in text
    wellness_request = fake.requests[-1]
    assert wellness_request.url.path == "/api/v1/athlete/i42/wellness"
    assert wellness_request.headers["authorization"] == (
        "Basic " + base64.b64encode(f"API_KEY:{API_KEY}".encode()).decode()
    )


def test_login_page_shows_client_and_security_headers(hosted):
    """The login page names the requesting client and can't be framed."""
    http, _fake, _store = hosted
    req = _start_login(http, _register(http), _pkce()[1])

    response = http.get("/login", params={"req": req})

    assert response.status_code == 200
    assert "Test Client" in response.text
    assert "localhost:9999" in response.text
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert "form-action 'self' http://localhost:9999" in response.headers["content-security-policy"]


def test_foreign_athlete_is_rejected(hosted):
    """A signed-in user can't read another athlete's data."""
    http, fake, _store = hosted
    tokens = _login(http)
    requests_before = len(fake.requests)

    text = _tool_text(
        _call_tool(http, tokens["access_token"], "get_wellness_data", {"athlete_id": "i99"})
    )

    assert "only access the athlete you signed in with (i42)" in text
    assert len(fake.requests) == requests_before


def test_mcp_requires_token(hosted):
    """Unauthenticated MCP requests get a 401 pointing at the resource metadata."""
    http, _fake, _store = hosted

    response = _call_tool(http, "not-a-token", "get_wellness_data")

    assert response.status_code == 401
    assert "resource_metadata" in response.headers["www-authenticate"]
    metadata = http.get("/.well-known/oauth-protected-resource/mcp").json()
    assert metadata["resource"] == f"{BASE_URL}/mcp"


def test_refresh_rotates_tokens(hosted):
    """Refreshing issues new tokens and invalidates the old ones."""
    http, _fake, _store = hosted
    tokens = _login(http)

    refreshed = http.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": tokens["client_id"],
        },
    )

    assert refreshed.status_code == 200, refreshed.text
    new_tokens = refreshed.json()
    assert _call_tool(http, tokens["access_token"], "get_wellness_data").status_code == 401
    assert "Wellness Data" in _tool_text(
        _call_tool(http, new_tokens["access_token"], "get_wellness_data")
    )
    reused = http.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": tokens["client_id"],
        },
    )
    assert reused.status_code == 400


def test_authorization_code_is_single_use(hosted):
    """Exchanging the same code twice fails."""
    http, _fake, _store = hosted
    tokens = _login(http)

    second = http.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": tokens["code"],
            "redirect_uri": REDIRECT_URI,
            "client_id": tokens["client_id"],
            "code_verifier": tokens["verifier"],
        },
    )

    assert second.status_code == 400
    assert second.json()["error"] == "invalid_grant"


def test_rejected_key_revokes_grant(hosted):
    """When Intervals.icu rejects the stored key, the user is told to reconnect and the token stops working."""
    http, fake, _store = hosted
    tokens = _login(http)
    fake.reject_key = True

    text = _tool_text(_call_tool(http, tokens["access_token"], "get_wellness_data"))

    assert "Reconnect the Intervals.icu connector" in text
    assert _call_tool(http, tokens["access_token"], "get_wellness_data").status_code == 401


def test_bad_credentials_rerender_form(hosted):
    """Wrong credentials show an error on the form instead of redirecting."""
    http, _fake, _store = hosted
    req = _start_login(http, _register(http), _pkce()[1])

    response = _submit_login(http, req, api_key="wrong-key")

    assert response.status_code == 400
    assert "rejected this API key" in response.text
    assert "wrong-key" not in response.text
    assert 'value="i42"' in response.text


def test_invalid_athlete_id_rerenders_form(hosted):
    """Malformed athlete IDs are rejected before calling Intervals.icu."""
    http, fake, _store = hosted
    req = _start_login(http, _register(http), _pkce()[1])
    requests_before = len(fake.requests)

    response = _submit_login(http, req, athlete_id="not-an-id")

    assert response.status_code == 400
    assert "ATHLETE_ID must be all digits" in response.text
    assert len(fake.requests) == requests_before


def test_cancel_redirects_with_access_denied(hosted):
    """Cancelling sends the user back to the client with access_denied."""
    http, _fake, _store = hosted
    req = _start_login(http, _register(http), _pkce()[1])

    response = _submit_login(http, req, action="cancel")

    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["error"] == ["access_denied"]
    assert query["state"] == ["client-state"]
    assert http.get("/login", params={"req": req}).status_code == 400


def test_too_many_attempts_invalidate_login(hosted):
    """After five failed attempts the sign-in link stops working."""
    http, _fake, _store = hosted
    req = _start_login(http, _register(http), _pkce()[1])

    for _ in range(login_module.MAX_ATTEMPTS_PER_LOGIN):
        assert _submit_login(http, req, api_key="wrong-key").status_code == 400
    response = _submit_login(http, req)

    assert response.status_code == 400
    assert "Too many failed sign-in attempts" in response.text
    assert http.get("/login", params={"req": req}).status_code == 400


def test_unknown_login_request(hosted):
    """An unknown or expired sign-in link shows an error page."""
    http, _fake, _store = hosted

    assert http.get("/login", params={"req": "missing"}).status_code == 400
    assert _submit_login(http, "missing").status_code == 400


def test_ip_rate_limit(hosted, monkeypatch):
    """Too many login posts from one IP are throttled."""
    http, _fake, _store = hosted
    monkeypatch.setattr(
        login_module,
        "_login_limiter",
        login_module._RateLimiter(2, 60.0),  # pylint: disable=protected-access
    )

    assert _submit_login(http, "missing").status_code == 400
    assert _submit_login(http, "missing").status_code == 400
    assert _submit_login(http, "missing").status_code == 429


def test_store_never_holds_plaintext_secrets(hosted, tmp_path):
    """API keys are encrypted and tokens are only stored as hashes."""
    http, _fake, _store = hosted
    tokens = _login(http)

    raw = b"".join(path.read_bytes() for path in tmp_path.glob("auth.sqlite3*"))

    assert API_KEY.encode() not in raw
    assert tokens["access_token"].encode() not in raw
    assert tokens["refresh_token"].encode() not in raw


def test_healthz(hosted):
    """The health check is public."""
    http, _fake, _store = hosted

    assert http.get("/healthz").json() == {"status": "ok"}


def _principal(grant_id: str, athlete_id: str = "i42") -> GrantAccessToken:
    return GrantAccessToken(
        token="t",
        client_id="c",
        scopes=["intervals"],
        grant_id=grant_id,
        athlete_id=athlete_id,
        api_key=API_KEY,
    )


def test_hosted_request_without_principal_never_uses_server_key(monkeypatch):
    """Hosted mode refuses to fall back to the server's API_KEY."""
    config = get_config()
    monkeypatch.setattr(config, "auth_mode", "hosted")
    monkeypatch.setattr(config, "api_key", "server-key")

    _url, _auth, _headers, error = client_module._prepare_request_config(  # pylint: disable=protected-access
        "/athlete/i1/wellness", "explicit-key", "GET"
    )

    assert error is not None and "Not authenticated" in error


def test_hosted_request_uses_principal_key(monkeypatch):
    """Hosted mode authenticates with the signed-in user's key, ignoring the api_key argument."""
    config = get_config()
    monkeypatch.setattr(config, "auth_mode", "hosted")
    monkeypatch.setattr(client_module, "current_principal", lambda: _principal("g1"))

    _url, auth, _headers, error = client_module._prepare_request_config(  # pylint: disable=protected-access
        "/athlete/i42/wellness", "explicit-key", "GET"
    )

    assert error is None
    request = next(auth.auth_flow(httpx.Request("GET", "https://intervals.icu")))
    assert request.headers["authorization"] == (
        "Basic " + base64.b64encode(f"API_KEY:{API_KEY}".encode()).decode()
    )


def test_resolve_athlete_id_with_principal(monkeypatch):
    """The principal's athlete wins; other athletes are rejected; i-prefix is ignored."""
    monkeypatch.setattr(validation_module, "current_principal", lambda: _principal("g1"))

    assert validation_module.resolve_athlete_id(None, "i1") == ("i42", None)
    assert validation_module.resolve_athlete_id("42", "i1") == ("i42", None)
    athlete_id, error = validation_module.resolve_athlete_id("i99", "i1")
    assert athlete_id == "" and error is not None


def test_gear_cache_is_isolated_per_grant(monkeypatch):
    """Two signed-in users never share cached gear, even for the same athlete id."""
    gear_module._GEAR_RAW_CACHE.clear()  # pylint: disable=protected-access
    calls: list[str] = []

    async def fake_request(*_args, **_kwargs):
        calls.append("call")
        return [{"id": "b1", "name": f"Bike {len(calls)}"}]

    monkeypatch.setattr(gear_module, "make_intervals_request", fake_request)
    monkeypatch.setattr(validation_module, "current_principal", lambda: _principal("g1"))

    monkeypatch.setattr(gear_module, "current_principal", lambda: _principal("g1"))
    first = asyncio.run(gear_module.get_gear_raw(athlete_id="i42"))
    assert asyncio.run(gear_module.get_gear_raw(athlete_id="i42")) == first

    monkeypatch.setattr(gear_module, "current_principal", lambda: _principal("g2"))
    second = asyncio.run(gear_module.get_gear_raw(athlete_id="i42"))

    assert len(calls) == 2
    assert second != first
    gear_module._GEAR_RAW_CACHE.clear()  # pylint: disable=protected-access


def test_current_principal_outside_request():
    """Outside of an MCP request there is no principal."""
    assert context_module.current_principal() is None
