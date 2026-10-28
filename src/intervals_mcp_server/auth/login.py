"""
Login page for hosted mode.

``GET /login?req=<id>`` renders a form asking for the user's Intervals.icu athlete ID
and API key. ``POST /login`` verifies the credentials against the Intervals.icu API,
creates a grant and redirects back to the MCP client with an authorization code.
"""

import html
import logging
import time
from collections import defaultdict, deque
from http import HTTPStatus
from urllib.parse import urlparse

import httpx  # pylint: disable=import-error
from mcp.server.fastmcp import FastMCP  # pylint: disable=import-error
from starlette.requests import Request  # pylint: disable=import-error
from starlette.responses import HTMLResponse, RedirectResponse, Response  # pylint: disable=import-error

from intervals_mcp_server.api.client import get_httpx_client
from intervals_mcp_server.auth.provider import LOGIN_PATH, HostedOAuthProvider
from intervals_mcp_server.auth.store import PendingAuthorization
from intervals_mcp_server.config import get_config
from intervals_mcp_server.utils.validation import validate_athlete_id

logger = logging.getLogger("intervals_icu_mcp_server")

MAX_ATTEMPTS_PER_LOGIN = 5
MAX_POSTS_PER_IP_PER_MINUTE = 10


class _RateLimiter:  # pylint: disable=too-few-public-methods
    """In-memory sliding-window limiter keyed by client IP."""

    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        """Record a hit for ``key`` and return whether it is within the limit."""
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > self.window_seconds:
            hits.popleft()
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        if len(self._hits) > 10_000:
            # Drop idle keys so the table can't grow without bound.
            for idle in [
                k for k, v in self._hits.items() if not v or now - v[-1] > self.window_seconds
            ]:
                del self._hits[idle]
        return True


_login_limiter = _RateLimiter(MAX_POSTS_PER_IP_PER_MINUTE, 60.0)


def _client_ip(request: Request) -> str:
    """Return the client IP, preferring the address appended by the reverse proxy."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def _redirect_source(redirect_uri: str) -> str:
    """Return the CSP source expression for the client's redirect URI."""
    parsed = urlparse(redirect_uri)
    if parsed.scheme in ("http", "https"):
        return f"{parsed.scheme}://{parsed.netloc}"
    return f"{parsed.scheme}:"


def _security_headers(form_target: str | None = None) -> dict[str, str]:
    # Browsers apply form-action to the redirect that follows a form POST, so the
    # client's redirect origin has to be allowed alongside 'self'.
    form_action = "'self'" + (f" {form_target}" if form_target else "")
    return {
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": (
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
            f"frame-ancestors 'none'; form-action {form_action}"
        ),
    }


_STYLE = """
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#f4f5f7;color:#1d2330;
margin:0;padding:16px;display:flex;justify-content:center}
main{background:#fff;max-width:420px;width:100%;margin-top:6vh;padding:28px;border-radius:12px;
box-shadow:0 1px 3px rgba(0,0,0,.08)}
h1{font-size:1.3rem;margin:0 0 8px}p{line-height:1.45;margin:0 0 14px}
label{display:block;font-weight:600;margin:14px 0 6px}
input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #c5cad3;border-radius:8px;font-size:1rem}
.hint{color:#5b6475;font-size:.85rem;margin-top:6px}
.error{background:#fdecec;color:#8a1c1c;padding:10px 12px;border-radius:8px}
.actions{display:flex;gap:10px;margin-top:22px}
button{flex:1;padding:11px;border-radius:8px;border:0;font-size:1rem;cursor:pointer}
.primary{background:#2457d6;color:#fff}.secondary{background:#e7e9ee;color:#1d2330}
@media (prefers-color-scheme:dark){body{background:#14171c;color:#e6e8ec}
main{background:#1d2128;box-shadow:none}input{background:#14171c;color:#e6e8ec;border-color:#3a404b}
.hint{color:#9aa3b2}.secondary{background:#2c313a;color:#e6e8ec}.error{background:#3d1c1c;color:#f3b4b4}}
"""


def _page(title: str, body: str) -> str:
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)}</title><style>{_STYLE}</style></head>"
        f"<body><main>{body}</main></body></html>"
    )


def _message_response(title: str, message: str, status_code: int) -> HTMLResponse:
    body = f"<h1>{html.escape(title)}</h1><p>{html.escape(message)}</p>"
    return HTMLResponse(_page(title, body), status_code=status_code, headers=_security_headers())


def _login_form_response(
    pending: PendingAuthorization,
    client_name: str,
    error: str | None = None,
    athlete_id: str = "",
    status_code: int = 200,
) -> HTMLResponse:
    redirect_uri = str(pending.params.redirect_uri)
    redirect_host = urlparse(redirect_uri).netloc or urlparse(redirect_uri).scheme
    error_html = f'<p class="error" role="alert">{html.escape(error)}</p>' if error else ""
    body = f"""
<h1>Connect Intervals.icu</h1>
<p><strong>{html.escape(client_name)}</strong> ({html.escape(redirect_host)}) is asking to read and
modify your Intervals.icu data. Only continue if you started this connection yourself.</p>
{error_html}
<form method="post" action="{LOGIN_PATH}">
<input type="hidden" name="req" value="{html.escape(pending.id)}">
<label for="athlete_id">Athlete ID</label>
<input id="athlete_id" name="athlete_id" placeholder="i123456" value="{html.escape(athlete_id)}"
 autocomplete="username" required>
<p class="hint">Shown in your Intervals.icu URL, e.g. intervals.icu/athlete/<strong>i123456</strong>/...</p>
<label for="api_key">API key</label>
<input id="api_key" name="api_key" type="password" autocomplete="current-password" required>
<p class="hint">In Intervals.icu go to Settings &rarr; Developer Settings (API) and generate a key.
Regenerating the key later disconnects this client.</p>
<div class="actions">
<button class="secondary" type="submit" name="action" value="cancel" formnovalidate>Cancel</button>
<button class="primary" type="submit" name="action" value="login">Connect</button>
</div>
</form>"""
    return HTMLResponse(
        _page("Connect Intervals.icu", body),
        status_code=status_code,
        headers=_security_headers(_redirect_source(redirect_uri)),
    )


def _redirect(url: str, form_target: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=302, headers=_security_headers(form_target))


async def verify_credentials(  # pylint: disable=too-many-return-statements
    athlete_id: str, api_key: str
) -> tuple[str | None, str | None]:
    """Check an API key against the Intervals.icu API.

    Returns:
        Tuple of (canonical_athlete_id, error_message). Exactly one of them is None.
    """
    config = get_config()
    client = await get_httpx_client()
    try:
        response = await client.get(
            f"{config.intervals_api_base_url}/athlete/{athlete_id}",
            auth=httpx.BasicAuth("API_KEY", api_key),
            headers={"User-Agent": config.user_agent, "Accept": "application/json"},
            timeout=15.0,
        )
    except httpx.HTTPError as exc:
        logger.warning("Credential check could not reach Intervals.icu: %s", type(exc).__name__)
        return None, "Could not reach Intervals.icu. Please try again in a moment."

    if response.status_code == HTTPStatus.UNAUTHORIZED:
        return None, "Intervals.icu rejected this API key. Check that you copied the whole key."
    if response.status_code in (HTTPStatus.FORBIDDEN, HTTPStatus.NOT_FOUND):
        return None, f"This API key does not have access to athlete {athlete_id}."
    if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
        return None, "Intervals.icu is rate limiting requests. Please try again in a minute."
    if response.status_code >= 400:
        logger.warning("Credential check failed with HTTP %s", response.status_code)
        return None, "Intervals.icu returned an unexpected error. Please try again."

    try:
        canonical = response.json().get("id")
    except (ValueError, AttributeError):
        canonical = None
    if isinstance(canonical, str):
        try:
            validate_athlete_id(canonical)
            return canonical, None
        except ValueError:
            pass
    return athlete_id, None


def register_login_routes(mcp: FastMCP, provider: HostedOAuthProvider) -> None:
    """Register the login page routes on the FastMCP server."""

    async def _load(pending_id: str) -> tuple[PendingAuthorization, str] | None:
        pending = await provider.get_pending(pending_id) if pending_id else None
        if pending is None:
            return None
        client = await provider.get_client(pending.client_id)
        if client is None:
            return None
        return pending, client.client_name or "An MCP client"

    @mcp.custom_route(LOGIN_PATH, methods=["GET"], include_in_schema=False)
    async def login_page(request: Request) -> Response:
        loaded = await _load(request.query_params.get("req", ""))
        if loaded is None:
            return _message_response(
                "Sign-in link expired",
                "This sign-in link is invalid or has expired. Start the connection again from your MCP client.",
                HTTPStatus.BAD_REQUEST,
            )
        pending, client_name = loaded
        return _login_form_response(pending, client_name)

    @mcp.custom_route(LOGIN_PATH, methods=["POST"], include_in_schema=False)
    async def login_submit(request: Request) -> Response:  # pylint: disable=too-many-return-statements
        if not _login_limiter.allow(_client_ip(request)):
            return _message_response(
                "Too many attempts",
                "Too many sign-in attempts. Wait a minute and try again.",
                HTTPStatus.TOO_MANY_REQUESTS,
            )

        form = await request.form()
        loaded = await _load(str(form.get("req", "")))
        if loaded is None:
            return _message_response(
                "Sign-in link expired",
                "This sign-in link is invalid or has expired. Start the connection again from your MCP client.",
                HTTPStatus.BAD_REQUEST,
            )
        pending, client_name = loaded
        form_target = _redirect_source(str(pending.params.redirect_uri))

        if form.get("action") == "cancel":
            return _redirect(await provider.deny_login(pending), form_target)

        if await provider.store.record_attempt(pending.id) > MAX_ATTEMPTS_PER_LOGIN:
            await provider.store.delete_pending(pending.id)
            return _message_response(
                "Too many attempts",
                "Too many failed sign-in attempts. Start the connection again from your MCP client.",
                HTTPStatus.BAD_REQUEST,
            )

        athlete_id = str(form.get("athlete_id", "")).strip()
        api_key = str(form.get("api_key", "")).strip()
        try:
            validate_athlete_id(athlete_id)
            if not athlete_id or not api_key:
                raise ValueError("Enter both your athlete ID and API key.")
        except ValueError as exc:
            return _login_form_response(
                pending, client_name, str(exc), athlete_id, HTTPStatus.BAD_REQUEST
            )

        verified_id, error = await verify_credentials(athlete_id, api_key)
        if verified_id is None:
            return _login_form_response(
                pending, client_name, error, athlete_id, HTTPStatus.BAD_REQUEST
            )

        redirect_url = await provider.complete_login(pending, verified_id, api_key)
        if redirect_url is None:
            return _message_response(
                "Sign-in link already used",
                "This sign-in link was already used. Start the connection again from your MCP client.",
                HTTPStatus.BAD_REQUEST,
            )
        logger.info("Hosted login completed for athlete %s", verified_id)
        return _redirect(redirect_url, form_target)
