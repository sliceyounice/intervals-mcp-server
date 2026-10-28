"""
Access to the authenticated user of the current MCP request.

The SDK's ``get_access_token()`` reads a contextvar that, with stateful streamable HTTP,
is captured when a session starts rather than per request. The lowlevel ``request_ctx``
holds the Starlette request of the message being handled, so it is read first.
"""

from mcp.server.auth.middleware.auth_context import get_access_token  # pylint: disable=import-error
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser  # pylint: disable=import-error
from mcp.server.lowlevel.server import request_ctx  # pylint: disable=import-error

from intervals_mcp_server.auth.models import GrantAccessToken


def current_principal() -> GrantAccessToken | None:
    """Return the hosted-mode access token of the current request, if any."""
    try:
        request = request_ctx.get().request
    except LookupError:
        request = None

    token = None
    if request is not None:
        user = request.scope.get("user")
        if isinstance(user, AuthenticatedUser):
            token = user.access_token
    else:
        token = get_access_token()

    return token if isinstance(token, GrantAccessToken) else None
