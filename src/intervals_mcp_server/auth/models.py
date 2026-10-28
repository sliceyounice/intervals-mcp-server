"""
Token and grant models for hosted mode.

These extend the MCP SDK's OAuth models with the grant they belong to. The SDK never
serializes these objects back to clients, so carrying the decrypted API key on the
access token (in memory only) is safe.
"""

# pylint: disable=too-few-public-methods  # pydantic data models

from mcp.server.auth.provider import AccessToken, AuthorizationCode, RefreshToken  # pylint: disable=import-error

# The single scope granted to MCP clients; it covers every tool.
MCP_SCOPE = "intervals"


class GrantAuthCode(AuthorizationCode):
    """Authorization code issued after a successful login."""

    grant_id: str


class GrantRefreshToken(RefreshToken):
    """Refresh token bound to a grant."""

    grant_id: str


class GrantAccessToken(AccessToken):
    """Access token bound to a grant, carrying the user's Intervals.icu credentials."""

    grant_id: str
    athlete_id: str
    api_key: str
