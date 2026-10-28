"""
OAuth authorization server provider for hosted mode.

Implements the MCP SDK's ``OAuthAuthorizationServerProvider``. Instead of redirecting
to a third-party OAuth server, ``authorize()`` sends the user to this server's own
login page (see ``auth/login.py``), which calls ``complete_login()`` once the user's
Intervals.icu credentials have been verified.
"""

import secrets
import time

from mcp.server.auth.provider import (  # pylint: disable=import-error
    AuthorizationParams,
    AuthorizeError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken  # pylint: disable=import-error

from intervals_mcp_server.auth.models import (
    MCP_SCOPE,
    GrantAccessToken,
    GrantAuthCode,
    GrantRefreshToken,
)
from intervals_mcp_server.auth.store import AuthStore, PendingAuthorization

AUTH_CODE_TTL_SECONDS = 5 * 60
ACCESS_TOKEN_TTL_SECONDS = 60 * 60
REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60

LOGIN_PATH = "/login"


def _new_secret() -> str:
    """Return a random URL-safe secret with 256 bits of entropy."""
    return secrets.token_urlsafe(32)


class HostedOAuthProvider:
    """Authorization server that authenticates users with their Intervals.icu API key."""

    def __init__(self, store: AuthStore, public_base_url: str) -> None:
        self.store = store
        self.public_base_url = public_base_url.rstrip("/")

    # Client registration -------------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Load a dynamically registered client."""
        return await self.store.get_client(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Persist a dynamically registered client."""
        await self.store.save_client(client_info)

    # Authorization ---------------------------------------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """Remember the authorization request and send the user to the login page."""
        if client.client_id is None:
            raise AuthorizeError(error="unauthorized_client", error_description="Unknown client")
        pending_id = _new_secret()
        await self.store.create_pending(pending_id, client.client_id, params)
        return f"{self.public_base_url}{LOGIN_PATH}?req={pending_id}"

    async def get_pending(self, pending_id: str) -> PendingAuthorization | None:
        """Load a pending login for the login page."""
        return await self.store.get_pending(pending_id)

    async def complete_login(
        self, pending: PendingAuthorization, athlete_id: str, api_key: str
    ) -> str | None:
        """Create a grant for verified credentials and return the client redirect URL.

        Returns None if the pending login was already used (e.g. a double submit).
        """
        if not await self.store.delete_pending(pending.id):
            return None

        grant_id = _new_secret()
        code = _new_secret()
        params = pending.params
        code_data = {
            "scopes": [MCP_SCOPE],
            "code_challenge": params.code_challenge,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "resource": params.resource,
        }
        await self.store.create_grant_with_code(
            grant_id=grant_id,
            client_id=pending.client_id,
            athlete_id=athlete_id,
            api_key=api_key,
            code=code,
            code_data=code_data,
            code_expires_at=time.time() + AUTH_CODE_TTL_SECONDS,
        )
        return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)

    async def deny_login(self, pending: PendingAuthorization) -> str:
        """Cancel a pending login and return the client redirect URL with an error."""
        await self.store.delete_pending(pending.id)
        return construct_redirect_uri(
            str(pending.params.redirect_uri),
            error="access_denied",
            error_description="The user cancelled the sign-in.",
            state=pending.params.state,
        )

    # Authorization codes ---------------------------------------------------------

    async def load_authorization_code(  # pylint: disable=unused-argument
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> GrantAuthCode | None:
        """Load an authorization code.

        The SDK rejects the code if its client_id differs from the requesting client
        or if it has expired, so both come from the stored record.
        """
        record = await self.store.get_auth_code(authorization_code)
        if record is None:
            return None
        return GrantAuthCode(
            code=authorization_code,
            client_id=record.client_id,
            grant_id=record.grant_id,
            expires_at=record.expires_at,
            **record.data,
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: GrantAuthCode
    ) -> OAuthToken:
        """Exchange a (single-use) authorization code for access and refresh tokens."""
        if not await self.store.consume_auth_code(authorization_code.code):
            raise TokenError(
                error="invalid_grant", error_description="authorization code was already used"
            )
        return await self._issue_tokens(
            authorization_code.grant_id, client, authorization_code.scopes
        )

    # Refresh tokens ----------------------------------------------------------------

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> GrantRefreshToken | None:
        """Load a refresh token issued to this client."""
        record = await self.store.get_token(refresh_token, "refresh")
        if record is None or record.client_id != client.client_id:
            return None
        return GrantRefreshToken(
            token=refresh_token,
            client_id=record.client_id,
            scopes=record.scopes,
            expires_at=record.expires_at,
            grant_id=record.grant_id,
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: GrantRefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Rotate the refresh token and issue a new access token."""
        return await self._issue_tokens(
            refresh_token.grant_id, client, scopes or refresh_token.scopes
        )

    # Access tokens -----------------------------------------------------------------

    async def load_access_token(self, token: str) -> GrantAccessToken | None:
        """Resolve a bearer token to its grant and decrypted Intervals.icu credentials."""
        record = await self.store.get_token(token, "access")
        if record is None:
            return None
        return GrantAccessToken(
            token=token,
            client_id=record.client_id,
            scopes=record.scopes,
            expires_at=record.expires_at,
            grant_id=record.grant_id,
            athlete_id=record.athlete_id,
            api_key=record.api_key,
        )

    async def revoke_token(self, token: GrantAccessToken | GrantRefreshToken) -> None:
        """Revoke the whole grant behind an access or refresh token."""
        await self.store.revoke_grant(token.grant_id)

    async def _issue_tokens(
        self, grant_id: str, client: OAuthClientInformationFull, scopes: list[str]
    ) -> OAuthToken:
        access_token = _new_secret()
        refresh_token = _new_secret()
        now = int(time.time())
        await self.store.issue_tokens(
            grant_id=grant_id,
            client_id=client.client_id or "",
            scopes=scopes,
            access_token=access_token,
            access_expires_at=now + ACCESS_TOKEN_TTL_SECONDS,
            refresh_token=refresh_token,
            refresh_expires_at=now + REFRESH_TOKEN_TTL_SECONDS,
        )
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL_SECONDS,
            scope=" ".join(scopes),
            refresh_token=refresh_token,
        )
