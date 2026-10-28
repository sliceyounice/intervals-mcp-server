"""
FastMCP server construction for hosted (multi-user) mode.
"""

from mcp.server.auth.settings import (  # pylint: disable=import-error
    AuthSettings,
    ClientRegistrationOptions,
    RevocationOptions,
)
from mcp.server.fastmcp import FastMCP  # pylint: disable=import-error
from mcp.server.transport_security import TransportSecuritySettings  # pylint: disable=import-error
from starlette.requests import Request  # pylint: disable=import-error
from starlette.responses import JSONResponse, Response  # pylint: disable=import-error

from intervals_mcp_server.auth.login import register_login_routes
from intervals_mcp_server.auth.models import MCP_SCOPE
from intervals_mcp_server.auth.provider import HostedOAuthProvider
from intervals_mcp_server.auth.store import get_store
from intervals_mcp_server.config import Config, validate_hosted_config


def build_hosted_mcp(config: Config) -> FastMCP:
    """Create the FastMCP instance with OAuth, the login page and a health check.

    Uses stateless streamable HTTP so every request carries its own bearer token and
    restarts don't invalidate client sessions. No server lifespan is set: with
    stateless HTTP the lifespan runs once per request, so closing shared resources
    there would break concurrent requests.
    """
    validate_hosted_config(config)
    provider = HostedOAuthProvider(get_store(), config.public_base_url)

    server = FastMCP(
        "intervals-icu",
        host=config.host,
        port=config.port,
        stateless_http=True,
        auth_server_provider=provider,
        auth=AuthSettings(
            issuer_url=config.public_base_url,  # type: ignore[arg-type]
            resource_server_url=f"{config.public_base_url}/mcp",  # type: ignore[arg-type]
            required_scopes=[MCP_SCOPE],
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=[MCP_SCOPE],
                default_scopes=[MCP_SCOPE],
            ),
            revocation_options=RevocationOptions(enabled=True),
        ),
        # Newer SDKs turn on Host/Origin checks when bound to localhost, which rejects
        # the public Host header a reverse proxy forwards. Every /mcp request needs a
        # bearer token, so DNS-rebinding protection adds nothing here.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    register_login_routes(server, provider)

    @server.custom_route("/healthz", methods=["GET"], include_in_schema=False)
    async def healthz(_request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    return server
