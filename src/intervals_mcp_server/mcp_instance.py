"""
Shared MCP instance module.

This module provides a shared FastMCP instance that can be imported by both
the server module and tool modules without creating cyclic imports.
"""

from mcp.server.fastmcp import FastMCP  # pylint: disable=import-error

from intervals_mcp_server.api.client import setup_api_client
from intervals_mcp_server.config import AUTH_MODE_HOSTED, get_config

_config = get_config()

if _config.auth_mode == AUTH_MODE_HOSTED:
    from intervals_mcp_server.auth.hosted import build_hosted_mcp  # pylint: disable=import-outside-toplevel

    mcp: FastMCP = build_hosted_mcp(_config)  # pylint: disable=invalid-name
else:
    mcp = FastMCP(  # pylint: disable=invalid-name
        "intervals-icu", lifespan=setup_api_client, host=_config.host, port=_config.port
    )
