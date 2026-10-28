"""
Hosted (multi-user) authentication for Intervals.icu MCP Server.

When AUTH_MODE=hosted, the server acts as an OAuth 2.1 authorization server for MCP
clients. Users sign in on a login page with their own Intervals.icu API key and
athlete ID; the key is stored encrypted and used for that user's tool calls.
"""
