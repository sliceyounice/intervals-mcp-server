"""
Configuration management for Intervals.icu MCP Server.

This module handles loading and validation of configuration from environment variables.
"""

import logging
import os
from dataclasses import dataclass

from intervals_mcp_server.utils.validation import validate_athlete_id

# Try to load environment variables from .env file if it exists
try:
    from dotenv import load_dotenv

    _ = load_dotenv()
except ImportError:
    # python-dotenv not installed, proceed without it
    pass

logger = logging.getLogger("intervals_icu_mcp_server")

AUTH_MODE_API_KEY = "api_key"
AUTH_MODE_HOSTED = "hosted"
AUTH_MODES = (AUTH_MODE_API_KEY, AUTH_MODE_HOSTED)


@dataclass
class Config:  # pylint: disable=too-many-instance-attributes
    """Configuration settings for the Intervals.icu MCP Server.

    Hosted-mode settings are only used when ``auth_mode`` is ``hosted``.
    """

    api_key: str
    athlete_id: str
    intervals_api_base_url: str
    user_agent: str
    auth_mode: str = AUTH_MODE_API_KEY
    public_base_url: str = ""
    token_encryption_key: str = ""
    db_path: str = "/data/intervals-mcp.sqlite3"
    host: str = "127.0.0.1"
    port: int = 8000


_config_instance: Config | None = None  # pylint: disable=invalid-name


def load_config() -> Config:
    """
    Load configuration from environment variables.

    Returns:
        Config: Configuration instance with loaded values.

    Raises:
        ValueError: If athlete_id is invalid (when non-empty) or AUTH_MODE is unknown.
    """
    api_key = os.getenv("API_KEY", "")
    athlete_id = os.getenv("ATHLETE_ID", "")
    intervals_api_base_url = os.getenv("INTERVALS_API_BASE_URL", "https://intervals.icu/api/v1")
    user_agent = "intervalsicu-mcp-server/1.0"

    auth_mode = os.getenv("AUTH_MODE", AUTH_MODE_API_KEY).strip().lower()
    if auth_mode not in AUTH_MODES:
        raise ValueError(f"Unsupported AUTH_MODE value. Use one of: {', '.join(AUTH_MODES)}.")

    if auth_mode == AUTH_MODE_HOSTED:
        # Every user brings their own key; the operator's credentials must never be
        # used as a fallback for someone else's requests.
        if api_key or athlete_id:
            logger.warning(
                "AUTH_MODE=hosted: ignoring API_KEY and ATHLETE_ID environment variables."
            )
        api_key = ""
        athlete_id = ""

    # Validate athlete_id if provided (empty string is allowed)
    if athlete_id:
        validate_athlete_id(athlete_id)

    return Config(
        api_key=api_key,
        athlete_id=athlete_id,
        intervals_api_base_url=intervals_api_base_url,
        user_agent=user_agent,
        auth_mode=auth_mode,
        public_base_url=os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/"),
        token_encryption_key=os.getenv("TOKEN_ENCRYPTION_KEY", "").strip(),
        db_path=os.getenv("DB_PATH", "/data/intervals-mcp.sqlite3"),
        host=os.getenv("FASTMCP_HOST", "127.0.0.1"),
        port=int(os.getenv("FASTMCP_PORT", "8000")),
    )


def validate_hosted_config(config: Config) -> None:
    """
    Validate the settings required to run in hosted (multi-user) mode.

    Args:
        config: The configuration to validate.

    Raises:
        ValueError: If a required hosted-mode setting is missing or invalid.
    """
    missing = [
        name
        for name, value in (
            ("PUBLIC_BASE_URL", config.public_base_url),
            ("TOKEN_ENCRYPTION_KEY", config.token_encryption_key),
            ("DB_PATH", config.db_path),
        )
        if not value
    ]
    if missing:
        raise ValueError(f"AUTH_MODE=hosted requires: {', '.join(missing)}.")

    if not config.public_base_url.startswith(("https://", "http://localhost", "http://127.0.0.1")):
        raise ValueError("PUBLIC_BASE_URL must use https:// (http is only allowed for localhost).")

    # Imported lazily so api_key mode does not depend on cryptography at import time.
    from cryptography.fernet import Fernet  # pylint: disable=import-outside-toplevel,import-error

    try:
        Fernet(config.token_encryption_key.encode())
    except ValueError as exc:
        raise ValueError(
            "TOKEN_ENCRYPTION_KEY must be a Fernet key "
            '(generate one with: python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())").'
        ) from exc


def get_config() -> Config:
    """
    Get the configuration instance (singleton pattern).

    Returns:
        Config: The configuration instance.
    """
    global _config_instance  # pylint: disable=global-statement  # noqa: PLW0603 - singleton pattern
    if _config_instance is None:
        _config_instance = load_config()
    return _config_instance
