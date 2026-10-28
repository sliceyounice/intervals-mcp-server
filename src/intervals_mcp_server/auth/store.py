"""
SQLite persistence for hosted mode.

Stores registered MCP clients, in-progress logins, grants (one per completed login,
holding the Fernet-encrypted Intervals.icu API key) and the authorization codes and
tokens issued for them. Codes and tokens are stored as SHA-256 hashes only.

Each operation opens its own short-lived connection in a worker thread, so the store
needs no lifecycle management and is safe to share across concurrent requests.
"""

import hashlib
import json
import logging
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, TypeVar

import anyio.to_thread  # pylint: disable=import-error
from cryptography.fernet import Fernet, InvalidToken  # pylint: disable=import-error
from mcp.server.auth.provider import AuthorizationParams  # pylint: disable=import-error
from mcp.shared.auth import OAuthClientInformationFull  # pylint: disable=import-error

from intervals_mcp_server.config import get_config

logger = logging.getLogger("intervals_icu_mcp_server")

T = TypeVar("T")

PENDING_TTL_SECONDS = 15 * 60
# Registered clients that never complete a login are dropped after this long.
UNUSED_CLIENT_TTL_SECONDS = 24 * 60 * 60
# Grants are created just before their authorization code; don't purge them in between.
GRANT_GRACE_SECONDS = 10 * 60
PURGE_INTERVAL_SECONDS = 5 * 60

_SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    info TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_login_at REAL
);
CREATE TABLE IF NOT EXISTS pending_auth (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    params TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS grants (
    grant_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    athlete_id TEXT NOT NULL,
    api_key_enc BLOB NOT NULL,
    created_at REAL NOT NULL,
    last_used_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    data TEXT NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
    grant_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS tokens_grant_idx ON tokens (grant_id);
CREATE INDEX IF NOT EXISTS auth_codes_grant_idx ON auth_codes (grant_id);
"""


def hash_secret(value: str) -> str:
    """Return the SHA-256 hex digest used to store codes and tokens."""
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass
class PendingAuthorization:
    """An /authorize request waiting for the user to sign in."""

    id: str
    client_id: str
    params: AuthorizationParams
    attempts: int
    expires_at: float


@dataclass
class AuthCodeRecord:
    """A stored authorization code."""

    grant_id: str
    client_id: str
    data: dict[str, Any]
    expires_at: float


@dataclass
class TokenRecord:
    """A stored access or refresh token joined with its grant."""

    grant_id: str
    client_id: str
    scopes: list[str]
    expires_at: int
    athlete_id: str
    api_key: str


class AuthStore:
    """SQLite-backed storage for hosted-mode OAuth state."""

    def __init__(self, db_path: str, encryption_key: str) -> None:
        self._db_path = db_path
        self._fernet = Fernet(encryption_key.encode())
        self._last_purge = 0.0
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)
        self._purge(time.time())

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    async def _run(self, func: Callable[[sqlite3.Connection], T]) -> T:
        """Run ``func`` in a transaction on a fresh connection in a worker thread."""

        def _call() -> T:
            with closing(self._connect()) as conn:
                with conn:  # commits on success, rolls back on error
                    return func(conn)

        return await anyio.to_thread.run_sync(_call)

    def _encrypt(self, value: str) -> bytes:
        return self._fernet.encrypt(value.encode())

    def _decrypt(self, value: bytes) -> str | None:
        try:
            return self._fernet.decrypt(value).decode()
        except InvalidToken:
            logger.error("Could not decrypt a stored API key (was TOKEN_ENCRYPTION_KEY changed?).")
            return None

    # Housekeeping -------------------------------------------------------------

    def _purge(self, now: float) -> None:
        with closing(self._connect()) as conn:
            with conn:
                self._purge_with(conn, now)

    def _purge_with(self, conn: sqlite3.Connection, now: float) -> None:
        conn.execute("DELETE FROM pending_auth WHERE expires_at < ?", (now,))
        conn.execute("DELETE FROM auth_codes WHERE expires_at < ?", (now,))
        conn.execute("DELETE FROM tokens WHERE expires_at < ?", (now,))
        conn.execute(
            """DELETE FROM grants WHERE created_at < ?
               AND grant_id NOT IN (SELECT grant_id FROM tokens)
               AND grant_id NOT IN (SELECT grant_id FROM auth_codes)""",
            (now - GRANT_GRACE_SECONDS,),
        )
        conn.execute(
            "DELETE FROM clients WHERE last_login_at IS NULL AND created_at < ?",
            (now - UNUSED_CLIENT_TTL_SECONDS,),
        )
        self._last_purge = now

    def _maybe_purge(self, conn: sqlite3.Connection, now: float) -> None:
        if now - self._last_purge >= PURGE_INTERVAL_SECONDS:
            self._purge_with(conn, now)

    async def purge_expired(self) -> None:
        """Delete expired logins, codes, tokens, orphaned grants and unused clients."""
        await self._run(lambda conn: self._purge_with(conn, time.time()))

    # Clients ------------------------------------------------------------------

    async def save_client(self, client: OAuthClientInformationFull) -> None:
        """Persist a dynamically registered client."""

        def _save(conn: sqlite3.Connection) -> None:
            now = time.time()
            self._maybe_purge(conn, now)
            conn.execute(
                "INSERT OR REPLACE INTO clients (client_id, info, created_at) VALUES (?, ?, ?)",
                (client.client_id, client.model_dump_json(), now),
            )

        await self._run(_save)

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Load a registered client by ID."""

        def _get(conn: sqlite3.Connection) -> str | None:
            row = conn.execute(
                "SELECT info FROM clients WHERE client_id = ?", (client_id,)
            ).fetchone()
            return row["info"] if row else None

        info = await self._run(_get)
        return OAuthClientInformationFull.model_validate_json(info) if info else None

    # Pending logins -----------------------------------------------------------

    async def create_pending(
        self, pending_id: str, client_id: str, params: AuthorizationParams
    ) -> None:
        """Store an /authorize request until the user submits the login form."""

        def _create(conn: sqlite3.Connection) -> None:
            now = time.time()
            self._maybe_purge(conn, now)
            conn.execute(
                "INSERT INTO pending_auth (id, client_id, params, expires_at) VALUES (?, ?, ?, ?)",
                (pending_id, client_id, params.model_dump_json(), now + PENDING_TTL_SECONDS),
            )

        await self._run(_create)

    async def get_pending(self, pending_id: str) -> PendingAuthorization | None:
        """Load an unexpired pending login."""

        def _get(conn: sqlite3.Connection) -> sqlite3.Row | None:
            return conn.execute(
                "SELECT * FROM pending_auth WHERE id = ? AND expires_at >= ?",
                (pending_id, time.time()),
            ).fetchone()

        row = await self._run(_get)
        if row is None:
            return None
        return PendingAuthorization(
            id=row["id"],
            client_id=row["client_id"],
            params=AuthorizationParams.model_validate_json(row["params"]),
            attempts=row["attempts"],
            expires_at=row["expires_at"],
        )

    async def record_attempt(self, pending_id: str) -> int:
        """Increment and return the number of login attempts for a pending login."""

        def _record(conn: sqlite3.Connection) -> int:
            conn.execute(
                "UPDATE pending_auth SET attempts = attempts + 1 WHERE id = ?", (pending_id,)
            )
            row = conn.execute(
                "SELECT attempts FROM pending_auth WHERE id = ?", (pending_id,)
            ).fetchone()
            return int(row["attempts"]) if row else 0

        return await self._run(_record)

    async def delete_pending(self, pending_id: str) -> bool:
        """Delete a pending login. Returns False if it was already consumed."""

        def _delete(conn: sqlite3.Connection) -> bool:
            cursor = conn.execute("DELETE FROM pending_auth WHERE id = ?", (pending_id,))
            return cursor.rowcount > 0

        return await self._run(_delete)

    # Grants and authorization codes ---------------------------------------------

    async def create_grant_with_code(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        grant_id: str,
        client_id: str,
        athlete_id: str,
        api_key: str,
        code: str,
        code_data: dict[str, Any],
        code_expires_at: float,
    ) -> None:
        """Create a grant for a successful login together with its authorization code."""

        def _create(conn: sqlite3.Connection) -> None:
            now = time.time()
            conn.execute(
                """INSERT INTO grants (grant_id, client_id, athlete_id, api_key_enc, created_at, last_used_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (grant_id, client_id, athlete_id, self._encrypt(api_key), now, now),
            )
            conn.execute(
                "INSERT INTO auth_codes (code_hash, grant_id, client_id, data, expires_at) VALUES (?, ?, ?, ?, ?)",
                (hash_secret(code), grant_id, client_id, json.dumps(code_data), code_expires_at),
            )
            conn.execute(
                "UPDATE clients SET last_login_at = ? WHERE client_id = ?", (now, client_id)
            )

        await self._run(_create)

    async def get_auth_code(self, code: str) -> AuthCodeRecord | None:
        """Load an authorization code, if it exists. Expiry is checked by the caller."""

        def _get(conn: sqlite3.Connection) -> sqlite3.Row | None:
            return conn.execute(
                "SELECT grant_id, client_id, data, expires_at FROM auth_codes WHERE code_hash = ?",
                (hash_secret(code),),
            ).fetchone()

        row = await self._run(_get)
        if row is None:
            return None
        return AuthCodeRecord(
            grant_id=row["grant_id"],
            client_id=row["client_id"],
            data=json.loads(row["data"]),
            expires_at=row["expires_at"],
        )

    async def consume_auth_code(self, code: str) -> bool:
        """Delete an authorization code. Returns False if it was already used."""

        def _consume(conn: sqlite3.Connection) -> bool:
            cursor = conn.execute(
                "DELETE FROM auth_codes WHERE code_hash = ?", (hash_secret(code),)
            )
            return cursor.rowcount > 0

        return await self._run(_consume)

    async def revoke_grant(self, grant_id: str) -> None:
        """Delete a grant together with its codes and tokens."""

        def _revoke(conn: sqlite3.Connection) -> None:
            conn.execute("DELETE FROM tokens WHERE grant_id = ?", (grant_id,))
            conn.execute("DELETE FROM auth_codes WHERE grant_id = ?", (grant_id,))
            conn.execute("DELETE FROM grants WHERE grant_id = ?", (grant_id,))

        await self._run(_revoke)

    # Tokens -------------------------------------------------------------------

    async def issue_tokens(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        grant_id: str,
        client_id: str,
        scopes: list[str],
        access_token: str,
        access_expires_at: int,
        refresh_token: str,
        refresh_expires_at: int,
    ) -> None:
        """Store a new access/refresh token pair, replacing the grant's previous tokens."""

        def _issue(conn: sqlite3.Connection) -> None:
            conn.execute("DELETE FROM tokens WHERE grant_id = ?", (grant_id,))
            conn.executemany(
                """INSERT INTO tokens (token_hash, kind, grant_id, client_id, scopes, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                [
                    (
                        hash_secret(access_token),
                        "access",
                        grant_id,
                        client_id,
                        " ".join(scopes),
                        access_expires_at,
                    ),
                    (
                        hash_secret(refresh_token),
                        "refresh",
                        grant_id,
                        client_id,
                        " ".join(scopes),
                        refresh_expires_at,
                    ),
                ],
            )

        await self._run(_issue)

    async def get_token(self, token: str, kind: str) -> TokenRecord | None:
        """Load an unexpired token of the given kind joined with its grant."""

        def _get(conn: sqlite3.Connection) -> sqlite3.Row | None:
            now = time.time()
            row = conn.execute(
                """SELECT t.grant_id, t.client_id, t.scopes, t.expires_at, g.athlete_id, g.api_key_enc
                   FROM tokens t JOIN grants g ON g.grant_id = t.grant_id
                   WHERE t.token_hash = ? AND t.kind = ? AND t.expires_at >= ?""",
                (hash_secret(token), kind, now),
            ).fetchone()
            if row is not None and kind == "access":
                conn.execute(
                    "UPDATE grants SET last_used_at = ? WHERE grant_id = ?", (now, row["grant_id"])
                )
            return row

        row = await self._run(_get)
        if row is None:
            return None
        api_key = self._decrypt(row["api_key_enc"])
        if api_key is None:
            return None
        return TokenRecord(
            grant_id=row["grant_id"],
            client_id=row["client_id"],
            scopes=row["scopes"].split(),
            expires_at=row["expires_at"],
            athlete_id=row["athlete_id"],
            api_key=api_key,
        )


_store: AuthStore | None = None  # pylint: disable=invalid-name


def get_store() -> AuthStore:
    """Return the process-wide store, creating it from configuration on first use."""
    global _store  # pylint: disable=global-statement  # noqa: PLW0603 - singleton pattern
    if _store is None:
        config = get_config()
        _store = AuthStore(config.db_path, config.token_encryption_key)
    return _store


def set_store(store: AuthStore | None) -> None:
    """Replace the process-wide store (used by tests)."""
    global _store  # pylint: disable=global-statement  # noqa: PLW0603 - singleton pattern
    _store = store
